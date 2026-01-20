// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package fsim

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/fsim/chunking"
	"github.com/fido-device-onboard/go-fdo/serviceinfo"
)

// WiFiOwner implements the fdo.wifi FSIM for owner-side WiFi configuration.
// It follows the specification in fdo.wifi-setup.md and uses the generic chunking strategy.
type WiFiOwner struct {
	// Networks to configure on the device
	networks []*WiFiNetwork

	// Certificates and CA bundles to send
	certificates []WiFiCertificate
	caBundles    []WiFiCABundle

	// Internal state
	currentNetworkIndex int
	currentCertIndex    int
	currentCAIndex      int
	sendState           wifiSendState

	// Chunking senders
	csrReceiver *chunking.ChunkReceiver
	certSender  *chunking.ChunkSender
	caSender    *chunking.ChunkSender

	// Results
	lastCSR     []byte
	lastCSRMeta map[string]any
	certResult  *chunking.ResultMessage
	caResult    *chunking.ResultMessage
}

type wifiSendState int

const (
	wifiStateIdle wifiSendState = iota
	wifiStateSendingNetwork
	wifiStateWaitingCSR
	wifiStateSendingCert
	wifiStateSendingCA
)

// WiFiCertificate represents a certificate to send to the device.
type WiFiCertificate struct {
	NetworkID string         // Required: network_id (field -1)
	SSID      string         // Optional: ssid (field -2)
	CertRole  int            // Optional: cert_role (field -3): 0=client, 1=intermediate, 2=ca
	CertData  []byte         // Certificate data (DER or PEM)
	Metadata  map[string]any // Optional: metadata (field -4)
	HashAlg   string         // Optional: hash algorithm
}

// WiFiCABundle represents a CA bundle to send to the device.
type WiFiCABundle struct {
	NetworkID string         // Required: network_id (field -1)
	BundleID  string         // Optional: bundle_id (field -2)
	CAData    []byte         // CA certificate data (DER or PEM, possibly concatenated)
	Metadata  map[string]any // Optional: metadata (field -3)
	HashAlg   string         // Optional: hash algorithm
}

var _ serviceinfo.OwnerModule = (*WiFiOwner)(nil)

// HandleInfo implements serviceinfo.OwnerModule.
func (w *WiFiOwner) HandleInfo(ctx context.Context, messageName string, messageBody io.Reader) error {
	return w.receive(ctx, messageName, messageBody)
}

// ProduceInfo implements serviceinfo.OwnerModule.
func (w *WiFiOwner) ProduceInfo(ctx context.Context, producer *serviceinfo.Producer) (blockPeer, moduleDone bool, _ error) {
	return w.produceInfo(ctx, producer)
}

// Transition implements serviceinfo.OwnerModule.
func (w *WiFiOwner) Transition(active bool) error {
	if !active {
		w.reset()
	}
	return nil
}

// AddNetwork adds a network configuration to send to the device.
func (w *WiFiOwner) AddNetwork(network *WiFiNetwork) {
	w.networks = append(w.networks, network)
}

// AddCertificate adds a certificate to send to the device.
func (w *WiFiOwner) AddCertificate(cert WiFiCertificate) {
	if cert.HashAlg == "" {
		cert.HashAlg = "sha256"
	}
	w.certificates = append(w.certificates, cert)
}

// AddCABundle adds a CA bundle to send to the device.
func (w *WiFiOwner) AddCABundle(bundle WiFiCABundle) {
	if bundle.HashAlg == "" {
		bundle.HashAlg = "sha256"
	}
	w.caBundles = append(w.caBundles, bundle)
}

// reset clears the internal state.
func (w *WiFiOwner) reset() {
	w.currentNetworkIndex = 0
	w.currentCertIndex = 0
	w.currentCAIndex = 0
	w.sendState = wifiStateIdle
	w.csrReceiver = nil
	w.certSender = nil
	w.caSender = nil
	w.lastCSR = nil
	w.lastCSRMeta = nil
	w.certResult = nil
	w.caResult = nil
}

// produceInfo generates messages to send to the device.
func (w *WiFiOwner) produceInfo(ctx context.Context, producer *serviceinfo.Producer) (blockPeer, moduleDone bool, _ error) {
	switch w.sendState {
	case wifiStateIdle:
		// Check if we have networks to send
		if w.currentNetworkIndex < len(w.networks) {
			w.sendState = wifiStateSendingNetwork
			return w.produceInfo(ctx, producer)
		}

		// Check if we have certificates to send
		if w.currentCertIndex < len(w.certificates) {
			w.sendState = wifiStateSendingCert
			return w.produceInfo(ctx, producer)
		}

		// Check if we have CA bundles to send
		if w.currentCAIndex < len(w.caBundles) {
			w.sendState = wifiStateSendingCA
			return w.produceInfo(ctx, producer)
		}

		// All done
		return false, true, nil

	case wifiStateSendingNetwork:
		network := w.networks[w.currentNetworkIndex]

		// Encode network as CBOR map with integer keys
		networkMap := make(map[any]any)
		networkMap[0] = network.Version
		networkMap[1] = network.NetworkID
		networkMap[2] = network.SSID
		networkMap[3] = network.AuthType

		if len(network.Password) > 0 {
			networkMap[4] = network.Password
		}
		if len(network.CACerts) > 0 {
			certs := make([]any, len(network.CACerts))
			for i, cert := range network.CACerts {
				certs[i] = cert
			}
			networkMap[5] = certs
		}
		networkMap[6] = network.TrustLevel

		if network.FastRoaming != nil {
			networkMap[7] = network.FastRoaming
		}
		if network.Hotspot2 != nil {
			networkMap[8] = network.Hotspot2
		}
		if network.EAPUsername != "" {
			networkMap[9] = network.EAPUsername
		}
		if len(network.EAPPassword) > 0 {
			networkMap[10] = network.EAPPassword
		}

		// Encode and send
		var buf bytes.Buffer
		if err := cbor.NewEncoder(&buf).Encode(networkMap); err != nil {
			return false, false, fmt.Errorf("failed to encode network-add: %w", err)
		}

		if err := producer.WriteChunk("network-add", buf.Bytes()); err != nil {
			return false, false, fmt.Errorf("failed to send network-add: %w", err)
		}

		slog.Debug("fdo.wifi sent network-add",
			"network_id", network.NetworkID,
			"ssid", network.SSID)

		w.currentNetworkIndex++

		// If this is an enterprise network, wait for CSR
		if network.AuthType == 3 { // wpa3-enterprise
			w.sendState = wifiStateWaitingCSR
			return true, false, nil // Block to wait for CSR
		}

		w.sendState = wifiStateIdle
		return false, false, nil

	case wifiStateWaitingCSR:
		// Waiting for device to send CSR
		return true, false, nil

	case wifiStateSendingCert:
		return w.sendCertificate(producer)

	case wifiStateSendingCA:
		return w.sendCABundle(producer)
	}

	return false, false, nil
}

// sendCertificate sends a certificate using the chunking strategy.
func (w *WiFiOwner) sendCertificate(producer *serviceinfo.Producer) (blockPeer, moduleDone bool, _ error) {
	// Initialize sender if needed
	if w.certSender == nil {
		cert := &w.certificates[w.currentCertIndex]
		w.certSender = chunking.NewChunkSender("cert", cert.CertData)

		if cert.HashAlg != "" {
			w.certSender.BeginFields.HashAlg = cert.HashAlg
		}

		// Set FSIM-specific fields per fdo.wifi-setup.md
		w.certSender.BeginFields.FSIMFields[-1] = cert.NetworkID
		if cert.SSID != "" {
			w.certSender.BeginFields.FSIMFields[-2] = cert.SSID
		}
		if cert.CertRole >= 0 {
			w.certSender.BeginFields.FSIMFields[-3] = cert.CertRole
		}
		if cert.Metadata != nil {
			w.certSender.BeginFields.FSIMFields[-4] = cert.Metadata
		}
	}

	// Send begin
	if w.certSender.GetBytesSent() == 0 {
		if err := w.certSender.SendBegin(producer); err != nil {
			return false, false, fmt.Errorf("failed to send cert-begin: %w", err)
		}
		slog.Debug("fdo.wifi sent cert-begin")
		return false, false, nil
	}

	// Send chunks
	if !w.certSender.IsCompleted() {
		done, err := w.certSender.SendNextChunk(producer)
		if err != nil {
			return false, false, fmt.Errorf("failed to send cert chunk: %w", err)
		}
		if !done {
			return false, false, nil
		}

		// Send end
		if err := w.certSender.SendEnd(producer); err != nil {
			return false, false, fmt.Errorf("failed to send cert-end: %w", err)
		}
		slog.Debug("fdo.wifi sent cert-end")

		// Wait for result
		return true, false, nil
	}

	// Result received, move to next
	w.certSender = nil
	w.currentCertIndex++
	w.sendState = wifiStateIdle
	return false, false, nil
}

// sendCABundle sends a CA bundle using the chunking strategy.
func (w *WiFiOwner) sendCABundle(producer *serviceinfo.Producer) (blockPeer, moduleDone bool, _ error) {
	// Initialize sender if needed
	if w.caSender == nil {
		bundle := &w.caBundles[w.currentCAIndex]
		w.caSender = chunking.NewChunkSender("ca", bundle.CAData)

		if bundle.HashAlg != "" {
			w.caSender.BeginFields.HashAlg = bundle.HashAlg
		}

		// Set FSIM-specific fields
		w.caSender.BeginFields.FSIMFields[-1] = bundle.NetworkID
		if bundle.BundleID != "" {
			w.caSender.BeginFields.FSIMFields[-2] = bundle.BundleID
		}
		if bundle.Metadata != nil {
			w.caSender.BeginFields.FSIMFields[-3] = bundle.Metadata
		}
	}

	// Send begin
	if w.caSender.GetBytesSent() == 0 {
		if err := w.caSender.SendBegin(producer); err != nil {
			return false, false, fmt.Errorf("failed to send ca-begin: %w", err)
		}
		slog.Debug("fdo.wifi sent ca-begin")
		return false, false, nil
	}

	// Send chunks
	if !w.caSender.IsCompleted() {
		done, err := w.caSender.SendNextChunk(producer)
		if err != nil {
			return false, false, fmt.Errorf("failed to send ca chunk: %w", err)
		}
		if !done {
			return false, false, nil
		}

		// Send end
		if err := w.caSender.SendEnd(producer); err != nil {
			return false, false, fmt.Errorf("failed to send ca-end: %w", err)
		}
		slog.Debug("fdo.wifi sent ca-end")

		// Wait for result
		return true, false, nil
	}

	// Result received, move to next
	w.caSender = nil
	w.currentCAIndex++
	w.sendState = wifiStateIdle
	return false, false, nil
}

// receive processes incoming messages from the device.
func (w *WiFiOwner) receive(ctx context.Context, messageName string, messageBody io.Reader) error {
	slog.Debug("fdo.wifi owner received message", "key", messageName)

	// Handle CSR chunked messages (device sends to owner)
	if strings.HasPrefix(messageName, "csr-") {
		return w.handleCSRMessage(messageName, messageBody)
	}

	// Handle cert-result
	if messageName == "cert-result" {
		if w.certSender == nil {
			return fmt.Errorf("received cert-result without active transfer")
		}

		result, err := w.certSender.HandleResult(messageBody)
		if err != nil {
			return fmt.Errorf("failed to decode cert-result: %w", err)
		}

		w.certResult = result

		if result.StatusCode == 0 {
			slog.Info("fdo.wifi certificate installed", "message", result.Message)
		} else {
			slog.Warn("fdo.wifi certificate failed", "status", result.StatusCode, "message", result.Message)
		}

		return nil
	}

	// Handle ca-result
	if messageName == "ca-result" {
		if w.caSender == nil {
			return fmt.Errorf("received ca-result without active transfer")
		}

		result, err := w.caSender.HandleResult(messageBody)
		if err != nil {
			return fmt.Errorf("failed to decode ca-result: %w", err)
		}

		w.caResult = result

		if result.StatusCode == 0 {
			slog.Info("fdo.wifi CA bundle installed", "message", result.Message)
		} else {
			slog.Warn("fdo.wifi CA bundle failed", "status", result.StatusCode, "message", result.Message)
		}

		return nil
	}

	slog.Warn("fdo.wifi owner received unknown message", "key", messageName)
	return nil
}

// handleCSRMessage processes CSR chunked messages from the device.
func (w *WiFiOwner) handleCSRMessage(messageName string, messageBody io.Reader) error {
	// Initialize receiver on first message
	if w.csrReceiver == nil {
		w.csrReceiver = &chunking.ChunkReceiver{
			PayloadName: "csr",
			OnBegin:     w.onCSRBegin,
			OnChunk:     w.onCSRChunk,
			OnEnd:       w.onCSREnd,
		}
	}

	// Handle the message
	if err := w.csrReceiver.HandleMessage(messageName, messageBody); err != nil {
		w.csrReceiver = nil
		return err
	}

	// After successful end, CSR is available in w.lastCSR
	if strings.HasSuffix(messageName, "-end") && !w.csrReceiver.IsReceiving() {
		slog.Info("fdo.wifi received CSR", "size", len(w.lastCSR))
		w.csrReceiver = nil

		// Unblock to continue sending certificates
		w.sendState = wifiStateIdle
	}

	return nil
}

// onCSRBegin is called when csr-begin is received.
func (w *WiFiOwner) onCSRBegin(begin chunking.BeginMessage) error {
	// Extract network_id from field -1
	networkID, _ := begin.FSIMFields[-1].(string)
	ssid, _ := begin.FSIMFields[-2].(string)

	slog.Debug("fdo.wifi csr-begin", "network_id", networkID, "ssid", ssid)

	// Store metadata for application use
	w.lastCSRMeta = make(map[string]any)
	w.lastCSRMeta["network_id"] = networkID
	w.lastCSRMeta["ssid"] = ssid
	if csrType, ok := begin.FSIMFields[-3].(int); ok {
		w.lastCSRMeta["csr_type"] = csrType
	}
	if metadata, ok := begin.FSIMFields[-4].(map[string]any); ok {
		w.lastCSRMeta["metadata"] = metadata
	}

	return nil
}

// onCSRChunk is called for each csr-data-<n> chunk.
func (w *WiFiOwner) onCSRChunk(data []byte) error {
	return nil
}

// onCSREnd is called when csr-end is received.
func (w *WiFiOwner) onCSREnd(end chunking.EndMessage) error {
	// Store the complete CSR
	w.lastCSR = w.csrReceiver.GetBuffer()
	return nil
}

// GetLastCSR returns the last received CSR and its metadata.
func (w *WiFiOwner) GetLastCSR() (csrData []byte, metadata map[string]any) {
	return w.lastCSR, w.lastCSRMeta
}

// SendCSRResult sends a csr-result message to acknowledge CSR processing.
// This should be called by the application after processing the CSR.
func (w *WiFiOwner) SendCSRResult(statusCode int, message string) {
	// Store for next ProduceInfo call
	// In a real implementation, this would need to be queued and sent
	slog.Debug("fdo.wifi csr-result queued", "status", statusCode, "message", message)
}
