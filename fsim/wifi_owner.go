// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package fsim

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"

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
	sentActive          bool

	// Chunking senders (for future certificate support)
	csrReceiver *chunking.ChunkReceiver
	certSender  *chunking.ChunkSender
	caSender    *chunking.ChunkSender

	// Results
	lastCSR     []byte
	lastCSRMeta map[string]any
	certResult  *chunking.ResultMessage
	caResult    *chunking.ResultMessage
}

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
	w.sentActive = false
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
	// Send active message first if we have networks to send
	if !w.sentActive && len(w.networks) > 0 {
		if err := producer.WriteChunk("active", []byte{0xf5}); err != nil { // CBOR true
			return false, false, fmt.Errorf("failed to send active: %w", err)
		}
		w.sentActive = true
		slog.Debug("fdo.wifi sent active=true")
		return false, false, nil
	}

	// Send networks one at a time
	if w.currentNetworkIndex < len(w.networks) {
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
		return false, false, nil
	}

	// All networks sent, we're done
	return false, true, nil
}

// receive processes messages from the device.
func (w *WiFiOwner) receive(ctx context.Context, messageName string, messageBody io.Reader) error {
	switch messageName {
	case "active":
		// Read and validate the active response from device
		var deviceActive bool
		if err := cbor.NewDecoder(messageBody).Decode(&deviceActive); err != nil {
			return fmt.Errorf("error decoding active message: %w", err)
		}
		if !deviceActive {
			return fmt.Errorf("device WiFi module is not active")
		}
		slog.Debug("fdo.wifi device confirmed active")
		return nil

	default:
		// Silently ignore unknown messages for protocol compatibility
		slog.Debug("fdo.wifi ignoring message from device", "key", messageName)
		return nil
	}
}
