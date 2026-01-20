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

// WiFiHandler defines the interface for handling WiFi network configuration.
// Applications must implement this interface to process WiFi setup according to fdo.wifi-setup.md.
type WiFiHandler interface {
	// AddNetwork is called when a network-add message is received.
	// The network parameter contains the CBOR-decoded network configuration.
	// Returns error if the network cannot be added.
	AddNetwork(network *WiFiNetwork) error

	// GenerateCSR generates a Certificate Signing Request for the given network.
	// Returns the CSR data (DER or PEM format) and optional metadata.
	GenerateCSR(networkID, ssid string) (csrData []byte, metadata map[string]any, err error)

	// InstallCertificate is called when a client certificate is received.
	// Returns status code (0=success, 1=warning, 2=error) and optional message.
	InstallCertificate(networkID, ssid string, certData []byte, metadata map[string]any) (statusCode int, message string, err error)

	// InstallCACerts is called when CA certificates are received.
	// Returns status code and optional message.
	InstallCACerts(networkID, bundleID string, caData []byte, metadata map[string]any) (statusCode int, message string, err error)
}

// WiFiNetwork represents a WiFi network configuration per fdo.wifi-setup.md.
type WiFiNetwork struct {
	Version     string         // Key 0: Version (e.g., "1.0")
	NetworkID   string         // Key 1: Network identifier
	SSID        string         // Key 2: SSID
	AuthType    int            // Key 3: Authentication type (0=open, 1=wpa2-psk, 2=wpa3-psk, 3=wpa3-enterprise)
	Password    []byte         // Key 4: Password (for PSK) or EAP method (for enterprise)
	CACerts     [][]byte       // Key 5: CA certificates (for enterprise)
	TrustLevel  int            // Key 6: Trust level (0=onboard-only, 1=full-access)
	FastRoaming map[string]any // Key 7: Fast roaming configuration (optional)
	Hotspot2    map[string]any // Key 8: Hotspot 2.0 configuration (optional)
	EAPUsername string         // Key 9: EAP username (optional)
	EAPPassword []byte         // Key 10: EAP password (optional)
}

// WiFi implements the fdo.wifi FSIM for device-side WiFi configuration.
// It follows the specification in fdo.wifi-setup.md and uses the generic chunking strategy.
type WiFi struct {
	// Handler processes WiFi configuration (application-provided)
	Handler WiFiHandler

	// Active indicates if the module is active
	Active bool

	// Internal state for chunked transfers
	csrReceiver  *chunking.ChunkReceiver
	certReceiver *chunking.ChunkReceiver
	caReceiver   *chunking.ChunkReceiver

	// Current network context
	currentNetworkID string
	currentSSID      string

	// Result storage
	csrResultStatus  int
	csrResultMsg     string
	certResultStatus int
	certResultMsg    string
	caResultStatus   int
	caResultMsg      string
}

var _ serviceinfo.DeviceModule = (*WiFi)(nil)

// Transition implements serviceinfo.DeviceModule.
func (w *WiFi) Transition(active bool) error {
	if !active {
		w.reset()
	}
	return nil
}

// Receive implements serviceinfo.DeviceModule.
func (w *WiFi) Receive(ctx context.Context, messageName string, messageBody io.Reader, respond func(string) io.Writer, yield func()) error {
	slog.Debug("fdo.wifi received message", "key", messageName)

	// Handle active query
	if messageName == "active" {
		var active bool
		if err := cbor.NewDecoder(messageBody).Decode(&active); err != nil {
			return fmt.Errorf("invalid active message: %w", err)
		}
		writer := respond("active")
		return cbor.NewEncoder(writer).Encode(w.Active)
	}

	// Handle network-add
	if messageName == "network-add" {
		return w.handleNetworkAdd(messageBody)
	}

	// Handle CSR chunked messages (device sends to owner)
	if strings.HasPrefix(messageName, "csr-") {
		return w.handleCSRMessage(messageName, messageBody, respond)
	}

	// Handle certificate chunked messages (owner sends to device)
	if strings.HasPrefix(messageName, "cert-") {
		return w.handleCertMessage(messageName, messageBody, respond)
	}

	// Handle CA chunked messages (owner sends to device)
	if strings.HasPrefix(messageName, "ca-") {
		return w.handleCAMessage(messageName, messageBody, respond)
	}

	// Handle error
	if messageName == "error" {
		var errCode uint
		if err := cbor.NewDecoder(messageBody).Decode(&errCode); err != nil {
			return fmt.Errorf("invalid error message: %w", err)
		}
		return fmt.Errorf("wifi error %d: %s", errCode, wifiErrorString(errCode))
	}

	slog.Warn("fdo.wifi received unknown message", "key", messageName)
	return nil
}

// Yield implements serviceinfo.DeviceModule.
func (w *WiFi) Yield(ctx context.Context, respond func(string) io.Writer, yield func()) error {
	// Device may need to send CSR after receiving network-add
	// This would be triggered by the application calling a method
	return nil
}

// reset clears the internal state.
func (w *WiFi) reset() {
	w.csrReceiver = nil
	w.certReceiver = nil
	w.caReceiver = nil
	w.currentNetworkID = ""
	w.currentSSID = ""
}

// handleNetworkAdd processes network-add messages.
func (w *WiFi) handleNetworkAdd(messageBody io.Reader) error {
	if w.Handler == nil {
		return fmt.Errorf("no WiFi handler configured")
	}

	// Decode network configuration as CBOR map with integer keys
	var networkMap map[any]any
	if err := cbor.NewDecoder(messageBody).Decode(&networkMap); err != nil {
		return fmt.Errorf("invalid network-add format: %w", err)
	}

	// Parse network configuration
	network := &WiFiNetwork{}

	if v, ok := networkMap[0].(string); ok {
		network.Version = v
	}
	if v, ok := networkMap[1].(string); ok {
		network.NetworkID = v
	}
	if v, ok := networkMap[2].(string); ok {
		network.SSID = v
	}
	if v, ok := networkMap[3].(int); ok {
		network.AuthType = v
	} else if v, ok := networkMap[3].(uint64); ok {
		network.AuthType = int(v)
	}

	// Key 4 can be password (bstr) or EAP method (int)
	if v, ok := networkMap[4].([]byte); ok {
		network.Password = v
	} else if v, ok := networkMap[4].(int); ok {
		// EAP method for enterprise networks
		network.Password = []byte{byte(v)}
	} else if v, ok := networkMap[4].(uint64); ok {
		network.Password = []byte{byte(v)}
	}

	// Key 5: CA certificates (array of bstr)
	if v, ok := networkMap[5].([]any); ok {
		for _, cert := range v {
			if certBytes, ok := cert.([]byte); ok {
				network.CACerts = append(network.CACerts, certBytes)
			}
		}
	}

	if v, ok := networkMap[6].(int); ok {
		network.TrustLevel = v
	} else if v, ok := networkMap[6].(uint64); ok {
		network.TrustLevel = int(v)
	}

	// Optional fields
	if v, ok := networkMap[7].(map[any]any); ok {
		network.FastRoaming = convertToStringMap(v)
	}
	if v, ok := networkMap[8].(map[any]any); ok {
		network.Hotspot2 = convertToStringMap(v)
	}
	if v, ok := networkMap[9].(string); ok {
		network.EAPUsername = v
	}
	if v, ok := networkMap[10].([]byte); ok {
		network.EAPPassword = v
	}

	slog.Debug("fdo.wifi network-add",
		"network_id", network.NetworkID,
		"ssid", network.SSID,
		"auth_type", network.AuthType)

	// Call application handler
	return w.Handler.AddNetwork(network)
}

// handleCSRMessage processes CSR-related messages (device perspective - receiving result).
func (w *WiFi) handleCSRMessage(messageName string, messageBody io.Reader, respond func(string) io.Writer) error {
	// For device side, we only receive csr-result from owner
	if messageName == "csr-result" {
		var result chunking.ResultMessage
		data, err := io.ReadAll(messageBody)
		if err != nil {
			return fmt.Errorf("failed to read csr-result: %w", err)
		}
		if err := result.UnmarshalCBOR(data); err != nil {
			return fmt.Errorf("failed to decode csr-result: %w", err)
		}

		w.csrResultStatus = result.StatusCode
		w.csrResultMsg = result.Message

		slog.Debug("fdo.wifi csr-result", "status", result.StatusCode, "message", result.Message)
		return nil
	}

	return fmt.Errorf("unexpected CSR message on device: %s", messageName)
}

// handleCertMessage processes certificate chunked messages.
func (w *WiFi) handleCertMessage(messageName string, messageBody io.Reader, respond func(string) io.Writer) error {
	if w.Handler == nil {
		return fmt.Errorf("no WiFi handler configured")
	}

	// Initialize receiver on first message
	if w.certReceiver == nil {
		w.certReceiver = &chunking.ChunkReceiver{
			PayloadName: "cert",
			OnBegin:     w.onCertBegin,
			OnChunk:     w.onCertChunk,
			OnEnd:       w.onCertEnd,
		}
	}

	// Handle the message
	if err := w.certReceiver.HandleMessage(messageName, messageBody); err != nil {
		w.certReceiver = nil
		return err
	}

	// After successful end, send result
	if strings.HasSuffix(messageName, "-end") && !w.certReceiver.IsReceiving() {
		result := chunking.ResultMessage{
			StatusCode: w.certResultStatus,
			Message:    w.certResultMsg,
		}
		resultData, err := result.MarshalCBOR()
		if err != nil {
			return fmt.Errorf("failed to encode cert-result: %w", err)
		}

		writer := respond("cert-result")
		if _, err := writer.Write(resultData); err != nil {
			return fmt.Errorf("failed to send cert-result: %w", err)
		}

		w.certReceiver = nil
	}

	return nil
}

// handleCAMessage processes CA certificate chunked messages.
func (w *WiFi) handleCAMessage(messageName string, messageBody io.Reader, respond func(string) io.Writer) error {
	if w.Handler == nil {
		return fmt.Errorf("no WiFi handler configured")
	}

	// Initialize receiver on first message
	if w.caReceiver == nil {
		w.caReceiver = &chunking.ChunkReceiver{
			PayloadName: "ca",
			OnBegin:     w.onCABegin,
			OnChunk:     w.onCAChunk,
			OnEnd:       w.onCAEnd,
		}
	}

	// Handle the message
	if err := w.caReceiver.HandleMessage(messageName, messageBody); err != nil {
		w.caReceiver = nil
		return err
	}

	// After successful end, send result
	if strings.HasSuffix(messageName, "-end") && !w.caReceiver.IsReceiving() {
		result := chunking.ResultMessage{
			StatusCode: w.caResultStatus,
			Message:    w.caResultMsg,
		}
		resultData, err := result.MarshalCBOR()
		if err != nil {
			return fmt.Errorf("failed to encode ca-result: %w", err)
		}

		writer := respond("ca-result")
		if _, err := writer.Write(resultData); err != nil {
			return fmt.Errorf("failed to send ca-result: %w", err)
		}

		w.caReceiver = nil
	}

	return nil
}

// onCertBegin is called when cert-begin is received.
func (w *WiFi) onCertBegin(begin chunking.BeginMessage) error {
	// Extract network_id from field -1 (required)
	networkID, ok := begin.FSIMFields[-1].(string)
	if !ok || networkID == "" {
		return fmt.Errorf("missing required network_id field (-1)")
	}

	w.currentNetworkID = networkID

	// Extract optional SSID from field -2
	if ssid, ok := begin.FSIMFields[-2].(string); ok {
		w.currentSSID = ssid
	}

	slog.Debug("fdo.wifi cert-begin", "network_id", networkID, "ssid", w.currentSSID)
	return nil
}

// onCertChunk is called for each cert-data-<n> chunk.
func (w *WiFi) onCertChunk(data []byte) error {
	// Chunks are accumulated in the receiver's buffer
	return nil
}

// onCertEnd is called when cert-end is received.
func (w *WiFi) onCertEnd(end chunking.EndMessage) error {
	// Get the complete certificate data
	certData := w.certReceiver.GetBuffer()

	// Extract optional metadata from field -4
	var metadata map[string]any
	if m, ok := end.FSIMFields[-4].(map[string]any); ok {
		metadata = m
	} else if m, ok := end.FSIMFields[-4].(map[any]any); ok {
		metadata = convertToStringMap(m)
	}

	// Call application handler
	statusCode, message, err := w.Handler.InstallCertificate(w.currentNetworkID, w.currentSSID, certData, metadata)
	if err != nil {
		return err
	}

	w.certResultStatus = statusCode
	w.certResultMsg = message

	return nil
}

// onCABegin is called when ca-begin is received.
func (w *WiFi) onCABegin(begin chunking.BeginMessage) error {
	// Extract network_id from field -1 (required)
	networkID, ok := begin.FSIMFields[-1].(string)
	if !ok || networkID == "" {
		return fmt.Errorf("missing required network_id field (-1)")
	}

	w.currentNetworkID = networkID

	// Extract optional bundle_id from field -2
	if bundleID, ok := begin.FSIMFields[-2].(string); ok {
		w.currentSSID = bundleID // Reuse field for bundle_id
	}

	slog.Debug("fdo.wifi ca-begin", "network_id", networkID)
	return nil
}

// onCAChunk is called for each ca-data-<n> chunk.
func (w *WiFi) onCAChunk(data []byte) error {
	return nil
}

// onCAEnd is called when ca-end is received.
func (w *WiFi) onCAEnd(end chunking.EndMessage) error {
	// Get the complete CA data
	caData := w.caReceiver.GetBuffer()

	// Extract optional metadata
	var metadata map[string]any
	if m, ok := end.FSIMFields[-3].(map[string]any); ok {
		metadata = m
	} else if m, ok := end.FSIMFields[-3].(map[any]any); ok {
		metadata = convertToStringMap(m)
	}

	// Call application handler
	statusCode, message, err := w.Handler.InstallCACerts(w.currentNetworkID, w.currentSSID, caData, metadata)
	if err != nil {
		return err
	}

	w.caResultStatus = statusCode
	w.caResultMsg = message

	return nil
}

// SendCSR sends a CSR to the owner using the chunking strategy.
// This should be called by the application after receiving a network-add for an enterprise network.
func (w *WiFi) SendCSR(ctx context.Context, networkID, ssid string, respond func(string) io.Writer, yield func()) error {
	if w.Handler == nil {
		return fmt.Errorf("no WiFi handler configured")
	}

	// Generate CSR via application handler
	csrData, metadata, err := w.Handler.GenerateCSR(networkID, ssid)
	if err != nil {
		return fmt.Errorf("failed to generate CSR: %w", err)
	}

	// Create sender
	sender := chunking.NewChunkSender("csr", csrData)
	sender.BeginFields.HashAlg = "sha256"
	sender.BeginFields.FSIMFields[-1] = networkID
	sender.BeginFields.FSIMFields[-2] = ssid
	sender.BeginFields.FSIMFields[-3] = 0 // csr_type: eap-tls
	if metadata != nil {
		sender.BeginFields.FSIMFields[-4] = metadata
	}

	// Send begin
	beginData, err := sender.BeginFields.MarshalCBOR()
	if err != nil {
		return fmt.Errorf("failed to encode csr-begin: %w", err)
	}
	writer := respond("csr-begin")
	if _, err := writer.Write(beginData); err != nil {
		return fmt.Errorf("failed to send csr-begin: %w", err)
	}
	yield()

	// Send chunks
	chunkIndex := 0
	bytesSent := int64(0)
	for bytesSent < int64(len(csrData)) {
		chunkKey := fmt.Sprintf("csr-data-%d", chunkIndex)

		// Calculate chunk
		remaining := int64(len(csrData)) - bytesSent
		chunkLen := int64(sender.ChunkSize)
		if chunkLen > remaining {
			chunkLen = remaining
		}
		chunk := csrData[bytesSent : bytesSent+chunkLen]

		// Encode and send
		var buf bytes.Buffer
		if err := cbor.NewEncoder(&buf).Encode(chunk); err != nil {
			return fmt.Errorf("failed to encode chunk: %w", err)
		}

		writer := respond(chunkKey)
		if _, err := writer.Write(buf.Bytes()); err != nil {
			return fmt.Errorf("failed to send chunk: %w", err)
		}

		bytesSent += chunkLen
		chunkIndex++
		yield()
	}

	// Send end
	hash, _ := chunking.ComputeHash("sha256", csrData)
	sender.EndFields.HashValue = hash
	endData, err := sender.EndFields.MarshalCBOR()
	if err != nil {
		return fmt.Errorf("failed to encode csr-end: %w", err)
	}
	writer = respond("csr-end")
	if _, err := writer.Write(endData); err != nil {
		return fmt.Errorf("failed to send csr-end: %w", err)
	}
	yield()

	return nil
}

// convertToStringMap converts map[any]any to map[string]any.
func convertToStringMap(m map[any]any) map[string]any {
	result := make(map[string]any)
	for k, v := range m {
		if str, ok := k.(string); ok {
			result[str] = v
		}
	}
	return result
}

// wifiErrorString returns a human-readable error message for error codes.
func wifiErrorString(code uint) string {
	switch code {
	case 1000:
		return "Invalid configuration format"
	case 1001:
		return "Authentication not supported"
	case 1002:
		return "Certificate provisioning not available"
	case 1003:
		return "Invalid network configuration"
	case 1004:
		return "Trust level not authorized"
	default:
		return fmt.Sprintf("Unknown error (%d)", code)
	}
}
