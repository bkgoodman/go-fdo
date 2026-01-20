// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package fsim

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/fsim/chunking"
	"github.com/fido-device-onboard/go-fdo/serviceinfo"
)

// PayloadHandler defines the interface for handling payload delivery.
// Applications must implement this interface to process payloads according to fdo.payload.md.
type PayloadHandler interface {
	// SupportsMimeType checks if the device supports the given MIME type.
	// This is called when payload-begin is received to validate the mime_type field.
	SupportsMimeType(mimeType string) bool

	// BeginPayload prepares to receive a payload.
	// mimeType: MIME type from field -1 (required)
	// name: Optional payload name from field -2
	// size: Total size in bytes (0 if not provided)
	// metadata: Optional metadata map from field -3
	// Returns error if MIME type is unsupported or preparation fails.
	BeginPayload(mimeType, name string, size uint64, metadata map[string]any) error

	// ReceiveChunk processes a data chunk.
	// Returns error if chunk cannot be processed.
	ReceiveChunk(data []byte) error

	// EndPayload finalizes and applies the payload.
	// Returns status code (0=success, 1=warning, 2=error) and optional message.
	EndPayload() (statusCode int, message string, err error)

	// CancelPayload aborts the current transfer.
	CancelPayload() error
}

// Payload implements the fdo.payload FSIM for device-side payload delivery.
// It follows the specification in fdo.payload.md and uses the generic chunking strategy.
type Payload struct {
	// Handler processes received payloads (application-provided)
	Handler PayloadHandler

	// Active indicates if the module is active
	Active bool

	// Internal state
	receiver     *chunking.ChunkReceiver
	resultStatus int
	resultMsg    string
}

var _ serviceinfo.DeviceModule = (*Payload)(nil)

// Transition implements serviceinfo.DeviceModule.
func (p *Payload) Transition(active bool) error {
	if !active {
		p.reset()
	}
	return nil
}

// Receive implements serviceinfo.DeviceModule.
func (p *Payload) Receive(ctx context.Context, messageName string, messageBody io.Reader, respond func(string) io.Writer, yield func()) error {
	// Handle active query
	if messageName == "active" {
		var active bool
		if err := cbor.NewDecoder(messageBody).Decode(&active); err != nil {
			return fmt.Errorf("invalid active message: %w", err)
		}
		w := respond("active")
		return cbor.NewEncoder(w).Encode(p.Active)
	}

	// Handle chunked payload messages
	if strings.HasPrefix(messageName, "payload-") {
		return p.handleChunkedMessage(messageName, messageBody, respond)
	}

	slog.Warn("fdo.payload received unknown message", "key", messageName)
	return nil
}

// Yield implements serviceinfo.DeviceModule.
func (p *Payload) Yield(ctx context.Context, respond func(string) io.Writer, yield func()) error {
	return nil
}

// reset clears the internal state.
func (p *Payload) reset() {
	if p.receiver != nil && p.receiver.IsReceiving() && p.Handler != nil {
		p.Handler.CancelPayload()
	}
	p.receiver = nil
}

// handleChunkedMessage processes payload-begin, payload-data-<n>, and payload-end messages.
func (p *Payload) handleChunkedMessage(messageName string, messageBody io.Reader, respond func(string) io.Writer) error {
	if p.Handler == nil {
		return p.sendError(respond, 4, "No payload handler configured", "")
	}

	// Initialize receiver on first chunked message
	if p.receiver == nil {
		p.receiver = &chunking.ChunkReceiver{
			PayloadName: "payload",
			OnBegin:     p.onBegin,
			OnChunk:     p.onChunk,
			OnEnd:       p.onEnd,
		}
	}

	// Handle the message using the chunking receiver
	if err := p.receiver.HandleMessage(messageName, messageBody); err != nil {
		// On error, send error response and reset
		p.sendError(respond, 6, "Transfer error", err.Error())
		p.receiver = nil
		if p.Handler != nil {
			p.Handler.CancelPayload()
		}
		return err
	}

	// After successful end message, send result per fdo.payload.md
	if strings.HasSuffix(messageName, "-end") && !p.receiver.IsReceiving() {
		// Send payload-result as array [status_code, ?message]
		result := chunking.ResultMessage{
			StatusCode: p.resultStatus,
			Message:    p.resultMsg,
		}
		resultData, err := result.MarshalCBOR()
		if err != nil {
			return fmt.Errorf("failed to encode result: %w", err)
		}

		w := respond("payload-result")
		if _, err := w.Write(resultData); err != nil {
			return fmt.Errorf("failed to send result: %w", err)
		}

		p.receiver = nil
	}

	return nil
}

// onBegin is called when payload-begin is received.
func (p *Payload) onBegin(begin chunking.BeginMessage) error {
	// Extract MIME type from field -1 (required per fdo.payload.md)
	mimeType, ok := begin.FSIMFields[-1].(string)
	if !ok || mimeType == "" {
		return fmt.Errorf("missing required mime_type field (-1)")
	}

	// Check if MIME type is supported
	if !p.Handler.SupportsMimeType(mimeType) {
		return fmt.Errorf("MIME type '%s' not supported", mimeType)
	}

	// Extract optional name from field -2
	name, _ := begin.FSIMFields[-2].(string)

	// Extract optional metadata from field -3
	var metadata map[string]any
	if m, ok := begin.FSIMFields[-3].(map[string]any); ok {
		metadata = m
	} else if m, ok := begin.FSIMFields[-3].(map[any]any); ok {
		// Convert map[any]any to map[string]any
		metadata = make(map[string]any)
		for k, v := range m {
			if ks, ok := k.(string); ok {
				metadata[ks] = v
			}
		}
	}

	slog.Debug("fdo.payload begin",
		"mime_type", mimeType,
		"name", name,
		"size", begin.TotalSize)

	// Call application handler
	return p.Handler.BeginPayload(mimeType, name, begin.TotalSize, metadata)
}

// onChunk is called for each payload-data-<n> chunk.
func (p *Payload) onChunk(data []byte) error {
	return p.Handler.ReceiveChunk(data)
}

// onEnd is called when payload-end is received.
func (p *Payload) onEnd(end chunking.EndMessage) error {
	// Finalize and apply the payload
	statusCode, message, err := p.Handler.EndPayload()
	if err != nil {
		return err
	}

	// Store result for sending after HandleMessage completes
	p.resultStatus = statusCode
	p.resultMsg = message

	slog.Debug("fdo.payload end", "status", statusCode, "message", message)
	return nil
}

// sendError sends an error message to the owner per fdo.payload.md error format.
func (p *Payload) sendError(respond func(string) io.Writer, code int, message, details string) error {
	// Error format: map with keys 0=code, 1=message, 2=details
	errorMsg := make(map[any]any)
	errorMsg[0] = code
	errorMsg[1] = message
	if details != "" {
		errorMsg[2] = details
	}

	w := respond("error")
	if err := cbor.NewEncoder(w).Encode(errorMsg); err != nil {
		return fmt.Errorf("failed to encode error: %w", err)
	}

	return fmt.Errorf("payload error: %s", message)
}

// payloadErrorString returns a human-readable error message for error codes.
func payloadErrorString(code int) string {
	switch code {
	case 1:
		return "Unknown MIME Type"
	case 2:
		return "Invalid Format"
	case 3:
		return "Invalid Content"
	case 4:
		return "Unable to Apply"
	case 5:
		return "Unsupported Feature"
	case 6:
		return "Transfer Error"
	case 7:
		return "Resource Error"
	default:
		return fmt.Sprintf("Unknown Error (%d)", code)
	}
}
