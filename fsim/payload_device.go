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
	"github.com/fido-device-onboard/go-fdo/serviceinfo"
)

// PayloadHandler defines the interface for handling payload delivery.
// Applications must implement this interface to process payloads.
type PayloadHandler interface {
	// SupportsMimeType checks if the device supports the given MIME type.
	SupportsMimeType(mimeType string) bool

	// BeginPayload prepares to receive a payload.
	// Returns error if MIME type is unsupported or preparation fails.
	BeginPayload(mimeType, name string, size int64, metadata map[string]string) error

	// ReceiveChunk processes a data chunk.
	// Returns error if chunk cannot be processed.
	ReceiveChunk(data []byte) error

	// EndPayload finalizes and applies the payload.
	// Returns success status, message, optional output, and error.
	EndPayload() (success bool, message string, output string, err error)

	// CancelPayload aborts the current transfer.
	CancelPayload() error
}

// Payload implements the fdo.payload FSIM for device-side payload delivery.
type Payload struct {
	// Handler processes received payloads
	Handler PayloadHandler

	// Active indicates if the module is active
	Active bool

	// Internal state
	receiving    bool
	totalBytes   int64
	expectedSize int64
	buffer       bytes.Buffer
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
	if err := p.receive(ctx, messageName, messageBody, respond); err != nil {
		p.reset()
		return err
	}
	return nil
}

// Yield implements serviceinfo.DeviceModule.
func (p *Payload) Yield(ctx context.Context, respond func(string) io.Writer, yield func()) error {
	return nil
}

// reset clears the internal state.
func (p *Payload) reset() {
	if p.receiving && p.Handler != nil {
		p.Handler.CancelPayload()
	}
	p.receiving = false
	p.totalBytes = 0
	p.expectedSize = 0
	p.buffer.Reset()
}

// receive processes incoming messages.
func (p *Payload) receive(ctx context.Context, key string, messageBody io.Reader, respond func(string) io.Writer) error {
	slog.Debug("fdo.payload received message", "key", key)

	switch key {
	case "active":
		// Owner queries if module is active
		var active bool
		if err := cbor.NewDecoder(messageBody).Decode(&active); err != nil {
			return fmt.Errorf("invalid active message: %w", err)
		}

		// Respond with our active status
		w := respond("active")
		if err := cbor.NewEncoder(w).Encode(p.Active); err != nil {
			return err
		}

	case "begin":
		// Owner initiates payload transfer
		if p.Handler == nil {
			return p.sendError(respond, 4, "No payload handler configured", "")
		}

		var begin struct {
			MimeType string            `cbor:"mime_type"`
			Name     string            `cbor:"name,omitempty"`
			Size     int64             `cbor:"size,omitempty"`
			Metadata map[string]string `cbor:"metadata,omitempty"`
		}
		if err := cbor.NewDecoder(messageBody).Decode(&begin); err != nil {
			return p.sendError(respond, 2, "Invalid begin message format", err.Error())
		}

		// Check if MIME type is supported
		if !p.Handler.SupportsMimeType(begin.MimeType) {
			return p.sendError(respond, 1, fmt.Sprintf("MIME type '%s' not supported", begin.MimeType), "")
		}

		// Prepare to receive payload
		if err := p.Handler.BeginPayload(begin.MimeType, begin.Name, begin.Size, begin.Metadata); err != nil {
			return p.sendError(respond, 4, "Failed to prepare for payload", err.Error())
		}

		// Reset state
		p.receiving = true
		p.totalBytes = 0
		p.expectedSize = begin.Size
		p.buffer.Reset()

		// Respond ready
		w := respond("ready")
		if err := cbor.NewEncoder(w).Encode(true); err != nil {
			return err
		}

	case "data":
		// Owner sends data chunk
		if !p.receiving {
			return p.sendError(respond, 6, "Not ready to receive data", "Call begin first")
		}

		var data []byte
		if err := cbor.NewDecoder(messageBody).Decode(&data); err != nil {
			return p.sendError(respond, 6, "Invalid data chunk", err.Error())
		}

		// Process chunk
		if err := p.Handler.ReceiveChunk(data); err != nil {
			p.receiving = false
			return p.sendError(respond, 4, "Failed to process chunk", err.Error())
		}

		p.totalBytes += int64(len(data))

		// Acknowledge receipt
		w := respond("ack")
		if err := cbor.NewEncoder(w).Encode(int(p.totalBytes)); err != nil {
			return err
		}

	case "end":
		// Owner signals end of transfer
		if !p.receiving {
			return p.sendError(respond, 6, "No active transfer", "")
		}

		// Verify size if provided
		if p.expectedSize > 0 && p.totalBytes != p.expectedSize {
			p.receiving = false
			return p.sendError(respond, 6,
				fmt.Sprintf("Size mismatch: expected %d, received %d", p.expectedSize, p.totalBytes),
				"")
		}

		// Finalize and apply payload
		success, message, output, err := p.Handler.EndPayload()
		p.receiving = false

		if err != nil {
			return p.sendError(respond, 4, "Failed to apply payload", err.Error())
		}

		// Send result
		result := map[string]any{
			"success": success,
		}
		if message != "" {
			result["message"] = message
		}
		if output != "" {
			result["output"] = output
		}

		w := respond("result")
		if err := cbor.NewEncoder(w).Encode(result); err != nil {
			return err
		}

	default:
		slog.Warn("fdo.payload received unknown key", "key", key)
	}

	return nil
}

// sendError sends an error message to the owner.
func (p *Payload) sendError(respond func(string) io.Writer, code int, message, details string) error {
	errorMsg := map[string]any{
		"code":    code,
		"message": message,
	}
	if details != "" {
		errorMsg["details"] = details
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
