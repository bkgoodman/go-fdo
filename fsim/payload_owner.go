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

// PayloadOwner implements the fdo.payload FSIM for owner-side payload delivery.
type PayloadOwner struct {
	// Payloads to send to the device
	payloads []PayloadToSend

	// Internal state
	currentPayload *PayloadToSend
	currentIndex   int
	bytesSent      int64
	chunkSize      int
	waitingForAck  bool
	lastError      *PayloadErrorInfo
}

// PayloadToSend represents a payload to be sent to the device.
type PayloadToSend struct {
	MimeType string
	Name     string
	Data     []byte
	Metadata map[string]string
}

// PayloadErrorInfo contains error information from the device.
type PayloadErrorInfo struct {
	Code    int
	Message string
	Details string
}

var _ serviceinfo.OwnerModule = (*PayloadOwner)(nil)

// HandleInfo implements serviceinfo.OwnerModule.
func (p *PayloadOwner) HandleInfo(ctx context.Context, messageName string, messageBody io.Reader) error {
	// Delegate to receive method
	return p.receive(ctx, messageName, messageBody, nil)
}

// ProduceInfo implements serviceinfo.OwnerModule.
func (p *PayloadOwner) ProduceInfo(ctx context.Context, producer *serviceinfo.Producer) (blockPeer, moduleDone bool, _ error) {
	return p.produceInfo(ctx, producer)
}

// AddPayload adds a payload to be sent to the device.
func (p *PayloadOwner) AddPayload(mimeType, name string, data []byte, metadata map[string]string) {
	p.payloads = append(p.payloads, PayloadToSend{
		MimeType: mimeType,
		Name:     name,
		Data:     data,
		Metadata: metadata,
	})
}

// Transition implements serviceinfo.OwnerModule.
func (p *PayloadOwner) Transition(active bool) error {
	if !active {
		p.reset()
	}
	return nil
}

// reset clears the internal state.
func (p *PayloadOwner) reset() {
	p.currentPayload = nil
	p.currentIndex = 0
	p.bytesSent = 0
	p.waitingForAck = false
	p.lastError = nil
}

// produceInfo generates messages to send to the device.
func (p *PayloadOwner) produceInfo(ctx context.Context, producer *serviceinfo.Producer) (blockPeer, moduleDone bool, _ error) {
	// If waiting for acknowledgment, block peer
	if p.waitingForAck {
		return true, false, nil
	}

	// If no current payload, start the next one
	if p.currentPayload == nil {
		if p.currentIndex >= len(p.payloads) {
			// No more payloads to send
			return false, true, nil
		}

		p.currentPayload = &p.payloads[p.currentIndex]
		p.bytesSent = 0

		// Set default chunk size (4KB)
		if p.chunkSize == 0 {
			p.chunkSize = 4096
		}

		// Send begin message
		begin := map[string]any{
			"mime_type": p.currentPayload.MimeType,
		}
		if p.currentPayload.Name != "" {
			begin["name"] = p.currentPayload.Name
		}
		if len(p.currentPayload.Data) > 0 {
			begin["size"] = int64(len(p.currentPayload.Data))
		}
		if p.currentPayload.Metadata != nil {
			begin["metadata"] = p.currentPayload.Metadata
		}

		var buf bytes.Buffer
		if err := cbor.NewEncoder(&buf).Encode(begin); err != nil {
			return false, false, fmt.Errorf("failed to encode begin: %w", err)
		}

		if err := producer.WriteChunk("begin", buf.Bytes()); err != nil {
			return false, false, fmt.Errorf("failed to send begin: %w", err)
		}

		slog.Debug("fdo.payload sent begin",
			"mime_type", p.currentPayload.MimeType,
			"name", p.currentPayload.Name,
			"size", len(p.currentPayload.Data))

		return false, false, nil
	}

	// Send data chunks
	if p.bytesSent < int64(len(p.currentPayload.Data)) {
		// Calculate chunk size
		remaining := int64(len(p.currentPayload.Data)) - p.bytesSent
		chunkLen := int64(p.chunkSize)
		if chunkLen > remaining {
			chunkLen = remaining
		}

		// Extract chunk
		chunk := p.currentPayload.Data[p.bytesSent : p.bytesSent+chunkLen]

		// Send data
		var buf bytes.Buffer
		if err := cbor.NewEncoder(&buf).Encode(chunk); err != nil {
			return false, false, fmt.Errorf("failed to encode data chunk: %w", err)
		}

		if err := producer.WriteChunk("data", buf.Bytes()); err != nil {
			return false, false, fmt.Errorf("failed to send data chunk: %w", err)
		}

		p.bytesSent += chunkLen
		p.waitingForAck = true

		slog.Debug("fdo.payload sent data chunk",
			"bytes", chunkLen,
			"total_sent", p.bytesSent,
			"total_size", len(p.currentPayload.Data))

		return false, false, nil
	}

	// All data sent, send end message
	var buf bytes.Buffer
	if err := cbor.NewEncoder(&buf).Encode(true); err != nil {
		return false, false, fmt.Errorf("failed to encode end: %w", err)
	}

	if err := producer.WriteChunk("end", buf.Bytes()); err != nil {
		return false, false, fmt.Errorf("failed to send end: %w", err)
	}

	slog.Debug("fdo.payload sent end")

	return false, false, nil
}

// receive processes incoming messages from the device.
func (p *PayloadOwner) receive(ctx context.Context, key string, messageBody io.Reader, respond func(string) io.Writer) error {
	slog.Debug("fdo.payload owner received message", "key", key)

	switch key {
	case "active":
		// Device responds with active status
		var active bool
		if err := cbor.NewDecoder(messageBody).Decode(&active); err != nil {
			return fmt.Errorf("invalid active response: %w", err)
		}

		slog.Debug("fdo.payload device active status", "active", active)

	case "ready":
		// Device is ready to receive payload data
		var ready bool
		if err := cbor.NewDecoder(messageBody).Decode(&ready); err != nil {
			return fmt.Errorf("invalid ready response: %w", err)
		}

		if !ready {
			return fmt.Errorf("device not ready for payload")
		}

		slog.Debug("fdo.payload device ready for data")

	case "ack":
		// Device acknowledges data receipt
		var bytesReceived int
		if err := cbor.NewDecoder(messageBody).Decode(&bytesReceived); err != nil {
			return fmt.Errorf("invalid ack response: %w", err)
		}

		slog.Debug("fdo.payload device acknowledged", "bytes", bytesReceived)
		p.waitingForAck = false

		// Verify acknowledgment matches what we sent
		if int64(bytesReceived) != p.bytesSent {
			return fmt.Errorf("ack mismatch: sent %d, device received %d", p.bytesSent, bytesReceived)
		}

	case "result":
		// Device reports final result
		var result struct {
			Success bool   `cbor:"success"`
			Message string `cbor:"message,omitempty"`
			Output  string `cbor:"output,omitempty"`
		}
		if err := cbor.NewDecoder(messageBody).Decode(&result); err != nil {
			return fmt.Errorf("invalid result response: %w", err)
		}

		if result.Success {
			slog.Info("fdo.payload applied successfully",
				"mime_type", p.currentPayload.MimeType,
				"name", p.currentPayload.Name,
				"message", result.Message)
		} else {
			slog.Warn("fdo.payload application failed",
				"mime_type", p.currentPayload.MimeType,
				"name", p.currentPayload.Name,
				"message", result.Message)
		}

		if result.Output != "" {
			slog.Debug("fdo.payload output", "output", result.Output)
		}

		// Move to next payload
		p.currentPayload = nil
		p.currentIndex++
		p.bytesSent = 0

	case "error":
		// Device reports an error
		var errorInfo struct {
			Code    int    `cbor:"code"`
			Message string `cbor:"message"`
			Details string `cbor:"details,omitempty"`
		}
		if err := cbor.NewDecoder(messageBody).Decode(&errorInfo); err != nil {
			return fmt.Errorf("invalid error response: %w", err)
		}

		p.lastError = &PayloadErrorInfo{
			Code:    errorInfo.Code,
			Message: errorInfo.Message,
			Details: errorInfo.Details,
		}

		slog.Error("fdo.payload device error",
			"code", errorInfo.Code,
			"message", errorInfo.Message,
			"details", errorInfo.Details)

		// Reset current payload
		p.currentPayload = nil
		p.bytesSent = 0

		return fmt.Errorf("payload error %d: %s", errorInfo.Code, errorInfo.Message)

	default:
		slog.Warn("fdo.payload owner received unknown key", "key", key)
	}

	return nil
}

// GetLastError returns the last error reported by the device.
func (p *PayloadOwner) GetLastError() *PayloadErrorInfo {
	return p.lastError
}

// SetChunkSize sets the chunk size for data transfer (default 4KB).
func (p *PayloadOwner) SetChunkSize(size int) {
	p.chunkSize = size
}
