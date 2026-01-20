// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package fsim

import (
	"context"
	"fmt"
	"io"
	"log/slog"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/fsim/chunking"
	"github.com/fido-device-onboard/go-fdo/serviceinfo"
)

// PayloadOwner implements the fdo.payload FSIM for owner-side payload delivery.
// It follows the specification in fdo.payload.md and uses the generic chunking strategy.
type PayloadOwner struct {
	// Payloads to send to the device
	payloads []PayloadToSend

	// Internal state
	currentSender *chunking.ChunkSender
	currentIndex  int
	sendState     payloadSendState
	lastResult    *PayloadResult
	lastError     *PayloadErrorInfo
}

type payloadSendState int

const (
	stateIdle payloadSendState = iota
	stateSendingBegin
	stateSendingChunks
	stateSendingEnd
	stateWaitingResult
)

// PayloadToSend represents a payload to be sent to the device per fdo.payload.md.
type PayloadToSend struct {
	MimeType string         // Required: MIME type (field -1)
	Name     string         // Optional: Payload name (field -2)
	Data     []byte         // Payload data
	Metadata map[string]any // Optional: Metadata map (field -3)
	HashAlg  string         // Optional: Hash algorithm (e.g., "sha256")
}

// PayloadResult represents the result received from the device.
type PayloadResult struct {
	StatusCode int    // 0=success, 1=warning, 2=error
	Message    string // Optional message
}

// PayloadErrorInfo contains error information from the device per fdo.payload.md.
type PayloadErrorInfo struct {
	Code    int    // Error code (see fdo.payload.md)
	Message string // Human-readable error message
	Details string // Optional additional details
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
func (p *PayloadOwner) AddPayload(mimeType, name string, data []byte, metadata map[string]any) {
	p.payloads = append(p.payloads, PayloadToSend{
		MimeType: mimeType,
		Name:     name,
		Data:     data,
		Metadata: metadata,
		HashAlg:  "sha256", // Default hash algorithm
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
	p.currentSender = nil
	p.currentIndex = 0
	p.sendState = stateIdle
	p.lastResult = nil
	p.lastError = nil
}

// produceInfo generates messages to send to the device using the chunking library.
func (p *PayloadOwner) produceInfo(ctx context.Context, producer *serviceinfo.Producer) (blockPeer, moduleDone bool, _ error) {
	// Check if we're done with all payloads
	if p.currentIndex >= len(p.payloads) && p.sendState == stateIdle {
		return false, true, nil
	}

	// Initialize sender for next payload if needed
	if p.currentSender == nil && p.currentIndex < len(p.payloads) {
		payload := &p.payloads[p.currentIndex]
		p.currentSender = chunking.NewChunkSender("payload", payload.Data)

		// Set hash algorithm if provided
		if payload.HashAlg != "" {
			p.currentSender.BeginFields.HashAlg = payload.HashAlg
		}

		// Set FSIM-specific fields per fdo.payload.md
		p.currentSender.BeginFields.FSIMFields[-1] = payload.MimeType // Required
		if payload.Name != "" {
			p.currentSender.BeginFields.FSIMFields[-2] = payload.Name
		}
		if payload.Metadata != nil {
			p.currentSender.BeginFields.FSIMFields[-3] = payload.Metadata
		}

		p.sendState = stateSendingBegin
	}

	// State machine for sending
	switch p.sendState {
	case stateSendingBegin:
		if err := p.currentSender.SendBegin(producer); err != nil {
			return false, false, fmt.Errorf("failed to send begin: %w", err)
		}
		slog.Debug("fdo.payload sent begin",
			"mime_type", p.currentSender.BeginFields.FSIMFields[-1],
			"size", len(p.currentSender.Data))
		p.sendState = stateSendingChunks
		return false, false, nil

	case stateSendingChunks:
		done, err := p.currentSender.SendNextChunk(producer)
		if err != nil {
			return false, false, fmt.Errorf("failed to send chunk: %w", err)
		}
		if done {
			p.sendState = stateSendingEnd
		}
		return false, false, nil

	case stateSendingEnd:
		if err := p.currentSender.SendEnd(producer); err != nil {
			return false, false, fmt.Errorf("failed to send end: %w", err)
		}
		slog.Debug("fdo.payload sent end")
		p.sendState = stateWaitingResult
		// Block peer to wait for result
		return true, false, nil

	case stateWaitingResult:
		// Waiting for device to send payload-result
		// This will be unblocked when we receive the result in HandleInfo
		return true, false, nil
	}

	return false, false, nil
}

// receive processes incoming messages from the device.
func (p *PayloadOwner) receive(ctx context.Context, key string, messageBody io.Reader, respond func(string) io.Writer) error {
	slog.Debug("fdo.payload owner received message", "key", key)

	switch key {
	case "active":
		// Device responds with active status (not used in chunking flow)
		slog.Debug("fdo.payload device active status received")

	case "payload-result":
		// Device reports final result per fdo.payload.md
		if p.currentSender == nil {
			return fmt.Errorf("received result without active transfer")
		}

		result, err := p.currentSender.HandleResult(messageBody)
		if err != nil {
			return fmt.Errorf("failed to decode result: %w", err)
		}

		p.lastResult = &PayloadResult{
			StatusCode: result.StatusCode,
			Message:    result.Message,
		}

		if result.StatusCode == 0 {
			slog.Info("fdo.payload applied successfully",
				"mime_type", p.currentSender.BeginFields.FSIMFields[-1],
				"message", result.Message)
		} else {
			slog.Warn("fdo.payload application failed",
				"mime_type", p.currentSender.BeginFields.FSIMFields[-1],
				"status", result.StatusCode,
				"message", result.Message)
		}

		// Move to next payload
		p.currentSender = nil
		p.currentIndex++
		p.sendState = stateIdle

	case "error":
		// Device reports an error per fdo.payload.md error format
		var errorMap map[any]any
		data, err := io.ReadAll(messageBody)
		if err != nil {
			return fmt.Errorf("failed to read error: %w", err)
		}
		if err := cbor.Unmarshal(data, &errorMap); err != nil {
			return fmt.Errorf("failed to decode error: %w", err)
		}

		// Extract error fields (keys 0, 1, 2)
		code, _ := errorMap[0].(int)
		message, _ := errorMap[1].(string)
		details, _ := errorMap[2].(string)

		p.lastError = &PayloadErrorInfo{
			Code:    code,
			Message: message,
			Details: details,
		}

		slog.Error("fdo.payload device error",
			"code", code,
			"message", message,
			"details", details)

		// Reset current payload
		p.currentSender = nil
		p.sendState = stateIdle

		return fmt.Errorf("payload error %d: %s", code, message)

	default:
		slog.Warn("fdo.payload owner received unknown key", "key", key)
	}

	return nil
}

// GetLastError returns the last error reported by the device.
func (p *PayloadOwner) GetLastError() *PayloadErrorInfo {
	return p.lastError
}

// GetLastResult returns the last result reported by the device.
func (p *PayloadOwner) GetLastResult() *PayloadResult {
	return p.lastResult
}

// SetChunkSize sets the chunk size for data transfer (default 1014 bytes per spec).
func (p *PayloadOwner) SetChunkSize(size int) {
	if p.currentSender != nil {
		p.currentSender.ChunkSize = size
	}
}
