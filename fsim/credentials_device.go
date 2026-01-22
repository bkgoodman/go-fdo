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

// CredentialsDevice implements the fdo.credentials FSIM for device-side credential reception.
// It follows the specification in fdo.credentials.md and supports three protocol flows:
// 1. Provisioned Credentials - Device receives shared secrets from owner
// 2. Enrolled Credentials - Device requests signed credentials (CSR, OAuth2 private key JWT)
// 3. Registered Credentials - Device registers public keys (SSH)
type CredentialsDevice struct {
	// Callbacks for credential handling
	OnCredentialReceived func(credentialID, credentialType string, data []byte, metadata map[string]any) error

	// Internal state
	active              bool
	receivingCredential bool

	// Chunking receiver for credential data
	credentialReceiver *chunking.ChunkReceiver

	// Current credential being received
	currentCredentialID   string
	currentCredentialType string
	currentMetadata       map[string]any
}

var _ serviceinfo.DeviceModule = (*CredentialsDevice)(nil)

// Transition implements serviceinfo.DeviceModule.
func (c *CredentialsDevice) Transition(active bool) error {
	if !active {
		// Reset state when module is deactivated
		c.active = false
		c.receivingCredential = false
		c.credentialReceiver = nil
		c.currentCredentialID = ""
		c.currentCredentialType = ""
		c.currentMetadata = nil
	}
	return nil
}

// Yield implements serviceinfo.DeviceModule.
func (c *CredentialsDevice) Yield(ctx context.Context, respond func(string) io.Writer, yield func()) error {
	// Nothing to send proactively
	return nil
}

// Receive implements serviceinfo.DeviceModule.
func (c *CredentialsDevice) Receive(ctx context.Context, messageName string, messageBody io.Reader, respond func(string) io.Writer, yield func()) error {
	slog.Debug("[fdo.credentials] Received message", "key", messageName)

	switch messageName {
	case "active":
		// Owner activates or deactivates the module
		// Just store the state, don't respond (like sysconfig pattern)
		var active bool
		if err := cbor.NewDecoder(messageBody).Decode(&active); err != nil {
			return fmt.Errorf("decode active: %w", err)
		}
		c.active = active
		slog.Debug("[fdo.credentials] Module active", "active", active)
		return nil

	case "credential-begin":
		// Owner starts sending a credential
		return c.handleCredentialBegin(messageBody)

	case "credential-end":
		// Owner finishes sending credential
		return c.handleCredentialEnd(messageBody, respond)

	default:
		// Check if it's a credential-data-N message
		if c.credentialReceiver != nil {
			if err := c.credentialReceiver.HandleMessage(messageName, messageBody); err == nil {
				return nil
			}
		}
		return fmt.Errorf("unexpected message: %s", messageName)
	}
}

// handleCredentialBegin processes the credential-begin message.
func (c *CredentialsDevice) handleCredentialBegin(messageBody io.Reader) error {
	// Initialize receiver if needed
	if c.credentialReceiver == nil {
		c.credentialReceiver = &chunking.ChunkReceiver{
			PayloadName: "credential",
			OnBegin: func(begin chunking.BeginMessage) error {
				// Extract FSIM-specific fields
				if credID, ok := begin.FSIMFields[-1].(string); ok {
					c.currentCredentialID = credID
				}
				if credType, ok := begin.FSIMFields[-2].(string); ok {
					c.currentCredentialType = credType
				}
				if metadata, ok := begin.FSIMFields[-3].(map[string]any); ok {
					c.currentMetadata = metadata
				}

				slog.Debug("[fdo.credentials] Receiving credential",
					"credential_id", c.currentCredentialID,
					"credential_type", c.currentCredentialType,
					"total_size", begin.TotalSize)
				return nil
			},
			OnChunk: func(data []byte) error {
				// Chunks are accumulated in receiver's buffer
				return nil
			},
			OnEnd: func(end chunking.EndMessage) error {
				// Credential fully received
				slog.Debug("[fdo.credentials] Credential received completely",
					"credential_id", c.currentCredentialID,
					"size", c.credentialReceiver.GetTotalBytes())
				return nil
			},
		}
	}

	// Handle the begin message
	if err := c.credentialReceiver.HandleMessage("credential-begin", messageBody); err != nil {
		return fmt.Errorf("handle credential-begin: %w", err)
	}

	c.receivingCredential = true
	return nil
}

// handleCredentialEnd processes the credential-end message and invokes the callback.
func (c *CredentialsDevice) handleCredentialEnd(messageBody io.Reader, respond func(string) io.Writer) error {
	// Handle the end message
	if err := c.credentialReceiver.HandleMessage("credential-end", messageBody); err != nil {
		return fmt.Errorf("handle credential-end: %w", err)
	}

	// Get the complete credential data
	credentialData := c.credentialReceiver.GetBuffer()

	// Invoke callback if provided
	if c.OnCredentialReceived != nil {
		if err := c.OnCredentialReceived(
			c.currentCredentialID,
			c.currentCredentialType,
			credentialData,
			c.currentMetadata,
		); err != nil {
			slog.Error("[fdo.credentials] Credential handling failed",
				"credential_id", c.currentCredentialID,
				"error", err)
			// Send error result
			c.sendCredentialResult(respond, 2, fmt.Sprintf("Failed to process credential: %v", err))
			return nil
		}
	}

	slog.Info("[fdo.credentials] Credential processed successfully",
		"credential_id", c.currentCredentialID,
		"credential_type", c.currentCredentialType)

	// Send success result
	c.sendCredentialResult(respond, 0, "Credential stored")

	// Reset state for next credential
	c.credentialReceiver = nil
	c.receivingCredential = false
	c.currentCredentialID = ""
	c.currentCredentialType = ""
	c.currentMetadata = nil

	return nil
}

// sendCredentialResult sends a credential-result message.
func (c *CredentialsDevice) sendCredentialResult(respond func(string) io.Writer, statusCode int, message string) {
	result := chunking.ResultMessage{
		StatusCode: statusCode,
		Message:    message,
	}
	data, err := cbor.Marshal(&result)
	if err != nil {
		slog.Error("[fdo.credentials] Failed to marshal result", "error", err)
		return
	}
	w := respond("credential-result")
	if _, err := w.Write(data); err != nil {
		slog.Error("[fdo.credentials] Failed to write result", "error", err)
	}
}

// NewCredentialsDevice creates a new CredentialsDevice with the given callback.
func NewCredentialsDevice(onCredentialReceived func(credentialID, credentialType string, data []byte, metadata map[string]any) error) *CredentialsDevice {
	return &CredentialsDevice{
		OnCredentialReceived: onCredentialReceived,
	}
}
