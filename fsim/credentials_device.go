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

	// Callback for generating/retrieving public keys (Registered Credentials flow)
	// Called when owner requests a public key. Returns the public key data.
	OnPublicKeyRequested func(credentialID, credentialType string, metadata map[string]any) ([]byte, error)

	// Internal state
	active              bool
	receivingCredential bool

	// Chunking receiver for credential data (Provisioned flow)
	credentialReceiver *chunking.ChunkReceiver

	// Current credential being received
	currentCredentialID   string
	currentCredentialType string
	currentMetadata       map[string]any
	currentCredentialData []byte // Store data from OnEnd callback before reset

	// Registered Credentials state (responding to owner requests)
	pendingPubkeyRequest *pubkeyRequestInfo // Current request from owner
	pubkeyResults        []RegisteredResult // Results from owner
}

// pubkeyRequestInfo holds info about a pending pubkey request from owner
type pubkeyRequestInfo struct {
	CredentialID   string
	CredentialType string
	Metadata       map[string]any
	PublicKeyData  []byte // Generated/retrieved public key
}

// RegisteredCredential represents a public key to register with the owner.
type RegisteredCredential struct {
	CredentialID   string         // Required: unique identifier (e.g., "ssh-admin-key")
	CredentialType string         // Required: "ssh_public_key"
	PublicKeyData  []byte         // Required: public key data (OpenSSH format)
	Metadata       map[string]any // Optional: username, authorized_hosts, key_type, comment
}

// RegisteredResult contains the result of a public key registration.
type RegisteredResult struct {
	CredentialID string
	StatusCode   int
	Message      string
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
		c.currentCredentialData = nil
		// Reset registered credentials state
		c.pendingPubkeyRequest = nil
	}
	return nil
}

// Yield implements serviceinfo.DeviceModule.
func (c *CredentialsDevice) Yield(ctx context.Context, respond func(string) io.Writer, yield func()) error {
	// Send public key in response to owner's pubkey-request
	// Note: Yield is only called once, so we must send all messages here
	if c.pendingPubkeyRequest != nil {
		req := c.pendingPubkeyRequest

		// Create sender
		sender := chunking.NewChunkSender("pubkey", req.PublicKeyData)
		sender.BeginFields.FSIMFields = make(map[int]any)
		sender.BeginFields.FSIMFields[-1] = req.CredentialID
		sender.BeginFields.FSIMFields[-2] = req.CredentialType
		if req.Metadata != nil {
			sender.BeginFields.FSIMFields[-3] = req.Metadata
		}

		slog.Debug("[fdo.credentials] Sending public key",
			"credential_id", req.CredentialID,
			"credential_type", req.CredentialType,
			"size", len(req.PublicKeyData))

		// Send begin message
		if err := sender.SendBeginToWriter(respond); err != nil {
			return fmt.Errorf("send pubkey-begin: %w", err)
		}
		slog.Debug("[fdo.credentials] Sent pubkey-begin")

		// Send all data chunks
		for {
			done, err := sender.SendNextChunkToWriter(respond)
			if err != nil {
				return fmt.Errorf("send pubkey-data: %w", err)
			}
			if done {
				break
			}
			slog.Debug("[fdo.credentials] Sent pubkey-data chunk")
		}

		// Send end message
		if err := sender.SendEndToWriter(respond); err != nil {
			return fmt.Errorf("send pubkey-end: %w", err)
		}
		slog.Debug("[fdo.credentials] Sent pubkey-end")

		// Clear pending request
		c.pendingPubkeyRequest = nil
	}

	return nil
}

// Receive implements serviceinfo.DeviceModule.
func (c *CredentialsDevice) Receive(ctx context.Context, messageName string, messageBody io.Reader, respond func(string) io.Writer, yield func()) error {
	slog.Debug("[fdo.credentials] Received message", "key", messageName)

	switch messageName {
	case "active":
		// Owner activates or deactivates the module
		var active bool
		if err := cbor.NewDecoder(messageBody).Decode(&active); err != nil {
			return fmt.Errorf("decode active: %w", err)
		}
		c.active = active
		slog.Debug("[fdo.credentials] Module active", "active", active)

		// Respond with active state (required by protocol)
		w := respond("active")
		if err := cbor.NewEncoder(w).Encode(c.active); err != nil {
			return fmt.Errorf("encode active response: %w", err)
		}
		return nil

	case "credential-begin":
		// Owner starts sending a credential
		return c.handleCredentialBegin(messageBody)

	case "credential-end":
		// Owner finishes sending credential
		return c.handleCredentialEnd(messageBody, respond)

	case "pubkey-request":
		// Owner requests a public key from device
		return c.handlePubkeyRequest(messageBody, yield)

	case "pubkey-result":
		// Owner responds to public key registration
		return c.handlePubkeyResult(messageBody)

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

// handlePubkeyRequest processes the pubkey-request message from the owner.
func (c *CredentialsDevice) handlePubkeyRequest(messageBody io.Reader, yield func()) error {
	// Decode request
	var request map[int]any
	if err := cbor.NewDecoder(messageBody).Decode(&request); err != nil {
		return fmt.Errorf("decode pubkey-request: %w", err)
	}

	credID, _ := request[-1].(string)
	credType, _ := request[-2].(string)
	metadata, _ := request[-3].(map[string]any)

	slog.Debug("[fdo.credentials] Received pubkey-request",
		"credential_id", credID,
		"credential_type", credType)

	// Call callback to get the public key
	if c.OnPublicKeyRequested == nil {
		return fmt.Errorf("no OnPublicKeyRequested callback configured")
	}

	pubkeyData, err := c.OnPublicKeyRequested(credID, credType, metadata)
	if err != nil {
		return fmt.Errorf("failed to get public key: %w", err)
	}

	// Store pending request - Yield will send the response
	c.pendingPubkeyRequest = &pubkeyRequestInfo{
		CredentialID:   credID,
		CredentialType: credType,
		Metadata:       metadata,
		PublicKeyData:  pubkeyData,
	}

	// Signal that we have data to send
	yield()
	return nil
}

// handlePubkeyResult processes the pubkey-result message from the owner.
func (c *CredentialsDevice) handlePubkeyResult(messageBody io.Reader) error {
	var result chunking.ResultMessage
	if err := cbor.NewDecoder(messageBody).Decode(&result); err != nil {
		return fmt.Errorf("decode pubkey-result: %w", err)
	}

	c.pubkeyResults = append(c.pubkeyResults, RegisteredResult{
		CredentialID: result.Message, // Use message as ID for now
		StatusCode:   result.StatusCode,
		Message:      result.Message,
	})

	if result.StatusCode == 0 {
		slog.Info("[fdo.credentials] Public key registered successfully",
			"message", result.Message)
	} else {
		slog.Warn("[fdo.credentials] Public key registration failed",
			"status", result.StatusCode,
			"message", result.Message)
	}

	return nil
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
				// Credential fully received - save data before reset clears buffer
				c.currentCredentialData = make([]byte, len(c.credentialReceiver.GetBuffer()))
				copy(c.currentCredentialData, c.credentialReceiver.GetBuffer())
				slog.Debug("[fdo.credentials] Credential received completely",
					"credential_id", c.currentCredentialID,
					"size", len(c.currentCredentialData))
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
	// Handle the end message (this calls OnEnd which saves the data before reset)
	if err := c.credentialReceiver.HandleMessage("credential-end", messageBody); err != nil {
		return fmt.Errorf("handle credential-end: %w", err)
	}

	// Use the credential data saved in OnEnd callback (buffer is reset after HandleMessage)
	credentialData := c.currentCredentialData

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
	c.currentCredentialData = nil

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
