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

// CredentialsOwner implements the fdo.credentials FSIM for owner-side credential provisioning.
// It follows the specification in fdo.credentials.md and supports three protocol flows:
// 1. Provisioned Credentials - Owner provisions shared secrets to device
// 2. Enrolled Credentials - Device requests signed credentials (CSR, OAuth2 private key JWT)
// 3. Registered Credentials - Device registers public keys (SSH)
type CredentialsOwner struct {
	// Credentials to provision (Provisioned Credentials flow)
	credentials []ProvisionedCredential

	// Public keys to request from device (Registered Credentials flow)
	PublicKeyRequests []PublicKeyRequest

	// Callback for public key registration (Registered Credentials flow)
	OnPublicKeyReceived func(credentialID, credentialType string, publicKey []byte, metadata map[string]any) error

	// Internal state
	currentCredentialIndex int
	sentActive             bool
	sendingCredential      bool
	sentBegin              bool // Track if credential-begin has been sent

	// Chunking sender for credential data
	credentialSender *chunking.ChunkSender

	// Result from device
	credentialResult *chunking.ResultMessage

	// Registered Credentials state
	currentPubkeyRequestIndex int                     // Current pubkey request being processed
	pubkeyReceiver            *chunking.ChunkReceiver // Receiver for pubkey from device
	currentPubkeyID           string
	currentPubkeyType         string
	currentPubkeyMetadata     map[string]any
	currentPubkeyData         []byte
	pendingPubkeyResult       *chunking.ResultMessage // Result to send back to device
	waitingForPubkey          bool                    // True when waiting for device to send pubkey
}

// PublicKeyRequest represents a request for the device to send a public key.
type PublicKeyRequest struct {
	CredentialID   string         // Required: unique identifier (e.g., "ssh-admin-key")
	CredentialType string         // Required: "ssh_public_key"
	Metadata       map[string]any // Optional: username, key_type, key_size hints
}

// ProvisionedCredential represents a credential to provision to the device.
type ProvisionedCredential struct {
	CredentialID   string         // Required: unique identifier for this credential
	CredentialType string         // Required: "password", "api_key", "oauth2_client_secret", "bearer_token"
	CredentialData []byte         // Required: serialized credential data (JSON or CBOR)
	Metadata       map[string]any // Optional: type-specific metadata
	HashAlg        string         // Optional: hash algorithm for verification
}

var _ serviceinfo.OwnerModule = (*CredentialsOwner)(nil)

// HandleInfo implements serviceinfo.OwnerModule.
func (c *CredentialsOwner) HandleInfo(ctx context.Context, messageName string, messageBody io.Reader) error {
	return c.receive(ctx, messageName, messageBody)
}

// ProduceInfo implements serviceinfo.OwnerModule.
func (c *CredentialsOwner) ProduceInfo(ctx context.Context, producer *serviceinfo.Producer) (blockPeer, moduleDone bool, _ error) {
	return c.produceInfo(ctx, producer)
}

// Transition implements serviceinfo.OwnerModule.
func (c *CredentialsOwner) Transition(active bool) error {
	if !active {
		// Reset state when module is deactivated
		c.currentCredentialIndex = 0
		c.sentActive = false
		c.sendingCredential = false
		c.sentBegin = false
		c.credentialSender = nil
		c.credentialResult = nil
		// Reset registered credentials state
		c.currentPubkeyRequestIndex = 0
		c.pubkeyReceiver = nil
		c.currentPubkeyID = ""
		c.currentPubkeyType = ""
		c.currentPubkeyMetadata = nil
		c.currentPubkeyData = nil
		c.pendingPubkeyResult = nil
		c.waitingForPubkey = false
	}
	return nil
}

// Yield implements serviceinfo.OwnerModule.
func (c *CredentialsOwner) Yield(ctx context.Context, producer *serviceinfo.Producer) error {
	// Send pending pubkey-result if any
	if c.pendingPubkeyResult != nil {
		data, err := cbor.Marshal(c.pendingPubkeyResult)
		if err != nil {
			return fmt.Errorf("encode pubkey-result: %w", err)
		}
		if err := producer.WriteChunk("pubkey-result", data); err != nil {
			return fmt.Errorf("send pubkey-result: %w", err)
		}
		slog.Debug("[fdo.credentials] Sent pubkey-result",
			"status", c.pendingPubkeyResult.StatusCode,
			"message", c.pendingPubkeyResult.Message)
		c.pendingPubkeyResult = nil
	}
	return nil
}

// produceInfo handles the owner-side message production for Provisioned Credentials flow.
func (c *CredentialsOwner) produceInfo(ctx context.Context, producer *serviceinfo.Producer) (blockPeer, moduleDone bool, _ error) {
	// Step 1: Send active=true if not sent yet
	if !c.sentActive {
		if err := producer.WriteChunk("active", []byte{0xf5}); err != nil { // CBOR true
			return false, false, fmt.Errorf("write active: %w", err)
		}
		c.sentActive = true
		slog.Debug("[fdo.credentials] Sent active=true")
		return false, false, nil
	}

	// Step 2: Send credentials one by one
	if c.currentCredentialIndex < len(c.credentials) {
		cred := c.credentials[c.currentCredentialIndex]

		// If we're waiting for credential-result, block until we receive it
		if c.sendingCredential && c.credentialSender != nil && c.credentialSender.IsCompleted() {
			// We've sent credential-end, now wait for device's credential-result
			return true, false, nil
		}

		// Initialize sender if not already sending
		if c.credentialSender == nil {
			c.credentialSender = chunking.NewChunkSender("credential", cred.CredentialData)
			c.credentialSender.BeginFields.FSIMFields = make(map[int]any)
			c.credentialSender.BeginFields.FSIMFields[-1] = cred.CredentialID
			c.credentialSender.BeginFields.FSIMFields[-2] = cred.CredentialType
			if cred.Metadata != nil {
				c.credentialSender.BeginFields.FSIMFields[-3] = cred.Metadata
			}
			if cred.HashAlg != "" {
				c.credentialSender.BeginFields.HashAlg = cred.HashAlg
			}
			c.sendingCredential = true
			slog.Debug("[fdo.credentials] Starting credential provisioning",
				"credential_id", cred.CredentialID,
				"credential_type", cred.CredentialType,
				"size", len(cred.CredentialData))
		}

		// Send begin message
		if !c.sentBegin {
			if err := c.credentialSender.SendBegin(producer); err != nil {
				return false, false, fmt.Errorf("send credential-begin: %w", err)
			}
			c.sentBegin = true
			slog.Debug("[fdo.credentials] Sent credential-begin")
			return false, false, nil
		}

		// Send data chunks
		done, err := c.credentialSender.SendNextChunk(producer)
		if err != nil {
			return false, false, fmt.Errorf("send credential-data: %w", err)
		}
		if !done {
			slog.Debug("[fdo.credentials] Sent credential-data chunk",
				"bytes_sent", c.credentialSender.GetBytesSent(),
				"total_size", len(cred.CredentialData))
			return false, false, nil
		}

		// Send end message
		if err := c.credentialSender.SendEnd(producer); err != nil {
			return false, false, fmt.Errorf("send credential-end: %w", err)
		}
		slog.Debug("[fdo.credentials] Sent credential-end")

		// Don't block - device will respond with credential-result immediately
		// The result will be received in HandleInfo
		return false, false, nil
	}

	// Step 3: Request public keys from device (Registered Credentials flow)
	if c.currentPubkeyRequestIndex < len(c.PublicKeyRequests) {
		// If waiting for device response, block until we receive pubkey-end
		if c.waitingForPubkey {
			return true, false, nil // Block peer - wait for device to send pubkey
		}

		req := c.PublicKeyRequests[c.currentPubkeyRequestIndex]

		// Send pubkey-request
		requestMsg := map[int]any{
			-1: req.CredentialID,
			-2: req.CredentialType,
		}
		if req.Metadata != nil {
			requestMsg[-3] = req.Metadata
		}
		data, err := cbor.Marshal(requestMsg)
		if err != nil {
			return false, false, fmt.Errorf("encode pubkey-request: %w", err)
		}
		if err := producer.WriteChunk("pubkey-request", data); err != nil {
			return false, false, fmt.Errorf("send pubkey-request: %w", err)
		}
		slog.Debug("[fdo.credentials] Sent pubkey-request",
			"credential_id", req.CredentialID,
			"credential_type", req.CredentialType)

		c.waitingForPubkey = true
		return false, false, nil
	}

	// Step 4: All done, send active=false
	if err := producer.WriteChunk("active", []byte{0xf4}); err != nil { // CBOR false
		return false, false, fmt.Errorf("write active=false: %w", err)
	}
	slog.Debug("[fdo.credentials] Sent active=false, module done")

	// Module complete
	return false, true, nil
}

// receive handles incoming messages from the device.
func (c *CredentialsOwner) receive(ctx context.Context, messageName string, messageBody io.Reader) error {
	slog.Debug("[fdo.credentials] Received message", "name", messageName)

	switch messageName {
	case "active":
		// Device responds with active status
		var deviceActive bool
		if err := cbor.NewDecoder(messageBody).Decode(&deviceActive); err != nil {
			return fmt.Errorf("decode active response: %w", err)
		}
		if !deviceActive {
			return fmt.Errorf("device module is not active")
		}
		slog.Debug("[fdo.credentials] Device confirmed active")
		return nil

	case "credential-result":
		// Device acknowledges credential provisioning
		var result chunking.ResultMessage
		if err := cbor.NewDecoder(messageBody).Decode(&result); err != nil {
			return fmt.Errorf("decode credential-result: %w", err)
		}
		c.credentialResult = &result

		cred := c.credentials[c.currentCredentialIndex]
		if result.StatusCode == 0 {
			slog.Info("[fdo.credentials] Credential provisioned successfully",
				"credential_id", cred.CredentialID,
				"credential_type", cred.CredentialType,
				"message", result.Message)
		} else {
			slog.Warn("[fdo.credentials] Credential provisioning failed",
				"credential_id", cred.CredentialID,
				"credential_type", cred.CredentialType,
				"status", result.StatusCode,
				"message", result.Message)
		}

		// Move to next credential
		c.currentCredentialIndex++
		c.credentialSender = nil
		c.sendingCredential = false
		c.sentBegin = false
		c.credentialResult = nil

		return nil

	case "pubkey-begin":
		// Device starts sending a public key for registration
		return c.handlePubkeyBegin(messageBody)

	case "pubkey-end":
		// Device finishes sending public key
		return c.handlePubkeyEnd(ctx, messageBody)

	default:
		// Check if it's a pubkey-data-N message
		if c.pubkeyReceiver != nil {
			if err := c.pubkeyReceiver.HandleMessage(messageName, messageBody); err == nil {
				return nil
			}
		}
		return fmt.Errorf("unexpected message: %s", messageName)
	}
}

// handlePubkeyBegin processes the pubkey-begin message from the device.
func (c *CredentialsOwner) handlePubkeyBegin(messageBody io.Reader) error {
	// Initialize receiver if needed
	if c.pubkeyReceiver == nil {
		c.pubkeyReceiver = &chunking.ChunkReceiver{
			PayloadName: "pubkey",
			OnBegin: func(begin chunking.BeginMessage) error {
				// Extract FSIM-specific fields
				if credID, ok := begin.FSIMFields[-1].(string); ok {
					c.currentPubkeyID = credID
				}
				if credType, ok := begin.FSIMFields[-2].(string); ok {
					c.currentPubkeyType = credType
				}
				if metadata, ok := begin.FSIMFields[-3].(map[string]any); ok {
					c.currentPubkeyMetadata = metadata
				}

				slog.Debug("[fdo.credentials] Receiving public key",
					"credential_id", c.currentPubkeyID,
					"credential_type", c.currentPubkeyType,
					"total_size", begin.TotalSize)
				return nil
			},
			OnChunk: func(data []byte) error {
				return nil
			},
			OnEnd: func(end chunking.EndMessage) error {
				// Save data before reset
				c.currentPubkeyData = make([]byte, len(c.pubkeyReceiver.GetBuffer()))
				copy(c.currentPubkeyData, c.pubkeyReceiver.GetBuffer())
				slog.Debug("[fdo.credentials] Public key received completely",
					"credential_id", c.currentPubkeyID,
					"size", len(c.currentPubkeyData))
				return nil
			},
		}
	}

	// Handle the begin message
	if err := c.pubkeyReceiver.HandleMessage("pubkey-begin", messageBody); err != nil {
		return fmt.Errorf("handle pubkey-begin: %w", err)
	}

	return nil
}

// handlePubkeyEnd processes the pubkey-end message and sends result.
func (c *CredentialsOwner) handlePubkeyEnd(ctx context.Context, messageBody io.Reader) error {
	// Handle the end message (this calls OnEnd which saves the data before reset)
	if err := c.pubkeyReceiver.HandleMessage("pubkey-end", messageBody); err != nil {
		return fmt.Errorf("handle pubkey-end: %w", err)
	}

	// Use the public key data saved in OnEnd callback
	pubkeyData := c.currentPubkeyData

	// Invoke callback if provided
	var resultStatus int
	var resultMessage string
	if c.OnPublicKeyReceived != nil {
		if err := c.OnPublicKeyReceived(
			c.currentPubkeyID,
			c.currentPubkeyType,
			pubkeyData,
			c.currentPubkeyMetadata,
		); err != nil {
			slog.Error("[fdo.credentials] Public key registration failed",
				"credential_id", c.currentPubkeyID,
				"error", err)
			resultStatus = 2
			resultMessage = fmt.Sprintf("Registration failed: %v", err)
		} else {
			slog.Info("[fdo.credentials] Public key registered successfully",
				"credential_id", c.currentPubkeyID,
				"credential_type", c.currentPubkeyType)
			resultStatus = 0
			resultMessage = "Public key registered"
		}
	} else {
		// No callback, just acknowledge receipt
		slog.Info("[fdo.credentials] Public key received (no handler)",
			"credential_id", c.currentPubkeyID,
			"credential_type", c.currentPubkeyType,
			"size", len(pubkeyData))
		resultStatus = 0
		resultMessage = "Public key received"
	}

	// Reset state for next public key request
	c.pubkeyReceiver = nil
	c.currentPubkeyID = ""
	c.currentPubkeyType = ""
	c.currentPubkeyMetadata = nil
	c.currentPubkeyData = nil
	c.waitingForPubkey = false
	c.currentPubkeyRequestIndex++ // Move to next request

	// Store result for sending via Yield
	c.pendingPubkeyResult = &chunking.ResultMessage{
		StatusCode: resultStatus,
		Message:    resultMessage,
	}

	return nil
}

// NewCredentialsOwner creates a new CredentialsOwner with the given credentials to provision.
func NewCredentialsOwner(credentials []ProvisionedCredential) *CredentialsOwner {
	return &CredentialsOwner{
		credentials: credentials,
	}
}
