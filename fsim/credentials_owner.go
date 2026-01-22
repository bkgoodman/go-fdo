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

	// Internal state
	currentCredentialIndex int
	sentActive             bool
	sendingCredential      bool
	sentBegin              bool // Track if credential-begin has been sent

	// Chunking sender for credential data
	credentialSender *chunking.ChunkSender

	// Result from device
	credentialResult *chunking.ResultMessage
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
	}
	return nil
}

// Yield implements serviceinfo.OwnerModule.
func (c *CredentialsOwner) Yield(ctx context.Context, producer *serviceinfo.Producer) error {
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

	// Step 3: All credentials sent, send active=false
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

	default:
		return fmt.Errorf("unexpected message: %s", messageName)
	}
}

// NewCredentialsOwner creates a new CredentialsOwner with the given credentials to provision.
func NewCredentialsOwner(credentials []ProvisionedCredential) *CredentialsOwner {
	return &CredentialsOwner{
		credentials: credentials,
	}
}
