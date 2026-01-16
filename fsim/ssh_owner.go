// SPDX-FileCopyrightText: (C) 2024 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package fsim

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/serviceinfo"
)

// SSHOwner implements the fdo.ssh FSIM for SSH key enrollment on the owner side.
//
// This module is purely callback-based and performs NO key validation or parsing.
// All keys are treated as opaque strings.
type SSHOwner struct {
	// AuthorizedKeys is a list of SSH keys to install on the device.
	// Each entry can specify the key, username, and sudo flag.
	// Keys are treated as opaque strings - no validation is performed.
	AuthorizedKeys []SSHKeyInstall

	// OnHostKeys is called when the device reports its SSH host keys.
	// Keys are passed as opaque strings.
	// The implementation is responsible for:
	// - Storing keys in known_hosts files
	// - Storing keys in databases
	// - Any validation or parsing if desired
	// This callback is optional.
	OnHostKeys func(hostKeys []string) error

	// Internal state
	keyIndex        int
	pendingResponse *pendingSSHResponse
}

type pendingSSHResponse struct {
	messageType string
	data        []byte
	errorCode   *uint
}

var _ serviceinfo.OwnerModule = (*SSHOwner)(nil)

// HandleInfo implements serviceinfo.OwnerModule.
func (s *SSHOwner) HandleInfo(ctx context.Context, messageName string, messageBody io.Reader) error {
	switch messageName {
	case "active":
		var deviceActive bool
		if err := cbor.NewDecoder(messageBody).Decode(&deviceActive); err != nil {
			return fmt.Errorf("error decoding active message: %w", err)
		}
		if !deviceActive {
			return fmt.Errorf("device SSH module is not active")
		}
		return nil

	case "host-keys":
		return s.handleHostKeys(messageBody)

	case "error":
		var errCode uint
		if err := cbor.NewDecoder(messageBody).Decode(&errCode); err != nil {
			return fmt.Errorf("error decoding error code: %w", err)
		}
		return fmt.Errorf("device reported SSH error %d: %s", errCode, sshErrorString(errCode))

	default:
		return fmt.Errorf("unknown message %s", messageName)
	}
}

// ProduceInfo implements serviceinfo.OwnerModule.
func (s *SSHOwner) ProduceInfo(ctx context.Context, producer *serviceinfo.Producer) (blockPeer, moduleDone bool, _ error) {
	// Send pending response if any
	if s.pendingResponse != nil {
		if s.pendingResponse.errorCode != nil {
			var buf bytes.Buffer
			if err := cbor.NewEncoder(&buf).Encode(*s.pendingResponse.errorCode); err != nil {
				return false, false, fmt.Errorf("error encoding error response: %w", err)
			}
			if err := producer.WriteChunk("error", buf.Bytes()); err != nil {
				return false, false, fmt.Errorf("error sending error response: %w", err)
			}
			s.pendingResponse = nil
			return false, true, nil
		}

		var buf bytes.Buffer
		if err := cbor.NewEncoder(&buf).Encode(s.pendingResponse.data); err != nil {
			return false, false, fmt.Errorf("error encoding %s: %w", s.pendingResponse.messageType, err)
		}
		if err := producer.WriteChunk(s.pendingResponse.messageType, buf.Bytes()); err != nil {
			return false, false, fmt.Errorf("error sending %s: %w", s.pendingResponse.messageType, err)
		}

		if debugEnabled() {
			slog.Debug("fdo.ssh: sent response", "type", s.pendingResponse.messageType)
		}

		s.pendingResponse = nil
		return false, false, nil
	}

	// Send authorized keys
	if s.keyIndex < len(s.AuthorizedKeys) {
		keyInstall := s.AuthorizedKeys[s.keyIndex]
		s.keyIndex++

		// Keys are treated as opaque strings - no validation
		var buf bytes.Buffer
		if err := cbor.NewEncoder(&buf).Encode(keyInstall); err != nil {
			return false, false, fmt.Errorf("error encoding add-key: %w", err)
		}

		if err := producer.WriteChunk("add-key", buf.Bytes()); err != nil {
			return false, false, fmt.Errorf("error sending add-key: %w", err)
		}

		if debugEnabled() {
			slog.Debug("fdo.ssh: sent add-key", "username", keyInstall.Username, "sudo", keyInstall.Sudo)
		}

		return false, false, nil
	}

	// All keys sent, module is done
	return false, true, nil
}

func (s *SSHOwner) handleHostKeys(messageBody io.Reader) error {
	var hostKeys []string
	if err := cbor.NewDecoder(messageBody).Decode(&hostKeys); err != nil {
		return fmt.Errorf("error decoding host-keys: %w", err)
	}

	if len(hostKeys) == 0 {
		return errors.New("device sent empty host keys list")
	}

	// Keys are treated as opaque strings - no validation
	// Call handler if provided
	if s.OnHostKeys != nil {
		if err := s.OnHostKeys(hostKeys); err != nil {
			return fmt.Errorf("error handling host keys: %w", err)
		}
	}

	if debugEnabled() {
		slog.Debug("fdo.ssh: received host keys", "count", len(hostKeys))
	}

	return nil
}

// AddAuthorizedKey adds an SSH public key to be installed on the device.
// The key is treated as an opaque string - no validation is performed.
func (s *SSHOwner) AddAuthorizedKey(key, username string, sudo bool) {
	s.AuthorizedKeys = append(s.AuthorizedKeys, SSHKeyInstall{
		Key:      key,
		Username: username,
		Sudo:     sudo,
	})
}

// Reset resets the module state for reuse.
func (s *SSHOwner) Reset() {
	s.keyIndex = 0
	s.pendingResponse = nil
}
