// SPDX-FileCopyrightText: (C) 2024 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package fsim

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/serviceinfo"
)

// SSH implements the fdo.ssh FSIM for SSH key enrollment on the device side.
// See fdo.ssh.md specification.
//
// This module is purely callback-based and performs NO OS-specific operations.
// All key installation, host key retrieval, and system configuration must be
// provided by the application via callbacks.
type SSH struct {
	// InstallAuthorizedKey is called when the owner sends an SSH public key to install.
	// The key, username, and sudo flag are passed as opaque strings/values.
	// The implementation is responsible for all OS-specific operations:
	// - Writing to authorized_keys files
	// - Creating users if needed
	// - Configuring sudo access
	// - Setting file permissions
	// This callback is REQUIRED.
	InstallAuthorizedKey func(key, username string, sudo bool) error

	// GetHostKeys returns the device's SSH host public keys as opaque strings.
	// The implementation is responsible for:
	// - Reading host key files from appropriate locations
	// - Generating keys if needed
	// - Returning keys in the format expected by SSH (typically OpenSSH format)
	// This callback is REQUIRED.
	GetHostKeys func() ([]string, error)

	// DefaultUsername is used when no username is specified in add-key.
	// If empty, the implementation should decide an appropriate default.
	DefaultUsername string

	// Internal state
	hostKeysSent bool
	pendingError *uint
}

// SSHKeyInstall represents the structure for installing an SSH key.
type SSHKeyInstall struct {
	Key      string `cbor:"key"`
	Username string `cbor:"username,omitempty"`
	Sudo     bool   `cbor:"sudo,omitempty"`
}

var _ serviceinfo.DeviceModule = (*SSH)(nil)

// Transition implements serviceinfo.DeviceModule.
func (s *SSH) Transition(active bool) error {
	if !active {
		s.reset()
	}
	return nil
}

// Receive implements serviceinfo.DeviceModule.
func (s *SSH) Receive(ctx context.Context, messageName string, messageBody io.Reader, respond func(string) io.Writer, yield func()) error {
	if err := s.receive(ctx, messageName, messageBody); err != nil {
		s.reset()
		return err
	}
	return nil
}

func (s *SSH) receive(ctx context.Context, messageName string, messageBody io.Reader) error {
	switch messageName {
	case "add-key":
		return s.receiveAddKey(messageBody)

	case "error":
		var errCode uint
		if err := cbor.NewDecoder(messageBody).Decode(&errCode); err != nil {
			return fmt.Errorf("error decoding error code: %w", err)
		}
		s.pendingError = &errCode
		return fmt.Errorf("SSH operation failed with error code %d: %s", errCode, sshErrorString(errCode))

	default:
		return fmt.Errorf("unknown message %s", messageName)
	}
}

// Yield implements serviceinfo.DeviceModule.
func (s *SSH) Yield(ctx context.Context, respond func(message string) io.Writer, yield func()) error {
	// Check for pending error
	if s.pendingError != nil {
		return fmt.Errorf("SSH operation failed with error code %d", *s.pendingError)
	}

	// Send host keys once
	if !s.hostKeysSent {
		if err := s.sendHostKeys(respond); err != nil {
			return err
		}
		s.hostKeysSent = true
		yield()
	}

	return nil
}

func (s *SSH) receiveAddKey(messageBody io.Reader) error {
	var keyInstall SSHKeyInstall
	if err := cbor.NewDecoder(messageBody).Decode(&keyInstall); err != nil {
		return fmt.Errorf("error decoding add-key: %w", err)
	}

	// Check that callback is provided
	if s.InstallAuthorizedKey == nil {
		return errors.New("InstallAuthorizedKey callback is required but not provided")
	}

	// Determine username
	username := keyInstall.Username
	if username == "" {
		username = s.DefaultUsername
	}

	// Install key via callback - key is treated as opaque string
	if err := s.InstallAuthorizedKey(keyInstall.Key, username, keyInstall.Sudo); err != nil {
		return fmt.Errorf("error installing authorized key: %w", err)
	}

	if debugEnabled() {
		slog.Debug("fdo.ssh: authorized key installed", "username", username, "sudo", keyInstall.Sudo)
	}

	return nil
}

func (s *SSH) sendHostKeys(respond func(string) io.Writer) error {
	// Check that callback is provided
	if s.GetHostKeys == nil {
		return errors.New("GetHostKeys callback is required but not provided")
	}

	// Get host keys via callback - keys are treated as opaque strings
	hostKeys, err := s.GetHostKeys()
	if err != nil {
		return fmt.Errorf("error getting host keys: %w", err)
	}

	if len(hostKeys) == 0 {
		return errors.New("no SSH host keys found")
	}

	if err := cbor.NewEncoder(respond("host-keys")).Encode(hostKeys); err != nil {
		return fmt.Errorf("error sending host-keys: %w", err)
	}

	if debugEnabled() {
		slog.Debug("fdo.ssh: host keys sent", "count", len(hostKeys))
	}

	return nil
}

func (s *SSH) reset() {
	s.hostKeysSent = false
	s.pendingError = nil
}

func sshErrorString(code uint) string {
	switch code {
	case 1:
		return "Bad request / Invalid format"
	case 2:
		return "Permission denied"
	case 3:
		return "User not found"
	case 4:
		return "Filesystem error"
	case 5:
		return "SSH service not available"
	default:
		return "Unknown error"
	}
}
