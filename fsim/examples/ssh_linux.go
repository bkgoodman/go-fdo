// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

// Package examples provides example implementations of FSIM callbacks for real-world systems.
// These implementations are NOT part of the core library and should be adapted for your environment.
package examples

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// LinuxSSHInstaller provides a Linux-specific implementation for installing SSH keys.
// This is an EXAMPLE implementation for standard Linux systems with OpenSSH.
// Adapt this for your specific environment (embedded systems, BSD, etc.).
type LinuxSSHInstaller struct {
	// DefaultUsername is used when no username is specified
	DefaultUsername string
}

// InstallAuthorizedKey installs an SSH public key for the specified user.
// This example implementation:
// - Writes to /home/username/.ssh/authorized_keys or /root/.ssh/authorized_keys
// - Creates .ssh directory if needed
// - Sets appropriate permissions
// - Optionally grants sudo access
func (l *LinuxSSHInstaller) InstallAuthorizedKey(key, username string, sudo bool) error {
	// Use default username if not specified
	if username == "" {
		if l.DefaultUsername != "" {
			username = l.DefaultUsername
		} else {
			username = "root"
		}
	}

	// Determine home directory
	var homeDir string
	if username == "root" {
		homeDir = "/root"
	} else {
		homeDir = filepath.Join("/home", username)
	}

	// Check if user exists
	if _, err := os.Stat(homeDir); os.IsNotExist(err) {
		return fmt.Errorf("user home directory does not exist: %s", homeDir)
	}

	// Create .ssh directory if it doesn't exist
	sshDir := filepath.Join(homeDir, ".ssh")
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		return fmt.Errorf("error creating .ssh directory: %w", err)
	}

	// Set ownership of .ssh directory (best-effort if running as root)
	_ = chownUser(sshDir, username)

	// Append key to authorized_keys
	authorizedKeysPath := filepath.Join(sshDir, "authorized_keys")
	f, err := os.OpenFile(authorizedKeysPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("error opening authorized_keys: %w", err)
	}
	defer f.Close()

	// Ensure key ends with newline
	keyLine := strings.TrimSpace(key) + "\n"
	if _, err := f.WriteString(keyLine); err != nil {
		return fmt.Errorf("error writing to authorized_keys: %w", err)
	}

	// Set ownership of authorized_keys (best-effort if running as root)
	_ = chownUser(authorizedKeysPath, username)

	// Handle sudo flag if requested
	if sudo {
		if err := grantSudoAccess(username); err != nil {
			// Log but don't fail - sudo setup is best-effort
			return fmt.Errorf("warning: failed to grant sudo access: %w", err)
		}
	}

	return nil
}

// LinuxSSHHostKeys provides a Linux-specific implementation for retrieving SSH host keys.
// This is an EXAMPLE implementation for standard Linux systems with OpenSSH.
type LinuxSSHHostKeys struct {
	// HostKeyPaths specifies where to look for host keys
	// If empty, defaults to standard OpenSSH locations
	HostKeyPaths []string

	// GenerateIfMissing determines whether to generate keys if none exist
	GenerateIfMissing bool
}

// GetHostKeys retrieves SSH host public keys from the system.
// This example implementation:
// - Reads from /etc/ssh/ssh_host_*_key.pub
// - Optionally generates keys if missing
func (l *LinuxSSHHostKeys) GetHostKeys() ([]string, error) {
	paths := l.HostKeyPaths
	if len(paths) == 0 {
		// Default OpenSSH locations
		paths = []string{
			"/etc/ssh/ssh_host_rsa_key.pub",
			"/etc/ssh/ssh_host_ecdsa_key.pub",
			"/etc/ssh/ssh_host_ed25519_key.pub",
		}
	}

	var hostKeys []string
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			continue // Skip missing keys
		}

		keyStr := strings.TrimSpace(string(data))
		if keyStr != "" {
			hostKeys = append(hostKeys, keyStr)
		}
	}

	// If no keys found and generation is enabled, try to generate them
	if len(hostKeys) == 0 && l.GenerateIfMissing {
		if err := generateHostKeys(); err != nil {
			return nil, fmt.Errorf("no host keys found and generation failed: %w", err)
		}

		// Try reading again
		for _, path := range paths {
			data, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			keyStr := strings.TrimSpace(string(data))
			if keyStr != "" {
				hostKeys = append(hostKeys, keyStr)
			}
		}
	}

	if len(hostKeys) == 0 {
		return nil, fmt.Errorf("no SSH host keys found")
	}

	return hostKeys, nil
}

// Helper functions for Linux-specific operations

// chownUser attempts to set file ownership to the specified user.
// This is a best-effort operation and will fail silently if not running as root.
func chownUser(path, username string) error {
	cmd := exec.Command("chown", username+":"+username, path)
	return cmd.Run()
}

// grantSudoAccess attempts to grant sudo access to the user.
// This is a best-effort operation.
func grantSudoAccess(username string) error {
	// Try adding to sudoers.d
	sudoersPath := filepath.Join("/etc/sudoers.d", username)
	content := fmt.Sprintf("%s ALL=(ALL) NOPASSWD: ALL\n", username)

	if err := os.WriteFile(sudoersPath, []byte(content), 0440); err != nil {
		return err
	}

	return nil
}

// generateHostKeys attempts to generate SSH host keys using ssh-keygen.
func generateHostKeys() error {
	// Check if ssh-keygen is available
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		return fmt.Errorf("ssh-keygen not found: %w", err)
	}

	keyTypes := []struct {
		typ  string
		path string
	}{
		{"rsa", "/etc/ssh/ssh_host_rsa_key"},
		{"ecdsa", "/etc/ssh/ssh_host_ecdsa_key"},
		{"ed25519", "/etc/ssh/ssh_host_ed25519_key"},
	}

	var lastErr error
	for _, kt := range keyTypes {
		// Skip if key already exists
		if _, err := os.Stat(kt.path); err == nil {
			continue
		}

		cmd := exec.Command("ssh-keygen", "-t", kt.typ, "-f", kt.path, "-N", "")
		if err := cmd.Run(); err != nil {
			lastErr = err
			continue
		}
	}

	return lastErr
}

// LinuxKnownHostsWriter provides a Linux-specific implementation for storing device host keys.
// This is an EXAMPLE implementation that writes to a known_hosts file.
type LinuxKnownHostsWriter struct {
	// KnownHostsPath specifies where to write known_hosts entries
	// If empty, defaults to /etc/ssh/known_hosts
	KnownHostsPath string

	// GetHostname is called to determine the hostname for each device
	// If nil, a generic "device-{guid}" format is used
	GetHostname func(deviceGUID string) string
}

// OnHostKeys writes device host keys to the known_hosts file.
func (l *LinuxKnownHostsWriter) OnHostKeys(deviceGUID string, hostKeys []string) error {
	knownHostsPath := l.KnownHostsPath
	if knownHostsPath == "" {
		knownHostsPath = "/etc/ssh/known_hosts"
	}

	// Open known_hosts file for appending
	f, err := os.OpenFile(knownHostsPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("error opening known_hosts: %w", err)
	}
	defer f.Close()

	// Determine hostname
	hostname := deviceGUID
	if l.GetHostname != nil {
		hostname = l.GetHostname(deviceGUID)
	}

	// Write each host key
	for _, key := range hostKeys {
		line := fmt.Sprintf("%s %s\n", hostname, key)
		if _, err := f.WriteString(line); err != nil {
			return fmt.Errorf("error writing to known_hosts: %w", err)
		}
	}

	return nil
}
