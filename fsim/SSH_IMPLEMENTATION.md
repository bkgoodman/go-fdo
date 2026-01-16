# fdo.ssh FSIM Implementation Guide

Copyright &copy; 2026 Dell Technologies and FIDO Alliance

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

This document describes the implementation of the `fdo.ssh` FSIM (SSH key enrollment module) for FDO device onboarding.

## Overview

The `fdo.ssh` FSIM enables SSH key provisioning during FDO device onboarding. It allows the Onboarding Service (OBS) to:

1. Install SSH authorized keys on devices for remote access
2. Obtain device SSH host keys for known_hosts verification

The implementation is minimal, OS-agnostic, and works across different SSH implementations (OpenSSH, Dropbear, etc.).

## Basic SSH Enrollment Flow

| Step | What Happens | Device Sends | Operation | Request Key | Response Key | Purpose |
| --------- | ----------- | ------------ | ------- |----- |
| **1. Install authorized keys** | OBS sends SSH public keys to device | - |  | `fdo.ssh:add-key` | `add-key` | Install SSH authorized keys |
| | Device installs keys in authorized_keys | - | - | - | - | - |
| **2. Report host keys** | Device sends its SSH host public keys | `fdo.ssh:host-keys` | - | - | `host-keys` | Report SSH host keys |

## Message Format Details

| FSIM Key | Direction | Value Type | Content |
| -------- | --------- | ---------- | ------- |
| `fdo.ssh:active` | Bidirectional | `bool` | Module activation |
| `fdo.ssh:add-key` | Owner → Device | `SSHKeyInstall` | SSH public key + username + sudo flag |
| `fdo.ssh:host-keys` | Device → Owner | `array of tstr` | Device SSH host public keys |
| `fdo.ssh:error` | Owner → Device | `uint` | Error code (1-5) |

### SSHKeyInstall Structure

    type SSHKeyInstall struct {
        Key      string `cbor:"key"`               // Required: SSH public key
        Username string `cbor:"username,omitempty"` // Optional: target username
        Sudo     bool   `cbor:"sudo,omitempty"`     // Optional: grant sudo access
    }

## Implementation Files

- **`ssh_device.go`** - Device-side SSH module (462 lines)
- **`ssh_owner.go`** - Owner-side SSH module (189 lines)
- **`fdo.ssh.md`** - FSIM specification

## Device-Side Usage

### Basic Setup

    import (
        "github.com/fido-device-onboard/go-fdo/fsim"
    )
    
    // Create SSH module with default behavior
    sshModule := &fsim.SSH{
        DefaultUsername: "admin", // Used when no username specified
    }
    
    // Register module
    deviceModules := map[string]serviceinfo.DeviceModule{
        "fdo.ssh": sshModule,
    }

### Custom Key Installation

    sshModule := &fsim.SSH{
        // Custom authorized key installation
        InstallAuthorizedKey: func(key, username string, sudo bool) error {
            // Your custom logic here
            // - Validate username
            // - Create user if needed
            // - Write to authorized_keys
            // - Configure sudo access
            return installKey(key, username, sudo)
        },
        
        // Custom host key retrieval
        GetHostKeys: func() ([]string, error) {
            // Read from custom location
            return readHostKeys("/custom/path")
        },
    }

### Default Behavior

If callbacks are not provided, the module uses defaults:

**InstallAuthorizedKey (default):**

- Writes to `/home/username/.ssh/authorized_keys` or `/root/.ssh/authorized_keys`
- Creates `.ssh` directory if needed (mode 0700)
- Sets file permissions to 0600
- Attempts to set ownership (if running as root)
- Grants sudo by writing to `/etc/sudoers.d/username` (best-effort)

**GetHostKeys (default):**

- Reads from `/etc/ssh/ssh_host_*_key.pub`
- Supports RSA, ECDSA, and Ed25519 keys
- Generates keys if none exist (using `ssh-keygen` or manual generation)

## Owner-Side Usage

### Basic Setup

    import (
        "github.com/fido-device-onboard/go-fdo/fsim"
    )
    
    // Create SSH owner module
    sshOwner := &fsim.SSHOwner{
        // Keys to install on device
        AuthorizedKeys: []fsim.SSHKeyInstall{
            {
                Key:      "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... admin@company.com",
                Username: "admin",
                Sudo:     true,
            },
            {
                Key:      "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC... operator@company.com",
                Username: "operator",
                Sudo:     false,
            },
        },
        
        // Handle device host keys
        OnHostKeys: func(hostKeys []string) error {
            // Store in known_hosts file or database
            return storeHostKeys(deviceHostname, hostKeys)
        },
    }
    
    // Register module
    ownerModules := map[string]serviceinfo.OwnerModule{
        "fdo.ssh": sshOwner,
    }

### Dynamic Key Addition

    sshOwner := &fsim.SSHOwner{
        OnHostKeys: hostKeyHandler,
    }
    
    // Add keys dynamically
    err := sshOwner.AddAuthorizedKey(
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... user@host",
        "newuser",
        false, // no sudo
    )

### Host Key Storage Example

    OnHostKeys: func(hostKeys []string) error {
        // Parse device GUID from context
        guid := getDeviceGUID(ctx)
        
        // Store in database
        for _, key := range hostKeys {
            keyType, fingerprint, _ := fsim.ParseSSHPublicKey(key)
            db.StoreHostKey(guid, keyType, fingerprint, key)
        }
        
        // Write to known_hosts file
        knownHostsFile := "/etc/ssh/known_hosts"
        f, _ := os.OpenFile(knownHostsFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
        defer f.Close()
        
        hostname := getDeviceHostname(guid)
        for _, key := range hostKeys {
            fmt.Fprintf(f, "%s %s\n", hostname, key)
        }
        
        return nil
    }

## Helper Functions

### Generate SSH Key Pair

    // Generate Ed25519 key pair
    publicKey, privateKey, err := fsim.GenerateSSHKeyPair("ed25519")
    
    // Generate RSA key pair
    publicKey, privateKey, err := fsim.GenerateSSHKeyPair("rsa")

### Parse SSH Public Key

    keyType, fingerprint, err := fsim.ParseSSHPublicKey(
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... user@host",
    )
    // keyType: "ssh-ed25519"
    // fingerprint: "SHA256:abc123..."

## Error Codes

| Error Code | Description | Meaning |
| ---------- | ----------- | ------- |
| 1 | Bad request / Invalid format | SSH key format is invalid |
| 2 | Permission denied | Cannot install key (insufficient permissions) |
| 3 | User not found | Username doesn't exist and can't be created |
| 4 | Filesystem error | Can't write to authorized_keys |
| 5 | SSH service not available | SSH not installed or configured |

## Security Considerations

### Device Side

1. **Key Validation**: Always validate SSH public key format before installation
2. **File Permissions**: Ensure `.ssh` directory is 0700 and `authorized_keys` is 0600
3. **User Validation**: Validate usernames against system policies
4. **Sudo Access**: Carefully control sudo flag - implement authorization checks
5. **Audit Logging**: Log all key installation events

### Owner Side

1. **Key Management**: Store private keys securely (never transmit them)
2. **Host Key Verification**: Always verify device host keys on subsequent connections
3. **Authorization**: Implement policies about which keys can be installed
4. **Key Rotation**: Plan for key rotation and revocation
5. **Audit Trail**: Log all key installations and host key receipts

## OS-Specific Considerations

### Linux (Most Distributions)

- Default paths work out of the box
- Sudo via `/etc/sudoers.d/` is standard
- User creation may require additional tools

### Embedded Linux / BusyBox

- May use Dropbear instead of OpenSSH
- Paths may differ (e.g., `/etc/dropbear/`)
- Implement custom `InstallAuthorizedKey` callback

### BSD Systems

- Similar to Linux but may use different groups for sudo (e.g., `wheel`)
- Adjust sudo implementation accordingly

## Example: Complete Integration

### Device Side

    package main
    
    import (
        "fmt"
        "os"
        "path/filepath"
        
        "github.com/fido-device-onboard/go-fdo/fsim"
    )
    
    func main() {
        sshModule := &fsim.SSH{
            DefaultUsername: "fdo-user",
            
            InstallAuthorizedKey: func(key, username string, sudo bool) error {
                // Ensure user exists
                if err := ensureUser(username); err != nil {
                    return err
                }
                
                // Install key
                homeDir := filepath.Join("/home", username)
                sshDir := filepath.Join(homeDir, ".ssh")
                os.MkdirAll(sshDir, 0700)
                
                authKeysPath := filepath.Join(sshDir, "authorized_keys")
                f, _ := os.OpenFile(authKeysPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
                defer f.Close()
                
                fmt.Fprintf(f, "%s\n", key)
                
                // Grant sudo if requested
                if sudo {
                    sudoersPath := filepath.Join("/etc/sudoers.d", username)
                    content := fmt.Sprintf("%s ALL=(ALL) NOPASSWD: ALL\n", username)
                    os.WriteFile(sudoersPath, []byte(content), 0440)
                }
                
                return nil
            },
        }
        
        // Use in FDO onboarding...
    }
    
    func ensureUser(username string) error {
        // Check if user exists, create if needed
        // Implementation depends on OS
        return nil
    }

### Owner Side

    package main

    import (
        "database/sql"
        "fmt"
        
        "github.com/fido-device-onboard/go-fdo/fsim"
    )
    
    func main() {
        db, _ := sql.Open("postgres", "connection_string")
        
        sshOwner := &fsim.SSHOwner{
            OnHostKeys: func(hostKeys []string) error {
                // Store in database
                for _, key := range hostKeys {
                    keyType, fingerprint, _ := fsim.ParseSSHPublicKey(key)
                    
                    _, err := db.Exec(
                        "INSERT INTO device_host_keys (device_id, key_type, fingerprint, public_key) VALUES ($1, $2, $3, $4)",
                        currentDeviceID, keyType, fingerprint, key,
                    )
                    if err != nil {
                        return err
                    }
                }
                
                fmt.Printf("Stored %d host keys for device\n", len(hostKeys))
                return nil
            },
        }
        
        // Add keys to install
        sshOwner.AddAuthorizedKey(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... admin@company.com",
            "admin",
            true,
        )
        
        // Use in FDO onboarding...
    }

## Testing

### Unit Testing Device Module

    func TestSSHKeyInstallation(t *testing.T) {
        var installedKey string
        var installedUser string
        var installedSudo bool
        
        sshModule := &fsim.SSH{
            InstallAuthorizedKey: func(key, username string, sudo bool) error {
                installedKey = key
                installedUser = username
                installedSudo = sudo
                return nil
            },
            GetHostKeys: func() ([]string, error) {
                return []string{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA..."}, nil
            },
        }
        
        // Test key installation
        // ... (use serviceinfo test framework)
    }

### Integration Testing

    func TestSSHEnrollmentFlow(t *testing.T) {
        // Set up device and owner modules
        deviceSSH := &fsim.SSH{DefaultUsername: "test"}
        ownerSSH := &fsim.SSHOwner{
            AuthorizedKeys: []fsim.SSHKeyInstall{
                {Key: testPublicKey, Username: "test", Sudo: true},
            },
        }
        
        // Run FDO protocol with SSH module
        // Verify keys are installed
        // Verify host keys are received
    }

## Troubleshooting

### Key Installation Fails

#### Error: Permission denied

- Check if device process has write access to home directories
- May need to run as root or with appropriate capabilities

#### Error: User not found

- Implement user creation in `InstallAuthorizedKey`
- Or ensure users exist before onboarding

#### Error: Filesystem error

- Check disk space
- Verify filesystem is writable
- Check SELinux/AppArmor policies

### Host Keys Not Received

#### No host keys found

- Check `/etc/ssh/ssh_host_*_key.pub` exists
- Module will attempt to generate keys if missing
- May need `ssh-keygen` installed

#### Invalid host key format

- Ensure keys are in OpenSSH public key format
- Check for file corruption

### SSH Connection Fails After Onboarding

#### Permission denied (publickey)

- Verify key was actually written to authorized_keys
- Check file permissions (should be 0600)
- Check directory permissions (.ssh should be 0700)
- Verify SSH service is running

#### Host key verification failed

- Ensure host keys were properly stored in known_hosts
- Check hostname matches

## Production Deployment Checklist

### Device Side

- [ ] Implement secure key installation (proper permissions)
- [ ] Validate usernames against policy
- [ ] Implement audit logging
- [ ] Test with actual SSH connections
- [ ] Handle edge cases (disk full, user exists, etc.)
- [ ] Configure SSH service to start on boot

### Owner Side

- [ ] Implement secure host key storage
- [ ] Set up known_hosts management
- [ ] Implement key rotation policies
- [ ] Set up monitoring for key installations
- [ ] Document which keys are installed on which devices
- [ ] Plan for key revocation

## References

- **Specification**: `fdo.ssh.md` - Full FSIM specification
- **RFC 4253**: SSH Transport Layer Protocol
- **RFC 4716**: SSH Public Key File Format
- **OpenSSH**: Manual pages for authorized_keys and known_hosts formats
