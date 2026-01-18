# FDO Service Info Module: fdo.ssh

Copyright &copy; 2026 Dell Technologies and FIDO Alliance
Author: Brad Goodman, Dell Technologies

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

------------------

This specification defines the 'SSH' (Secure Shell key enrollment) FDO serviceinfo module (FSIM) for the purpose of SSH key provisioning during device onboarding. An FSIM is a set of key-value pairs; they define the onboarding operations that can be performed on a given FDO device. FSIM key-value pairs are exchanged between the device and its owning Device Management Service. It is up to the owning Device Management Service and the device to interpret the key-value pairs in accordance with the FSIM specification.

This specification provides a minimal, OS-agnostic mechanism for SSH key enrollment that works across different operating systems and SSH implementations (OpenSSH, Dropbear, etc.).

## fdo.ssh FSIM Definition

The SSH module provides functionality to provision SSH access during FDO device onboarding. It enables the owning Device Management Service to install authorized SSH public keys on the device and obtain the device's SSH host public keys for verification of subsequent connections.

The SSH FSIM supports the following functionality:

- Installation of SSH authorized keys for remote access
- Optional username and privilege specification
- Retrieval of device SSH host keys for known_hosts verification

The following table describes key-value pairs for the SSH FSIM.

| Direction | Key Name            | Value           | Meaning                                                    |
| --------- | ------------------- | --------------- | ---------------------------------------------------------- |
| o <-> d   | `fdo.ssh:active`    | `bool`          | Instructs the device to activate or deactivate the module  |
| o --> d   | `fdo.ssh:add-key`   | `SSHKeyInstall` | Install SSH authorized public key                          |
| o <-- d   | `fdo.ssh:host-keys` | `array of tstr` | Device SSH host public keys                                |
| o --> d   | `fdo.ssh:error`     | `uint`          | Error indication                                           |

## Data Structures

### SSHKeyInstall

The `SSHKeyInstall` structure contains the information needed to install an SSH authorized key on the device.

    SSHKeyInstall = {
        key: tstr,           ; SSH public key in OpenSSH format
        ? username: tstr,    ; Optional username for the key
        ? sudo: bool         ; Optional flag indicating privileged access
    }

**Fields:**

- **key** (required): SSH public key in OpenSSH authorized_keys format (e.g., "ssh-rsa AAAAB3NzaC1yc2EA... user@host")
- **username** (optional): Username for which the key should be installed. If not specified, the device implementation decides the target user (could be a default user, root, or implementation-specific behavior)
- **sudo** (optional): Boolean flag indicating whether the user should have privileged (sudo/root) access. How this is implemented is device-specific (e.g., adding to sudoers file, wheel group, etc.)

## fdo.ssh:add-key

The owning Device Management Service sends `fdo.ssh:add-key` to install an SSH authorized public key on the device.

The device receives the `SSHKeyInstall` structure and performs the following actions:

1. Parse the SSH public key to validate format
2. Determine the target user (from username field or implementation default)
3. Install the key in the appropriate authorized_keys file
4. If sudo flag is set, configure privileged access according to device policy

**Implementation Notes:**

- The device determines where to install the key (e.g., `/home/username/.ssh/authorized_keys`, `/root/.ssh/authorized_keys`)
- The device may create the user account if it doesn't exist, or may return an error
- The device may create necessary directories and set appropriate permissions
- Key format validation should follow OpenSSH standards
- Multiple keys can be installed by sending multiple `fdo.ssh:add-key` messages

**Example key formats:**

    ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC... user@example.com
    ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl user@example.com
    ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTY... user@example.com

## fdo.ssh:host-keys

The device sends `fdo.ssh:host-keys` to report its SSH host public keys to the owning Device Management Service.

The value is an array of text strings, where each string is an SSH host public key in OpenSSH known_hosts format.

**Purpose:**

The owning Device Management Service can use these host keys to populate its `known_hosts` file, enabling verification of the device's identity on subsequent SSH connections. This prevents man-in-the-middle attacks by ensuring that future connections are to the same device that was onboarded.

**Implementation Notes:**

- The device should send all available host key types (RSA, ECDSA, Ed25519, etc.)
- Keys should be in OpenSSH public key format
- The device may generate new host keys if none exist
- The order of keys in the array is not significant

**Example response:**

    [
      "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...",
      "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTY...",
      "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIC4..."
    ]

## fdo.ssh:error

The device sends `fdo.ssh:error` when an SSH operation fails.

The following table lists error codes:

| Error Number | Description                   | Sent in response to |
| ------------ | ----------------------------- | ------------------- |
| 1            | Bad request / Invalid format  | fdo.ssh:add-key     |
| 2            | Permission denied             | fdo.ssh:add-key     |
| 3            | User not found                | fdo.ssh:add-key     |
| 4            | Filesystem error              | fdo.ssh:add-key     |
| 5            | SSH service not available     | fdo.ssh:add-key     |

**Error Descriptions:**

- **Error 1 (Bad request)**: The SSH key format is invalid or the request is malformed
- **Error 2 (Permission denied)**: The device cannot install the key due to insufficient permissions
- **Error 3 (User not found)**: The specified username does not exist and the device cannot or will not create it
- **Error 4 (Filesystem error)**: Cannot write to authorized_keys file or create necessary directories
- **Error 5 (SSH service not available)**: SSH service is not installed or cannot be configured

## Example Exchange

The following table describes an example exchange for the SSH FSIM:

| Device sends | Owner sends | Meaning |
| ------------ | ----------- | ------- |
| `[fdo.ssh:active, True]` | - | Device instructs owner to activate the SSH FSIM |
| - | `[fdo.ssh:add-key, {key: "ssh-rsa AAAA...", username: "admin", sudo: true}]` | Owner installs admin key with sudo |
| - | `[fdo.ssh:add-key, {key: "ssh-ed25519 AAAA...", username: "operator"}]` | Owner installs operator key without sudo |
| `[fdo.ssh:host-keys, ["ssh-rsa AAAA...", "ssh-ed25519 AAAA..."]]` | - | Device reports host keys |
| `[fdo.ssh:active, False]` | - | Device instructs owner to deactivate the SSH FSIM |

## Security Considerations

### Key Management

1. **Private Key Security**: SSH private keys must never be transmitted. Only public keys are exchanged in this FSIM.

2. **Key Validation**: Devices should validate SSH public key format before installation to prevent malformed entries in authorized_keys files.

3. **Host Key Verification**: The owning Device Management Service should store device host keys and verify them on subsequent connections to prevent man-in-the-middle attacks.

### Access Control

1. **Privilege Escalation**: The sudo flag should be carefully controlled. Devices may implement additional authorization checks before granting privileged access.

2. **Username Validation**: Devices should validate usernames against system policies and may reject certain usernames (e.g., system accounts).

3. **Key Restrictions**: Implementations may support SSH key options (e.g., `command=`, `from=`, `no-port-forwarding`) by including them in the key string.

### Implementation Security

1. **File Permissions**: Devices must set appropriate permissions on authorized_keys files (typically 0600) and .ssh directories (typically 0700).

2. **Atomic Operations**: Key installation should be atomic to prevent partial updates in case of errors.

3. **Audit Logging**: Implementations should log SSH key installation events for security auditing.

## Implementation Flexibility

This specification intentionally leaves the following details to the implementation:

### Device-Side Flexibility

- **authorized_keys Location**: Device determines where to store keys based on username and system configuration
- **User Account Management**: Device decides whether to create users, and how to configure them
- **Privilege Implementation**: Device interprets the sudo flag according to its security model (sudoers, wheel group, etc.)
- **SSH Service Management**: Device may enable/start SSH service if needed, or assume it's already running
- **Host Key Generation**: Device may generate new host keys if none exist, or use existing keys
- **Key Validation**: Device may implement additional validation beyond format checking

### Owner-Side Flexibility

- **Key Generation**: Owner generates SSH key pairs using any standard SSH key generation tool
- **Key Distribution**: Owner decides which keys to install on which devices
- **known_hosts Management**: Owner decides how to use device host keys (known_hosts file, database, etc.)
- **Policy Enforcement**: Owner may implement policies about key types, key sizes, usernames, etc.

## OS and SSH Implementation Compatibility

This FSIM is designed to work across:

- **Operating Systems**: Linux (all distributions), BSD variants, embedded systems, etc.
- **SSH Implementations**: OpenSSH, Dropbear, proprietary implementations
- **Key Types**: RSA, ECDSA, Ed25519, and future key types supported by SSH

The use of standard OpenSSH key formats ensures broad compatibility.

## Use Cases

### Basic Remote Access

Install a single SSH key for administrative access:

    Owner sends: fdo.ssh:add-key {
        key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqn... admin@company.com",
        username: "admin",
        sudo: true
    }

### Multiple User Access

Install keys for multiple users with different privilege levels:

    Owner sends: fdo.ssh:add-key {
        key: "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC... admin@company.com",
        username: "admin",
        sudo: true
    }
    
    Owner sends: fdo.ssh:add-key {
        key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIC4... operator@company.com",
        username: "operator",
        sudo: false
    }

### Default User Access

Install key without specifying username (device uses default):

    Owner sends: fdo.ssh:add-key {
        key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIC4... user@company.com"
    }

### Host Key Verification

After onboarding, the owner receives host keys and can verify subsequent connections:

    Device sends: fdo.ssh:host-keys [
        "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...",
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIC4..."
    ]
    
    Owner adds to known_hosts:
    device-hostname ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...
    device-hostname ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIC4...

## Relationship to Other FSIMs

The SSH FSIM can be used in conjunction with other FSIMs:

- **fdo.command**: Can be used to configure SSH service settings after key installation
- **fdo.download**: Can be used to download SSH configuration files
- **fdo.csr**: Can be used for certificate-based authentication in addition to key-based authentication

## References

[RFC 4253] Ylonen, T. and C. Lonvick, Ed., "The Secure Shell (SSH) Transport Layer Protocol", RFC 4253, DOI 10.17487/RFC4253, January 2006, <https://www.rfc-editor.org/info/rfc4253>.

[RFC 4716] Galbraith, J. and R. Thayer, "The Secure Shell (SSH) Public Key File Format", RFC 4716, DOI 10.17487/RFC4716, November 2006, <https://www.rfc-editor.org/info/rfc4716>.

[OpenSSH] OpenSSH Manual Pages, "AUTHORIZED_KEYS FILE FORMAT", <https://man.openbsd.org/sshd.8#AUTHORIZED_KEYS_FILE_FORMAT>.

[OpenSSH] OpenSSH Manual Pages, "SSH_KNOWN_HOSTS FILE FORMAT", <https://man.openbsd.org/sshd.8#SSH_KNOWN_HOSTS_FILE_FORMAT>.
