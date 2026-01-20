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

| Direction | Key Name                   | Value          | Meaning                                                    |
| --------- | -------------------------- | -------------- | ---------------------------------------------------------- |
| o <-> d   | `fdo.ssh:active`           | `bool`         | Instructs the device to activate or deactivate the module  |
| o --> d   | `fdo.ssh:key-begin`        | `map`          | Announces the start of an SSH key installation transfer    |
| o --> d   | `fdo.ssh:key-data-<n>`     | `bstr`         | Chunk of SSH key data (0-based index)                      |
| o --> d   | `fdo.ssh:key-end`          | `map`          | Signals completion of SSH key transfer                     |
| o <-- d   | `fdo.ssh:key-result`       | `[int, ?tstr]` | Status for the corresponding key installation              |
| o <-- d   | `fdo.ssh:hostkey-begin`    | `map`          | Announces the start of a host key transfer                 |
| o <-- d   | `fdo.ssh:hostkey-data-<n>` | `bstr`         | Chunk of host key data (0-based index)                     |
| o <-- d   | `fdo.ssh:hostkey-end`      | `map`          | Signals completion of host key transfer                    |

This FSIM follows the generic chunking strategy defined in `chunking-strategy.md`.

## Data Structures

### Key Installation Metadata

The `fdo.ssh:key-begin` message uses the generic chunking `begin` structure with FSIM-specific metadata in negative keys:

    key-begin = {
        ? 0: uint,        ; total_size (optional)
        ? 1: tstr,        ; hash_alg (optional, e.g., "sha256")
        ? 2: map,         ; reserved for generic metadata
        ? -1: tstr,       ; username (optional)
        ? -2: bool        ; sudo flag (optional)
    }

**FSIM-Specific Fields (negative keys):**

- **-1 (username)**: Username for which the key should be installed. If not specified, the device implementation decides the target user (could be a default user, root, or implementation-specific behavior)
- **-2 (sudo)**: Boolean flag indicating whether the user should have privileged (sudo/root) access. How this is implemented is device-specific (e.g., adding to sudoers file, wheel group, etc.)

The key data itself (SSH public key in OpenSSH authorized_keys format) is transmitted via `fdo.ssh:key-data-<n>` chunks as raw bytes.

### Host Key Metadata

The `fdo.ssh:hostkey-begin` message uses the generic chunking `begin` structure with optional FSIM-specific metadata:

    hostkey-begin = {
        ? 0: uint,        ; total_size (optional)
        ? 1: tstr,        ; hash_alg (optional)
        ? 2: map,         ; reserved for generic metadata
        ? -1: tstr        ; key_type (optional, e.g., "ssh-rsa", "ssh-ed25519")
    }

**FSIM-Specific Fields (negative keys):**

- **-1 (key_type)**: SSH key type identifier (e.g., "ssh-rsa", "ecdsa-sha2-nistp256", "ssh-ed25519"). This is informational and also present in the key data itself.

## Key Installation Protocol

The owner installs SSH authorized keys using the chunking protocol:

1. **Owner sends `fdo.ssh:key-begin`** with metadata (username, sudo flag)
2. **Owner sends `fdo.ssh:key-data-<n>`** chunks containing the SSH public key bytes
3. **Owner sends `fdo.ssh:key-end`** to signal completion
4. **Device sends `fdo.ssh:key-result`** with status code

The device processes the key installation:

1. Receive and buffer all key data chunks
2. Verify hash if provided in `key-begin`
3. Parse the SSH public key to validate format
4. Determine target user (username from metadata or implementation default)
5. Install the key in the appropriate authorized_keys file
6. If sudo flag is set, configure privileged access per device policy
7. Send `fdo.ssh:key-result` with status

**Implementation Notes:**

- The device determines where to install the key (e.g., `/home/username/.ssh/authorized_keys`, `/root/.ssh/authorized_keys`)
- The device may create the user account if it doesn't exist, or may return an error
- The device may create necessary directories and set appropriate permissions
- Key format validation should follow OpenSSH standards
- Multiple keys can be installed by repeating the chunking sequence

**Example key formats:**

    ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC... user@example.com
    ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl user@example.com
    ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTY... user@example.com

## Host Key Transfer Protocol

The device sends its SSH host public keys to the owner using the chunking protocol. Each host key is sent as a separate chunked transfer:

1. **Device sends `fdo.ssh:hostkey-begin`** with optional metadata (key_type)
2. **Device sends `fdo.ssh:hostkey-data-<n>`** chunks containing the SSH host public key bytes
3. **Device sends `fdo.ssh:hostkey-end`** to signal completion
4. Repeat for each host key type

**Purpose:**

The owning Device Management Service can use these host keys to populate its `known_hosts` file, enabling verification of the device's identity on subsequent SSH connections. This prevents man-in-the-middle attacks by ensuring that future connections are to the same device that was onboarded.

**Implementation Notes:**

- The device should send all available host key types (RSA, ECDSA, Ed25519, etc.)
- Each key type is sent as a separate chunked transfer
- Keys should be in OpenSSH public key format
- The device may generate new host keys if none exist
- The order of keys is not significant

**Example key formats:**

    ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...
    ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTY...
    ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIC4...

## fdo.ssh:key-result

The device sends `fdo.ssh:key-result` to report the outcome of the key installation. This follows the generic result message format from `chunking-strategy.md`:

    key-result = [
        code: int,         ; 0=success, 1=warning, 2=error
        ? message: tstr    ; optional human-readable note (warnings/errors)
    ]

**Status Codes:**

- **0 (success)**: Key was successfully installed; message MAY be omitted
- **1 (warning)**: Key was installed but with caveats (e.g., created default user, deprecated key type); message SHOULD describe the warning
- **2 (error)**: Key installation failed; message SHOULD describe the failure cause

**Examples (non-normative):**

- Invalid key format → `[2, "invalid SSH key format"]`
- User not found and not created → `[2, "user not found"]`
- Permission denied → `[2, "permission denied"]`
- Unsupported key option ignored but key installed → `[1, "key option ignored"]`
- Success → `[0]` or `[0, "key installed for user admin"]`

**Note:** Success or failure here means the FDO layer accepted/applied the key. It does not guarantee the underlying SSH implementation will accept it for login; operators should still verify reachability.

## Example Exchange

The following table describes an example exchange for the SSH FSIM using the chunking protocol:

| Direction | Message | Meaning |
| --------- | ------- | ------- |
| o --> d | `[fdo.ssh:active, true]` | Owner activates the SSH FSIM |
| d --> o | `[fdo.ssh:active, true]` | Device confirms activation |
| o --> d | `[fdo.ssh:key-begin, {-1: "admin", -2: true}]` | Owner begins key transfer with username and sudo flag |
| o --> d | `[fdo.ssh:key-data-0, h'73736820...]` | Owner sends key data chunk 0 |
| o --> d | `[fdo.ssh:key-data-1, h'414141...]` | Owner sends key data chunk 1 |
| o --> d | `[fdo.ssh:key-end, {}]` | Owner signals completion |
| d --> o | `[fdo.ssh:key-result, [0, "key installed"]]` | Device reports success |
| o --> d | `[fdo.ssh:key-begin, {-1: "operator"}]` | Owner begins second key transfer |
| o --> d | `[fdo.ssh:key-data-0, h'73736820...]` | Owner sends key data |
| o --> d | `[fdo.ssh:key-end, {}]` | Owner signals completion |
| d --> o | `[fdo.ssh:key-result, [0]]` | Device reports success |
| d --> o | `[fdo.ssh:hostkey-begin, {-1: "ssh-rsa"}]` | Device begins host key transfer |
| d --> o | `[fdo.ssh:hostkey-data-0, h'73736820...]` | Device sends host key data |
| d --> o | `[fdo.ssh:hostkey-end, {}]` | Device signals completion |
| d --> o | `[fdo.ssh:hostkey-begin, {-1: "ssh-ed25519"}]` | Device begins second host key transfer |
| d --> o | `[fdo.ssh:hostkey-data-0, h'73736820...]` | Device sends host key data |
| d --> o | `[fdo.ssh:hostkey-end, {}]` | Device signals completion |
| o --> d | `[fdo.ssh:active, false]` | Owner deactivates the SSH FSIM |
| d --> o | `[fdo.ssh:active, false]` | Device confirms deactivation |

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

Install a single SSH key for administrative access using chunking:

    Owner sends: fdo.ssh:key-begin {-1: "admin", -2: true}
    Owner sends: fdo.ssh:key-data-0 <key bytes>
    Owner sends: fdo.ssh:key-end {}
    Device sends: fdo.ssh:key-result [0]

### Multiple User Access

Install keys for multiple users with different privilege levels by repeating the chunking sequence:

    # First key (admin with sudo)
    Owner sends: fdo.ssh:key-begin {-1: "admin", -2: true}
    Owner sends: fdo.ssh:key-data-0 <key bytes>
    Owner sends: fdo.ssh:key-end {}
    Device sends: fdo.ssh:key-result [0]
    
    # Second key (operator without sudo)
    Owner sends: fdo.ssh:key-begin {-1: "operator", -2: false}
    Owner sends: fdo.ssh:key-data-0 <key bytes>
    Owner sends: fdo.ssh:key-end {}
    Device sends: fdo.ssh:key-result [0]

### Default User Access

Install key without specifying username (device uses default):

    Owner sends: fdo.ssh:key-begin {}
    Owner sends: fdo.ssh:key-data-0 <key bytes>
    Owner sends: fdo.ssh:key-end {}
    Device sends: fdo.ssh:key-result [0]

### Host Key Verification

After onboarding, the owner receives host keys via chunking and can verify subsequent connections:

    # Device sends first host key
    Device sends: fdo.ssh:hostkey-begin {-1: "ssh-rsa"}
    Device sends: fdo.ssh:hostkey-data-0 <key bytes>
    Device sends: fdo.ssh:hostkey-end {}
    
    # Device sends second host key
    Device sends: fdo.ssh:hostkey-begin {-1: "ssh-ed25519"}
    Device sends: fdo.ssh:hostkey-data-0 <key bytes>
    Device sends: fdo.ssh:hostkey-end {}
    
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
