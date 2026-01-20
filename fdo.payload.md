# FDO Service Info Module: fdo.payload

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

## Overview

**Module Name**: `fdo.payload`  
**Version**: 1.0  
**Status**: Draft

## Purpose

The `fdo.payload` FSIM enables owners to deliver payloads that devices MAY actively interpret and apply during onboarding. Unlike `fdo.upload`, whose role is simply to move raw bytes, `fdo.payload` is intended for higher-level content (scripts, declarative configs, manifests) that can be executed or consumed immediately by the target system. By standardizing around well-known MIME types and data formats, the module encourages interoperability: a single payload authored by a service can be understood by diverse device classes without custom tooling.

Common use cases include:

- Shell scripts for system configuration
- Cloud-init configuration files
- Ansible playbooks
- Custom JSON/YAML configuration
- Binary firmware updates
- Container images or manifests

The device interprets the payload based on the MIME type and applies it according to its implementation. The module supports chunked transfer for large payloads and provides detailed error reporting.

## Key-Value Pairs

<!-- markdownlint-disable MD033 -->
| Key | Direction | Type | Description |
| --- | --------- | ---- | ----------- |
| `fdo.payload:active` | Bidirectional | Boolean | Module activation status |
| `fdo.payload:payload-begin` | Owner → Device | Map | Announces payload transfer (per chunking strategy) |
| `fdo.payload:payload-data-<n>` | Owner → Device | Byte string | Payload data chunk `n` (0-based) |
| `fdo.payload:payload-end` | Owner → Device | Map | Signals completion of payload transfer |
| `fdo.payload:payload-result` | Device → Owner | Array | Final result with status/message |
| `fdo.payload:error` | Device → Owner | Object | Error during transfer |
<!-- markdownlint-enable MD033 -->

## Data Structures

### PayloadBegin

Payload transfers use the generic `payload-begin` map from the chunking strategy. `fdo.payload` reserves the following negative keys for MIME metadata:

    {
      0: 4096,                      / total_size per chunk spec /
      1: "sha256",                  / optional hash algorithm /
      -1: "application/x-sh",       / mime_type (required) /
      -2: "setup.sh",               / payload name (optional) /
      -3: {                         / payload metadata (optional) /
        "description": "Initial setup script",
        "version": "1.0"
      }
    }

#### PayloadBegin Schema Extensions

| Key | Name | Type | Requirement | Description |
| --- | ---- | ---- | ----------- | ----------- |
| `-1` | mime_type | tstr | **Required** | MIME type of the payload; devices MUST validate support before accepting data. |
| `-2` | name | tstr | Optional | Descriptive name for the payload (e.g., filename). |
| `-3` | metadata | map | Optional | Additional FSIM-defined metadata (version, description, etc.). |

All non-negative keys remain reserved for the generic chunking fields (`total_size`, `hash_alg`, etc.) as documented in `chunking-strategy.md`.

### PayloadResult

Devices MUST send `fdo.payload:payload-result` after processing the payload. It follows the generic result array shape from the chunking strategy:

    [
      0,                                / status_code: 0=success, 1=warning, 2=error /
      "Script executed successfully"     / optional message /
    ]

| Index | Name | Type | Description |
| ----- | ---- | ---- | ----------- |
| 0 | status_code | int | Mandatory status (0=success, 1=warning, 2=error; devices MAY extend with additional values ≥3). |
| 1 | message | tstr | Optional human-readable status. |

**Status Code Semantics**:

- `status_code = 0` (success): Payload was successfully applied and is usable
- `status_code = 1` (warning): Payload was applied but with warnings (e.g., partial execution); payload is usable
- `status_code = 2` (error): Payload was NOT applied; payload is unusable and should not be considered applied

Owners SHOULD treat `status_code = 2` as a failure and consult `fdo.payload:error` for detailed diagnostics when provided.

### PayloadError

Error during payload transfer or processing.

    {
      0: 2,
      1: "Invalid YAML syntax at line 15",
      2: "expected mapping, found sequence"
    }

#### PayloadError Schema

    0: code (uint, required)
    1: message (string, required)
    2: details (string, optional)

**Fields**:

- `code` (required): Numeric error code (see Error Codes)
- `message` (required): Human-readable error message
- `details` (optional): Additional error details

## Error Codes

| Code | Name | Description |
| ---- | ---- | ----------- |
| 1 | Unknown MIME Type | Device does not support the specified MIME type |
| 2 | Invalid Format | Payload format/syntax is invalid |
| 3 | Invalid Content | Payload content contains invalid parameters or values |
| 4 | Unable to Apply | Runtime error prevented payload application |
| 5 | Unsupported Feature | Payload uses features not supported by device |
| 6 | Transfer Error | Error during data transfer (corruption, timeout) |
| 7 | Resource Error | Insufficient resources (disk space, memory) |

## Message Details

### fdo.payload:active

**Direction**: Bidirectional

Indicates whether the payload module is active.

**Device → Owner**: Device sends `true` if it supports payload delivery
**Owner → Device**: Owner may query device support (optional)

### fdo.payload:payload-begin

**Direction**: Owner → Device

Announces a payload transfer by sending the `payload-begin` map described above (generic chunk fields plus MIME metadata). Devices MUST validate the MIME type (`-1` key) before accepting data. If the MIME type is unsupported, they SHOULD immediately return `fdo.payload:error` with code `1`.

### fdo.payload:payload-data-\<n\>

**Direction**: Owner → Device

Sends payload chunk `n` (0-based). Chunks MUST follow the same size guidelines and ordering rules defined in `chunking-strategy.md`. Owners MAY retransmit a chunk by reusing the same index.

### fdo.payload:payload-end

**Direction**: Owner → Device

Signals completion of the payload transfer. Owners SHOULD provide a hash in the `payload-end` map when a `hash_alg` was advertised in `payload-begin`. Devices MUST verify the hash when present before applying the payload.

### fdo.payload:payload-result

**Direction**: Device → Owner

Reports the final status using the result array described earlier. Devices SHOULD include execution output (index 2) when available.

### fdo.payload:error

**Direction**: Device → Owner

Reports an error during transfer or processing.

**CBOR Structure**: PayloadError object

**Processing**:

- Can be sent at any point during transfer
- Terminates the current payload transfer
- Owner should not send more data after receiving error

## Common MIME Types

The following MIME types are **non-normative** examples of formats a device MAY choose to recognize; implementations can support any subset or define vendor-specific types as needed.

### Scripts and Executables

- `application/x-sh` - Shell script (bash, sh)
- `application/x-python` - Python script
- `application/x-perl` - Perl script
- `application/x-executable` - Binary executable

### Configuration Formats

- `text/cloud-config` - Cloud-init configuration
- `application/x-yaml` - YAML configuration
- `application/json` - JSON configuration
- `application/toml` - TOML configuration
- `text/x-ini` - INI configuration

### Infrastructure as Code

- `application/x-ansible` - Ansible playbook
- `application/x-terraform` - Terraform configuration
- `application/x-dockerfile` - Dockerfile

### Container and Orchestration

- `application/vnd.docker.distribution.manifest.v2+json` - Docker manifest
- `application/vnd.kubernetes.yaml` - Kubernetes manifest

### Custom Types

Vendors may define custom MIME types using the `application/vnd.` prefix:

- `application/vnd.company.config+json`
- `application/vnd.vendor.firmware+bin`

## Protocol Flow

### Sequence Diagram

    Owner                           Device
      |                               |
      | fdo.payload:payload-begin     |
      |------------------------------>|
      |                               | Validate MIME type & resources
      |                               |
      | fdo.payload:payload-data-0    |
      |------------------------------>|
      |                               | Accumulate chunk0
      |                               |
      | fdo.payload:payload-data-1    |
      |------------------------------>|
      |                               | Accumulate chunk1
      |                               |
      | ...                           |
      |                               |
      | fdo.payload:payload-end       |
      |------------------------------>|
      |                               | Verify hash/size, apply payload
      | fdo.payload:payload-result    |
      |<------------------------------|

### Unsupported MIME Type

    Owner → Device: fdo.payload:payload-begin {
      -1: "application/x-custom"
    }
    Device → Owner: fdo.payload:error {
      0: 1,
      1: "MIME type not supported"
    }

## Implementation Requirements

### Device Implementation

**MUST**:

- Implement callback-based payload handling
- Support at least one MIME type
- Validate MIME type before accepting payload
- Accumulate chunks correctly
- Report detailed errors with appropriate codes
- Prevent execution of untrusted payloads without validation

**SHOULD**:

- Support common MIME types (shell scripts, cloud-init, JSON)
- Validate payload syntax before execution
- Provide meaningful error messages
- Log payload application for audit purposes
- Implement size limits to prevent resource exhaustion

**MAY**:

- Support custom MIME types
- Provide execution output in result
- Implement payload caching or rollback

### Owner Implementation

**MUST**:

- Specify valid MIME type
- Send data in manageable chunks
- Handle errors gracefully
- Wait for acknowledgments before sending next chunk

**SHOULD**:

- Provide accurate size information
- Include descriptive metadata
- Retry on transfer errors
- Validate payload before sending

## Security Considerations

### Payload Validation

- Devices MUST validate payload syntax before execution
- Devices SHOULD implement sandboxing for script execution
- Devices MUST NOT execute payloads from untrusted sources without validation
- Devices SHOULD verify payload signatures if supported

### Resource Protection

- Devices MUST implement size limits to prevent resource exhaustion
- Devices SHOULD monitor execution time and terminate runaway processes
- Devices MUST protect against path traversal and injection attacks

### Error Information

- Error messages SHOULD be informative but not leak sensitive system information
- Devices SHOULD sanitize error output to prevent information disclosure

### Execution Context

- Scripts SHOULD run with minimal privileges
- Devices SHOULD implement execution timeouts
- Devices MUST prevent payloads from modifying critical system files without authorization

## Callback-Based Design

The device implementation delegates all payload processing to application-provided callbacks:

    type PayloadHandler interface {
        // SupportsMimeType checks if device supports the MIME type
        SupportsMimeType(mimeType string) bool
    
        // BeginPayload prepares to receive a payload
        BeginPayload(mimeType, name string, size int64, metadata map[string]string) error
    
        // ReceiveChunk processes a data chunk
        ReceiveChunk(data []byte) error
    
        // EndPayload finalizes and applies the payload
        EndPayload() (success bool, message string, output string, err error)
    
        // CancelPayload aborts the current transfer
        CancelPayload() error
    }

This design:

- Keeps the FSIM OS-agnostic
- Allows applications to implement custom payload handlers
- Enables validation and security policies at the application level
- Supports diverse payload types without modifying the core FSIM

## Example Use Cases

Two representative scenarios illustrate how devices might act on payload content:

### Shell Script Execution

    MIME Type: application/x-sh
    Payload: h'23212f62696e2f626173680a6563686f2022436f6e6669677572696e67206465766963652e2e2e220a' / "#!/bin/bash\necho \"Configuring device...\"\n" /
    Result: [0, "Script executed", h'436f6e66...']

### Declarative Configuration (cloud-init)

    MIME Type: text/cloud-config
    Payload: h'23636c6f75642d636f6e6669670a7061636b616765733a0a20202d206e67696e780a'
    Result: [0, "Cloud-init applied"]

## Relationship to Other FSIMs

The `fdo.payload` FSIM complements other configuration FSIMs:

- **fdo.ssh**: Configures SSH access (authentication)
- **fdo.sysconfig**: Configures basic system parameters (identity, time, network)
- **fdo.csr**: Configures certificates (security credentials)
- **fdo.payload**: Delivers arbitrary configuration payloads (scripts, configs, binaries)

Together, these FSIMs provide comprehensive device onboarding:

1. Basic system configuration (fdo.sysconfig)
2. Security credentials (fdo.csr, fdo.ssh)
3. Advanced configuration (fdo.payload)

## Design Rationale

### Why MIME Types?

- Industry-standard content type identification
- Extensible without protocol changes
- Clear contract between owner and device
- Supports custom vendor types

### Why Chunked Transfer?

- Supports large payloads (cloud-init configs can be >1MB)
- Allows progress tracking
- Enables error recovery
- Reduces memory requirements

### Why Detailed Error Codes?

- Helps owners diagnose configuration issues
- Enables automated error handling
- Improves user experience
- Facilitates debugging

### Why Callback-Based?

- Maintains OS-agnostic design
- Allows application-level security policies
- Supports diverse payload types
- Enables custom validation logic

## Future Extensions

Potential future enhancements (informative, not normative):

- Payload signatures for verification
- Compression support
- Multi-part payloads
- Payload dependencies
- Rollback support
- Dry-run/validation mode

These may be standardized in future revisions based on implementation experience.
