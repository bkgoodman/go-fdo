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

The `fdo.payload` FSIM enables the owner to deliver arbitrary payloads to devices during onboarding, with explicit MIME type identification. This allows devices to receive and apply various types of configuration data, scripts, or binary content based on their capabilities.

Common use cases include:

- Shell scripts for system configuration
- Cloud-init configuration files
- Ansible playbooks
- Custom JSON/YAML configuration
- Binary firmware updates
- Container images or manifests

The device interprets the payload based on the MIME type and applies it according to its implementation. The module supports chunked transfer for large payloads and provides detailed error reporting.

## Key-Value Pairs

| Key | Direction | Type | Description |
| --- | --------- | ---- | ----------- |
| `fdo.payload:active` | Bidirectional | Boolean | Module activation status |
| `fdo.payload:begin` | Owner → Device | Object | Initiates payload transfer |
| `fdo.payload:ready` | Device → Owner | Boolean | Device ready to receive |
| `fdo.payload:data` | Owner → Device | Bytes | Payload data chunk |
| `fdo.payload:ack` | Device → Owner | Integer | Acknowledge chunk receipt |
| `fdo.payload:end` | Owner → Device | Boolean | End of payload transfer |
| `fdo.payload:result` | Device → Owner | Object | Final result with status |
| `fdo.payload:error` | Device → Owner | Object | Error during transfer |

## Data Structures

### PayloadBegin

Initiates a payload transfer.

```
{
  0: "application/x-sh",
  1: "setup.sh",
  2: 4096,
  3: {
    "description": "Initial setup script",
    "version": "1.0"
  }
}
```

#### PayloadBegin Schema
```
0: mime_type (string, required)
1: name (string, optional)
2: size (uint, optional)
3: metadata (map, optional)
```

**Fields**:

- `mime_type` (required): MIME type of the payload
- `name` (optional): Descriptive name for the payload
- `size` (optional): Total size in bytes (for progress tracking)
- `metadata` (optional): Additional key-value metadata

### PayloadResult

Final result after payload processing.

```
{
  0: true,
  1: "Script executed successfully",
  2: h'436f6e66696775726174696f6e206170706c6965640a' / "Configuration applied\n" /
}
```

#### PayloadResult Schema
```
0: success (bool, required)
1: message (string, optional)
2: output (binary string, optional)
```

**Fields**:

- `success` (required): Boolean indicating success or failure
- `message` (optional): Human-readable status message
- `output` (optional): Output from payload execution (stdout/stderr)

### PayloadError

Error during payload transfer or processing.

```
{
  0: 2,
  1: "Invalid YAML syntax at line 15",
  2: "expected mapping, found sequence"
}
```

#### PayloadError Schema
```
0: code (uint, required)
1: message (string, required)
2: details (string, optional)
```

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

### fdo.payload:begin

**Direction**: Owner → Device

Initiates a payload transfer with metadata.

**CBOR Structure**: PayloadBegin object

**Processing**:

1. Device receives payload metadata
2. Device checks if MIME type is supported
3. Device validates size and resource availability
4. Device responds with `fdo.payload:ready` or `fdo.payload:error`

### fdo.payload:ready

**Direction**: Device → Owner

Indicates device is ready to receive payload data.

**CBOR Structure**: Boolean `true`

### fdo.payload:data

**Direction**: Owner → Device

Sends a chunk of payload data.

**CBOR Structure**: Byte string containing payload chunk

**Processing**:

1. Owner sends payload in chunks (recommended max 4KB per chunk)
2. Device accumulates chunks
3. Device responds with `fdo.payload:ack` containing total bytes received

### fdo.payload:ack

**Direction**: Device → Owner

Acknowledges receipt of data chunk.

**CBOR Structure**: Integer (total bytes received so far)

**Processing**:

- Owner uses this to track transfer progress
- Owner can retry if acknowledgment doesn't match expected value

### fdo.payload:end

**Direction**: Owner → Device

Signals end of payload transfer.

**CBOR Structure**: Boolean `true`

**Processing**:

1. Device verifies all data received (checks size if provided)
2. Device processes/applies payload based on MIME type
3. Device responds with `fdo.payload:result`

### fdo.payload:result

**Direction**: Device → Owner

Reports final result of payload processing.

**CBOR Structure**: PayloadResult object

**Processing**:

- `success: true` indicates payload was successfully applied
- `success: false` indicates failure (see error details in message)
- Optional output field contains execution results

### fdo.payload:error

**Direction**: Device → Owner

Reports an error during transfer or processing.

**CBOR Structure**: PayloadError object

**Processing**:

- Can be sent at any point during transfer
- Terminates the current payload transfer
- Owner should not send more data after receiving error

## Common MIME Types

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

### Successful Transfer

```
Owner → Device: fdo.payload:active?
Device → Owner: fdo.payload:active = true

Owner → Device: fdo.payload:begin {
  0: "application/x-sh",
  2: 1024
}
Device → Owner: fdo.payload:ready = true

Owner → Device: fdo.payload:data h'...' / 512 bytes /
Device → Owner: fdo.payload:ack = 512

Owner → Device: fdo.payload:data h'...' / 512 bytes /
Device → Owner: fdo.payload:ack = 1024

Owner → Device: fdo.payload:end = true
Device → Owner: fdo.payload:result {
  0: true,
  1: "Applied"
}
```

### Error During Transfer

```
Owner → Device: fdo.payload:begin {
  0: "text/cloud-config"
}
Device → Owner: fdo.payload:ready = true

Owner → Device: fdo.payload:data h'...' / chunk 1 /
Device → Owner: fdo.payload:ack = 512

Owner → Device: fdo.payload:data h'...' / chunk 2 /
Device → Owner: fdo.payload:error {
  0: 6,
  1: "Checksum mismatch"
}
```

### Unsupported MIME Type

```
Owner → Device: fdo.payload:begin {
  0: "application/x-custom"
}
Device → Owner: fdo.payload:error {
  0: 1,
  1: "MIME type not supported"
}
```

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

### Shell Script Execution

```
MIME Type: application/x-sh
Payload: h'23212f62696e2f626173680a6563686f2022436f6e6669677572696e67206465766963652e2e2e220a' / "#!/bin/bash\necho \"Configuring device...\"\n" /
Result: {
  0: true,
  2: h'436f6e6669677572696e67206465766963652e2e2e0a' / "Configuring device...\n" /
}
```

### Cloud-Init Configuration

```
MIME Type: text/cloud-config
Payload: h'23636c6f75642d636f6e6669670a7061636b616765733a0a20202d206e67696e780a' / "#cloud-config\npackages:\n  - nginx\n" /
Result: {
  0: true,
  1: "Cloud-init applied"
}
```

### JSON Configuration

```
MIME Type: application/json
Payload: h'7b2273657474696e67223a202276616c7565222c2022656e61626c6564223a20747275657d' / {"setting": "value", "enabled": true} /
Result: {
  0: true,
  1: "Configuration updated"
}
```

### Firmware Update

```
MIME Type: application/vnd.vendor.firmware+bin
Payload: h'...' / binary firmware data /
Result: {
  0: true,
  1: "Firmware updated, reboot required"
}
```

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
