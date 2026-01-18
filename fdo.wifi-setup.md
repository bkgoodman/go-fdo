# fdo.wifi FSIM Specification

## Overview

The `fdo.wifi` FSIM provides Wi-Fi network configuration and credential provisioning for FDO devices. This FSIM supports both basic Wi-Fi setup (SSID/password) and certificate-based authentication for WPA3-Enterprise networks in a single, unified interface.

## Security Model Compatibility

### Single-Sided Attestation Mode
- **Basic Wi-Fi Setup Only**: SSID, authentication type, password, trust level
- **No Certificate Provisioning**: Certificate-based authentication not available
- **Trust Level**: Limited to "onboard-only" networks

### Owner/Delegate Attestation Mode
- **Full Wi-Fi Setup**: Basic and certificate-based Wi-Fi configuration
- **Certificate Provisioning**: CSR/certificate enrollment for WPA3-Enterprise
- **Trust Level**: Both "onboard-only" and "full-access" networks

## Message Flow

The FSIM follows a sequential network-by-network flow:

```
1. s --> d: fdo.wifi:active = true
2. s --> d: fdo.wifi:network-add (basic network)
3. s --> d: fdo.wifi:network-add (certificate network)
4. s <-- d: fdo.wifi:cert-req (CSR for certificate network)
5. s --> d: fdo.wifi:cert-res (signed certificate)
```

## Key-Value Message Specification

The following table describes key-value pairs for the fdo.wifi FSIM. All structured messages use CBOR encoding for compactness and consistency with FDO protocol:

| Direction | Key Name | Value | Meaning |
| --------- | -------- | ----- | ------- |
| s --> d | `fdo.wifi:active` | `bool` | Activate/deactivate module |
| s --> d | `fdo.wifi:network-add` | `cbor` | Add network configuration |
| s <-- d | `fdo.wifi:cert-req` | `cbor` | CSR for certificate-based network |
| s --> d | `fdo.wifi:cert-res` | `cbor` | Signed certificate for network |
| s --> d | `fdo.wifi:error` | `uint` | Error indication |

## Message Details

### fdo.wifi:active

**Direction**: s --> d  
**Value**: `bool`

Activates or deactivates the Wi-Fi setup module on the device.

- `true`: Activate Wi-Fi setup module
- `false`: Deactivate Wi-Fi setup module

### fdo.wifi:network-add

**Direction**: s --> d  
**Value**: `cbor`

Adds a network configuration. Device processes networks sequentially. Uses CBOR encoding for compactness and consistency with FDO protocol.

#### Basic Network
```
{
  0: "1.0",
  1: "net-001",
  2: "Setup-WiFi",
  3: 1, / wpa2-psk /
  4: h'73657475702d70617373776f7264', / setup-password /
  5: 0 / onboard-only /
}
```

#### Certificate-Based Network
```
{
  0: "1.0",
  1: "net-002",
  2: "Enterprise-WiFi",
  3: 3, / wpa3-enterprise /
  4: 0, / eap-tls /
  5: [
    h'4d494944647a4343416c2b2e2e2e', / CA cert 1 /
    h'4d494944647a4343416c2b2e2e2e'  / CA cert 2 /
  ],
  6: 1 / full-access /
}
```

#### Schema Definition

##### Network Configuration Schema
```
0: version (string)
1: network_id (string)
2: ssid (string)
3: auth_type (enumerated)
4: password (binary string, optional)
5: eap_method (enumerated, optional)
6: ca_certificates (array of binary strings, optional)
7: trust_level (enumerated)
```

##### Authentication Type Enumeration
```
0: open
1: wpa2-psk
2: wpa3-psk
3: wpa3-enterprise
```

##### EAP Method Enumeration
```
0: eap-tls
1: eap-peap
2: eap-ttls
```

##### Trust Level Enumeration
```
0: onboard-only
1: full-access
```

### fdo.wifi:cert-req

**Direction**: s <-- d  
**Value**: `cbor`

Device sends CSR for certificate-based network. Uses CBOR encoding for compactness and consistency with FDO protocol.

```
{
  0: "1.0",
  1: "net-002",
  2: "Enterprise-WiFi",
  3: h'4d49424a564a43422e2e2e' / base64 decoded CSR /
}
```

#### CSR Request Schema
```
0: version (string)
1: network_id (string)
2: ssid (string)
3: csr (binary string)
```

### fdo.wifi:cert-res

**Direction**: s --> d  
**Value**: `cbor`

Service responds with signed certificate. Uses CBOR encoding for compactness and consistency with FDO protocol.

```
{
  0: "1.0",
  1: "net-002",
  2: "Enterprise-WiFi",
  3: h'4d494944647a4343416c2b2e2e2e' / base64 decoded certificate /
}
```

#### Certificate Response Schema
```
0: version (string)
1: network_id (string)
2: ssid (string)
3: client_certificate (binary string)
```

### fdo.wifi:error

**Direction**: s --> d  
**Value**: `uint`

Error indication for FSIM operation failures.

#### Error Codes
- `1000`: Invalid configuration format
- `1001`: Authentication not supported
- `1002`: Certificate provisioning not available
- `1003`: Invalid network configuration
- `1004`: Trust level not authorized

## Sequential Flow Example

```
1. s --> d: fdo.wifi-setup:active = true
2. s --> d: fdo.wifi-setup:network-add (basic SSID/password)
   → Device configures and connects to network
3. s --> d: fdo.wifi-setup:network-add (certificate network)
   → Device generates CSR
4. s <-- d: fdo.wifi-setup:cert-req (CSR for network)
5. s --> d: fdo.wifi-setup:cert-res (signed certificate)
   → Device installs certificate and connects to network
6. s --> d: fdo.wifi-setup:network-add (another basic network)
   → Device configures and connects to network
```

## Security Model

### Single-Sided Mode
- **Basic networks only**: SSID/password configuration
- **No certificate provisioning**: Certificate-based networks not allowed
- **Trust level**: Limited to "onboard-only"

### Owner/Delegate Mode
- **Full capabilities**: Basic and certificate-based networks
- **Certificate provisioning**: CSR/certificate enrollment supported
- **Trust levels**: Both "onboard-only" and "full-access"

### Certificate Security
- **Client-side key generation**: Preferred approach
- **CSR validation**: Required before certificate issuance
- **Network binding**: Certificate tied to specific network ID

## Implementation Notes

### CBOR Encoding Requirements
- **Mandatory**: All structured messages MUST use CBOR encoding
- **Consistency**: Follows FDO protocol encoding standards
- **Compactness**: Binary format for efficient transmission
- **Parsing**: Use standard CBOR libraries compatible with FDO ecosystem

### Device Requirements
- Basic Wi-Fi configuration support
- CSR generation for certificate networks
- Trust level enforcement
- Sequential network processing
- CBOR encoding/decoding capability

### Service Requirements
- Network configuration management
- Certificate signing capability
- Device authorization validation
- CBOR message processing

### Error Handling
- Configuration validation
- Certificate provisioning failures
- Network-specific error reporting
- CBOR parsing error handling

### TODO: Certificate Chunking Implementation

#### **Critical Issue - Certificate Size Limitations**
Current `fdo.wifi:cert-res` message uses single message format, but certificates can exceed MTU limits:

- **Typical certificates**: 1-4 KB each
- **Certificate chains**: 5-20 KB total
- **FDO MTU limits**: ~1200-1400 bytes per message
- **Current design**: Will fail with large certificates

#### **Required Implementation**
Following the `fdo.upload` pattern (1014 byte chunks):

```
Current (broken):
s --> d: fdo.wifi:cert-res (single large certificate)

Fixed (chunking):
s --> d: fdo.wifi:cert-res-chunk-1 (first 1014 bytes)
s --> d: fdo.wifi:cert-res-chunk-2 (second 1014 bytes)
...
s --> d: fdo.wifi:cert-res-complete (transfer complete)
```

#### **Implementation Tasks**
- [ ] Add chunking messages to FSIM specification
- [ ] Implement service-side chunking logic
- [ ] Implement device-side reassembly logic
- [ ] Add integrity verification (hash/checksum)
- [ ] Add timeout and error handling for incomplete transfers
- [ ] Test with large certificates (2-20 KB)
- [ ] Update message flow documentation

#### **Related Issue - fdo.csr Module**
The existing `fdo.csr` FSIM has the same problem:
- `fdo.csr:simpleenroll-res`: Single certificate message
- `fdo.csr:cacerts-res`: Single CA bundle message
- Both will fail with large certificates

**Investigation needed**: Check if existing fdo.csr implementations handle chunking or if specification needs updating.
