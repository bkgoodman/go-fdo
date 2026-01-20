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

```text
1. s → d: fdo.wifi:active = true
2. s → d: fdo.wifi:network-add (basic network)
3. s → d: fdo.wifi:network-add (certificate network metadata)
4. d → s: fdo.wifi:csr-begin / csr-data-<n> / csr-end (device sends CSR)
5. s → d: fdo.wifi:csr-result (ack CSR processing)
6. s → d: fdo.wifi:cert-begin / cert-data-<n> / cert-end (owner returns signed cert)
7. d → s: fdo.wifi:cert-result (device installs client cert)
8. s → d: fdo.wifi:ca-begin / ca-data-<n> / ca-end (optional CA bundle)
9. d → s: fdo.wifi:ca-result (device stores CA material)
```

## Key-Value Message Specification

The following table describes key-value pairs for the fdo.wifi FSIM. All structured messages use CBOR encoding for compactness and consistency with FDO protocol:

| Direction | Key Name | Value | Meaning |
| --------- | -------- | ----- | ------- |
| s → d | `fdo.wifi:active` | `bool` | Activate/deactivate module |
| s → d | `fdo.wifi:network-add` | `cbor` | Add network configuration |
| d → s | `fdo.wifi:csr-begin` | `map` | Announces a CSR payload using the [chunking strategy](./chunking-strategy.md) |
| d → s | `fdo.wifi:csr-data-<n>` | `bstr` | CSR chunk `n` (0-based) |
| d → s | `fdo.wifi:csr-end` | `map` | Completes CSR payload, may include hash |
| s → d | `fdo.wifi:csr-result` | `array` | Result array `[status, ?message]` acknowledging CSR processing |
| s → d | `fdo.wifi:cert-begin` | `map` | Announces client certificate payload per chunking strategy |
| s → d | `fdo.wifi:cert-data-<n>` | `bstr` | Client certificate chunk `n` (0-based) |
| s → d | `fdo.wifi:cert-end` | `map` | Completes client certificate payload |
| d → s | `fdo.wifi:cert-result` | `array` | Result array `[status, ?message]` for certificate installation |
| s → d | `fdo.wifi:ca-begin` | `map` | Announces CA bundle payload (one or more CA certs) |
| s → d | `fdo.wifi:ca-data-<n>` | `bstr` | CA chunk `n` |
| s → d | `fdo.wifi:ca-end` | `map` | Completes CA bundle payload |
| d → s | `fdo.wifi:ca-result` | `array` | Result array `[status, ?message]` for CA processing |
| s → d | `fdo.wifi:error` | `uint` | Error indication |

All chunk-capable keys follow the shared protocol so CSRs, signed certificates, and CA bundles can exceed MTU limits without inventing Wi-Fi-specific transport rules.

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

```cbor
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

```cbor
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

#### Fast Roaming Network

```cbor
{
  0: "1.0",
  1: "net-003",
  2: "CorporateWiFi",
  3: 3, / wpa3-enterprise /
  4: 0, / eap-tls /
  5: [
    h'4d494944647a4343416c2b2e2e2e' / CA cert /
  ],
  6: 1, / full-access /
  7: {   / fast_roaming object /
    0: true,                    / enabled /
    1: h'ABCD'                  / mobility_domain: 0xABCD /
  }
}
```

#### Hotspot 2.0 Seeding Network

```cbor
{
  0: "1.0",
  1: "net-004",
  2: "HotspotNetwork",
  3: 3, / wpa3-enterprise /
  4: 1, / eap-peap - credential-based EAP method /
  5: [
    h'4d494944647a4343416c2b2e2e2e' / CA cert /
  ],
  6: 1, / full-access /
  8: {   / hotspot2 object /
    0: [h'001BC504BD'],                / roaming consortium OI /
    1: "hotspot.example.com",          / domain name /
    2: "Example Hotspot Operator",     / operator name /
    3: 0                               / credential - device has stored EAP credentials /
  },
  9: "user123@example.com",             / EAP username /
  10: h'70617373776f7264'               / EAP password /
}
```

**Note**: For Hotspot 2.0 credential-based authentication, device credentials (EAP username/password) are provided through the `eap_username` and `eap_password` fields. The `hotspot2.auth_method` field indicates what type of credentials the device should expect or how it should obtain them.

#### Schema Definition

##### Network Configuration Schema

```text
0: version (string)
1: network_id (string)
2: ssid (string)
3: auth_type (enumerated)
4: password (binary string, optional)
5: eap_method (enumerated, optional)
6: ca_certificates (array of binary strings, optional)
7: trust_level (enumerated)
8: fast_roaming (FastRoaming object, optional)
9: hotspot2 (Hotspot2 object, optional)
10: eap_username (string, optional)
11: eap_password (binary string, optional)
```

#### Conditional Requirements

- For `auth_type = open` (0): `password`, `eap_method`, and `ca_certificates` MUST be omitted.
- For `auth_type = wpa2-psk` (1): `password` MUST be present; `eap_method` and `ca_certificates` MUST be omitted.
- For `auth_type = wpa3-psk` (2) - WPA3-SAE (Personal):
  - `password` MUST be present (8-63 characters recommended for WPA3-SAE compatibility)
  - `eap_method` and `ca_certificates` MUST be omitted
  - Devices SHOULD support WPA3-SAE (Simultaneous Authentication of Equals) protocol
- For `auth_type = wpa3-enterprise` (3):
  - `eap_method` MUST be present.
  - `ca_certificates` MUST be present with at least one CA cert; order MUST be root-to-leaf (trust anchor first).
  - `password` MUST be omitted (credentials are certificate/EAP based).
  - For EAP methods requiring credentials (`eap-peap`, `eap-ttls`): `eap_username` and `eap_password` MAY be provided for device authentication.
- `trust_level` MUST be present for all networks; devices MUST enforce policy (e.g., single-sided may only allow `onboard-only`).

##### Authentication Type Enumeration

```text
0: open
1: wpa2-psk
2: wpa3-psk
3: wpa3-enterprise
```

##### EAP Method Enumeration

```text
0: eap-tls
1: eap-peap
2: eap-ttls
```

##### Trust Level Enumeration

```text
0: onboard-only
1: full-access
```

##### FastRoaming Object Schema

```text
0: enabled (boolean)
1: mobility_domain (binary string, optional)  // 2 bytes, MDID in network byte order
```

##### Hotspot2 Object Schema

```text
0: roaming_consortium (array of binary strings)  // Organization Identifiers (OIs), 3-5 bytes each
1: domain_name (string, optional)               // Domain for online signup
2: operator_name (string, optional)             // Human-readable operator name
3: auth_method (enumerated, optional)           // Hotspot 2.0 authentication method
```

##### Hotspot2 Authentication Method Enumeration

```text
0: credential     // Device has stored credentials (username/password)
1: subscription   // Device has operator subscription
2: online_signup  // Device should use online signup process
```

### fdo.wifi:csr-begin / csr-data-\<n\> / csr-end / csr-result

**Direction**: d → s

Client devices chunk their CSRs so the owner (or delegate) can sign them without MTU constraints. The CSR payload follows the generic begin/data/end/result contract.

#### Wi-Fi CSR Begin Fields

| Key | Field | Type | Requirement | Description |
| --- | ----- | ---- | ----------- | ----------- |
| `-1` | network_id | tstr | **Required** | Matches the network the CSR belongs to. |
| `-2` | ssid | tstr | Optional | Human-readable SSID. |
| `-3` | csr_type | int | Optional | `0=eap-tls`, `1=vendor-specific`. |
| `-4` | metadata | map | Optional | Device-defined hints (e.g., key slot, algorithm). |

Example:

```cbor
{
  0: 3072,
  -1: "net-002",
  -2: "Enterprise-WiFi",
  -3: 0
}
```

The device streams `fdo.wifi:csr-data-0`, `csr-data-1`, … until the CSR DER/PEM blob is complete, then sends `csr-end` (hash optional). The service replies with `csr-result = [status, ?message]` to indicate whether the CSR was accepted for signing.

### fdo.wifi:cert-begin / cert-data-\<n\> / cert-end / cert-result

**Direction**: s → d

Certificate payloads reuse the generic chunking strategy so large PEM/DER blobs fit inside ServiceInfo. The service sends `cert-begin`, followed by numbered `cert-data-<n>` chunks, then a `cert-end`. The device responds with `cert-result`, a CBOR array following the strategy doc's `[status, ?message]` format.

#### Wi-Fi Certificate Begin Fields

Within the generic `cert-begin` map, the Wi-Fi FSIM reserves negative keys for module-specific metadata:

| Key | Field | Type | Requirement | Description |
| --- | ----- | ---- | ----------- | ----------- |
| `-1` | network_id | tstr | **Required** | Matches the `network_id` used in `cert-req`/`network-add`. |
| `-2` | ssid | tstr | Optional | Human-readable SSID for logging. |
| `-3` | cert_role | int | Optional | `0=client`, `1=intermediate`, `2=ca`. |
| `-4` | metadata | map | Optional | Vendor-defined hints (e.g., storage slot, expiration). |

Example `cert-begin` map:

```cbor
{
  0: 6144,                   / total_size /
  1: "sha256",               / hash_alg /
  -1: "net-002",
  -2: "Enterprise-WiFi",
  -3: 0,                      / client cert /
  -4: { "slot": "wifi-client" }
}
```

#### Certificate Chunk Flow

```text
Service → Device: fdo.wifi:cert-begin {...}
Service → Device: fdo.wifi:cert-data-0 = h'...'
Service → Device: fdo.wifi:cert-data-1 = h'...'
Service → Device: fdo.wifi:cert-end {1: h'<sha256>'}
Device  → Service: fdo.wifi:cert-result [0, "installed"]
```

- Chunks MUST be contiguous starting at index 0.
- Hashes, length checks, retransmission, and timeouts inherit the behavior defined in `chunking-strategy.md`.
- Certificate chain ordering: The device MUST expect the certificate chain to be ordered from leaf to root, with the end-entity certificate first, followed by intermediate certificates, and ending with the trust anchor (root CA).
- Certificate network_id MUST match a network previously added via `network-add`, otherwise device returns error status.
- Status code semantics:
  - `cert-result[0] = 0` (success): Certificate was successfully applied and is usable
  - `cert-result[0] = 1` (warning): Certificate was applied but with warnings (e.g., expiration soon); certificate is usable
  - `cert-result[0] = 2` (error): Certificate was NOT applied; certificate is unusable and should not be used for network authentication

### fdo.wifi:ca-begin / ca-data-\<n\> / ca-end / ca-result

**Direction**: s → d

Owners often need to provision a CA chain alongside the client certificate. This flow mirrors the certificate payload but allows separate metadata so devices can store CA material in distinct trust anchors.

| Key | Field | Type | Requirement | Description |
| --- | ----- | ---- | ----------- | ----------- |
| `-1` | network_id | tstr | **Required** | Associates the CA bundle with the Wi-Fi network. |
| `-2` | bundle_id | tstr | Optional | Distinguishes multiple CA bundles (e.g., "root", "intermediate"). |
| `-3` | metadata | map | Optional | Storage slot, rotation hints, etc. |

Devices treat the payload bytes as concatenated DER or PEM objects (implementation-defined). After verifying size/hash, they respond with `ca-result = [status, ?message]`. CA bundle network_id MUST match a network previously added via `network-add`, otherwise device returns error status. Owners may send multiple CA bundles sequentially if a chain requires separate handling.

- Status code semantics:
  - `ca-result[0] = 0` (success): CA bundle was successfully stored and is usable
  - `ca-result[0] = 1` (warning): CA bundle was stored but with warnings; bundle is usable
  - `ca-result[0] = 2` (error): CA bundle was NOT stored; bundle is unusable

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

## Sequential Flow Requirements

**Network Addition Phase**: All `network-add` messages MUST be sent before any certificate operations (CSR, cert, CA).

**Certificate Operations Phase**: CSR, certificate, and CA bundle transfers may proceed only for networks that were previously added via `network-add`.

**Validation Rule**: Any certificate operation (csr-begin, cert-begin, ca-begin) referencing a network_id that was not previously added via `network-add` MUST return an error status in the corresponding result message.

## Sequential Flow Example

```text
1. s --> d: fdo.wifi-setup:active = true
2. s --> d: fdo.wifi-setup:network-add (basic SSID/password)
   → Device adds network to configuration
3. s --> d: fdo.wifi-setup:network-add (certificate network metadata)
   → Device adds network and prepares for CSR
4. d --> s: fdo.wifi-setup:csr-begin / csr-data-<n> / csr-end (device sends CSR)
   → CSR for network added in step 3
5. s --> d: fdo.wifi-setup:csr-result (ack CSR processing)
6. s --> d: fdo.wifi-setup:cert-begin / cert-data-<n> / cert-end (owner returns signed cert)
   → Certificate for network added in step 3
7. d --> s: fdo.wifi-setup:cert-result (device installs certificate)
   → Status = 0 (success) means cert is applied and usable
   → Status = 1 (warning) means cert is applied but with warnings
   → Status = 2 (error) means cert was NOT applied and is unusable
8. s --> d: fdo.wifi-setup:ca-begin / ca-data-<n> / ca-end (optional CA bundle)
   → CA bundle for network added in step 3
9. d --> s: fdo.wifi-setup:ca-result (device stores CA material)
   → Status semantics same as cert-result
```

### Sequence Diagrams

#### Basic Network Configuration

```text
Service                          Device
  |                               |
  | fdo.wifi:active(true)         |
  |------------------------------>|
  |                               | Activate WiFi module
  |                               |
  | fdo.wifi:network-add(basic)   |
  |------------------------------>|
  |                               | Configure SSID/password
  |                               | Connect to network
  |                               |
  | (network connected)           |
  |<------------------------------|
```

#### Certificate & CSR Flow

```text
Service                          Device
  |                               |
  | fdo.wifi:active(true)         |
  |------------------------------>|
  |                               |
  | fdo.wifi:network-add(meta)    |
  |------------------------------>|
  |                               | Prepare CSR
  |                               |
  | fdo.wifi:csr-begin            |
  |<------------------------------|
  | fdo.wifi:csr-data-0           |
  |<------------------------------|
  | ...                           |
  | fdo.wifi:csr-end              |
  |<------------------------------|
  |                               | Sign CSR
  |                               |
  | fdo.wifi:csr-result([0])      |
  |------------------------------>|
  | fdo.wifi:cert-begin           |
  |------------------------------>|
  | fdo.wifi:cert-data-0          |
  |------------------------------>|
  | ...                           |
  | fdo.wifi:cert-end             |
  |------------------------------>|
  |                               | Install certificate
  |                               |
  | fdo.wifi:cert-result([0])     |
  |<------------------------------|
  |                               |
  | (network connected)           |
  |<------------------------------|
```

#### CA Bundle Provisioning

```text
Service                          Device
  |                               |
  | fdo.wifi:ca-begin             |
  |------------------------------>|
  | fdo.wifi:ca-data-0            |
  |------------------------------>|
  | ...                           |
  | fdo.wifi:ca-end               |
  |------------------------------>|
  |                               | Store CA material
  |                               |
  | fdo.wifi:ca-result([0])       |
  |<------------------------------|
```

#### Chunked Certificate Transfer

```text
Service                          Device
  |                               |
  | fdo.wifi:cert-begin(meta)     |
  |------------------------------>|
  |                               | Prepare for cert transfer
  |                               |
  | fdo.wifi:cert-data-0          |
  |------------------------------>|
  |                               | Accumulate chunk 0
  |                               |
  | fdo.wifi:cert-data-1          |
  |------------------------------>|
  |                               | Accumulate chunk 1
  |                               |
  | ...                           |
  |                               |
  | fdo.wifi:cert-end             |
  |------------------------------>|
  |                               | Install certificate, verify hash/length
  |                               |
  | fdo.wifi:cert-result([0,...]) |
  |<------------------------------|
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

### Certificate Chunking for Large Data

Certificate blobs often exceed MTU, so the Wi-Fi FSIM now **fully reuses** the shared chunking strategy: numbered `cert-data-<n>` keys instead of per-chunk ACKs, optional length/hash in `cert-begin`, and a final `cert-result` status array. Implementations get automatic alignment with other FSIMs (payload, future modules) and avoid divergent reliability semantics. Chunk sizing, retransmission, and integrity rules are inherited directly from [`chunking-strategy.md`](./chunking-strategy.md); no Wi-Fi-specific deviations apply.
