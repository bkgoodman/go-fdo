// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

// Package chunking provides generic chunking support for FDO Service Info Modules (FSIMs)
// following the pattern defined in chunking-strategy.md.
//
// This package implements the common begin/data/end/result message flow that allows
// FSIMs to transmit large payloads without being constrained by MTU limits.
package chunking

import (
	"github.com/fido-device-onboard/go-fdo/cbor"
)

// BeginMessage represents the *-begin message structure from chunking-strategy.md.
// It contains generic fields (non-negative keys) and FSIM-specific fields (negative keys).
type BeginMessage struct {
	// Generic fields (keys 0-127 reserved by chunking spec)
	TotalSize uint64         // Key 0: Total bytes that will be transmitted (optional)
	HashAlg   string         // Key 1: Hash algorithm identifier (e.g., "sha256", "sha384")
	Metadata  map[string]any // Key 2: Optional FSIM-specific metadata

	// FSIM-specific fields use negative integer keys to avoid collisions
	// Example: -1 for network_id, -2 for ssid, etc.
	FSIMFields map[int]any
}

// MarshalCBOR encodes BeginMessage to CBOR map format.
func (b *BeginMessage) MarshalCBOR() ([]byte, error) {
	m := make(map[any]any)

	// Add generic fields if present
	if b.TotalSize > 0 {
		m[0] = b.TotalSize
	}
	if b.HashAlg != "" {
		m[1] = b.HashAlg
	}
	if len(b.Metadata) > 0 {
		m[2] = b.Metadata
	}

	// Add FSIM-specific fields (negative keys)
	for key, val := range b.FSIMFields {
		if key >= 0 {
			continue // Skip non-negative keys to avoid conflicts
		}
		m[key] = val
	}

	return cbor.Marshal(m)
}

// UnmarshalCBOR decodes BeginMessage from CBOR map format.
func (b *BeginMessage) UnmarshalCBOR(data []byte) error {
	var m map[any]any
	if err := cbor.Unmarshal(data, &m); err != nil {
		return err
	}

	b.FSIMFields = make(map[int]any)

	for key, val := range m {
		switch k := key.(type) {
		case int:
			switch k {
			case 0:
				if v, ok := val.(uint64); ok {
					b.TotalSize = v
				}
			case 1:
				if v, ok := val.(string); ok {
					b.HashAlg = v
				}
			case 2:
				if v, ok := val.(map[any]any); ok {
					b.Metadata = convertToStringMap(v)
				}
			default:
				// Negative keys are FSIM-specific
				if k < 0 {
					b.FSIMFields[k] = val
				}
			}
		case uint64:
			// Handle uint64 keys (CBOR may decode as uint64)
			switch k {
			case 0:
				if v, ok := val.(uint64); ok {
					b.TotalSize = v
				}
			case 1:
				if v, ok := val.(string); ok {
					b.HashAlg = v
				}
			case 2:
				if v, ok := val.(map[any]any); ok {
					b.Metadata = convertToStringMap(v)
				}
			}
		}
	}

	return nil
}

// EndMessage represents the *-end message structure from chunking-strategy.md.
type EndMessage struct {
	// Generic fields (keys 0-127 reserved by chunking spec)
	Status    int    // Key 0: FSIM-specific status code (e.g., 0 = success)
	HashValue []byte // Key 1: Hash of the full payload
	Message   string // Key 2: Optional human-readable note or error string

	// FSIM-specific fields use negative integer keys
	FSIMFields map[int]any
}

// MarshalCBOR encodes EndMessage to CBOR map format.
func (e *EndMessage) MarshalCBOR() ([]byte, error) {
	m := make(map[any]any)

	// Add generic fields if present
	if e.Status != 0 {
		m[0] = e.Status
	}
	if len(e.HashValue) > 0 {
		m[1] = e.HashValue
	}
	if e.Message != "" {
		m[2] = e.Message
	}

	// Add FSIM-specific fields (negative keys)
	for key, val := range e.FSIMFields {
		if key >= 0 {
			continue
		}
		m[key] = val
	}

	return cbor.Marshal(m)
}

// UnmarshalCBOR decodes EndMessage from CBOR map format.
func (e *EndMessage) UnmarshalCBOR(data []byte) error {
	var m map[any]any
	if err := cbor.Unmarshal(data, &m); err != nil {
		return err
	}

	e.FSIMFields = make(map[int]any)

	for key, val := range m {
		switch k := key.(type) {
		case int:
			switch k {
			case 0:
				if v, ok := val.(int); ok {
					e.Status = v
				}
			case 1:
				if v, ok := val.([]byte); ok {
					e.HashValue = v
				}
			case 2:
				if v, ok := val.(string); ok {
					e.Message = v
				}
			default:
				if k < 0 {
					e.FSIMFields[k] = val
				}
			}
		case uint64:
			switch k {
			case 0:
				if v, ok := val.(int); ok {
					e.Status = v
				} else if v, ok := val.(uint64); ok {
					e.Status = int(v)
				}
			case 1:
				if v, ok := val.([]byte); ok {
					e.HashValue = v
				}
			case 2:
				if v, ok := val.(string); ok {
					e.Message = v
				}
			}
		}
	}

	return nil
}

// ResultMessage represents the *-result message structure from chunking-strategy.md.
// This is sent by the receiver to acknowledge completion of the transfer.
type ResultMessage struct {
	StatusCode int    // 0=success, 1=warning, 2=error (FSIMs may define additional values)
	Message    string // Optional human-readable description or error detail
}

// MarshalCBOR encodes ResultMessage to CBOR array format: [status_code, ?message]
func (r *ResultMessage) MarshalCBOR() ([]byte, error) {
	if r.Message == "" {
		return cbor.Marshal([]any{r.StatusCode})
	}
	return cbor.Marshal([]any{r.StatusCode, r.Message})
}

// UnmarshalCBOR decodes ResultMessage from CBOR array format.
func (r *ResultMessage) UnmarshalCBOR(data []byte) error {
	var arr []any
	if err := cbor.Unmarshal(data, &arr); err != nil {
		return err
	}

	if len(arr) > 0 {
		if v, ok := arr[0].(int); ok {
			r.StatusCode = v
		} else if v, ok := arr[0].(uint64); ok {
			r.StatusCode = int(v)
		}
	}

	if len(arr) > 1 {
		if v, ok := arr[1].(string); ok {
			r.Message = v
		}
	}

	return nil
}

// convertToStringMap converts a map[any]any to map[string]any for metadata.
func convertToStringMap(m map[any]any) map[string]any {
	result := make(map[string]any)
	for k, v := range m {
		if str, ok := k.(string); ok {
			result[str] = v
		}
	}
	return result
}
