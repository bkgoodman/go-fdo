// SPDX-FileCopyrightText: (C) 2024 Intel Corperation & Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
	"io"
	"github.com/fido-device-onboard/go-fdo/cbor"
)

type capabilityFlags struct {
	Flags []byte //`cbor:bstr`
	VendorUnique []string //`cbor:omitempty`
}

func (f capabilityFlags) FlatMarshalCBOR(w io.Writer) error {
	e:=cbor.NewEncoder(w)
	if err := e.Encode(f.Flags); err != nil {
		return err
	}
	if len(f.VendorUnique) > 0 {
		e.Encode(f.VendorUnique)
	}
	return nil
}

func (f *capabilityFlags) FlatUnmarshalCBOR(r io.Reader) error {
	if err := cbor.NewDecoder(r).Decode(&f.Flags); err != nil {
		return err
	}
	cbor.NewDecoder(r).Decode(&f.VendorUnique)
	return nil
}

const (
    DelegateSupportFlag = 1
)

var VendorUniqueFlags = []string{"com.example.test"}

// These are based on implmenetation, and therefore 
// should be contants
var CapabilityFlags = capabilityFlags{
	Flags: []byte{DelegateSupportFlag}, // Delegate support
	//VendorUnique: VendorUniqueFlags,
}

