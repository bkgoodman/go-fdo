// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package cose

import (
	"reflect"
	"testing"

	"github.com/fido-device-onboard/go-fdo/cbor"
)

func TestDecodeSerializedOrEmptyHeaderMap(t *testing.T) {
	var input = []byte{0x43, 0xa1, 0x01, 0x26}
	expect, err := newSerializedOrEmptyHeaderMap(map[Label]any{
		{Int64: 1}: -7,
	})
	if err != nil {
		t.Fatalf("error encoding expected serializedOrEmptyHeaderMap: %v", err)
	}
	var got serializedOrEmptyHeaderMap
	if err := cbor.Unmarshal(input, &got); err != nil {
		t.Fatalf("error decoding % x: %v", input, err)
	}
	if !reflect.DeepEqual(expect, got) {
		t.Fatalf("expected %#v, got %#v", expect, got)
	}
}