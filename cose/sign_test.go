// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package cose_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/cose"
)

func TestSignAndVerify(t *testing.T) {
	key256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Errorf("error generating ec key p256: %v", err)
		return
	}

	key384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Errorf("error generating ec key p384: %v", err)
		return
	}

	header, err := cose.NewHeader(nil, nil)
	if err != nil {
		t.Error(err)
		return
	}

	payload := cbor.NewBstr[any]([]byte("Hello world"))

	s1 := cose.Sign1[any]{
		Header:  header,
		Payload: &payload,
	}

	t.Run("es256", func(t *testing.T) {
		if err := s1.Sign(key256, nil); err != nil {
			t.Errorf("error signing: %v", err)
			return
		}
		passed, err := s1.Verify(key256.Public(), nil)
		if err != nil {
			t.Errorf("error verifying: %v", err)
			return
		}
		if !passed {
			t.Error("verification failed")
			return
		}
	})

	t.Run("es384", func(t *testing.T) {
		if err := s1.Sign(key384, nil); err != nil {
			t.Errorf("error signing: %v", err)
			return
		}
		passed, err := s1.Verify(key384.Public(), nil)
		if err != nil {
			t.Errorf("error verifying: %v", err)
			return
		}
		if !passed {
			t.Error("verification failed")
			return
		}
	})
}