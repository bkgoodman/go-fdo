// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
	"crypto"
	"crypto/rsa"
	"fmt"

	"github.com/fido-device-onboard/go-fdo/cose"
)

// sigInfo is used to encode parameters for the device attestation signature.
//
// sigInfo flows in both directions, initially from the protocol client
// (eASigInfo), then to the protocol client (eBSigInfo). The types eASigInfo and
// eBSigInfo are intended to clarify these two cases in the protocol message
// descriptions.
//
//	sigInfo = [
//	    sgType: DeviceSgType,
//	    Info: bstr
//	]
//	eASigInfo = sigInfo  ;; from Device to Rendezvous/Owner
//	eBSigInfo = sigInfo  ;; from Owner/Rendezvous to Device
//
//	DeviceSgType //= (
//	    StSECP256R1: ES256,  ;; ECDSA secp256r1 = NIST-P-256 = prime256v1
//	    StSECP384R1: ES384,  ;; ECDSA secp384r1 = NIST-P-384
//	    StRSA2048:   RS256,  ;; RSA 2048 bit
//	    StRSA3072:   RS384,  ;; RSA 3072 bit
//	    StEPID10:    90,     ;; Intel® EPID 1.0 signature
//	    StEPID11:    91      ;; Intel® EPID 1.1 signature
//	)
//
//	COSECompatibleSignatureTypes = (
//	    ES256: -7,  ;; From COSE spec, table 5
//	    ES384: -35, ;; From COSE spec, table 5
//	    PS256: -37, ;; From IANA
//	    PS384: -38, ;; From IANA
//	    RS256: -257,;; From https://datatracker.ietf.org/doc/html/draft-ietf-cose-webauthn-algorithms-05
//	    RS384: -258 ;; From https://datatracker.ietf.org/doc/html/draft-ietf-cose-webauthn-algorithms-05
//	)
type sigInfo struct {
	Type cose.SignatureAlgorithm
	Info []byte
}

/*
// This function is not used because HMAC support is implicitly required in FDO
// by the rules: RSA2048->SHA256, RSA3072->SHA384, secp256r1->SHA256,
// secp384r1->SHA384.

func sigInfoFor(key crypto.Signer, usePSS bool, hmac KeyedHasher) sigInfo {
	switch _, isECDSA := key.Public().(*ecdsa.PublicKey); {
	case isECDSA && hmac.Supports(HmacSha384Hash):
		return sigInfo{Type: cose.ES384Alg}
	case isECDSA && !hmac.Supports(HmacSha384Hash):
		return sigInfo{Type: cose.ES256Alg}
	case !isECDSA && usePSS && hmac.Supports(HmacSha384Hash):
		return sigInfo{Type: cose.PS384Alg}
	case !isECDSA && !usePSS && hmac.Supports(HmacSha384Hash):
		return sigInfo{Type: cose.RS384Alg}
	case !isECDSA && usePSS && !hmac.Supports(HmacSha384Hash):
		return sigInfo{Type: cose.PS384Alg}
	case !isECDSA && !usePSS && !hmac.Supports(HmacSha384Hash):
		return sigInfo{Type: cose.RS256Alg}
	}
	panic("unreachable")
}
*/

func sigInfoFor(key crypto.Signer, usePSS bool) (*sigInfo, error) {
	opts, err := signOptsFor(key, usePSS)
	if err != nil {
		return nil, err
	}
	algID, err := cose.SignatureAlgorithmFor(key, opts)
	if err != nil {
		return nil, err
	}
	return &sigInfo{Type: algID}, nil
}

func signOptsFor(key crypto.Signer, usePSS bool) (crypto.SignerOpts, error) {
	var opts crypto.SignerOpts
	if rsaPub, ok := key.Public().(*rsa.PublicKey); ok {
		switch rsaPub.Size() {
		case 2048 / 8:
			opts = crypto.SHA256
		case 3072 / 8:
			opts = crypto.SHA384
		default:
			return nil, fmt.Errorf("unsupported RSA key size: %d bits", rsaPub.Size()*8)
		}

		if usePSS {
			opts = &rsa.PSSOptions{
				SaltLength: rsa.PSSSaltLengthEqualsHash,
				Hash:       opts.(crypto.Hash),
			}
		}
	}
	return opts, nil
}