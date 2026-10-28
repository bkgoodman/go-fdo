// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

//go:build (tpm || tpmsim) && !tinygo

package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/google/go-tpm/tpm2"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/serviceinfo"
	"github.com/fido-device-onboard/go-fdo/tpm"
)

// tpmQuoteDevice is the device side of the fdo.tpm-quote demo: it answers
// the Owner's challenge with tpm.AttestDeviceKey and activates the Owner's
// credential with tpm.ActivateAKCredential.
//
// FDO_TPM_QUOTE_TAMPER simulates a lying device, for negative tests:
// nonce (quote with a stale nonce), dak (certify another TPM key instead of
// the Device Key), quote (alter the quote after signing), activate (return a
// wrong secret, as an AK outside the EK's TPM would).
// FDO_TPM_QUOTE_EK_CERT_FILE sends that DER file as the EK certificate
// instead of the TPM's own (e.g. another genuine TPM's certificate).
type tpmQuoteDevice struct{}

var _ serviceinfo.DeviceModule = (*tpmQuoteDevice)(nil)

func addTPMQuoteFSIM(fsims map[string]serviceinfo.DeviceModule) {
	fsims[tpmQuoteModule] = &tpmQuoteDevice{}
}

func tpmQuoteTamper(what string) bool { return os.Getenv("FDO_TPM_QUOTE_TAMPER") == what }

// The credential store's TPM connection (swtpm accepts one connection).
func tpmQuoteTPM() (tpm.TPM, error) {
	s, ok := credStore.(interface{ TPM() tpm.TPM })
	if !ok || s.TPM() == nil {
		return nil, errors.New("credential store is not TPM-backed")
	}
	return s.TPM(), nil
}

// Transition implements serviceinfo.DeviceModule.
func (d *tpmQuoteDevice) Transition(bool) error { return nil }

// Yield implements serviceinfo.DeviceModule.
func (d *tpmQuoteDevice) Yield(context.Context, func(string) io.Writer, func()) error { return nil }

// Receive implements serviceinfo.DeviceModule.
func (d *tpmQuoteDevice) Receive(ctx context.Context, name string, body io.Reader, respond func(string) io.Writer, yield func()) error {
	reply := func(msg string, v any) error { return cbor.NewEncoder(respond(msg)).Encode(v) }
	switch name {
	case "challenge":
		var ch tpmQuoteChallenge
		if err := cbor.NewDecoder(body).Decode(&ch); err != nil {
			return err
		}
		ev, err := d.evidence(ch)
		if err != nil {
			fmt.Printf("[fdo.tpm-quote] evidence failed: %v\n", err)
			return reply("error", err.Error())
		}
		fmt.Printf("[fdo.tpm-quote] sent evidence: AK, EK cert (%d bytes), Certify(Device Key), Quote of PCRs %v\n", len(ev.EKCert), ch.PCRs)
		return reply("evidence", ev)
	case "credential":
		var c tpmQuoteCredential
		if err := cbor.NewDecoder(body).Decode(&c); err != nil {
			return err
		}
		secret, err := d.activate(c)
		if err != nil {
			fmt.Printf("[fdo.tpm-quote] activation failed: %v\n", err)
			return reply("error", err.Error())
		}
		fmt.Printf("[fdo.tpm-quote] activated the Owner's credential for the AK with the EK\n")
		return reply("activated", secret)
	default:
		return nil
	}
}

func (d *tpmQuoteDevice) evidence(ch tpmQuoteChallenge) (*tpm.AttestEvidence, error) {
	t, err := tpmQuoteTPM()
	if err != nil {
		return nil, err
	}
	var opt tpm.AttestOptions
	if tpmQuoteTamper("nonce") {
		opt.QuoteNonce = sha256.New().Sum(nil)
	}
	if tpmQuoteTamper("dak") {
		other, err := tpm2.CreatePrimary{
			PrimaryHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(nil)},
			InPublic:      tpm2.New2B(tpm2.ECCSRKTemplate),
		}.Execute(t)
		if err != nil {
			return nil, err
		}
		defer func() { _, _ = tpm2.FlushContext{FlushHandle: other.ObjectHandle}.Execute(t) }()
		opt.CertifyHandle = other.ObjectHandle
	}
	ev, err := tpm.AttestDeviceKey(t, ch.Nonce, ch.PCRs, opt)
	if err != nil {
		return nil, err
	}
	if tpmQuoteTamper("quote") {
		ev.QuoteInfo = append([]byte(nil), ev.QuoteInfo...)
		ev.QuoteInfo[len(ev.QuoteInfo)-1] ^= 0x01
	}
	if f := os.Getenv("FDO_TPM_QUOTE_EK_CERT_FILE"); f != "" {
		if ev.EKCert, err = os.ReadFile(f); err != nil {
			return nil, err
		}
	}
	return ev, nil
}

func (d *tpmQuoteDevice) activate(c tpmQuoteCredential) ([]byte, error) {
	if tpmQuoteTamper("activate") {
		return []byte("not the secret"), nil
	}
	t, err := tpmQuoteTPM()
	if err != nil {
		return nil, err
	}
	return tpm.ActivateAKCredential(t, c.IDObject, c.EncSecret)
}

// tpmPCRExtend extends a PCR (SHA-256 bank) with SHA-256 of text: demo
// stand-in for a boot measurement. Spec: "<index>:<text>".
func tpmPCRExtend(spec string) error {
	idx, text, ok := strings.Cut(spec, ":")
	p, err := strconv.ParseUint(idx, 10, 8)
	if !ok || err != nil || p > 23 {
		return fmt.Errorf("-tpm-pcr-extend wants <index>:<text>, got %q", spec)
	}
	t, err := tpmOpen(tpmPath)
	if err != nil {
		return err
	}
	defer func() { _ = t.Close() }()
	digest := sha256.Sum256([]byte(text))
	if _, err := (tpm2.PCRExtend{
		PCRHandle: tpm2.AuthHandle{Handle: tpm2.TPMHandle(p), Auth: tpm2.PasswordAuth(nil)},
		Digests:   tpm2.TPMLDigestValues{Digests: []tpm2.TPMTHA{{HashAlg: tpm2.TPMAlgSHA256, Digest: digest[:]}}},
	}).Execute(t); err != nil {
		return fmt.Errorf("PCR_Extend %d: %w", p, err)
	}
	fmt.Printf("PCR[%d] sha256 extended with sha256(%q) = %x\n", p, text, digest)
	return nil
}
