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

// TCG EK Credential Profile: persistent RSA 2048 EK and its certificate.
const (
	ekRSAHandle   = tpm2.TPMHandle(0x81010001)
	ekRSACertNV   = 0x01C00002
	nvReadChunkSz = 512
)

// tpmQuoteDevice is the device side of the fdo.tpm-quote demo. It answers
// the Owner's challenge with a fresh AK, the EK certificate, the Device Key's
// public area, TPM2_Certify(Device Key, by AK) and TPM2_Quote (by AK), both
// with the Owner nonce, then activates the Owner's credential for the AK.
//
// FDO_TPM_QUOTE_TAMPER simulates a lying device, for negative tests:
// nonce (quote with a stale nonce), dak (certify another TPM key instead of
// the Device Key), quote (alter the quote after signing), activate (return a
// wrong secret, as an AK outside the EK's TPM would).
// FDO_TPM_QUOTE_EK_CERT_FILE sends that DER file as the EK certificate
// instead of the TPM's own (e.g. another genuine TPM's certificate).
//
// The AK is a primary created from a fixed template in the Endorsement
// hierarchy, so the TPM recreates the same key (same name) on demand. It is
// created and flushed within each step: nothing stays loaded between
// messages, so an aborted TO2 leaks no transient object (swtpm keeps them
// across connections and has three slots).
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

// loadAK creates (recreates) the AK; the caller flushes it.
func loadAK(t tpm.TPM) (*tpm2.NamedHandle, *tpm2.TPMTPublic, func(), error) {
	cp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHEndorsement, Auth: tpm2.PasswordAuth(nil)},
		InPublic:      tpm2.New2B(akTemplate()),
	}.Execute(t)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("create AK: %w", err)
	}
	flush := func() { _, _ = tpm2.FlushContext{FlushHandle: cp.ObjectHandle}.Execute(t) }
	pub, err := cp.OutPublic.Contents()
	if err != nil {
		flush()
		return nil, nil, nil, err
	}
	return &tpm2.NamedHandle{Handle: cp.ObjectHandle, Name: cp.Name}, pub, flush, nil
}

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

func akTemplate() tpm2.TPMTPublic {
	return tpm2.TPMTPublic{
		Type: tpm2.TPMAlgECC, NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{FixedTPM: true, FixedParent: true, SensitiveDataOrigin: true,
			UserWithAuth: true, NoDA: true, Restricted: true, SignEncrypt: true},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
			CurveID: tpm2.TPMECCNistP256,
			Scheme: tpm2.TPMTECCScheme{Scheme: tpm2.TPMAlgECDSA,
				Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSigSchemeECDSA{HashAlg: tpm2.TPMAlgSHA256})},
		}),
	}
}

func (d *tpmQuoteDevice) evidence(ch tpmQuoteChallenge) (*tpmQuoteEvidence, error) {
	t, err := tpmQuoteTPM()
	if err != nil {
		return nil, err
	}

	// AK: restricted signing key, a primary in the Endorsement hierarchy
	ak, akPub, flushAK, err := loadAK(t)
	if err != nil {
		return nil, err
	}
	defer flushAK()
	akAuth := tpm2.AuthHandle{Handle: ak.Handle, Name: ak.Name, Auth: tpm2.PasswordAuth(nil)}

	ekCert, err := readNV(t, ekRSACertNV)
	if err != nil {
		return nil, fmt.Errorf("EK certificate (NV 0x%08X): %w", ekRSACertNV, err)
	}
	ekCert = trimDER(ekCert)
	if f := os.Getenv("FDO_TPM_QUOTE_EK_CERT_FILE"); f != "" {
		if ekCert, err = os.ReadFile(f); err != nil {
			return nil, err
		}
	}

	// Device Key (or, tampered, another TPM key) certified by the AK. The
	// Device Key's authPolicy is PolicyCommandCode(TPM_CC_Certify).
	certHandle := tpm2.TPMHandle(tpm.DAKHandle)
	if tpmQuoteTamper("dak") {
		other, err := tpm2.CreatePrimary{
			PrimaryHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(nil)},
			InPublic:      tpm2.New2B(tpm2.ECCSRKTemplate),
		}.Execute(t)
		if err != nil {
			return nil, err
		}
		defer func() { _, _ = tpm2.FlushContext{FlushHandle: other.ObjectHandle}.Execute(t) }()
		certHandle = other.ObjectHandle
	}
	rp, err := tpm2.ReadPublic{ObjectHandle: certHandle}.Execute(t)
	if err != nil {
		return nil, fmt.Errorf("Device Key: %w", err)
	}
	dakPub, err := rp.OutPublic.Contents()
	if err != nil {
		return nil, err
	}
	var objAuth tpm2.Session = tpm2.PasswordAuth(nil)
	if certHandle == tpm2.TPMHandle(tpm.DAKHandle) {
		ps, closePS, err := tpm2.PolicySession(t, dakPub.NameAlg, 16)
		if err != nil {
			return nil, err
		}
		defer func() { _ = closePS() }()
		if _, err := (tpm2.PolicyCommandCode{PolicySession: ps.Handle(), Code: tpm2.TPMCCCertify}).Execute(t); err != nil {
			return nil, err
		}
		objAuth = ps
	}
	certify, err := tpm2.Certify{
		ObjectHandle:   tpm2.AuthHandle{Handle: certHandle, Name: rp.Name, Auth: objAuth},
		SignHandle:     akAuth,
		QualifyingData: tpm2.TPM2BData{Buffer: ch.Nonce},
		InScheme:       tpm2.TPMTSigScheme{Scheme: tpm2.TPMAlgNull},
	}.Execute(t)
	if err != nil {
		return nil, fmt.Errorf("Certify(Device Key by AK): %w", err)
	}

	// Quote
	nonce := ch.Nonce
	if tpmQuoteTamper("nonce") {
		nonce = sha256.New().Sum(nil)
	}
	sel := tpm2.TPMLPCRSelection{PCRSelections: []tpm2.TPMSPCRSelection{{Hash: tpm2.TPMAlgSHA256, PCRSelect: pcrBitmap(ch.PCRs)}}}
	quote, err := tpm2.Quote{
		SignHandle:     akAuth,
		QualifyingData: tpm2.TPM2BData{Buffer: nonce},
		InScheme:       tpm2.TPMTSigScheme{Scheme: tpm2.TPMAlgNull},
		PCRSelect:      sel,
	}.Execute(t)
	if err != nil {
		return nil, fmt.Errorf("Quote: %w", err)
	}
	var values [][]byte
	for _, p := range ch.PCRs {
		r, err := tpm2.PCRRead{PCRSelectionIn: tpm2.TPMLPCRSelection{PCRSelections: []tpm2.TPMSPCRSelection{
			{Hash: tpm2.TPMAlgSHA256, PCRSelect: pcrBitmap([]uint{p})}}}}.Execute(t)
		if err != nil || len(r.PCRValues.Digests) != 1 {
			return nil, fmt.Errorf("PCRRead %d: %v", p, err)
		}
		values = append(values, r.PCRValues.Digests[0].Buffer)
	}
	quoteInfo := quote.Quoted.Bytes()
	if tpmQuoteTamper("quote") {
		quoteInfo = append([]byte(nil), quoteInfo...)
		quoteInfo[len(quoteInfo)-1] ^= 0x01
	}

	return &tpmQuoteEvidence{
		AKPublic:    tpm2.Marshal(akPub),
		EKCert:      ekCert,
		DAKPublic:   tpm2.Marshal(dakPub),
		CertifyInfo: certify.CertifyInfo.Bytes(),
		CertifySig:  tpm2.Marshal(certify.Signature),
		QuoteInfo:   quoteInfo,
		QuoteSig:    tpm2.Marshal(quote.Signature),
		PCRValues:   values,
	}, nil
}

func (d *tpmQuoteDevice) activate(c tpmQuoteCredential) ([]byte, error) {
	if tpmQuoteTamper("activate") {
		return []byte("not the secret"), nil
	}
	t, err := tpmQuoteTPM()
	if err != nil {
		return nil, err
	}
	ak, _, flushAK, err := loadAK(t)
	if err != nil {
		return nil, err
	}
	defer flushAK()
	ek, err := tpm2.ReadPublic{ObjectHandle: ekRSAHandle}.Execute(t)
	if err != nil {
		return nil, fmt.Errorf("EK (0x%08X): %w", ekRSAHandle, err)
	}
	// The EK's authPolicy is PolicySecret(TPM_RH_ENDORSEMENT).
	ps, closePS, err := tpm2.PolicySession(t, tpm2.TPMAlgSHA256, 16)
	if err != nil {
		return nil, err
	}
	defer func() { _ = closePS() }()
	if _, err := (tpm2.PolicySecret{
		AuthHandle:    tpm2.AuthHandle{Handle: tpm2.TPMRHEndorsement, Auth: tpm2.PasswordAuth(nil)},
		PolicySession: ps.Handle(),
	}).Execute(t); err != nil {
		return nil, fmt.Errorf("PolicySecret(endorsement): %w", err)
	}
	r, err := tpm2.ActivateCredential{
		ActivateHandle: tpm2.AuthHandle{Handle: ak.Handle, Name: ak.Name, Auth: tpm2.PasswordAuth(nil)},
		KeyHandle:      tpm2.AuthHandle{Handle: ekRSAHandle, Name: ek.Name, Auth: ps},
		CredentialBlob: tpm2.TPM2BIDObject{Buffer: c.IDObject},
		Secret:         tpm2.TPM2BEncryptedSecret{Buffer: c.EncSecret},
	}.Execute(t)
	if err != nil {
		return nil, fmt.Errorf("ActivateCredential: %w", err)
	}
	return r.CertInfo.Buffer, nil
}

func readNV(t tpm.TPM, index uint32) ([]byte, error) {
	rp, err := tpm2.NVReadPublic{NVIndex: tpm2.TPMHandle(index)}.Execute(t)
	if err != nil {
		return nil, err
	}
	pub, err := rp.NVPublic.Contents()
	if err != nil {
		return nil, err
	}
	var out []byte
	for off := uint16(0); off < pub.DataSize; {
		n := min(uint16(nvReadChunkSz), pub.DataSize-off)
		r, err := tpm2.NVRead{
			AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMHandle(index), Name: rp.NVName, Auth: tpm2.PasswordAuth(nil)},
			NVIndex:    tpm2.NamedHandle{Handle: tpm2.TPMHandle(index), Name: rp.NVName},
			Size:       n, Offset: off,
		}.Execute(t)
		if err != nil {
			return nil, err
		}
		out = append(out, r.Data.Buffer...)
		off += n
	}
	return out, nil
}

// trimDER drops padding after a DER SEQUENCE (EK certificate NV areas may be
// larger than the certificate).
func trimDER(b []byte) []byte {
	if len(b) < 4 || b[0] != 0x30 {
		return b
	}
	l, hdr := int(b[1]), 2
	if l&0x80 != 0 {
		n := l & 0x7f
		if n == 0 || n > 3 || len(b) < 2+n {
			return b
		}
		l = 0
		for _, c := range b[2 : 2+n] {
			l = l<<8 | int(c)
		}
		hdr += n
	}
	if hdr+l <= len(b) {
		return b[:hdr+l]
	}
	return b
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
