// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package tpm

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"

	"github.com/google/go-tpm/tpm2"
)

// Attestation of the Device Key (DAK): a restricted attestation key (AK)
// certifies the DAK (TPM2_Certify, permitted by the DAK's authPolicy) and
// quotes PCRs; MakeCredential/ActivateCredential against the TPM's EK proves
// the AK is in the TPM with that EK. Used at DI (the factory checks that the
// EK it records belongs to the DAK's TPM) and in TO2 (fdo.tpm-quote).

// TCG EK Credential Profile: persistent RSA 2048 EK and its certificate.
const (
	EKRSAHandle = tpm2.TPMHandle(0x81010001)
	EKRSACertNV = 0x01C00002
)

// AttestEvidence is what the device returns for an attestation request.
type AttestEvidence struct {
	AKPublic    []byte   `cbor:"1,keyasint"` // TPMT_PUBLIC
	EKCert      []byte   `cbor:"2,keyasint"` // DER, from TPM NV
	DAKPublic   []byte   `cbor:"3,keyasint"` // TPMT_PUBLIC of the Device Key
	CertifyInfo []byte   `cbor:"4,keyasint"` // TPMS_ATTEST (signed bytes)
	CertifySig  []byte   `cbor:"5,keyasint"` // TPMT_SIGNATURE
	QuoteInfo   []byte   `cbor:"6,keyasint"` // TPMS_ATTEST (signed bytes); empty without PCRs
	QuoteSig    []byte   `cbor:"7,keyasint"` // TPMT_SIGNATURE
	PCRValues   [][]byte `cbor:"8,keyasint"` // SHA-256 bank, in request order
}

// AttestOptions are test hooks for simulating a lying device.
type AttestOptions struct {
	CertifyHandle tpm2.TPMHandle // certify this object instead of the DAK
	QuoteNonce    []byte         // quote with this nonce instead of the caller's
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

// loadAK creates the AK: a primary from a fixed template in the Endorsement
// hierarchy, so the TPM recreates the same key (same name) each time. The
// caller flushes it; nothing stays loaded between steps (swtpm keeps
// transient objects across connections and has three slots).
func loadAK(t TPM) (*tpm2.NamedHandle, *tpm2.TPMTPublic, func(), error) {
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

// ReadEKCertRSA reads the RSA 2048 EK certificate from TPM NV.
func ReadEKCertRSA(t TPM) ([]byte, error) {
	rp, err := tpm2.NVReadPublic{NVIndex: tpm2.TPMHandle(EKRSACertNV)}.Execute(t)
	if err != nil {
		return nil, fmt.Errorf("EK certificate (NV 0x%08X): %w", EKRSACertNV, err)
	}
	pub, err := rp.NVPublic.Contents()
	if err != nil {
		return nil, err
	}
	var out []byte
	for off := uint16(0); off < pub.DataSize; {
		n := min(uint16(512), pub.DataSize-off)
		r, err := tpm2.NVRead{
			AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMHandle(EKRSACertNV), Name: rp.NVName, Auth: tpm2.PasswordAuth(nil)},
			NVIndex:    tpm2.NamedHandle{Handle: tpm2.TPMHandle(EKRSACertNV), Name: rp.NVName},
			Size:       n, Offset: off,
		}.Execute(t)
		if err != nil {
			return nil, fmt.Errorf("EK certificate (NV 0x%08X): %w", EKRSACertNV, err)
		}
		out = append(out, r.Data.Buffer...)
		off += n
	}
	return trimDER(out), nil
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

// PCRBitmap is a TPMS_PCR_SELECTION bitmap for PCRs 0-23.
func PCRBitmap(pcrs []uint) []byte {
	bm := make([]byte, 3)
	for _, p := range pcrs {
		if p < 24 {
			bm[p/8] |= 1 << (p % 8)
		}
	}
	return bm
}

// AttestDeviceKey creates the AK, certifies the DAK with it and, if pcrs is
// not empty, quotes those PCRs (SHA-256 bank); nonce goes into both.
func AttestDeviceKey(t TPM, nonce []byte, pcrs []uint, opt AttestOptions) (*AttestEvidence, error) {
	ak, akPub, flushAK, err := loadAK(t)
	if err != nil {
		return nil, err
	}
	defer flushAK()
	akAuth := tpm2.AuthHandle{Handle: ak.Handle, Name: ak.Name, Auth: tpm2.PasswordAuth(nil)}

	ekCert, err := ReadEKCertRSA(t)
	if err != nil {
		return nil, err
	}

	// Certify the DAK; its authPolicy is PolicyCommandCode(TPM_CC_Certify).
	certHandle := tpm2.TPMHandle(DAKHandle)
	if opt.CertifyHandle != 0 {
		certHandle = opt.CertifyHandle
	}
	rp, err := tpm2.ReadPublic{ObjectHandle: certHandle}.Execute(t)
	if err != nil {
		return nil, fmt.Errorf("device key: %w", err)
	}
	dakPub, err := rp.OutPublic.Contents()
	if err != nil {
		return nil, err
	}
	objAuth := tpm2.PasswordAuth(nil)
	if certHandle == tpm2.TPMHandle(DAKHandle) {
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
		QualifyingData: tpm2.TPM2BData{Buffer: nonce},
		InScheme:       tpm2.TPMTSigScheme{Scheme: tpm2.TPMAlgNull},
	}.Execute(t)
	if err != nil {
		return nil, fmt.Errorf("certify (device key by AK): %w", err)
	}
	ev := &AttestEvidence{
		AKPublic:    tpm2.Marshal(akPub),
		EKCert:      ekCert,
		DAKPublic:   tpm2.Marshal(dakPub),
		CertifyInfo: certify.CertifyInfo.Bytes(),
		CertifySig:  tpm2.Marshal(certify.Signature),
	}
	if len(pcrs) == 0 {
		return ev, nil
	}

	quoteNonce := nonce
	if opt.QuoteNonce != nil {
		quoteNonce = opt.QuoteNonce
	}
	quote, err := tpm2.Quote{
		SignHandle:     akAuth,
		QualifyingData: tpm2.TPM2BData{Buffer: quoteNonce},
		InScheme:       tpm2.TPMTSigScheme{Scheme: tpm2.TPMAlgNull},
		PCRSelect:      tpm2.TPMLPCRSelection{PCRSelections: []tpm2.TPMSPCRSelection{{Hash: tpm2.TPMAlgSHA256, PCRSelect: PCRBitmap(pcrs)}}},
	}.Execute(t)
	if err != nil {
		return nil, fmt.Errorf("quote: %w", err)
	}
	for _, p := range pcrs {
		r, err := tpm2.PCRRead{PCRSelectionIn: tpm2.TPMLPCRSelection{PCRSelections: []tpm2.TPMSPCRSelection{
			{Hash: tpm2.TPMAlgSHA256, PCRSelect: PCRBitmap([]uint{p})}}}}.Execute(t)
		if err != nil || len(r.PCRValues.Digests) != 1 {
			return nil, fmt.Errorf("PCRRead %d: %v", p, err)
		}
		ev.PCRValues = append(ev.PCRValues, r.PCRValues.Digests[0].Buffer)
	}
	ev.QuoteInfo = quote.Quoted.Bytes()
	ev.QuoteSig = tpm2.Marshal(quote.Signature)
	return ev, nil
}

// ActivateAKCredential recovers the secret of a MakeCredential to the RSA
// EK for the AK; it fails unless the AK is in the TPM that holds that EK.
func ActivateAKCredential(t TPM, idObject, encSecret []byte) ([]byte, error) {
	ak, _, flushAK, err := loadAK(t)
	if err != nil {
		return nil, err
	}
	defer flushAK()
	ek, err := tpm2.ReadPublic{ObjectHandle: EKRSAHandle}.Execute(t)
	if err != nil {
		return nil, fmt.Errorf("EK (0x%08X): %w", EKRSAHandle, err)
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
		KeyHandle:      tpm2.AuthHandle{Handle: EKRSAHandle, Name: ek.Name, Auth: ps},
		CredentialBlob: tpm2.TPM2BIDObject{Buffer: idObject},
		Secret:         tpm2.TPM2BEncryptedSecret{Buffer: encSecret},
	}.Execute(t)
	if err != nil {
		return nil, fmt.Errorf("ActivateCredential: %w", err)
	}
	return r.CertInfo.Buffer, nil
}

// --- Verifier side (no TPM needed) ---

// ParseEKCert parses an EK certificate and returns its RSA public key.
// It does not check the issuer; see VerifyEKCertChain.
func ParseEKCert(der []byte) (*x509.Certificate, *rsa.PublicKey, error) {
	c, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, fmt.Errorf("EK certificate: %w", err)
	}
	k, ok := c.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, nil, fmt.Errorf("EK certificate: only RSA EKs are handled, got %T", c.PublicKey)
	}
	return c, k, nil
}

// VerifyEKCertChain checks that an EK certificate chains to roots (TPM
// vendor CAs).
func VerifyEKCertChain(c *x509.Certificate, roots *x509.CertPool) error {
	// TPM EK certificates carry the TPM manufacturer/model/version as a
	// directoryName in a critical SAN (TCG EK Credential Profile), which
	// crypto/x509 does not mark as handled.
	var unhandled []asn1.ObjectIdentifier
	for _, oid := range c.UnhandledCriticalExtensions {
		if !oid.Equal(asn1.ObjectIdentifier{2, 5, 29, 17}) {
			unhandled = append(unhandled, oid)
		}
	}
	cc := *c
	cc.UnhandledCriticalExtensions = unhandled
	_, err := cc.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	return err
}

// VerifyAK checks that the AK is a TPM-generated restricted ECDSA signing
// key and returns its public key and name.
func VerifyAK(public []byte) (*ecdsa.PublicKey, []byte, error) {
	akPub, err := tpm2.Unmarshal[tpm2.TPMTPublic](public)
	if err != nil {
		return nil, nil, fmt.Errorf("AK public: %w", err)
	}
	a := akPub.ObjectAttributes
	if !a.Restricted || !a.SignEncrypt || a.Decrypt || !a.FixedTPM || !a.FixedParent || !a.SensitiveDataOrigin {
		return nil, nil, fmt.Errorf("AK is not a TPM-generated restricted signing key: %+v", a)
	}
	k, err := tpm2.Pub(*akPub)
	if err != nil {
		return nil, nil, fmt.Errorf("AK public key: %w", err)
	}
	ec, ok := k.(*ecdsa.PublicKey)
	if !ok {
		return nil, nil, fmt.Errorf("AK: only ECDSA AKs are handled, got %T", k)
	}
	name, err := tpm2.ObjectName(akPub)
	if err != nil {
		return nil, nil, err
	}
	return ec, name.Buffer, nil
}

// VerifyCertify checks that the AK certified the Device Key whose public key
// is deviceKey (from the voucher), with nonce. It returns the attestation and
// the Device Key's TPM name.
func VerifyCertify(ev *AttestEvidence, ak *ecdsa.PublicKey, nonce []byte, deviceKey crypto.PublicKey) (*tpm2.TPMSAttest, []byte, error) {
	dakPub, err := tpm2.Unmarshal[tpm2.TPMTPublic](ev.DAKPublic)
	if err != nil {
		return nil, nil, fmt.Errorf("device key public: %w", err)
	}
	dakKey, err := tpm2.Pub(*dakPub)
	if err != nil {
		return nil, nil, err
	}
	if eq, ok := dakKey.(interface{ Equal(crypto.PublicKey) bool }); !ok || !eq.Equal(deviceKey) {
		return nil, nil, errors.New("certified key is not the voucher's Device Key (public key differs from the device certificate)")
	}
	if !dakPub.ObjectAttributes.FixedTPM {
		return nil, nil, errors.New("device key is not fixedTPM")
	}
	dakName, err := tpm2.ObjectName(dakPub)
	if err != nil {
		return nil, nil, err
	}
	certify, err := checkAttest(ev.CertifyInfo, ev.CertifySig, ak, nonce, tpm2.TPMSTAttestCertify)
	if err != nil {
		return nil, nil, fmt.Errorf("certify: %w", err)
	}
	ci, err := certify.Attested.Certify()
	if err != nil {
		return nil, nil, err
	}
	if !bytes.Equal(ci.Name.Buffer, dakName.Buffer) {
		return nil, nil, fmt.Errorf("certify: certified object %x is not the Device Key %x", ci.Name.Buffer, dakName.Buffer)
	}
	return certify, dakName.Buffer, nil
}

// VerifyQuote checks the AK's quote of pcrs (SHA-256 bank) with nonce, that
// the reported values match the quoted digest, and that it is from the same
// boot as certify.
func VerifyQuote(ev *AttestEvidence, ak *ecdsa.PublicKey, nonce []byte, pcrs []uint, certify *tpm2.TPMSAttest) error {
	quote, err := checkAttest(ev.QuoteInfo, ev.QuoteSig, ak, nonce, tpm2.TPMSTAttestQuote)
	if err != nil {
		return fmt.Errorf("quote: %w", err)
	}
	qi, err := quote.Attested.Quote()
	if err != nil {
		return err
	}
	if len(ev.PCRValues) != len(pcrs) {
		return fmt.Errorf("quote: %d PCR values for %d requested PCRs", len(ev.PCRValues), len(pcrs))
	}
	if sel := qi.PCRSelect.PCRSelections; len(sel) != 1 || sel[0].Hash != tpm2.TPMAlgSHA256 || !bytes.Equal(sel[0].PCRSelect, PCRBitmap(pcrs)) {
		return fmt.Errorf("quote: PCR selection %+v is not the requested %v", qi.PCRSelect, pcrs)
	}
	h := sha256.New()
	for _, v := range ev.PCRValues {
		h.Write(v)
	}
	if !bytes.Equal(h.Sum(nil), qi.PCRDigest.Buffer) {
		return errors.New("quote: reported PCR values do not match the quoted PCR digest")
	}
	if certify.ClockInfo.ResetCount != quote.ClockInfo.ResetCount || certify.ClockInfo.RestartCount != quote.ClockInfo.RestartCount {
		return errors.New("quote and certify are from different boots")
	}
	return nil
}

// MakeAKCredential is TPM2_MakeCredential in software: secret encrypted to
// the RSA EK for the object named akName. Returns idObject and encSecret.
func MakeAKCredential(ek *rsa.PublicKey, akName, secret []byte) ([]byte, []byte, error) {
	ekPub := tpm2.RSAEKTemplate
	ekPub.Unique = tpm2.NewTPMUPublicID(tpm2.TPMAlgRSA, &tpm2.TPM2BPublicKeyRSA{Buffer: ek.N.Bytes()})
	kem, err := tpm2.ImportEncapsulationKey(&ekPub)
	if err != nil {
		return nil, nil, fmt.Errorf("EK public key: %w", err)
	}
	return tpm2.CreateCredential(rand.Reader, kem, akName, secret)
}

// checkAttest verifies a TPMS_ATTEST signed by the AK: TPM_GENERATED, type,
// nonce, ECDSA signature over SHA-256 of the attest bytes.
func checkAttest(info, sig []byte, ak *ecdsa.PublicKey, nonce []byte, typ tpm2.TPMISTAttest) (*tpm2.TPMSAttest, error) {
	attest, err := tpm2.Unmarshal[tpm2.TPMSAttest](info)
	if err != nil {
		return nil, fmt.Errorf("TPMS_ATTEST: %w", err)
	}
	if attest.Magic != tpm2.TPMGeneratedValue || attest.Type != typ {
		return nil, fmt.Errorf("not a TPM-generated attestation of type 0x%x", uint16(typ))
	}
	if !bytes.Equal(attest.ExtraData.Buffer, nonce) {
		return nil, fmt.Errorf("nonce %x is not the verifier's %x (replayed or stale)", attest.ExtraData.Buffer, nonce)
	}
	s, err := tpm2.Unmarshal[tpm2.TPMTSignature](sig)
	if err != nil {
		return nil, fmt.Errorf("signature: %w", err)
	}
	es, err := s.Signature.ECDSA()
	if err != nil {
		return nil, fmt.Errorf("signature: %w", err)
	}
	digest := sha256.Sum256(info)
	r, ss := new(big.Int).SetBytes(es.SignatureR.Buffer), new(big.Int).SetBytes(es.SignatureS.Buffer)
	if !ecdsa.Verify(ak, digest[:], r, ss) {
		return nil, errors.New("AK signature does not verify")
	}
	return attest, nil
}

// VerifyEKBinding is the DI-time check a factory runs before recording an EK
// in the voucher: the AK certifies the DAK (deviceKey) and activates a
// credential made to the EK, so the EK is in the TPM that holds the DAK.
// Device and verifier run in the same process here (one TPM connection).
func VerifyEKBinding(t TPM, deviceKey crypto.PublicKey) (ekCert []byte, err error) {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ev, err := AttestDeviceKey(t, nonce, nil, AttestOptions{})
	if err != nil {
		return nil, err
	}
	return ev.EKCert, VerifyEKBindingEvidence(t, ev, ev.EKCert, nonce, deviceKey)
}

// VerifyEKBindingEvidence checks evidence against the EK in ekCertDER (which
// may differ from the TPM's own, to test the check) and activates.
func VerifyEKBindingEvidence(t TPM, ev *AttestEvidence, ekCertDER, nonce []byte, deviceKey crypto.PublicKey) error {
	_, ekPub, err := ParseEKCert(ekCertDER)
	if err != nil {
		return err
	}
	ak, akName, err := VerifyAK(ev.AKPublic)
	if err != nil {
		return err
	}
	if _, _, err := VerifyCertify(ev, ak, nonce, deviceKey); err != nil {
		return err
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return err
	}
	idObject, encSecret, err := MakeAKCredential(ekPub, akName, secret)
	if err != nil {
		return err
	}
	got, err := ActivateAKCredential(t, idObject, encSecret)
	if err != nil {
		return fmt.Errorf("EK is not in the TPM holding the Device Key: %w", err)
	}
	if !bytes.Equal(got, secret) {
		return errors.New("EK is not in the TPM holding the Device Key (wrong activation secret)")
	}
	return nil
}
