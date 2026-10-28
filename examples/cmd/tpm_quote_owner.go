// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"os"
	"path/filepath"

	"github.com/google/go-tpm/tpm2"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/serviceinfo"
)

// fdo.tpm-quote demo (see fdo-sim/fsim-repository/fdo.tpm-quote.md; the
// message names and encodings here are a demo, not the spec).
//
//	o -> d  challenge   {1: nonce, 2: [PCR index] (SHA-256 bank)}
//	d -> o  evidence    tpmQuoteEvidence
//	o -> d  credential  {1: idObject, 2: encSecret}  (TPM2_MakeCredential to the EK for the AK)
//	d -> o  activated   secret recovered with TPM2_ActivateCredential
//	d -> o  error       tstr
//
// The Owner accepts the evidence only if every link holds:
//
//	EK certificate -> trusted CA (stands in for the TPM vendor)
//	AK is a restricted signing key in the TPM with that EK (ActivateCredential)
//	AK certified the voucher's Device Key (TPM2_Certify, Owner nonce)
//	AK quoted the PCRs (TPM2_Quote, Owner nonce, same boot as the Certify)
const tpmQuoteModule = "fdo.tpm-quote"

type tpmQuoteChallenge struct {
	Nonce []byte `cbor:"1,keyasint"`
	PCRs  []uint `cbor:"2,keyasint"`
}

type tpmQuoteEvidence struct {
	AKPublic    []byte   `cbor:"1,keyasint"` // TPMT_PUBLIC
	EKCert      []byte   `cbor:"2,keyasint"` // DER, from TPM NV
	DAKPublic   []byte   `cbor:"3,keyasint"` // TPMT_PUBLIC of the Device Key
	CertifyInfo []byte   `cbor:"4,keyasint"` // TPMS_ATTEST (signed bytes)
	CertifySig  []byte   `cbor:"5,keyasint"` // TPMT_SIGNATURE
	QuoteInfo   []byte   `cbor:"6,keyasint"` // TPMS_ATTEST (signed bytes)
	QuoteSig    []byte   `cbor:"7,keyasint"` // TPMT_SIGNATURE
	PCRValues   [][]byte `cbor:"8,keyasint"` // in challenge order
}

type tpmQuoteCredential struct {
	IDObject  []byte `cbor:"1,keyasint"`
	EncSecret []byte `cbor:"2,keyasint"`
}

type tpmQuoteOwner struct {
	roots *x509.CertPool
	pcrs  []uint

	state  int // 0 send challenge, 1 await evidence, 2 send credential, 3 await activated, 4 done
	nonce  []byte
	secret []byte
	cred   tpmQuoteCredential
}

var _ serviceinfo.OwnerModule = (*tpmQuoteOwner)(nil)

func newTPMQuoteOwner(caFile string, pcrs []uint) (*tpmQuoteOwner, error) {
	pemBytes, err := os.ReadFile(filepath.Clean(caFile))
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	n := 0
	for block, rest := pem.Decode(pemBytes); block != nil; block, rest = pem.Decode(rest) {
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", caFile, err)
		}
		roots.AddCert(c)
		n++
	}
	if n == 0 {
		return nil, fmt.Errorf("%s: no certificates", caFile)
	}
	return &tpmQuoteOwner{roots: roots, pcrs: pcrs}, nil
}

func tqLog(format string, args ...any) { log.Printf("[fdo.tpm-quote] "+format, args...) }

// HandleInfo implements serviceinfo.OwnerModule.
func (o *tpmQuoteOwner) HandleInfo(ctx context.Context, messageName string, messageBody io.Reader) error {
	switch messageName {
	case "active":
		var active bool
		if err := cbor.NewDecoder(messageBody).Decode(&active); err != nil {
			return err
		}
		if !active {
			return fmt.Errorf("%s: device module not active", tpmQuoteModule)
		}
		return nil
	case "error":
		var msg string
		_ = cbor.NewDecoder(messageBody).Decode(&msg)
		tqLog("FAIL  device error: %s", msg)
		return fmt.Errorf("%s: device error: %s", tpmQuoteModule, msg)
	case "evidence":
		var ev tpmQuoteEvidence
		if err := cbor.NewDecoder(messageBody).Decode(&ev); err != nil {
			return fmt.Errorf("%s: decoding evidence: %w", tpmQuoteModule, err)
		}
		cred, err := o.verify(ctx, &ev)
		if err != nil {
			tqLog("FAIL  %v", err)
			return fmt.Errorf("%s: %w", tpmQuoteModule, err)
		}
		o.cred, o.state = *cred, 2
		return nil
	case "activated":
		var secret []byte
		if err := cbor.NewDecoder(messageBody).Decode(&secret); err != nil {
			return err
		}
		if !bytes.Equal(secret, o.secret) {
			tqLog("FAIL  ActivateCredential: device returned the wrong secret (AK is not in the TPM with this EK)")
			return fmt.Errorf("%s: credential activation failed", tpmQuoteModule)
		}
		tqLog("PASS  AK is in the TPM with the certified EK (ActivateCredential returned the secret)")
		tqLog("VERIFIED: PCR quote is from the genuine TPM (EK cert -> CA) that holds the voucher's Device Key")
		o.state = 4
		return nil
	default:
		return nil
	}
}

// ProduceInfo implements serviceinfo.OwnerModule.
func (o *tpmQuoteOwner) ProduceInfo(ctx context.Context, producer *serviceinfo.Producer) (blockPeer, moduleDone bool, _ error) {
	switch o.state {
	case 0:
		o.nonce = make([]byte, 32)
		if _, err := rand.Read(o.nonce); err != nil {
			return false, false, err
		}
		body, err := cbor.Marshal(tpmQuoteChallenge{Nonce: o.nonce, PCRs: o.pcrs})
		if err != nil {
			return false, false, err
		}
		if err := producer.WriteChunk("active", []byte{0xf5}); err != nil {
			return false, false, err
		}
		if err := producer.WriteChunk("challenge", body); err != nil {
			return false, false, err
		}
		tqLog("sent challenge: nonce %x, PCRs %v (sha256)", o.nonce, o.pcrs)
		o.state = 1
	case 2:
		body, err := cbor.Marshal(o.cred)
		if err != nil {
			return false, false, err
		}
		if err := producer.WriteChunk("credential", body); err != nil {
			return false, false, err
		}
		tqLog("sent MakeCredential challenge for the AK, encrypted to the EK")
		o.state = 3
	case 4:
		return false, true, nil
	}
	return false, false, nil
}

// verify checks everything except the credential activation and returns the
// MakeCredential challenge for it.
func (o *tpmQuoteOwner) verify(ctx context.Context, ev *tpmQuoteEvidence) (*tpmQuoteCredential, error) {
	ekRSA, err := o.verifyEKCert(ev.EKCert)
	if err != nil {
		return nil, err
	}
	_, akECDSA, akName, err := verifyAK(ev.AKPublic)
	if err != nil {
		return nil, err
	}
	certify, err := o.verifyCertify(ctx, ev, akECDSA)
	if err != nil {
		return nil, err
	}
	if err := o.verifyQuote(ev, akECDSA, certify); err != nil {
		return nil, err
	}

	// MakeCredential: only the TPM with this EK can recover the secret, and
	// only for a key with this AK's name.
	o.secret = make([]byte, 32)
	if _, err := rand.Read(o.secret); err != nil {
		return nil, err
	}
	ekPub := tpm2.RSAEKTemplate
	ekPub.Unique = tpm2.NewTPMUPublicID(tpm2.TPMAlgRSA, &tpm2.TPM2BPublicKeyRSA{Buffer: ekRSA.N.Bytes()})
	ekKEM, err := tpm2.ImportEncapsulationKey(&ekPub)
	if err != nil {
		return nil, fmt.Errorf("EK public key: %w", err)
	}
	idObject, encSecret, err := tpm2.CreateCredential(rand.Reader, ekKEM, akName, o.secret)
	if err != nil {
		return nil, fmt.Errorf("MakeCredential: %w", err)
	}
	return &tpmQuoteCredential{IDObject: idObject, EncSecret: encSecret}, nil
}

// verifyEKCert: EK certificate chains to a trusted TPM CA.
func (o *tpmQuoteOwner) verifyEKCert(der []byte) (*rsa.PublicKey, error) {
	ekCert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("EK certificate: %w", err)
	}
	// TPM EK certificates carry the TPM manufacturer/model/version as a
	// directoryName in a critical SAN (TCG EK Credential Profile), which
	// crypto/x509 does not mark as handled.
	var unhandled []asn1.ObjectIdentifier
	for _, oid := range ekCert.UnhandledCriticalExtensions {
		if !oid.Equal(asn1.ObjectIdentifier{2, 5, 29, 17}) {
			unhandled = append(unhandled, oid)
		}
	}
	ekCert.UnhandledCriticalExtensions = unhandled
	if _, err := ekCert.Verify(x509.VerifyOptions{Roots: o.roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		return nil, fmt.Errorf("EK certificate does not chain to the trusted TPM CA: %w", err)
	}
	ekRSA, ok := ekCert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("EK certificate: only RSA EKs are handled in this demo, got %T", ekCert.PublicKey)
	}
	tqLog("PASS  EK certificate %q chains to the trusted TPM CA (issuer %q)", ekCert.Subject.String(), ekCert.Issuer.String())
	return ekRSA, nil
}

// verifyAK: the AK is a TPM-generated restricted signing key.
func verifyAK(public []byte) (*tpm2.TPMTPublic, *ecdsa.PublicKey, []byte, error) {
	akPub, err := tpm2.Unmarshal[tpm2.TPMTPublic](public)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("AK public: %w", err)
	}
	a := akPub.ObjectAttributes
	if !a.Restricted || !a.SignEncrypt || a.Decrypt || !a.FixedTPM || !a.FixedParent || !a.SensitiveDataOrigin {
		return nil, nil, nil, fmt.Errorf("AK is not a TPM-generated restricted signing key: %+v", a)
	}
	akKey, err := tpm2.Pub(*akPub)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("AK public key: %w", err)
	}
	akECDSA, ok := akKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, nil, nil, fmt.Errorf("AK: only ECDSA AKs are handled in this demo, got %T", akKey)
	}
	akName, err := tpm2.ObjectName(akPub)
	if err != nil {
		return nil, nil, nil, err
	}
	tqLog("PASS  AK is a restricted, fixedTPM signing key (name %x)", akName.Buffer)
	return akPub, akECDSA, akName.Buffer, nil
}

// verifyCertify: the AK certified the voucher's Device Key.
func (o *tpmQuoteOwner) verifyCertify(ctx context.Context, ev *tpmQuoteEvidence, ak *ecdsa.PublicKey) (*tpm2.TPMSAttest, error) {
	dakPub, err := tpm2.Unmarshal[tpm2.TPMTPublic](ev.DAKPublic)
	if err != nil {
		return nil, fmt.Errorf("device key public: %w", err)
	}
	dakKey, err := tpm2.Pub(*dakPub)
	if err != nil {
		return nil, err
	}
	chain, ok := serviceinfo.DeviceCertificateFromContext(ctx)
	if !ok || len(chain) == 0 {
		return nil, errors.New("no device certificate in the voucher to compare the Device Key with")
	}
	if eq, ok := dakKey.(interface{ Equal(crypto.PublicKey) bool }); !ok || !eq.Equal(chain[0].PublicKey) {
		return nil, errors.New("certified key is not the voucher's Device Key (public key differs from the device certificate)")
	}
	if !dakPub.ObjectAttributes.FixedTPM {
		return nil, errors.New("device key is not fixedTPM")
	}
	dakName, err := tpm2.ObjectName(dakPub)
	if err != nil {
		return nil, err
	}
	certify, err := o.checkAttest(ev.CertifyInfo, ev.CertifySig, ak, tpm2.TPMSTAttestCertify)
	if err != nil {
		return nil, fmt.Errorf("certify: %w", err)
	}
	ci, err := certify.Attested.Certify()
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(ci.Name.Buffer, dakName.Buffer) {
		return nil, fmt.Errorf("certify: certified object %x is not the Device Key %x", ci.Name.Buffer, dakName.Buffer)
	}
	tqLog("PASS  AK certified the voucher's Device Key (TPM2_Certify, nonce matches, fixedTPM; name %x)", dakName.Buffer)
	return certify, nil
}

// verifyQuote: the AK quoted the requested PCRs, in the same boot as the
// Certify, and the reported values match the quoted digest.
func (o *tpmQuoteOwner) verifyQuote(ev *tpmQuoteEvidence, ak *ecdsa.PublicKey, certify *tpm2.TPMSAttest) error {
	quote, err := o.checkAttest(ev.QuoteInfo, ev.QuoteSig, ak, tpm2.TPMSTAttestQuote)
	if err != nil {
		return fmt.Errorf("quote: %w", err)
	}
	qi, err := quote.Attested.Quote()
	if err != nil {
		return err
	}
	if len(ev.PCRValues) != len(o.pcrs) {
		return fmt.Errorf("quote: %d PCR values for %d requested PCRs", len(ev.PCRValues), len(o.pcrs))
	}
	if sel := qi.PCRSelect.PCRSelections; len(sel) != 1 || sel[0].Hash != tpm2.TPMAlgSHA256 || !bytes.Equal(sel[0].PCRSelect, pcrBitmap(o.pcrs)) {
		return fmt.Errorf("quote: PCR selection %+v is not the requested %v", qi.PCRSelect, o.pcrs)
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
	tqLog("PASS  AK quoted PCRs %v (nonce matches, digest matches the values, same boot as the Certify)", o.pcrs)
	for i, p := range o.pcrs {
		tqLog("      PCR[%2d] sha256 %x", p, ev.PCRValues[i])
	}
	return nil
}

// checkAttest verifies a TPMS_ATTEST signed by the AK: TPM_GENERATED, type,
// Owner nonce, ECDSA signature over SHA-256 of the attest bytes.
func (o *tpmQuoteOwner) checkAttest(info, sig []byte, ak *ecdsa.PublicKey, typ tpm2.TPMISTAttest) (*tpm2.TPMSAttest, error) {
	attest, err := tpm2.Unmarshal[tpm2.TPMSAttest](info)
	if err != nil {
		return nil, fmt.Errorf("TPMS_ATTEST: %w", err)
	}
	if attest.Magic != tpm2.TPMGeneratedValue || attest.Type != typ {
		return nil, fmt.Errorf("not a TPM-generated attestation of type 0x%x", uint16(typ))
	}
	if !bytes.Equal(attest.ExtraData.Buffer, o.nonce) {
		return nil, fmt.Errorf("nonce %x is not the Owner's %x (replayed or stale)", attest.ExtraData.Buffer, o.nonce)
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

func pcrBitmap(pcrs []uint) []byte {
	bm := make([]byte, 3)
	for _, p := range pcrs {
		if p < 24 {
			bm[p/8] |= 1 << (p % 8)
		}
	}
	return bm
}
