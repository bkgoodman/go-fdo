// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/serviceinfo"
	"github.com/fido-device-onboard/go-fdo/tpm"
)

// fdo.tpm-quote demo (see fdo-sim/fsim-repository/fdo.tpm-quote.md; the
// message names and encodings here are a demo, not the spec).
//
//	o -> d  challenge   {1: nonce, 2: [PCR index] (SHA-256 bank)}
//	d -> o  evidence    tpm.AttestEvidence
//	o -> d  credential  {1: idObject, 2: encSecret}  (TPM2_MakeCredential to the EK for the AK)
//	d -> o  activated   secret recovered with TPM2_ActivateCredential
//	d -> o  error       tstr
//
// The Owner accepts the evidence only if every link holds:
//
//	EK: recorded in the voucher by the manufacturer (OVEExtraInfo entry 0,
//	    PT_TPM_EK_CERT), or an EK certificate chaining to a trusted TPM CA
//	AK is a restricted signing key in the TPM with that EK (ActivateCredential)
//	AK certified the voucher's Device Key (TPM2_Certify, Owner nonce)
//	AK quoted the PCRs (TPM2_Quote, Owner nonce, same boot as the Certify)
const tpmQuoteModule = "fdo.tpm-quote"

// PT_TPM_EK_CERT: OVEExtraInfo / DMI_OVE_EXTRA_REQUEST key for the TPM EK
// certificate (Device Manufacturing Info appnote draft).
const ptTPMEKCert = 14

type tpmQuoteChallenge struct {
	Nonce []byte `cbor:"1,keyasint"`
	PCRs  []uint `cbor:"2,keyasint"`
}

type tpmQuoteCredential struct {
	IDObject  []byte `cbor:"1,keyasint"`
	EncSecret []byte `cbor:"2,keyasint"`
}

type tpmQuoteOwner struct {
	roots     *x509.CertPool // TPM vendor root CAs; nil = voucher EK only
	interDER  []byte         // TPM vendor intermediate CAs from the CA file (concatenated DER)
	pcrs      []uint
	voucherEK []byte // PT_TPM_EK_CERT from the voucher, if any

	state  int // 0 send challenge, 1 await evidence, 2 send credential, 3 await activated, 4 done
	nonce  []byte
	secret []byte
	cred   tpmQuoteCredential
}

var _ serviceinfo.OwnerModule = (*tpmQuoteOwner)(nil)

func newTPMQuoteOwner(caFile string, pcrs []uint, voucherEK []byte) (*tpmQuoteOwner, error) {
	o := &tpmQuoteOwner{pcrs: pcrs, voucherEK: voucherEK}
	if caFile == "" {
		return o, nil
	}
	pemBytes, err := os.ReadFile(filepath.Clean(caFile))
	if err != nil {
		return nil, err
	}
	o.roots = x509.NewCertPool()
	n := 0
	for block, rest := pem.Decode(pemBytes); block != nil; block, rest = pem.Decode(rest) {
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", caFile, err)
		}
		// Self-signed certificates are trust anchors; the others are
		// intermediates (e.g. Intel ODCA issuing CAs not stored in the TPM).
		if bytes.Equal(c.RawSubject, c.RawIssuer) && c.CheckSignatureFrom(c) == nil {
			o.roots.AddCert(c)
			n++
		} else {
			o.interDER = append(o.interDER, c.Raw...)
		}
	}
	if n == 0 {
		return nil, fmt.Errorf("%s: no self-signed root certificate", caFile)
	}
	return o, nil
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
		var ev tpm.AttestEvidence
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
		tqLog("PASS  AK is in the TPM with that EK (ActivateCredential returned the secret)")
		tqLog("VERIFIED: PCR quote is from the TPM that holds the voucher's Device Key, whose EK is anchored above")
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

// ekAnchor picks the EK to trust: the manufacturer's record in the voucher
// first, else the device's EK certificate if it chains to a trusted TPM CA.
func (o *tpmQuoteOwner) ekAnchor(deviceEKCert, deviceEKChain []byte) (*rsa.PublicKey, error) {
	if o.voucherEK != nil {
		c, k, err := tpm.ParseEKCert(o.voucherEK)
		if err != nil {
			return nil, fmt.Errorf("voucher EK: %w", err)
		}
		same := bytes.Equal(o.voucherEK, deviceEKCert)
		tqLog("PASS  EK anchored by the manufacturer: PT_TPM_EK_CERT in the voucher (OVEExtraInfo), %q; device reports the same EK certificate: %v",
			c.Subject.String(), same)
		return k, nil
	}
	if o.roots == nil {
		return nil, errors.New("no EK anchor: the voucher records no EK and no TPM CA is configured")
	}
	c, k, err := tpm.ParseEKCert(deviceEKCert)
	if err != nil {
		return nil, err
	}
	if err := tpm.VerifyEKCertChain(c, append(append([]byte(nil), o.interDER...), deviceEKChain...), o.roots); err != nil {
		return nil, fmt.Errorf("EK certificate does not chain to the trusted TPM CA: %w", err)
	}
	tqLog("PASS  EK certificate %q chains to the trusted TPM CA (issuer %q; %d bytes of intermediates from the TPM's EK chain NV)",
		c.Subject.String(), c.Issuer.String(), len(deviceEKChain))
	return k, nil
}

// verify checks everything except the credential activation and returns the
// MakeCredential challenge for it.
func (o *tpmQuoteOwner) verify(ctx context.Context, ev *tpm.AttestEvidence) (*tpmQuoteCredential, error) {
	ek, err := o.ekAnchor(ev.EKCert, ev.EKChain)
	if err != nil {
		return nil, err
	}
	ak, akName, err := tpm.VerifyAK(ev.AKPublic)
	if err != nil {
		return nil, err
	}
	tqLog("PASS  AK is a restricted, fixedTPM signing key (name %x)", akName)

	chain, ok := serviceinfo.DeviceCertificateFromContext(ctx)
	if !ok || len(chain) == 0 {
		return nil, errors.New("no device certificate in the voucher to compare the Device Key with")
	}
	certify, dakName, err := tpm.VerifyCertify(ev, ak, o.nonce, chain[0].PublicKey)
	if err != nil {
		return nil, err
	}
	tqLog("PASS  AK certified the voucher's Device Key (TPM2_Certify, nonce matches, fixedTPM; name %x)", dakName)

	if err := tpm.VerifyQuote(ev, ak, o.nonce, o.pcrs, certify); err != nil {
		return nil, err
	}
	tqLog("PASS  AK quoted PCRs %v (nonce matches, digest matches the values, same boot as the Certify)", o.pcrs)
	for i, p := range o.pcrs {
		tqLog("      PCR[%2d] sha256 %x", p, ev.PCRValues[i])
	}

	o.secret = make([]byte, 32)
	if _, err := rand.Read(o.secret); err != nil {
		return nil, err
	}
	idObject, encSecret, err := tpm.MakeAKCredential(ek, akName, o.secret)
	if err != nil {
		return nil, fmt.Errorf("MakeCredential: %w", err)
	}
	return &tpmQuoteCredential{IDObject: idObject, EncSecret: encSecret}, nil
}
