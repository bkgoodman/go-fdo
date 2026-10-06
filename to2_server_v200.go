// SPDX-FileCopyrightText: (C) 2024 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
	"context"
	"crypto"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math"
	"strings"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/cose"
	"github.com/fido-device-onboard/go-fdo/kex"
	"github.com/fido-device-onboard/go-fdo/protocol"
	"github.com/fido-device-onboard/go-fdo/serviceinfo"
)

// FDO 2.0 TO2 Server Handlers
//
// Key difference from 1.01: Device proves itself FIRST (anti-DoS measure)
// Flow: HelloDeviceProbe(80) -> HelloDeviceAck20(81) -> ProveDevice20(82) ->
//       ProveOVHdr20(83) -> GetOVNextEntry20(84) -> OVNextEntry20(85) ->
//       DeviceSvcInfoRdy20(86) -> SetupDevice20(87) -> DeviceSvcInfo20(88) ->
//       OwnerSvcInfo20(89) -> Done20(90) -> DoneAck20(91)

// helloDeviceAck20 handles TO2.HelloDeviceProbe (80) -> TO2.HelloDeviceAck20 (81)
// This is the first message in 2.0 - server acknowledges and prepares challenge
func (s *TO2Server) helloDeviceAck20(ctx context.Context, msg io.Reader) (*HelloDeviceAck20Msg, error) {
	// Parse request, keeping the received bytes: hashPrev is a hash of the
	// HelloDeviceProbe message as received.
	probeBytes, err := io.ReadAll(msg)
	if err != nil {
		return nil, fmt.Errorf("error reading TO2.HelloDeviceProbe request: %w", err)
	}
	var probe HelloDeviceProbeMsg
	if err := cbor.Unmarshal(probeBytes, &probe); err != nil {
		return nil, fmt.Errorf("error decoding TO2.HelloDeviceProbe request: %w", err)
	}
	if len(probe.HashTypes) == 0 {
		return nil, fmt.Errorf("TO2.HelloDeviceProbe offers no hash types")
	}

	// Store GUID for session
	if err := s.Session.SetGUID(ctx, probe.GUID); err != nil {
		return nil, fmt.Errorf("error associating device GUID to proof session: %w", err)
	}

	// Retrieve voucher to verify device exists
	ov, err := s.Vouchers.Voucher(ctx, probe.GUID)
	if err != nil || len(ov.Entries) == 0 {
		captureErr(ctx, protocol.ResourceNotFound, "")
		return nil, fmt.Errorf("error retrieving voucher for device %s: %w", probe.GUID.String(), err)
	}

	// Generate nonce for ProveDevice20
	var proveDeviceNonce protocol.Nonce
	if _, err := rand.Read(proveDeviceNonce[:]); err != nil {
		return nil, fmt.Errorf("error generating nonce for TO2.HelloDeviceAck20: %w", err)
	}
	if err := s.Session.SetProveDeviceNonce(ctx, proveDeviceNonce); err != nil {
		return nil, fmt.Errorf("error storing nonce: %w", err)
	}

	// hashPrev = hash[TO2.HelloDeviceProbe], using a hash type the Device offered
	probeHash, err := hashMessage(probe.HashTypes[0], probeBytes)
	if err != nil {
		return nil, err
	}

	// Build response with supported crypto options
	// For now, offer common suites - this could be made configurable
	return &HelloDeviceAck20Msg{
		CapabilityFlags:     GlobalCapabilityFlags,
		GUID:                probe.GUID,
		MaxOwnerMessageSize: 65535,
		KexSuites:           []kex.Suite{kex.ECDH384Suite, kex.ECDH256Suite},
		CipherSuites:        []kex.CipherSuiteID{kex.A256GcmCipher, kex.A128GcmCipher},
		NonceTO2ProveDVPrep: proveDeviceNonce,
		HashPrev:            probeHash,
	}, nil
}

// proveOVHdr20 handles TO2.ProveDevice20 (82) -> TO2.ProveOVHdr20 (83)
// In 2.0, device proves itself FIRST, then owner proves ownership
//
//nolint:gocyclo // Protocol implementation with device verification and key exchange
func (s *TO2Server) proveOVHdr20(ctx context.Context, msg io.Reader) (*cose.Sign1Tag[ProveOVHdr20Payload, []byte], error) {
	// Parse the EAT token from device. The payload is kept raw and verified
	// as received: an EAT is a CBOR map, and a re-encoding with a different
	// key order (e.g. from a non-deterministic encoder) would not verify.
	var proveDevice cose.Sign1Tag[cbor.RawBytes, []byte]
	if err := cbor.NewDecoder(msg).Decode(&proveDevice); err != nil {
		return nil, fmt.Errorf("error decoding TO2.ProveDevice20: %w", err)
	}
	var eat eatoken
	if err := cbor.Unmarshal([]byte(proveDevice.Payload.Val), &eat); err != nil {
		return nil, fmt.Errorf("error decoding TO2.ProveDevice20 EAT: %w", err)
	}

	// Get stored session data
	guid, err := s.Session.GUID(ctx)
	if err != nil {
		return nil, fmt.Errorf("error getting GUID from session: %w", err)
	}

	// Retrieve voucher
	ov, err := s.Vouchers.Voucher(ctx, guid)
	if err != nil {
		captureErr(ctx, protocol.ResourceNotFound, "")
		return nil, fmt.Errorf("error retrieving voucher: %w", err)
	}

	// Get device certificate from voucher to verify signature
	if ov.CertChain == nil || len(*ov.CertChain) == 0 {
		return nil, fmt.Errorf("voucher has no device certificate chain")
	}
	deviceCert := *ov.CertChain

	// Verify device signature on ProveDevice20
	devicePubKey := (*deviceCert[0]).PublicKey
	if ok, err := proveDevice.Verify(devicePubKey, nil, cose.AADProveDevice); err != nil {
		captureErr(ctx, protocol.InvalidMessageErrCode, "")
		return nil, fmt.Errorf("error verifying device signature: %w", err)
	} else if !ok {
		captureErr(ctx, protocol.InvalidMessageErrCode, "")
		return nil, fmt.Errorf("device signature verification failed")
	}

	// EAT nonce claim must be NonceTO2ProveDv, sent in HelloDeviceAck20 (anti-replay)
	storedNonce, err := s.Session.ProveDeviceNonce(ctx)
	if err != nil {
		return nil, fmt.Errorf("error getting stored nonce: %w", err)
	}
	payload, err := parseProveDevice20EAT(eat, storedNonce, guid)
	if err != nil {
		captureErr(ctx, protocol.InvalidMessageErrCode, "")
		return nil, err
	}

	// Now that device is verified, proceed with owner proof (similar to 1.01 proveOVHdr)
	// Begin key exchange with device's selected suite
	if !kex.Available(payload.KexSuiteName, payload.CipherSuiteName) {
		return nil, fmt.Errorf("unsupported key exchange/cipher suite")
	}

	expectedOwnerPubKey, err := ov.OwnerPublicKey()
	if err != nil {
		return nil, fmt.Errorf("error getting owner public key: %w", err)
	}

	// Get owner key for signing
	keyType := ov.Header.Val.ManufacturerKey.Type
	ownerKey, ownerPublicKeyProto, err := s.ownerKey(ctx, keyType, ov.Header.Val.ManufacturerKey.Encoding, ov.Header.Val.ManufacturerKey.RsaBits())
	if err != nil {
		return nil, fmt.Errorf("error getting owner key: %w", err)
	}

	// Handle delegate support
	var delegateChain *[]*cbor.X509Certificate
	if s.OnboardDelegate != "" {
		// Replace "=" with key type string for delegate name lookup
		delegateName := strings.ReplaceAll(s.OnboardDelegate, "=", (*ownerPublicKeyProto).Type.KeyString())
		dk, chain, err := s.DelegateKeys.DelegateKey(delegateName)
		if err != nil {
			return nil, fmt.Errorf("delegate chain %q not found: %w", delegateName, err)
		}

		// Verify delegate chain is valid for this owner
		if err := VerifyDelegateChain(chain, &expectedOwnerPubKey, nil); err != nil {
			return nil, fmt.Errorf("delegate chain verification failed: %w", err)
		}
		// Check for any fdo-ekt-permit-onboard-* permission
		if !DelegateCanOnboard(chain) {
			return nil, fmt.Errorf("delegate certificate does not have any fdo-ekt-permit-onboard-* permission")
		}

		certs := make([]*cbor.X509Certificate, len(chain))
		for i, cert := range chain {
			certs[i] = (*cbor.X509Certificate)(cert)
		}
		delegateChain = &certs

		// Use delegate key for signing instead of owner key
		ownerKey = dk
	} else {
		// Verify owner key matches voucher
		if !ownerKey.Public().(interface{ Equal(crypto.PublicKey) bool }).Equal(expectedOwnerPubKey) {
			return nil, fmt.Errorf("owner key does not match voucher")
		}
	}

	// Initialize key exchange session
	sess := payload.KexSuiteName.New(payload.XAKeyExchange, payload.CipherSuiteName)
	xB, err := sess.Parameter(rand.Reader, nil)
	if err != nil {
		return nil, fmt.Errorf("error generating key exchange parameter: %w", err)
	}
	if err := s.Session.SetXSession(ctx, payload.KexSuiteName, sess); err != nil {
		clear(xB)
		return nil, fmt.Errorf("error storing key exchange session: %w", err)
	}

	// Build ProveOVHdr20 response
	if len(ov.Entries) > math.MaxUint8 {
		return nil, fmt.Errorf("voucher has %d entries, exceeds uint8 max of 255", len(ov.Entries))
	}
	numEntries := uint8(len(ov.Entries)) //#nosec G115 -- bounds checked above

	proveOVHdrPayload := ProveOVHdr20Payload{
		OVHeader:            ov.Header,
		NumOVEntries:        numEntries,
		HMac:                ov.Hmac,
		NonceTO2ProveOV:     payload.NonceTO2ProveOVPrep,
		XBKeyExchange:       xB,
		MaxOwnerMessageSize: 65535,
		OwnerPubKey:         *ownerPublicKeyProto,
		DelegateChain:       delegateChain,
	}

	// Sign with owner (or delegate) key; unprotected headers are empty in 2.0
	s1 := &cose.Sign1Tag[ProveOVHdr20Payload, []byte]{
		Sign1: cose.Sign1[ProveOVHdr20Payload, []byte]{
			Payload: cbor.NewByteWrap(proveOVHdrPayload),
		},
	}
	opts, err := signOptsFor(ownerKey, false)
	if err != nil {
		return nil, fmt.Errorf("error determining signing options for ProveOVHdr20: %w", err)
	}
	if err := s1.Sign(ownerKey, nil, cose.AADProveOVHdr, opts); err != nil {
		return nil, fmt.Errorf("error signing ProveOVHdr20: %w", err)
	}

	return s1, nil
}

// ovNextEntry20 handles TO2.GetOVNextEntry20 (84) -> TO2.OVNextEntry20 (85)
// This is essentially the same as 1.01 - reuse the logic
func (s *TO2Server) ovNextEntry20(ctx context.Context, msg io.Reader) (*OVNextEntry20Msg, error) {
	var req GetOVNextEntry20Msg
	if err := cbor.NewDecoder(msg).Decode(&req); err != nil {
		return nil, fmt.Errorf("error decoding TO2.GetOVNextEntry20: %w", err)
	}

	guid, err := s.Session.GUID(ctx)
	if err != nil {
		return nil, fmt.Errorf("error getting GUID from session: %w", err)
	}

	ov, err := s.Vouchers.Voucher(ctx, guid)
	if err != nil {
		return nil, fmt.Errorf("error retrieving voucher: %w", err)
	}

	if int(req.OVEntryNum) >= len(ov.Entries) {
		return nil, fmt.Errorf("requested entry %d out of range", req.OVEntryNum)
	}

	entryBytes, err := cbor.Marshal(ov.Entries[req.OVEntryNum])
	if err != nil {
		return nil, fmt.Errorf("error encoding voucher entry: %w", err)
	}

	return &OVNextEntry20Msg{
		OVEntryNum: req.OVEntryNum,
		OVEntry:    entryBytes,
	}, nil
}

// setupDevice20 handles TO2.DeviceSvcInfoRdy20 (86) -> TO2.SetupDevice20 (87)
// Similar to 1.01 but message structures differ slightly
//
//nolint:gocyclo // Protocol implementation with credential handling
func (s *TO2Server) setupDevice20(ctx context.Context, msg io.Reader) (*cose.Sign1Tag[SetupDevice20Payload, []byte], error) {
	var req DeviceSvcInfoRdy20Msg
	if err := cbor.NewDecoder(msg).Decode(&req); err != nil {
		return nil, fmt.Errorf("error decoding TO2.DeviceSvcInfoRdy20: %w", err)
	}
	// req.ReplacementHMac is not used (FDO 2.0 Errata 1) and is ignored.

	// Store the Device's NonceTO2SetupDV, returned in SetupDevice20 and DoneAck20
	if err := s.Session.SetSetupDeviceNonce(ctx, req.NonceTO2SetupDVPrep); err != nil {
		return nil, fmt.Errorf("error storing setup device nonce: %w", err)
	}

	// Store MTU for service info exchange (same as 1.01)
	mtu := serviceinfo.DefaultMTU
	if req.MaxOwnerServiceInfoSz != nil {
		mtu = int(*req.MaxOwnerServiceInfoSz)
	}
	// Safe conversion to uint16 with bounds checking
	var mtu16 uint16
	if mtu >= 0 && mtu <= 65535 {
		mtu16 = uint16(mtu)
	} else {
		mtu16 = uint16(serviceinfo.DefaultMTU)
	}
	if err := s.Session.SetMTU(ctx, mtu16); err != nil {
		return nil, fmt.Errorf("error storing max service info size to send to device: %w", err)
	}

	guid, err := s.Session.GUID(ctx)
	if err != nil {
		return nil, fmt.Errorf("error getting GUID from session: %w", err)
	}

	ov, err := s.Vouchers.Voucher(ctx, guid)
	if err != nil {
		return nil, fmt.Errorf("error retrieving voucher: %w", err)
	}

	// Determine disposition based on server policy. Credential reuse is the
	// default; otherwise the Resale disposition provides new credentials.
	reuseCredential := true
	if s.ReuseCredential != nil {
		reuseCredential, err = s.ReuseCredential(ctx, *ov)
		if err != nil {
			return nil, fmt.Errorf("error checking credential reuse: %w", err)
		}
	}

	// Determine max service info size
	maxSvcInfoSz := uint16(serviceinfo.DefaultMTU)
	if s.MaxDeviceServiceInfoSize != nil {
		maxSvcInfoSz, err = s.MaxDeviceServiceInfoSize(ctx, *ov)
		if err != nil {
			return nil, fmt.Errorf("error getting max service info size: %w", err)
		}
	}

	mfgKey := ov.Header.Val.ManufacturerKey
	ownerKey, ownerPublicKey, err := s.ownerKey(ctx, mfgKey.Type, mfgKey.Encoding, mfgKey.RsaBits())
	if err != nil {
		return nil, fmt.Errorf("error getting owner key: %w", err)
	}

	payload := SetupDevice20Payload{
		DispositionCode:        DispCredReuse,
		MaxDeviceServiceInfoSz: &maxSvcInfoSz,
	}
	var signer crypto.Signer
	if reuseCredential {
		// No Owner2 key: sign with the key that signed ProveOVHdr20
		// (FDO 2.0 Errata 1).
		signer, err = s.proveOVHdrSigner20(ownerKey, ownerPublicKey)
		if err != nil {
			return nil, err
		}
	} else {
		var newGUID protocol.GUID
		if _, err := rand.Read(newGUID[:]); err != nil {
			return nil, fmt.Errorf("error generating new GUID: %w", err)
		}
		if err := s.Session.SetReplacementGUID(ctx, newGUID); err != nil {
			return nil, fmt.Errorf("error storing replacement GUID: %w", err)
		}
		rvInfo := ov.Header.Val.RvInfo
		if s.RvInfo != nil {
			if rvInfo, err = s.RvInfo(ctx, *ov); err != nil {
				return nil, fmt.Errorf("error getting replacement RV info: %w", err)
			}
		}
		if err := s.Session.SetRvInfo(ctx, rvInfo); err != nil {
			return nil, fmt.Errorf("error storing replacement RV info: %w", err)
		}

		// The Owner2 key is this Owner's key; signing with it proves possession.
		payload.DispositionCode = DispResale
		payload.ReplacementCred = &ReplacementCred20{
			RvInfo:          rvInfo,
			GUID:            newGUID,
			NonceTO2SetupDv: req.NonceTO2SetupDVPrep,
			Owner2PubKey:    *ownerPublicKey,
		}
		signer = ownerKey
	}

	s1 := &cose.Sign1Tag[SetupDevice20Payload, []byte]{
		Sign1: cose.Sign1[SetupDevice20Payload, []byte]{
			Payload: cbor.NewByteWrap(payload),
		},
	}
	opts, err := signOptsFor(signer, mfgKey.Type == protocol.RsaPssKeyType)
	if err != nil {
		return nil, fmt.Errorf("error determining signing options for SetupDevice20: %w", err)
	}
	if err := s1.Sign(signer, nil, cose.AADSetupDevice, opts); err != nil {
		return nil, fmt.Errorf("error signing SetupDevice20: %w", err)
	}
	return s1, nil
}

// proveOVHdrSigner20 returns the key that signs TO2.ProveOVHdr20: the
// configured onboarding Delegate key, or else the Owner key.
func (s *TO2Server) proveOVHdrSigner20(ownerKey crypto.Signer, ownerPublicKey *protocol.PublicKey) (crypto.Signer, error) {
	if s.OnboardDelegate == "" {
		return ownerKey, nil
	}
	delegateName := strings.ReplaceAll(s.OnboardDelegate, "=", ownerPublicKey.Type.KeyString())
	dk, _, err := s.DelegateKeys.DelegateKey(delegateName)
	if err != nil {
		return nil, fmt.Errorf("delegate chain %q not found: %w", delegateName, err)
	}
	return dk, nil
}

// doneAck20 handles TO2.Done20 (90) -> TO2.DoneAck20 (91)
func (s *TO2Server) doneAck20(ctx context.Context, msg io.Reader) (*DoneAck20Msg, error) {
	var req Done20Msg
	if err := cbor.NewDecoder(msg).Decode(&req); err != nil {
		return nil, fmt.Errorf("error decoding TO2.Done20: %w", err)
	}

	// Done20 echoes NonceTO2ProveDv, sent in HelloDeviceAck20
	proveDvNonce, err := s.Session.ProveDeviceNonce(ctx)
	if err != nil {
		return nil, fmt.Errorf("error getting stored prove device nonce: %w", err)
	}
	if req.NonceTO2ProveDv != proveDvNonce {
		captureErr(ctx, protocol.InvalidMessageErrCode, "")
		return nil, fmt.Errorf("nonce mismatch in TO2.Done20")
	}

	// DoneAck20 echoes the Device's NonceTO2SetupDV from DeviceSvcInfoRdy20
	setupDvNonce, err := s.Session.SetupDeviceNonce(ctx)
	if err != nil {
		return nil, fmt.Errorf("error getting stored setup device nonce: %w", err)
	}
	ack := &DoneAck20Msg{NonceTO2SetupDv: setupDvNonce}

	// A replacement voucher is only created for the Resale disposition with a
	// non-null ReplacementHMac. A null HMAC means the Device declined resale.
	replacementGUID, err := s.Session.ReplacementGUID(ctx)
	if errors.Is(err, ErrNotFound) || req.ReplacementHMAC == nil {
		return ack, nil
	} else if err != nil {
		return nil, fmt.Errorf("error retrieving replacement GUID for device: %w", err)
	}
	replacementHmac := *req.ReplacementHMAC

	// Get current and replacement voucher values
	currentGUID, err := s.Session.GUID(ctx)
	if err != nil {
		return nil, fmt.Errorf("error retrieving associated device GUID of proof session: %w", err)
	}
	currentOV, err := s.Vouchers.Voucher(ctx, currentGUID)
	if err != nil || len(currentOV.Entries) == 0 {
		return nil, fmt.Errorf("error retrieving voucher for device %s: %w", currentGUID.String(), err)
	}
	rvInfo, err := s.Session.RvInfo(ctx)
	if err != nil {
		return nil, fmt.Errorf("error retrieving rendezvous info for device: %w", err)
	}

	// Create and store a new voucher
	mfgKey := currentOV.Header.Val.ManufacturerKey
	_, ownerPublicKey, err := s.ownerKey(ctx, mfgKey.Type, mfgKey.Encoding, mfgKey.RsaBits())
	if err != nil {
		return nil, err
	}
	ov := &Voucher{
		Version: currentOV.Version,
		Header: *cbor.NewBstr(VoucherHeader{
			Version:         currentOV.Header.Val.Version,
			GUID:            replacementGUID,
			RvInfo:          rvInfo,
			DeviceInfo:      currentOV.Header.Val.DeviceInfo,
			ManufacturerKey: *ownerPublicKey,
			CertChainHash:   currentOV.Header.Val.CertChainHash,
		}),
		Hmac:      replacementHmac,
		CertChain: currentOV.CertChain,
		Entries:   nil,
	}
	if err := s.Vouchers.ReplaceVoucher(ctx, currentGUID, ov); err != nil {
		return nil, fmt.Errorf("error replacing persisted voucher: %w", err)
	}

	return ack, nil
}
