// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package sqlite_test

import (
	"context"
	"crypto/x509"
	"runtime"
	"testing"

	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/fdotest"
	"github.com/fido-device-onboard/go-fdo/kex"
	"github.com/fido-device-onboard/go-fdo/serviceinfo"
)

func TestClient(t *testing.T) {
	state, cleanup := newDB(t)
	defer func() { _ = cleanup() }()

	state.AutoExtend = true
	state.PreserveReplacedVouchers = true

	dnsAddr := "owner.fidoalliance.org"

	var fsims fdotest.FSIMList
	server := &fdo.Server{
		Tokens:    state,
		DI:        state,
		TO0:       state,
		TO1:       state,
		TO2:       state,
		RVBlobs:   state,
		Vouchers:  state,
		OwnerKeys: state,
		StartFSIMs: func(context.Context, fdo.GUID, string, []*x509.Certificate, fdo.Devmod, []string) serviceinfo.OwnerModuleList {
			return &fsims
		},
	}

	transport := &fdotest.Transport{Responder: server, T: t}

	fdotest.TestClient(&fdo.Client{
		Transport: transport,
		Cred:      fdo.DeviceCredential{Version: 101},
		Devmod: fdo.Devmod{
			Os:      runtime.GOOS,
			Arch:    runtime.GOARCH,
			Version: "Debian Bookworm",
			Device:  "go-validation",
			FileSep: ";",
			Bin:     runtime.GOARCH,
		},
		KeyExchange: kex.ECDH256Suite,
		CipherSuite: kex.A128GcmCipher,
	},
		&fdo.TO0Client{
			Transport: transport,
			Addrs: []fdo.RvTO2Addr{
				{
					DNSAddress:        &dnsAddr,
					Port:              8080,
					TransportProtocol: fdo.HTTPTransport,
				},
			},
			Vouchers:  state,
			OwnerKeys: state,
		},
		func(fsim serviceinfo.OwnerModule) { fsims = append(fsims, fsim) },
		t)
}