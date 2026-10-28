// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

//go:build !tpm && !tpmsim && !tinygo

package main

import (
	"fmt"

	"github.com/fido-device-onboard/go-fdo/serviceinfo"
)

func addTPMQuoteFSIM(map[string]serviceinfo.DeviceModule) {}
func tpmPCRExtend(string) error {
	return fmt.Errorf("TPM support not compiled (build with -tags=tpm or -tags=tpmsim)")
}

func tpmClearCredentials() error {
	return fmt.Errorf("TPM support not compiled (build with -tags=tpm or -tags=tpmsim)")
}
func tpmShowCredentials() error {
	return fmt.Errorf("TPM support not compiled (build with -tags=tpm or -tags=tpmsim)")
}
func tpmExportDAK() error {
	return fmt.Errorf("TPM support not compiled (build with -tags=tpm or -tags=tpmsim)")
}
func tpmProveDAK() error {
	return fmt.Errorf("TPM support not compiled (build with -tags=tpm or -tags=tpmsim)")
}
func tpmCheckSpec() error {
	return fmt.Errorf("TPM support not compiled (build with -tags=tpm or -tags=tpmsim)")
}
