// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fsim

import (
	"context"
	"fmt"
	"io"
	"log/slog"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/serviceinfo"
)

// BKG implements https://github.com/fido-alliance/conformance-test-tools-resources/blob/821c7114ae193148d276464a80c98d5535fa5681/docs/FDO/Pre-BKG/Step-by-step.md?plain=1#L36
// and should be registered to the "fido_alliance" module. It prints the
// dashboard token to the logger output.
type BKG struct{}

var _ serviceinfo.DeviceModule = (*BKG)(nil)

// Transition implements serviceinfo.DeviceModule.
func (d *BKG) Transition(active bool) error { 
	slog.Debug("BKG","BKGfsim","Transition")
	return nil }

// Receive implements serviceinfo.DeviceModule.
func (d *BKG) Receive(ctx context.Context, messageName string, messageBody io.Reader, respond func(string) io.Writer, yield func()) error {
	slog.Debug("BKG","BKGfsim","Receive")
	switch messageName {
	case "dev_conformance":
		var token string
		if err := cbor.NewDecoder(messageBody).Decode(token); err != nil {
			return err
		}
		slog.Info("FIDO Alliance interop dashboard", "access token", token)
		return nil

	default:
		return fmt.Errorf("unknown message %s", messageName)
	}
}

// Yield implements serviceinfo.DeviceModule.
func (d *BKG) Yield(ctx context.Context, respond func(message string) io.Writer, yield func()) error {
	slog.Debug("BKG","BKGfsim","Yield")
	return nil
}
