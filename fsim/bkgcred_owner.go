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

// Implement owner service info module for
// https://github.com/fido-alliance/fdo-sim/blob/main/fsim-repository/fdo.wget.md

// BKGcred implements the fdo.wget owner module.
type BKGcred_owner struct {
	// Internal state
    Name string
	sent bool
	done bool
}

var _ serviceinfo.OwnerModule = (*BKGcred_owner)(nil)

// HandleInfo implements serviceinfo.OwnerModule.
func (w *BKGcred_owner) HandleInfo(ctx context.Context, messageName string, messageBody io.Reader) error {
    slog.Info(fmt.Sprintf("BKGCRED message \"%s\"",messageName))
	switch messageName {
	case "active":
		var deviceActive bool
		if err := cbor.NewDecoder(messageBody).Decode(&deviceActive); err != nil {
			return fmt.Errorf("error decoding message %s: %w", messageName, err)
		}
		if !deviceActive {
			return fmt.Errorf("device service info module is not active")
		}
		return nil

	case "error":
		var msg string
		if err := cbor.NewDecoder(messageBody).Decode(&msg); err != nil {
			return fmt.Errorf("error decoding message %s: %w", messageName, err)
		}
		return fmt.Errorf("device reported error: %s", msg)

	case "d2o":
		var n string
		if err := cbor.NewDecoder(messageBody).Decode(&n); err != nil {
			return fmt.Errorf("error decoding message %s: %w", messageName, err)
		}
        slog.Warn(fmt.Sprintf("D2O got \"%s\"",n))
		return nil

	case "done":
		var n int64
		if err := cbor.NewDecoder(messageBody).Decode(&n); err != nil {
			return fmt.Errorf("error decoding message %s: %w", messageName, err)
		}
		w.done = true
		return nil

	default:
		fmt.Printf("bkgcred unsupported message %q", messageName)
        return nil
	}
}

// ProduceInfo implements serviceinfo.OwnerModule.
func (w *BKGcred_owner) ProduceInfo(ctx context.Context, producer *serviceinfo.Producer) (blockPeer, moduleDone bool, _ error) {
	if w.sent {
        slog.Warn("BKGCRED Produce","Sent",w.sent,"done",w.done)
		return false, w.done, nil
	}

	// Marshal message bodies
	trueBody, err := cbor.Marshal(true)
	if err != nil {
		return false, false, err
	}
	if err := producer.WriteChunk("active", trueBody); err != nil {
		return false, false, err
	}
	msgBody, err := cbor.Marshal("isawesome")
	if err != nil {
		return false, false, err
	}
	if err := producer.WriteChunk("bkg", msgBody); err != nil {
		return false, false, err
	}

	w.sent = true
	return false, false, nil
}
