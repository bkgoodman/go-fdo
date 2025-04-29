// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fsim

import (
	"context"
	"fmt"
	"io"
	"time"
    "log/slog"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/serviceinfo"
)

const defaultBKGcredTimeout = time.Hour

// BKGcred implements https://github.com/fido-alliance/fdo-sim/blob/main/fsim-repository/fdo.wget.md
// and should be registered to the "fdo.wget" module.
type BKGcred struct {
    Sent   bool
	Name   string

}


var _ serviceinfo.DeviceModule = (*BKGcred)(nil)

// Transition implements serviceinfo.DeviceModule.
func (d *BKGcred) Transition(active bool) error {
	d.reset()
	return nil
}

// Receive implements serviceinfo.DeviceModule.
func (d *BKGcred) Receive(ctx context.Context, messageName string, messageBody io.Reader, respond func(string) io.Writer, yield func()) error {
	if err := d.receive(ctx, messageName, messageBody); err != nil {
		d.reset()
		return err
	}
	return nil
}

func (d *BKGcred) receive(ctx context.Context, messageName string, messageBody io.Reader) error {
    slog.Warn(fmt.Sprintf("BKGCRED Recieve name \"%s\" body \"%v\"",messageName,messageBody))
	switch messageName {

	case "bkg":
            err := cbor.NewDecoder(messageBody).Decode(&d.Name)
            fmt.Printf("BKGcred got name \"%s\"\n",d.Name)
            if err != nil {
                    slog.Warn("BKGCRED Recieve decoder error")
                    return fmt.Errorf("BKGCred recieve Newdevoder error %s",err)
            }
            return nil


	default:
    	fmt.Printf("BKGcred device unknown message %s\n", messageName)
		return nil
	}
}


// Yield implements serviceinfo.DeviceModule.
func (d *BKGcred) Yield(ctx context.Context, respond func(message string) io.Writer, yield func()) error {
    code := 0
    fmt.Printf("bkgcred_device yelid returning code 0\n");
    if (!d.Sent) {
            d.Sent = true
	return cbor.NewEncoder(respond("d2o")).Encode("teststring")
    }
	return cbor.NewEncoder(respond("done")).Encode(code)
}

func (d *BKGcred) reset() {
	d.Name = ""
    d.Sent = false
}
