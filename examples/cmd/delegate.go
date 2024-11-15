// SPDX-FileCopyrightText: (C) 2024 Intel Corporation & Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/rand"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"encoding/hex"
	"encoding/base64"

	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/protocol"
	"github.com/fido-device-onboard/go-fdo/sqlite"
)

var delegateFlags = flag.NewFlagSet("delegate", flag.ContinueOnError)

var (
)

// Helper function - takes a hex byte string and
// turns it into a certificate by base64 encoding
// it and adding header/footer

func HexStringToCert(hexInput string) (string, error) {
    // Remove any whitespace or newlines from the input
    hexString := strings.ReplaceAll(string(hexInput), "\n", "")
    hexString = strings.ReplaceAll(hexString, " ", "")

    // Decode the hex string to bytes
    bytes, err := hex.DecodeString(hexString)
    if err != nil {
        return "",fmt.Errorf("Failed to decode hex string: %v", err)
    }

    // Encode the bytes to base64
    base64String := base64.StdEncoding.EncodeToString(bytes)

    // Split the base64 string into lines of 64 characters
    var lines []string
    for i := 0; i < len(base64String); i += 64 {
        end := i + 64
        if end > len(base64String) {
            end = len(base64String)
        }
        lines = append(lines, base64String[i:end])
    }

    // Print the certificate with headers
    certStr := "-----BEGIN CERTIFICATE-----"
    for _, line := range lines {
        certStr += line
    }
    certStr += "-----END CERTIFICATE-----"

    return certStr,err
}

func init() {
	delegateFlags.StringVar(&dbPath, "db", "", "SQLite database file path")
	delegateFlags.StringVar(&dbPass, "db-pass", "", "SQLite database encryption-at-rest passphrase")
	delegateFlags.StringVar(&printDelegateChain, "print-delegate-chain", "", "Print delegate chain of `type` and exit")
	delegateFlags.StringVar(&printDelegatePrivKey, "print-delegate-private", "", "Print delegate private key of `type` and exit")
}



func createDelegateCertificate(state *sqlite.DB,args []string) error {
	if (len(args) < 2) {
		return fmt.Errorf("Requires name and ownerKeyType")
	}
	name := args[0]

	// First one in chain is the "Owner" key in a voucher
	// Last one needs to be the one held by Onboarding Service/Server

	ownerKeyType := args[1]
	keyType, err := protocol.ParseKeyType(ownerKeyType)
	if (err != nil) {
		return fmt.Errorf("Invalid key type: %s",ownerKeyType)
	}
	lastPriv, lastPub, err := state.OwnerKey(keyType)
	if (err != nil) {
		return fmt.Errorf("Owner Key of type %s does not exist",ownerKeyType)
	}

	var chain []*x509.Certificate 
	issuer := fmt.Sprintf("%s_%s_Owner",name,ownerKeyType)
	for i,kt := range args[1:] {
		keyType, err = protocol.ParseKeyType(kt)
		if (err != nil) {
			return fmt.Errorf("Invalid key type: %s",ownerKeyType)
		}

		var priv crypto.Signer 
		switch keyType {
			case protocol.Secp256r1KeyType:
				priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			case protocol.Secp384r1KeyType:
				priv, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
			case protocol.Rsa2048RestrKeyType:
				priv, err = rsa.GenerateKey(rand.Reader, 2048)
			case protocol.RsaPssKeyType:
			case protocol.RsaPkcsKeyType:
				priv, err = rsa.GenerateKey(rand.Reader, 3072)
			default:
				return fmt.Errorf("unsupported key type: %v", keyType)
		}
		if err != nil {
			return fmt.Errorf("Failed to generate %s key: %v\n",kt,err)
		}

		_= lastPub

		var flags uint8
		subject := fmt.Sprintf("%s_%s_%d",name,kt,i)
		switch  {
			case i == 0:
				flags = fdo.DelegateFlagRoot
			case i == (len(args)-2):
				flags = fdo.DelegateFlagLeaf
			default:
				flags = fdo.DelegateFlagIntermediate
		}
		cert, err := fdo.GenerateDelegate(lastPriv,flags,priv.Public(),subject,issuer)
		fmt.Printf("%d: Subject=%s Issuer=%s IsCA=%v KeyUsage=%v\n",i,cert.Subject,cert.Issuer,cert.IsCA,cert.KeyUsage)
		if err != nil {
			return fmt.Errorf("Failed to generate Delegate: %v\n",err)
		}
		lastPriv=priv
		issuer = subject
		//chain = append([]*x509.Certificate{cert},chain...)
		chain = append(chain,cert)
	}

	// The last key would need to be "owner" key
	// used by the server, so save it's private
	if err := state.AddDelegateKey(name, lastPriv, chain); err != nil {
		return fmt.Errorf("Failed to add Delegate: %v\n",err)
	}
	return nil
}

// Print and validate chain (optinally against an Owner Key)
func doPrintDelegateChain(state *sqlite.DB,args []string) error {
	if (len(args) < 1) {
		return fmt.Errorf("No delegate chain name specified")
	}
	var ownerPub *crypto.PublicKey
	if (len(args) >=2 ) {
		keyType, err := protocol.ParseKeyType(args[1])
		if (err != nil) {
			return fmt.Errorf("Invalid owner key type: %s",args[1])
		}

		ownerPriv, _, err := state.OwnerKey(keyType)
		if (err != nil) {
			return fmt.Errorf("Owner Key of type %s does not exist",args[1])
		}
		op :=ownerPriv.Public()
		ownerPub = &op

	}
	_, chain, err := state.DelegateKey(args[0])
	if err != nil {
		return err
	}
	fmt.Println(fdo.CertChainToString("CERTIFICATE",chain))

	return fdo.VerifyDelegateChain(chain,ownerPub,nil)

	return nil
}

// Won't work with standard golang libraries
func verifyDelegateChain(chain []*x509.Certificate) error {
	root := x509.NewCertPool()
	root.AddCert(chain[0])
	intermediates := x509.NewCertPool()
	fmt.Printf("VFY w/ Root        : %s %s\n",chain[0].Subject,fdo.KeyUsageToString(chain[0].KeyUsage))
	for _,c := range chain[1:len(chain)-1] {
		intermediates.AddCert(c)
		fmt.Printf("VFY w/ Intermediate: %s %s\n",c.Subject,fdo.KeyUsageToString(chain[0].KeyUsage))
	}


	opts := x509.VerifyOptions{
		Roots: root,
		Intermediates: intermediates,

	}

	fmt.Printf("VFY w/ Leaf        : %s %s\n",chain[len(chain)-1].Subject,fdo.KeyUsageToString(chain[0].KeyUsage))
	_,err := chain[len(chain)-1].Verify(opts)
	if (err != nil) {
		return fmt.Errorf("Chain Verify returned: %v\n",err)
	}
	return nil
}

func doPrintDelegatePrivKey(state *sqlite.DB,args []string) error {
	if (len(args) < 1) {
		return fmt.Errorf("No delegate chain name specified")
	}
	var pemBlock *pem.Block
	key, _, err := state.DelegateKey(args[0])
	if err != nil {
		return err
	}


	// Private Key
	switch key.(type) {
		case *rsa.PrivateKey:
			der := x509.MarshalPKCS1PrivateKey(key.(*rsa.PrivateKey))
			pemBlock = &pem.Block{
				Type:  "PRIVATE KEY",
				Bytes: der,
			}
		case *ecdsa.PrivateKey:
			der, err := x509.MarshalECPrivateKey(key.(*ecdsa.PrivateKey))
			if err != nil {
				return err
			}
			pemBlock = &pem.Block{
				Type:  "EC PRIVATE KEY",
				Bytes: der,
			}

		default:
			err =  fmt.Errorf("Unknown Owner key type %T", key)
			return err
	}

	return pem.Encode(os.Stdout, pemBlock)
}

//nolint:gocyclo
func delegate(args []string) error { 
	if debug {
		level.Set(slog.LevelDebug)
	}

	if dbPath == "" {
		return errors.New("db flag is required")
	}

	if (len(args) < 1) {
		return errors.New("command requried")
	}

	state, err := sqlite.New(dbPath, dbPass)
	if err != nil {
		return err
	}

	switch args[0] {
		case "list" :
			fmt.Println("Listing")
		case "print":
			return doPrintDelegateChain(state,args[1:])
		case "key":
			return doPrintDelegatePrivKey(state,args[1:])
		case "create":
			return createDelegateCertificate(state,args[1:])
		default:
			return fmt.Errorf("Invalid command \"%s\"",args[0])
		
	}
	return nil
}


