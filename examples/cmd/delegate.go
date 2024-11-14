// SPDX-FileCopyrightText: (C) 2024 Intel Corporation & Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package main

import (
	"math/big"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/rand"
	"crypto/elliptic"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"encoding/asn1"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"time"
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

// "Leaf" certs cannot sign other certs
const (
	delegateFlagLeaf = iota
	delegateFlagIntermediate
	delegateFlagRoot
)
func generateDelegate(key crypto.Signer, flags uint8, delegateKey crypto.Signer,subject string,issuer string) (*x509.Certificate, error) {
		parent := &x509.Certificate{
			SerialNumber:          big.NewInt(2),
			Subject:               pkix.Name{CommonName: issuer},
			NotBefore:             time.Now(),
			NotAfter:              time.Now().Add(30 * 24 * time.Hour),
			BasicConstraintsValid: true,
			KeyUsage:		x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			IsCA:			true,
			//ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			UnknownExtKeyUsage:    []asn1.ObjectIdentifier{fdo.OID_delegateOnboard,fdo.OID_delegateUpload,fdo.OID_delegateRedirect},
		}
		template := &x509.Certificate{
			SerialNumber:          big.NewInt(1),
			Subject:               pkix.Name{CommonName: subject},
			NotBefore:             time.Now(),
			NotAfter:              time.Now().Add(30 * 24 * time.Hour),
			BasicConstraintsValid: true,
			IsCA:			false,
			KeyUsage:		x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			//ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			UnknownExtKeyUsage:    []asn1.ObjectIdentifier{fdo.OID_delegateOnboard,fdo.OID_delegateUpload,fdo.OID_delegateRedirect},
		}
		if (flags & (delegateFlagIntermediate | delegateFlagRoot))!= 0 {
			template.KeyUsage |= x509.KeyUsageCertSign 
			template.IsCA = true
		}
		

		//template.KeyUsage |= x509.KeyUsageCertSign 
		//template.IsCA = true
		der, err := x509.CreateCertificate(rand.Reader, template, parent, delegateKey.Public(), key)
		if err != nil {
			return nil, err
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, err
		}
		fmt.Printf(fdo.CertToString(cert,"CERTIFICATE"))


		// Let's Verify...
		derParent, err := x509.CreateCertificate(rand.Reader, parent, parent, key.Public(), key)
		certParent, err := x509.ParseCertificate(derParent)
		err = cert.CheckSignatureFrom(certParent)
		if (err != nil) { fmt.Printf("Verify error is: %w\n",err)}

		return cert, nil
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
				flags = delegateFlagRoot
			case i == (len(args)-2):
				flags = delegateFlagLeaf
			default:
				flags = delegateFlagIntermediate
		}
		cert, err := generateDelegate(lastPriv,flags,priv,subject,issuer)
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
	var ownerKey crypto.PublicKey
	if (len(args) >=2 ) {
		keyType, err := protocol.ParseKeyType(args[1])
		if (err != nil) {
			return fmt.Errorf("Invalid owner key type: %s",args[1])
		}

		ownerPriv, _, err := state.OwnerKey(keyType)
		if (err != nil) {
			return fmt.Errorf("Owner Key of type %s does not exist",args[1])
		}
		ownerKey = ownerPriv.Public()
	}
	_, chain, err := state.DelegateKey(args[0])
	if err != nil {
		return err
	}
	fmt.Println(fdo.CertChainToString("CERTIFICATE",chain))
	_ = ownerKey
	for i,c := range chain {
		fmt.Printf("%d: Subject=%s Issuer=%s IsCA=%v KeyUsage=%v\n",i,c.Subject,c.Issuer,c.IsCA,c.KeyUsage)
		if (i!= 0) {
			err := chain[i].CheckSignatureFrom(chain[i-1])
			if (err != nil) {
				fmt.Printf("Delegate Chain Validation error - %d not signed by %d: %w\n",i,i-1,err)
			}
		}
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

