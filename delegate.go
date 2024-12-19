// SPDX-FileCopyrightText: (C) 2024 Intel Corporation and Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
        "fmt"
        "encoding/pem"
        "os"
        "bytes"
        "crypto/x509"
        "crypto/rsa"
        "crypto/ecdsa"
        "crypto/elliptic"
        "crypto/rand"
        "math/big"
        "time"
        "strings"
        "regexp"
        "crypto"
        "encoding/asn1"
        "encoding/hex"
        "crypto/sha256"
        "crypto/x509/pkix"
        "github.com/fido-device-onboard/go-fdo/protocol"
)


// These OIDs are contants defined under "Delegate Protocol" in the sepcification

var OID_delegateBase asn1.ObjectIdentifier = asn1.ObjectIdentifier{1,3,6,1,4,1,45724,3}

var OID_delegateOnboard asn1.ObjectIdentifier = asn1.ObjectIdentifier{1,3,6,1,4,1,45724,3,1,1}
var OID_delegateRedirect asn1.ObjectIdentifier = asn1.ObjectIdentifier{1,3,6,1,4,1,45724,3,1,2}
var OID_delegateUpload asn1.ObjectIdentifier = asn1.ObjectIdentifier{1,3,6,1,4,1,45724,3,1,3}
var OID_delegateClaim asn1.ObjectIdentifier = asn1.ObjectIdentifier{1,3,6,1,4,1,45724,3,1,4}
var OID_delegateProvision asn1.ObjectIdentifier = asn1.ObjectIdentifier{1,3,6,1,4,1,45724,3,1,5}
var OID_delegateExtend asn1.ObjectIdentifier = asn1.ObjectIdentifier{1,3,6,1,4,1,45724,3,1,6}

var OID_Identifier asn1.ObjectIdentifier = asn1.ObjectIdentifier{1,3,6,1,4,1,45724,3,2}
var OID_IdentifierConstraints asn1.ObjectIdentifier = asn1.ObjectIdentifier{1,3,6,1,4,1,45724,3,3}

var oidMap  = map[int]string {
	1: "onboard",
	2: "upload",
	3: "redirect",
	4: "claim",
	5: "provision",
	6: "identifier",
	7: "extend",
}

func DelegateOIDtoString(oid asn1.ObjectIdentifier)string {
	if (oid.Equal(OID_delegateOnboard)) { return "onboard" }
	if (oid.Equal(OID_delegateUpload)) { return "upload" }
	if (oid.Equal(OID_delegateRedirect)) { return "redirect" }
	if (oid.Equal(OID_delegateClaim)) { return "claim" }
	if (oid.Equal(OID_delegateProvision)) { return "provision" }
	if (oid.Equal(OID_Identifier)) { return "identifier" }
	if (oid.Equal(OID_IdentifierConstraints)) { return "identConstraints" }
	return fmt.Sprintf("Unknown: %s\n",oid.String())
}

func DelegateStringToOID(str string) (asn1.ObjectIdentifier, error) {
	switch {
		case str == "onboard": return OID_delegateOnboard,nil
		case str == "upload": return OID_delegateUpload,nil
		case str == "redirect": return OID_delegateRedirect,nil
		case str == "claim": return OID_delegateClaim,nil
		case str == "provision": return OID_delegateProvision,nil
		default: return OID_delegateBase, fmt.Errorf("Invalid Delegate OID string")

	}
}
func certMissingOID(c *x509.Certificate,oid asn1.ObjectIdentifier) bool {
        //for _,o := range c.UnknownExtKeyUsage {
        for _,o := range c.Extensions {
                if (o.Id.Equal(oid)) {
                        return false
                }
        }
        return true
}

func KeyUsageToString(keyUsage x509.KeyUsage) (s string) {
        s = fmt.Sprintf("0x%x: ",keyUsage)
        if (int(keyUsage) & int(x509.KeyUsageDigitalSignature)) != 0 { s+= "KeyUsageDigitalSignature " }
        if (int(keyUsage) & int(x509.KeyUsageContentCommitment)) != 0 { s+= "KeyUsageContentCommitment " }
        if (int(keyUsage) & int(x509.KeyUsageKeyEncipherment)) != 0 { s+= "KeyUsageKeyEncipherment " }
        if (int(keyUsage) & int(x509.KeyUsageDataEncipherment)) != 0 { s+= "KeyUsageDataEncipherment " }
        if (int(keyUsage) & int(x509.KeyUsageKeyAgreement)) != 0 { s+= "KeyUsageKeyAgreement " }
        if (int(keyUsage) & int(x509.KeyUsageCertSign)) != 0 { s+= "KeyUsageCertSign " }
        if (int(keyUsage) & int(x509.KeyUsageCRLSign)) != 0 { s+= "KeyUsageCRLSign " }
        if (int(keyUsage) & int(x509.KeyUsageEncipherOnly)) != 0 { s+= "KeyUsageEncipherOnly " }
        if (int(keyUsage) & int(x509.KeyUsageDecipherOnly)) != 0 { s+= "KeyUsageDecipherOnly " }
        return
}

// "Leaf" certs cannot sign other certs
const (
        DelegateFlagLeaf = iota
        DelegateFlagIntermediate
        DelegateFlagRoot
)
// Helper functions for certificates and keys

func CertToString(cert *x509.Certificate, leader string) string {
        var pemData bytes.Buffer
        pemBlock := &pem.Block{
                Type:  leader,
                Bytes: cert.Raw,
        }
        if err := pem.Encode(&pemData, pemBlock); err != nil {
                fmt.Fprintf(os.Stderr, "Failed to encode certificate: %v\n", err)
                return ""
        }

        return(pemData.String())
}
// Take raw PEM enclodes byte array and convert to a 
// human-readible certificate string
func BytesToString(b []byte, leader string) string {
        // This is just going to take raw certificate bytes and dump to base64
        // inside BEGIN/END Certificate block
        var pemData bytes.Buffer
        pemBlock := &pem.Block{
                Type:  leader, // Should be usually "CERTIFICATE"
                Bytes: b,
        }
        if err := pem.Encode(&pemData, pemBlock); err != nil {
                fmt.Fprintf(os.Stderr, "Failed to encode certificate: %v\n", err)
                return ""
        }
        return pemData.String()
}
func CertChainToString(leader string,chain []*x509.Certificate) string {
        var result=""
        for _, cert := range chain {
                result += CertToString(cert,leader)
        }

        return result
}

func PrivKeyToString(key any) string {
        var pemData bytes.Buffer
        var pemBlock *pem.Block
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
                                return ""
                        }
                        pemBlock = &pem.Block{
                                Type:  "EC PRIVATE KEY",
                                Bytes: der,
                        }

                default:
                        return ("")
        }

        err := pem.Encode(&pemData, pemBlock)
        if (err != nil) {
                return ""
        }
        return pemData.String()
}


// See if the leaf of this chain specifies that this is signing-over
// to a named owner
// Returns nil string if no named owner
func GetKeyIdentifier(key protocol.PublicKey) (*string,error) {
        if (key.Encoding != protocol.X5ChainKeyEnc) { return nil, nil }
        chain, err := key.Chain()
        if (err != nil) { return nil, fmt.Errorf("Couldn't get x5chain: %v",err) }
        return  GetIdentifier(chain)
}

func GetCertIdentifierStr(cert *x509.Certificate) (string) {
        for _,x := range cert.Extensions {
                if (x.Id.Equal(OID_Identifier)) {
                        nostring :=  string(x.Value)
                        nostring = strings.Replace(nostring," ","",-1)
                        return nostring
                }
        }
        return ""
}
// Returns nil string if no named owner
func GetIdentifier(chain []*x509.Certificate) (*string,error) {
        if (len(chain) == 0) {
                return nil,fmt.Errorf("Cannot verify empty chain")
        }

        var id string
        id = GetCertIdentifierStr(chain[0])
        return &id, nil
}

// Verify a delegate chain against an optional owner key, 
// optionall for a given function
func processDelegateChain(chain []*x509.Certificate, ownerKey *crypto.PublicKey, oid *asn1.ObjectIdentifier, output bool, namedOwner *string) error {

        oidArray := []asn1.ObjectIdentifier{}
        if (oid != nil) {
                oidArray = append(oidArray,*oid)
        }

        if (len(chain) == 0) {
                return fmt.Errorf("Empty chain")
        }

        // If requested, verify that chain was rooted by Owner Key since we will often not have a cert for the Owner Key,
        // we will have to add a self-signed owner cert at the root of the chain
        if (ownerKey != nil) {
                issuer := chain[len(chain)-1].Issuer.CommonName
                public := ownerKey
                var rootPriv crypto.Signer
                var err error
                switch (*ownerKey).(type) {
                        case *ecdsa.PublicKey:
                                rootPriv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
                        case *rsa.PublicKey:
                                rootPriv, err = rsa.GenerateKey(rand.Reader, 2048)
                        default:
                                return fmt.Errorf("Unknown key type %T",ownerKey)
                }
                if (err != nil) { return fmt.Errorf("VerifyDelegate Error making ephemeral root CA key: %v",err) }
                if (output) { fmt.Printf("Ephemeral Root Key: %s\n",KeyToString(rootPriv.Public()))}
                rootOwner, err := GenerateDelegate(rootPriv, DelegateFlagRoot , *public,issuer,issuer, oidArray,0 ,getIdentConstraints(chain[len(chain)-1]))
                if (err != nil) {
                        return fmt.Errorf("VerifyDelegate Error createing ephemerial Owner Root Cert: %v",err)
                }
                chain = append(chain,rootOwner)
        }

        permstr := ""
        var prevOwner string 
        for i,c := range chain {
                var nextStr string
                var permstrs []string
                for _, o := range c.UnknownExtKeyUsage {
                        s := DelegateOIDtoString(o)
                        permstrs =  append(permstrs,s)
                }
                permstr = strings.Join(permstrs,"|")

                if output { fmt.Printf("%d: Subject=%s Issuer=%s  Algo=%s IsCA=%v KeyUsage=%s Perms=[%s] KeyType=%s\n",i,c.Subject,c.Issuer,
                        c.SignatureAlgorithm.String(),c.IsCA,KeyUsageToString(c.KeyUsage),permstr, KeyToString(c.PublicKey)) }

                var constrs string
                if i == 0 {
                        c,err := GetIdentifier(chain)
                        if (err != nil) {
                                return fmt.Errorf("GetIdentifier: %v",err)
                        }
                        if (c != nil) {
                                constrs = *c
                        }
                } else {
                        constrs = getIdentConstraints(c)
                }
                fmt.Printf("#%d (%s) has constraints \"%s\"\n",i,c.Subject,constrs)
                if (constrs != "") {
                        if (prevOwner != "") {
                                // We walk chains backwards. This means if a prior (child) had an owner set, this entry (parent)
                                // must permit the child
                                if !IsPermittedIdentifierRule(prevOwner,constrs) {
                                        return fmt.Errorf("NamedIdentifer in entry #%d %s not allowed by prior %s\n",i,prevOwner,constrs)
                                }
                        } 
                        nextStr = constrs
                }

                if (i!= 0) && (prevOwner == "") && (nextStr != "") { 
                    return fmt.Errorf("No NamedIdentifer in entry #%d (%s) but \"%s\" was indicated\n",i,c.Subject,nextStr)
                }

                prevOwner = nextStr

                // Cheeck Signatures on each
                if (i!= len(chain)-1) {
                        err := chain[i].CheckSignatureFrom(chain[i+1])
                        if (err != nil) {
				if (output) {
					fmt.Printf("THIS CERT:\n")
					fmt.Printf(CertToString(chain[i],"CERTIFICATE"))
					fmt.Printf("...WAS NOT SIGNED BY....\n")
					fmt.Printf(CertToString(chain[i+1],"CERTIFICATE"))
				}
                                return fmt.Errorf("VerifyDelegate Chain Validation error - (#%d) %s not signed by (#%d) %s: %v\n",i,chain[i].Subject,i+1,chain[i+1].Subject,err)
                        }
                        if (chain[i].Issuer.CommonName != chain[i+1].Subject.CommonName) {
                                return fmt.Errorf("Subject %s Issued by Issuer=%s, expected %s",c.Subject,c.Issuer,chain[i+1].Issuer)
                        }
                }

                // TODO we do NOT check expiration or revocation

                if ((oid != nil) && (certMissingOID(c,*oid))) { return fmt.Errorf("VerifyDelegate error - %s has no permission %v\n",c.Subject,DelegateOIDtoString(*oid)) }
                if ((c.KeyUsage & x509.KeyUsageDigitalSignature) == 0) { return fmt.Errorf("VerifyDelegate cert %s: No Digital Signature Usage",c.Subject) }
                if (c.BasicConstraintsValid == false)  { return fmt.Errorf("VerifyDelegate cert %s: Basic Constraints not valid",c.Subject) }

                // Leaf cert does not need to be a CA, but others do
                if (i != 0) {
                        if (c.IsCA == false)  { return fmt.Errorf("VerifyDelegate cert %s: Not a CA",c.Subject) }
                        if ((c.KeyUsage & x509.KeyUsageCertSign) == 0)  { return fmt.Errorf("VerifyDelegate cert %s: No CerSign Usage",c.Subject) }
                }
        }

        // If root (last entry in chain) cert scoped for only a specific named owner, 
        // but previous cert (namedOwner) explicitly scoped a different one - fail

        var rootIdent string =""
        for _,xx := range chain[len(chain)-1].Extensions {
                if (xx.Id.Equal(OID_IdentifierConstraints)) {
                        rootIdent = string(xx.Value)
                }
        }

        if (namedOwner != nil) && (rootIdent != "") {
                if !IsPermittedIdentifierRule(rootIdent,*namedOwner) {
                        return fmt.Errorf("Chain scoped to namedIdentifer \"%s\", but root only scoped for \"%s\"",*namedOwner,rootIdent)
                } 
        }

        return nil
}


func IsPermittedIdentifierRule(child string, parent string) bool {
    parent = strings.Replace(parent, " ", "", -1)
    child = strings.Replace(child, " ", "", -1)

    childIdentifiers := strings.Split(child, ",")
    parentIdentifiers := strings.Split(parent, ",")

    for _, c := range childIdentifiers {
        permitted := false
        for _, p := range parentIdentifiers {
            regexPattern := "^" + regexp.QuoteMeta(p) + "$"
            regexPattern = strings.ReplaceAll(regexPattern, `\*`, ".*")
            matched, err := regexp.MatchString(regexPattern, c)
            if err != nil {
                fmt.Println("Error matching regex:", err)
                return false
            }
            if matched {
                permitted = true
                break
            }
        }
        if !permitted {
            return false
        }
    }
    return true
}

// Get a list of indentifiers from the cert
func getIdentConstraints(cert *x509.Certificate) string{
        for _,xx := range cert.Extensions {
                if (xx.Id.Equal(OID_IdentifierConstraints)) {
                    return strings.Replace(string(xx.Value), " ", "", -1)
                }
        }

        return ""
}

func IsPermittedIdentifier(name string, permittedNames string) bool {
    name = strings.Replace(name," ","",-1)
    names := strings.Split(strings.Replace(permittedNames," ","",-1),",")
    for _, domain := range names {
        // Escape dots and replace wildcard '*' with '.*' for regex matching
        regexPattern := "^" + regexp.QuoteMeta(domain) + "$"
        regexPattern = regexp.MustCompile(`\\\*`).ReplaceAllString(regexPattern, ".*")

        matched, err := regexp.MatchString(regexPattern, name)
        if err != nil {
            fmt.Println("Error matching regex:", err)
            return false
        }
        if matched {
            return true
        }
    }
    return false
}

func VerifyDelegateChain(chain []*x509.Certificate, ownerKey *crypto.PublicKey, oid *asn1.ObjectIdentifier, namedOwner *string) error {
	return processDelegateChain(chain, ownerKey,oid, false,namedOwner )
}

func PrintDelegateChain(chain []*x509.Certificate, ownerKey *crypto.PublicKey, oid *asn1.ObjectIdentifier) error {
	return processDelegateChain(chain, ownerKey,oid, true,nil )
}

func DelegateChainSummary(chain []*x509.Certificate) (s string) {
        for _,c := range chain {
                s += c.Subject.CommonName+"->"
        }
        return
}

// This is a helper function, but also used in the verification process
// If the cert if a CA (Root or Intermediate), "ident" is a constraintIdentifier. 
// If the cert is a leaf, "ident" is an Identifer (name)
func GenerateDelegate(key crypto.Signer, flags uint8, delegateKey crypto.PublicKey,subject string,issuer string, 
        permissions []asn1.ObjectIdentifier, sigAlg x509.SignatureAlgorithm, ident string) (*x509.Certificate, error) {
                parent := &x509.Certificate{
                        SerialNumber:          big.NewInt(2),
                        Subject:               pkix.Name{CommonName: issuer},
                        NotBefore:             time.Now(),
                        NotAfter:              time.Now().Add(30 * 24 * time.Hour),
                        BasicConstraintsValid: true,
                        KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
                        IsCA:                  true,
                        UnknownExtKeyUsage:    permissions,
                }
                template := &x509.Certificate{
                        SerialNumber:          big.NewInt(1),
                        Subject:               pkix.Name{CommonName: subject},
                        NotBefore:             time.Now(),
                        NotAfter:              time.Now().Add(30 * 24 * time.Hour),
                        BasicConstraintsValid: true,
                        IsCA:                        false,
                        KeyUsage:              x509.KeyUsageDigitalSignature,
                        //UnknownExtKeyUsage:    permissions,
                }
                if (flags & (DelegateFlagIntermediate | DelegateFlagRoot))!= 0 {
                        template.KeyUsage |= x509.KeyUsageCertSign 
                        template.IsCA = true
                        if (ident != "") {
                            template.ExtraExtensions = []pkix.Extension{
                                    pkix.Extension{
                                        Id:    OID_IdentifierConstraints,
                                        Value: []byte(ident),
                                        Critical: true,
                                    },
                            }
                        }
                } else {
                        if (ident != "") {
                            template.ExtraExtensions = []pkix.Extension{
                                    pkix.Extension{
                                        Id:    OID_Identifier,
                                        Value: []byte(ident),
                                        Critical: true,
                                    },
                            }
                        }
                }


                for _,p := range permissions {
                        template.ExtraExtensions = append(template.ExtraExtensions,pkix.Extension{
                                Id:    p,
                                Value: nil,
                                Critical: true,
                        })
                }
                
                der, err := x509.CreateCertificate(rand.Reader, template, parent, delegateKey, key)
                if err != nil {
                        return nil, fmt.Errorf("CreateCertificate returned %v",err)
                }
                cert, err := x509.ParseCertificate(der)
                if err != nil {
                        return nil, err
                }

                // Let's Verify...
                derParent, err := x509.CreateCertificate(rand.Reader, parent, parent, key.Public(), key)
                certParent, err := x509.ParseCertificate(derParent)
                err = cert.CheckSignatureFrom(certParent)
                if (err != nil) { return nil,fmt.Errorf("Verify error is: %v\n",err)}

                return cert, nil
}

func hashkey() {
    // Example ECDSA public key
    pubKey := &ecdsa.PublicKey{
        Curve: elliptic.P256(),
        X:     big.NewInt(0),
        Y:     big.NewInt(0),
    }

    // Serialize the public key to DER format
    derBytes, err := x509.MarshalPKIXPublicKey(pubKey)
    if err != nil {
        fmt.Println("Error marshaling public key:", err)
        return
    }

    // Compute the SHA-256 hash of the serialized public key
    hash := sha256.Sum256(derBytes)

    // Convert the hash to a hexadecimal string
    fingerprint := hex.EncodeToString(hash[:])

    fmt.Println("Public key fingerprint:", fingerprint)
}

func KeyToString(key crypto.PublicKey) string {
    derBytes, err := x509.MarshalPKIXPublicKey(key)
    var fingerprint string
    if (err != nil) {
            fingerprint = fmt.Sprintf("Err: %v",err)
        } else {
            hash := sha256.Sum256(derBytes)
    fingerprint = hex.EncodeToString(hash[:])
    }

    switch key.(type) {
                case *ecdsa.PublicKey:
                        ec := key.(*ecdsa.PublicKey)
                        curve := ""
                        switch ec.Curve {
                                case elliptic.P256():
                                        curve="NIST P-256 / secp256r1"
                                case elliptic.P384():
                                        curve="NIST P-384 / secp384r1"
                                case elliptic.P521():
                                        curve="NIST P-521 / secp521r1"
                                default:
                                        curve = "Unknown"

                        }
                        return fmt.Sprintf("ECDSA %s Fingerprint: %s",curve,fingerprint)
                case *rsa.PublicKey:
                        rsa := key.(*rsa.PublicKey)
                        return fmt.Sprintf("RSA%d Fingerprint: %s",rsa.Size()*8,fingerprint)
                default:
                        return fmt.Sprintf("%T Fingerprint: %s",key,fingerprint)
        }
}