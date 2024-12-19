// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo_test

import (
    "testing"
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
    "crypto/x509"
    "encoding/asn1"
    "fmt"

	"github.com/fido-device-onboard/go-fdo"
)

func TestNameMatch(t *testing.T) {
        tests := []struct {
                Name string
                Rules string
                Result bool
        } {
                {"test","test",true},
                {"test","test2",false},
                {"test","test,test1,test2",true},
                {"test3","test,test1,test2",false},
                {"DNS:example.com","DNS:  example.com",true},
                {"DNS:example.com","DNS:  Example.com",false},
                {"DNS:test.example.com","DNS:meco.com,DNS: *.example.com",true},
                {"DNS:example.com","ID:112233",false},
                {"ID:112233","DNS:*.example.com,ID:112233",true},
                {"DNS:112233","DNS:*.example.com,ID:112233",false},
                {"DNS:mydom.example.com","DNS:*.example.com,ID:112233",true},
        }

        for _,test := range tests {
                result := fdo.IsPermittedIdentifier(test.Name,test.Rules)
                //fmt.Printf("%s %s %v %v\n",test.Name,test.Rules,test.Result,result)
                if (result != test.Result) {
                        t.Errorf("Failed: %s -> %s Shoud be %v  But %v\n",test.Name,test.Rules,test.Result,result)
                }
        }
}

func TestPermittedRules(t *testing.T) {
        for _,test := range []struct {
                Child string
                Parent string
                Result bool
        } {
                {"test","test",true},
                {"test","test1,test2",false},
                {"test1","test1,test2",true},
                {"test2","test1,test2",true},
                {"test1,test2","test1",false},
                {"joe.test1","*.test1,*.test2",true},
                {"joe.test2","*.test1,*.test2",true},
                {"joe.test3","*.test1,*.test2",false},
                {"DNS:subsub.sub.dom","DNS:*.dom",true},
                {"DNS:sub.dom","DNS:*.dom",true},
                {"DNS:sub.dom","DNS:*.dom",true},
                {"DNS:subsub.sub.dom","DNS:*.sub.dom",true},
                {"DNS:*.sub.dom","DNS:*.dom",true},
                {"DNS:*.dom","DNS:*.sub.dom",false},
                {"DNS:*.sub.dom","DNS:*.dom , DNS: *.dom2",true},
                {"DNS:*.sub.dom2","DNS:*.dom , DNS: *.dom2",true},
                {"DNS:*.sub.dom2","DNS:*.dom , DNS: *.dom2",true},
                {"DNS:*.sub1.dom","DNS:*.sub1.dom , DNS: *.sub2.dom",true},
                {"DNS:*.sub2.dom","DNS:*.sub1.dom , DNS: *.sub2.dom",true},
                {"DNS:*.sub3.dom","DNS:*.sub1.dom , DNS: *.sub2.dom",false},
                {"ID:1234-1111","ID:*-1111",true},
                {"ID:1234-1112","ID:*-1111",false},
                {"ID:*-1111","ID:*-1111",true},
                {"ID:*-1112","ID:*-1111",false},
        } {
                result := fdo.IsPermittedIdentifierRule(test.Child,test.Parent)
                //fmt.Printf("%s %s %v %v\n",test.Name,test.Rules,test.Result,result)
                if (result != test.Result) {
                        t.Errorf("Failed: %s -> %s Shoud be %v  But %v\n",test.Child,test.Parent,test.Result,result)
                }
        }
}

func TestDelegateIdentChains(t *testing.T) {
        for i,test := range []struct {
                Prev  string     // Send to verifier, as if from previous chain
                Root string
                Inter string
                Leaf string
                Result bool      // true means test should pass
        } {
                {"DNS:example.com", "","","DNS:example.com",true},
                {"DNS:1.example.com", "","","DNS:*.example.com",true},
                {"", "","","DNS:*.example.com",true},
                {"", "DNS:example.com","","",false},
                {"", "DNS:cocacola.com","","DNS:pepsi.com",false},
                {"", "","DNS:cocacola.com","DNS:pepsi.com",false},
                {"", "DNS:cocacola.com","DNS:pepsi.com","",false},
                {"", "","DNS:*.dom","DNS:*.sub.dom",true},
                {"", "","DNS:*.example.com","DNS:*.onboard.example.com",true},
                {"", "","DNS:*.example22.com","DNS:*.onboard.example.com",false},
                {"test", "","DNS:*.example22.com","DNS:*.onboard.example.com",false},
                {"", "DNS:*.dom","DNS:*.sub.dom","DNS:srv.sub.dom",true},
                {"", "DNS:*.sub.dom1,DNS:*.sub.dom2","DNS:*.sub.sub.dom1","DNS:srv.sub.sub.dom1",true},
                {"", "DNS:*.sub.dom1,DNS:*.sub.dom2","DNS:*.sub.sub.dom2","DNS:srv.sub.sub.dom2",true},
                {"", "DNS:*.sub.dom1,DNS:*.sub.dom2","DNS:*.sub.sub.dom1","DNS:srv.sub.sub.dom2",false},
                {"", "DNS:*.sub.dom1,DNS:*.sub.dom2","DNS:*.sub.sub.dom1,DNS:*.sub.sub.dom2","DNS:srv.sub.sub.dom2",true},
                {"DNS:*.dom", "DNS:*.dom","DNS:*.sub.dom","DNS:srv.sub.dom",true},
                {"DNS:*.bad", "DNS:*.dom","DNS:*.sub.dom","DNS:srv.sub.dom",false},
                {"DNS:*.dom", "DNS:*.sub.dom","DNS:*.sub.sub.dom","DNS:srv.sub.sub.dom",true},
                {"DNS:*.dom1", "DNS:*.sub.dom1","DNS:*.sub.sub.dom1","DNS:srv.sub.sub.dom1",true},
        } {
                t.Run(fmt.Sprintf("No_%d/%s/%s/%s/%s",i,test.Prev,test.Root,test.Inter,test.Leaf), func (t *testing.T) {
                        perms := []asn1.ObjectIdentifier{fdo.OID_delegateOnboard}
                        rootPriv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
                        if (err != nil) { t.Errorf("Generate Root Key: %v",err) }
                        rootCert, err := fdo.GenerateDelegate(rootPriv,fdo.DelegateFlagRoot,rootPriv.Public(),"Test Root CA","Test Root CA",perms,0 ,test.Root)
                        if (err != nil) { t.Errorf("Generate Root: %v",err) }

                        interPriv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
                        if (err != nil) { t.Errorf("Generate Intermediate Key: %v",err) }
                        interCert, err := fdo.GenerateDelegate(rootPriv,fdo.DelegateFlagIntermediate,interPriv.Public(),"Test Intermediate CA","Test Root CA",perms,0 ,test.Inter)
                        if (err != nil) { t.Errorf("Generate Intermediate: %v",err) }

                        leafPriv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
                        if (err != nil) { t.Errorf("Generate Leaf Key: %v",err) }
                        leafCert, err := fdo.GenerateDelegate(interPriv,fdo.DelegateFlagLeaf,leafPriv.Public(),"Test Leaf","Test Intermediate CA",perms,0 ,test.Leaf)
                        if (err != nil) { t.Errorf("Generate Leaf: %v",err) }

                        chain := []*x509.Certificate{leafCert,interCert,rootCert}
                        pub := rootPriv.Public()
                        //fdo.PrintDelegateChain(chain, &pub, &fdo.OID_delegateOnboard)
                        var prevstr *string
                        if test.Prev != "" { prevstr = &test.Prev }
                        //err =  fdo.VerifyDelegateChain(chain, nil, &fdo.OID_delegateOnboard, prevstr)
                        err =  fdo.VerifyDelegateChain(chain, &pub, &fdo.OID_delegateOnboard, prevstr)
                        if ((err != nil) == test.Result) { t.Errorf("VerifyDelegateChain (Prev \"%s\") FAIL: %v",test.Prev,err) }
                })
        }
}

