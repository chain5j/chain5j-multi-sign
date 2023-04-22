// Package kms
package kms

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/chain5j/chain5j-multi-sign/eckey"
)

func TestKms(t *testing.T) {
	keyGenStart := time.Now()
	fmt.Printf("KEYGEN...")
	fmt.Println()

	g1 := new(Party1Generator)
	g2 := new(Party2Generator)

	p1Msg1, err := g1.KeyGenPhase1()
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("p1 msg1 : %s\n", string(p1Msg1))

	p2msg1, err := g2.KeyGenPhase1(p1Msg1)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("p2 msg1 : %s\n", string(p2msg1))

	p1msg2, err := g1.KeyGenPhase2(p2msg1)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("p1 msg2 : %s\n", string(p1msg2))

	p2msg2, err := g2.KeyGenPhase2(p1msg2)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("p2 msg2 : %s\n", string(p2msg2))

	p1msg3, err := g1.KeyGenPhase3(p2msg2)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("p1 msg3 : %s\n", string(p1msg3))

	p2msg3, err := g2.KeyGenPhase3(p1msg3)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("p2 msg3 : %s\n", string(p2msg3))

	p1msg4, err := g1.KeyGenPhase4(p2msg3)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("p1 msg4 : %s\n", string(p1msg4))

	err = g2.KeyGenPhase4(p1msg4)
	if err != nil {
		t.Fatal(err)
	}

	key1, err := g1.KeyGenMaster()
	if err != nil {
		t.Fatal(err)
	}

	key2, err := g2.KeyGenMaster()
	if err != nil {
		t.Fatal(err)
	}

	fmt.Printf("party1 public : %x\n", eckey.FromECDSAPub(&key1.Sk1.PublicKey))
	fmt.Printf("party2 public : %x\n", eckey.FromECDSAPub(&key2.Sk2.PublicKey))

	fmt.Printf("party1 final public : %x\n", eckey.FromECDSAPub(key1.Pk))
	fmt.Printf("party2 final public : %x\n", eckey.FromECDSAPub(key2.Pk))

	jsonstr1, err := json.Marshal(&key1)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("key json: %s\n", string(jsonstr1))

	var kt MasterKey1
	err = json.Unmarshal(jsonstr1, &kt)
	if err != nil {
		t.Fatal(err)
	}

	jsonstr2, err := json.Marshal(&key2)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("key json: %s\n", string(jsonstr2))

	var kt2 MasterKey2
	err = json.Unmarshal(jsonstr2, &kt2)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Printf(" KeyGen DONE: %v\n", time.Since(keyGenStart))
	fmt.Println()

	fmt.Printf("Sign msg Start...")
	fmt.Println()
	signStart := time.Now()

	hash := sha256.New()
	hash.Write([]byte("123456"))
	h := hash.Sum(nil)

	ctx1 := NewParty1SignCtx(key1, h)
	ctx2 := NewParty2SignCtx(key2, h)

	signp2msg1, err := ctx2.SignPhase1()
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("p2 sign msg1 : %s\n", string(signp2msg1))

	signp1msg1, err := ctx1.SignPhase1(signp2msg1)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("p1 sign msg1 : %s\n", string(signp1msg1))

	signp2msg2, err := ctx2.SignPhase2(signp1msg1)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("p2 sign msg2 : %s\n", string(signp2msg2))

	signp1msg2, err := ctx1.SignPhase2(signp2msg2)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("p1 sign msg2: %s\n", string(signp1msg2))

	err = ctx2.SignPhase3(signp1msg2)
	if err != nil {
		t.Fatal(err)
	}

	r, s := ctx2.GetSignature()
	fmt.Printf("signature: r: %x, s: %x\n", r.Bytes(), s.Bytes())

	if ecdsa.Verify(key1.Pk, h, r, s) {
		fmt.Println("verify success")
	} else {
		t.Fatal("verify fail")
	}

	fmt.Printf("Sign DONE: %v\n", time.Since(signStart))
	fmt.Println()
}
