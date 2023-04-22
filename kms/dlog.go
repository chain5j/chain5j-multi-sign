// Package kms
package kms

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"math/big"

	"github.com/chain5j/chain5j-multi-sign/eckey"
)

type DLogProof struct {
	PublicShare       []byte   `json:"publicshare"`
	PkRandComm        []byte   `json:"pkrandcomm"`
	ChallengeResponse *big.Int `json:"challengeresp"`
}

func dlogProve(sk *ecdsa.PrivateKey) *DLogProof {
	keyRandComm, _ := ecdsa.GenerateKey(eckey.S256(), rand.Reader)

	pkbytes := eckey.FromECDSAPub(&sk.PublicKey)
	pkRandBytes := eckey.FromECDSAPub(&keyRandComm.PublicKey)

	h := sha256.New()
	h.Write(pkbytes)
	h.Write(pkRandBytes)
	challenge := h.Sum(nil)

	challengeMulSk := new(big.Int).Mul(new(big.Int).SetBytes(challenge), sk.D)
	challengeMulSk.Mod(challengeMulSk, sk.Curve.Params().N)

	challengeResponse := new(big.Int).Sub(keyRandComm.D, challengeMulSk)
	challengeResponse.Mod(challengeResponse, sk.Curve.Params().N)

	// 清除随机数
	keyRandComm.D.SetBytes([]byte{0})

	return &DLogProof{
		PublicShare:       pkbytes,
		PkRandComm:        pkRandBytes,
		ChallengeResponse: challengeResponse,
	}
}

func (proof *DLogProof) Verify() error {
	h := sha256.New()
	h.Write(proof.PublicShare)
	h.Write(proof.PkRandComm)
	challenge := h.Sum(nil)

	curve := eckey.S256()

	pk, err := eckey.UnmarshalPubkey(proof.PublicShare)
	if err != nil {
		return err
	}

	pkComm, err := eckey.UnmarshalPubkey(proof.PkRandComm)
	if err != nil {
		return err
	}

	pkChallenge := new(ecdsa.PublicKey)
	pkChallenge.X, pkChallenge.Y = curve.ScalarMult(pk.X, pk.Y, challenge)

	pkVerifier := new(ecdsa.PublicKey)
	pkVerifier.X, pkVerifier.Y = curve.ScalarBaseMult(proof.ChallengeResponse.Bytes())
	pkVerifier.X, pkVerifier.Y = curve.Add(pkVerifier.X, pkVerifier.Y, pkChallenge.X, pkChallenge.Y)

	if pkComm.X.Cmp(pkVerifier.X) == 0 && pkComm.Y.Cmp(pkVerifier.Y) == 0 {
		return nil
	} else {
		return invalidDlogProof
	}

	return nil
}
