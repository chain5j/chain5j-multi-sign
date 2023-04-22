// Package kms
package kms

import (
	"crypto/ecdsa"
	"encoding/json"
	"math/big"

	"github.com/chain5j/chain5j-multi-sign/eckey"
	"github.com/chain5j/chain5j-multi-sign/paillier"
)

func NewParty1SignCtx(sk *MasterKey1, hash []byte) *Party1SignCtx {
	return &Party1SignCtx{
		privateKey: sk,
	}
}

type Party1SignCtx struct {
	privateKey *MasterKey1
	hash       []byte

	k1    *ecdsa.PrivateKey
	k1Inv *big.Int

	r2Comm    Commitments
	r2PokComm Commitments

	s1 *big.Int
}

type SignParty1FirstMsg struct {
	R1Proof *DLogProof `json:"r1proof"`
}

type SignParty1SecondMsg struct {
	S *big.Int
}

func (ctx *Party1SignCtx) SignPhase1(msg []byte) ([]byte, error) {
	var party2Msg1 SignParty2FirstMsg
	if err := json.Unmarshal(msg, &party2Msg1); err != nil {
		return nil, err
	}

	k1Int := nonceRFC6979(ctx.privateKey.Sk1.D, party2Msg1.Hash)
	k1, err := eckey.ToECDSA(k1Int.Bytes())
	if err != nil {
		return nil, err
	}
	k1Inv := fermatInverse(k1Int, defaultKeyParams.Curve.Params().N)

	proof := dlogProve(k1)

	ctx.k1 = k1
	ctx.k1Inv = k1Inv
	ctx.r2Comm = party2Msg1.R2Commit
	ctx.r2PokComm = party2Msg1.R2PokCommit
	ctx.hash = party2Msg1.Hash

	return json.Marshal(&SignParty1FirstMsg{
		R1Proof: proof,
	})
}

func (ctx *Party1SignCtx) SignPhase2(msg []byte) ([]byte, error) {
	var party2Msg2 SignParty2SecondMsg
	if err := json.Unmarshal(msg, &party2Msg2); err != nil {
		return nil, err
	}

	if !verifySignCommitments(ctx.r2Comm, ctx.r2PokComm, party2Msg2.Witness) {
		return nil, invalidCommitments
	}

	ctx.s1 = party2Msg2.S1

	s, err := ctx.sign()
	if err != nil {
		return nil, err
	}

	return json.Marshal(&SignParty1SecondMsg{
		S: s,
	})
}

func (ctx *Party1SignCtx) sign() (*big.Int, error) {
	curve := defaultKeyParams.Curve
	N := curve.Params().N

	ps2, err := paillier.Decrypt(ctx.privateKey.PSk, ctx.s1.Bytes())
	if err != nil {
		return nil, err
	}
	s := new(big.Int).SetBytes(ps2)

	s.Mul(s, ctx.k1Inv)
	s.Mod(s, N)

	if s.Cmp(secp256k1halfN) == 1 {
		s.Sub(N, s)
	}

	return s, nil
}
