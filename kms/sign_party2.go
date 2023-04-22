// Package kms
package kms

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/json"
	"math/big"

	"github.com/chain5j/chain5j-multi-sign/eckey"
	"github.com/chain5j/chain5j-multi-sign/paillier"
)

type Party2SignCtx struct {
	privateKey *MasterKey2
	hash       []byte

	k2    *ecdsa.PrivateKey
	k1    *ecdsa.PublicKey
	k2Inv *big.Int

	r *big.Int
	s *big.Int

	witness *SignRCommWitness
}

func NewParty2SignCtx(sk *MasterKey2, hash []byte) *Party2SignCtx {
	return &Party2SignCtx{
		privateKey: sk,
		hash:       hash,
	}
}

type SignParty2FirstMsg struct {
	R2Commit    Commitments `json:"r2commit"`
	R2PokCommit Commitments `json:"r2pokcomm"`
	Hash        []byte      `json:"hash"`
}

type SignParty2SecondMsg struct {
	Witness *SignRCommWitness `json:"witness"`
	S1      *big.Int          `json:"s1"`
}

func (ctx *Party2SignCtx) SignPhase1() ([]byte, error) {
	k2Int := nonceRFC6979(ctx.privateKey.Sk2.D, ctx.hash)
	k2, err := eckey.ToECDSA(k2Int.Bytes())
	if err != nil {
		return nil, err
	}
	k2Inv := fermatInverse(k2Int, defaultKeyParams.Curve.Params().N)

	r2Commit, r2PokComm, witeness, err := createRCommitments(k2)
	if err != nil {
		return nil, err
	}

	ctx.witness = witeness
	ctx.k2 = k2
	ctx.k2Inv = k2Inv

	return json.Marshal(&SignParty2FirstMsg{
		R2Commit:    r2Commit,
		R2PokCommit: r2PokComm,
		Hash:        ctx.hash,
	})
}

func (ctx *Party2SignCtx) SignPhase2(msg []byte) ([]byte, error) {
	var err error
	var party1Msg1 SignParty1FirstMsg
	if err := json.Unmarshal(msg, &party1Msg1); err != nil {
		return nil, err
	}

	if err = party1Msg1.R1Proof.Verify(); err != nil {
		return nil, err
	}

	ctx.k1, err = eckey.UnmarshalPubkey(party1Msg1.R1Proof.PublicShare)
	if err != nil {
		return nil, err
	}

	r, s1, err := ctx.sign()
	ctx.r = r

	return json.Marshal(&SignParty2SecondMsg{
		Witness: ctx.witness,
		S1:      s1,
	})
}

func (ctx *Party2SignCtx) SignPhase3(msg []byte) error {
	var party1Msg2 SignParty1SecondMsg
	if err := json.Unmarshal(msg, &party1Msg2); err != nil {
		return err
	}

	ctx.s = party1Msg2.S
	return nil
}

func (ctx *Party2SignCtx) sign() (*big.Int, *big.Int, error) {
	curve := defaultKeyParams.Curve
	N := curve.Params().N
	// msg hash
	h := hashToInt(ctx.hash, curve)
	x2 := ctx.privateKey.Sk2.D

	// compute R
	r, _ := defaultKeyParams.Curve.ScalarMult(ctx.k1.X, ctx.k1.Y, ctx.k2.D.Bytes())
	r.Mod(r, N)

	// Sample rho in q^2.
	rho, err := rand.Int(rand.Reader, defaultKeyParams.QSquared)
	if err != nil {
		return nil, nil, err
	}
	// rhoq = rho * q
	rhoq := new(big.Int).Mod(new(big.Int).Mul(rho, defaultKeyParams.Q), defaultKeyParams.QSquared)

	// Compute c1 = rho * q + [k2^(-1) * m mod q].
	c1 := new(big.Int).Mul(ctx.k2Inv, h)
	c1.Mod(c1, N)
	c1.Add(c1, rhoq)
	c1bytes, err := paillier.Encrypt(ctx.privateKey.PPK, c1.Bytes())
	if err != nil {
		return nil, nil, err
	}

	// c2 = k2^(-1) * r * x2 mod n
	c2 := new(big.Int).Mul(ctx.k2Inv, r)
	c2.Mul(c2, x2)
	c2.Mod(c2, N)
	c2bytes := paillier.Mul(ctx.privateKey.PPK, ctx.privateKey.Ckey.Bytes(), c2.Bytes())

	// c = enc(c1+ c2)
	c := paillier.AddCipher(ctx.privateKey.PPK, c1bytes, c2bytes)
	return r, new(big.Int).SetBytes(c), nil
}

func (ctx *Party2SignCtx) GetSignature() (*big.Int, *big.Int) {
	return ctx.r, ctx.s
}
