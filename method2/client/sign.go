// Package client
//
// @author: xwc1125
// @date: 2019/9/25
package client

import (
	"errors"
	"math/big"

	"github.com/NebulousLabs/hdkey/eckey"
	"github.com/btcsuite/btcd/btcec"
	"github.com/chain5j/chain5j-multi-sign/method2/common"
	paillier "github.com/roasbeef/go-go-gadget-paillier"
)

var (
	signPhase1Msg = []byte("2P-ECDSA-SIGN-1")
	signPhase2Msg = []byte("2P-ECDSA-SIGN-2")
)

var ErrInvalidSignature = errors.New("invalid presignature created")

type Party1SignCtx struct {
	// Input
	msg []byte
	sk  *Party1PrivateKey

	// Sign phase 1
	k1         *eckey.SecretKey
	R1         *eckey.PublicKey
	R1PoK      *common.DLogPoK
	R1PoKNonce common.Nonce

	// Sign phase 3
	R2 *eckey.PublicKey
}

func (sk *Party1PrivateKey) NewSignCtx(msg []byte) *Party1SignCtx {
	return &Party1SignCtx{
		msg: msg,
		sk:  sk,
	}
}

func (c *Party1SignCtx) Zero() {
	c.k1.Zero()
}

func (p *Party1SignCtx) SignMsgPhase1(sid uint64) (*SignMsg1, error) {
	// TODO(conner): check sid

	k1, err := common.NewPrivKey(p.sk.Cfg.Q)
	if err != nil {
		return nil, err
	}

	// TODO(conner): include sid?
	R1PoK, err := common.NewDLogPK(signPhase1Msg, k1)
	if err != nil {
		return nil, err
	}

	R1Comm, R1Nonce, err := common.Commit(R1PoK.Bytes())
	if err != nil {
		return nil, err
	}

	p.k1 = k1
	p.R1 = k1.PublicKey()
	p.R1PoK = R1PoK
	p.R1PoKNonce = R1Nonce

	return &SignMsg1{
		R1PoKComm: R1Comm,
	}, nil
}

func (p *Party1SignCtx) SignMsgPhase3(sid uint64, m2 *SignMsg2) (*SignMsg3, error) {

	err := m2.R2PoK.Verify(signPhase2Msg)
	if err != nil {
		return nil, err
	}

	R2, err := m2.R2PoK.PK.Uncompress()
	if err != nil {
		return nil, err
	}

	p.R2 = R2

	return &SignMsg3{
		R1PoK:      p.R1PoK,
		R1PoKNonce: p.R1PoKNonce,
	}, nil
}

func (p *Party1SignCtx) SignMsgPhase5(sid uint64, m4 *SignMsg4) (*btcec.Signature, error) {
	s1Bytes, err := paillier.Decrypt(p.sk.PSK, m4.C3.Bytes())
	if err != nil {
		return nil, err
	}

	var s1 big.Int
	s1.SetBytes(s1Bytes)

	var k1Inv big.Int
	k1Inv.SetBytes(p.k1[:])
	k1Inv.ModInverse(&k1Inv, p.sk.Cfg.Q)

	var s2 big.Int
	s2.Mul(&k1Inv, &s1)
	s2.Mod(&s2, p.sk.Cfg.Q)

	var qMinusS big.Int
	qMinusS.Sub(p.sk.Cfg.Q, &s2)

	var s = new(big.Int)
	if s2.Cmp(&qMinusS) <= 0 {
		s.Set(&s2)
	} else {
		s.Set(&qMinusS)
	}

	R2x, R2y := p.R2.Coords()
	Rx, _ := btcec.S256().ScalarMult(R2x, R2y, p.k1[:])
	r := new(big.Int).Mod(Rx, p.sk.Cfg.Q)

	sig := &btcec.Signature{
		R: r,
		S: s,
	}

	validEcdsaSig := sig.Verify(p.msg, p.sk.PublicKey)
	if !validEcdsaSig {
		return nil, ErrInvalidSignature
	}

	return sig, nil
}
