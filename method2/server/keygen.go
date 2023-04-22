// Package server
//
// @author: xwc1125
// @date: 2019/9/25
package server

import (
	"bytes"
	"crypto/rand"
	"errors"
	"math/big"

	"github.com/NebulousLabs/hdkey/eckey"
	"github.com/btcsuite/btcd/btcec"
	"github.com/chain5j/chain5j-multi-sign/method2/common"
)

var (
	keyGenPhase1Msg = []byte("2P-ECDSA-KEYGEN-1")
	keyGenPhase2Msg = []byte("2P-ECDSA-KEYGEN-2")

	ErrFinalKeyMismatch = errors.New("final OT key doesn't match")
	ErrKeyNotGenerated  = errors.New("private key has not been generated")
)

// 生成x2
func (p *Party2) KeyGenPhase2(sid uint64, m1 *KeyGenMsg1) (*KeyGenMsg2, error) {

	// TODO(conner): check sid

	var x2 *eckey.SecretKey
	var err error
	if p.x2 != nil {
		x2 = p.x2
	} else {
		x2, err = common.NewPrivKey(p.cfg.Q) // 产生新的私钥
		if err != nil {
			return nil, err
		}
	}

	// TODO(conner): append sid?
	X2PoK, err := common.NewDLogPK(keyGenPhase2Msg, x2)
	if err != nil {
		return nil, err
	}

	rpVerifier, err := common.NewRangeProofVerifier(
		p.cfg.Q3, p.cfg.RangeSecBits,
	)
	if err != nil {
		return nil, err
	}

	p.X1PoKComm = m1.X1PoKComm
	p.x2 = x2
	p.X2 = x2.PublicKey()
	p.X2PoK = X2PoK
	p.RPVerifier = rpVerifier

	return &KeyGenMsg2{
		X2PoK:      X2PoK,
		RPChalComm: p.RPVerifier.Comm,
	}, nil
}

// 生成PPK，CKey
func (p *Party2) KeyGenPhase4(sid uint64, m3 *KeyGenMsg3) (*KeyGenMsg4, error) {

	err := p.X1PoKComm.Verify(m3.X1PoK.Bytes(), &m3.X1PoKNonce)
	if err != nil {
		return nil, err
	}

	err = m3.X1PoK.Verify(keyGenPhase1Msg)
	if err != nil {
		return nil, err
	}

	err = m3.PProof.Verify()
	if err != nil {
		return nil, err
	}

	X1, err := m3.X1PoK.PK.Uncompress()
	if err != nil {
		return nil, err
	}

	ckey := new(big.Int).SetBytes(m3.Ckey)
	c := new(big.Int).Set(ckey)

	p.RPVerifier.ReceiveCtxt(
		c, m3.PProof.PK, m3.RPCtxtPairs,
	)

	a, err := rand.Int(rand.Reader, p.cfg.Q)
	if err != nil {
		return nil, err
	}
	b, err := rand.Int(rand.Reader, p.cfg.QSquared)
	if err != nil {
		return nil, err
	}

	// Compute c' = b * (c^a) mod N^2.
	cPrime := new(big.Int).Set(c)
	cPrime.Exp(cPrime, a, m3.PProof.PK.NSquared)

	tmp := new(big.Int)
	tmp.Exp(m3.PProof.PK.G, b, m3.PProof.PK.NSquared)

	cPrime.Mul(cPrime, tmp)
	cPrime.Mod(cPrime, m3.PProof.PK.NSquared)

	// Commit to a and b.
	var data []byte
	data = append(data, a.Bytes()...)
	data = append(data, b.Bytes()...)
	abComm, abNonce, err := common.Commit(data)
	if err != nil {
		return nil, err
	}

	p.X1 = X1
	p.PPK = m3.PProof.PK
	p.CKey = ckey

	p.CPrime = cPrime
	p.A = a
	p.B = b
	p.ABNonce = abNonce

	return &KeyGenMsg4{
		RPChallenge: p.RPVerifier.Challenge,
		RPChalNonce: p.RPVerifier.Nonce,
		CPrime:      cPrime,
		ABComm:      abComm,
	}, nil
}

func (p *Party2) KeyGenPhase6(sid uint64, m5 *KeyGenMsg5) (*KeyGenMsg6, error) {
	err := p.RPVerifier.Verify(m5.RPProofPairs)
	if err != nil {
		return nil, err
	}

	p.AlphaComm = m5.AlphaComm

	return &KeyGenMsg6{
		A:       p.A,
		B:       p.B,
		ABNonce: p.ABNonce,
	}, nil
}

func (p *Party2) KeyGenPhase8(
	sid uint64,
	m7 *KeyGenMsg7) error {

	err := p.AlphaComm.Verify(m7.AlphaPK[:], &m7.AlphaNonce)
	if err != nil {
		return err
	}

	X1x, X1y := p.X1.Coords()

	// Compute QQ = a*X1 + b*G.
	aQx, aQy := btcec.S256().ScalarMult(X1x, X1y, p.A.Bytes())
	Bx, By := btcec.S256().ScalarBaseMult(p.B.Bytes())
	QQx, QQy := btcec.S256().Add(aQx, aQy, Bx, By)

	QQ, err := eckey.NewPublicKeyCoords(QQx, QQy)
	if err != nil {
		return err
	}
	QQC := QQ.Compress()

	if !bytes.Equal(m7.AlphaPK[:], QQC[:]) {
		return ErrFinalKeyMismatch
	}

	Qx, Qy := btcec.S256().ScalarMult(X1x, X1y, p.x2[:])
	Q, err := eckey.NewPublicKeyCoords(Qx, Qy)
	if err != nil {
		return err
	}

	p.Q = Q

	return nil
}

func (p *Party2) PrivateKey() (*Party2PrivateKey, error) {
	switch {
	case p.PPK == nil:
		return nil, ErrKeyNotGenerated
	case p.CKey == nil:
		return nil, ErrKeyNotGenerated
	case p.x2 == nil:
		return nil, ErrKeyNotGenerated
	case p.Q == nil:
		return nil, ErrKeyNotGenerated
	}

	Qcpk := p.Q.Compress()
	Q, err := btcec.ParsePubKey(Qcpk[:], btcec.S256())
	if err != nil {
		return nil, err
	}

	return &Party2PrivateKey{
		Cfg:       p.cfg,  // 通用
		PPK:       p.PPK,  // 第四次生成
		CKey:      p.CKey, // 第四次生成
		X2SK:      p.x2,   // 第二次生成
		PublicKey: Q,      // 公钥
	}, nil
}
