// Package client
//
// @author: xwc1125
// @date: 2019/9/25
package client

import (
	"crypto/rand"
	"errors"
	"math/big"

	"github.com/NebulousLabs/hdkey/eckey"
	"github.com/btcsuite/btcd/btcec"
	"github.com/chain5j/chain5j-multi-sign/method2/common"
	paillier "github.com/roasbeef/go-go-gadget-paillier"
)

var (
	keyGenPhase1Msg = []byte("2P-ECDSA-KEYGEN-1")
	keyGenPhase2Msg = []byte("2P-ECDSA-KEYGEN-2")

	ErrInvalidOTMac    = errors.New("invalid one-time MAC")
	ErrKeyNotGenerated = errors.New("private key has not been generated")
)

// 生成Sx1
func (p *Party1) KeyGenPhase1(sid uint64) (*KeyGenMsg1, error) {

	// TODO(conner): check sid

	var x1 *eckey.SecretKey
	var err error
	if p.Sx1 != nil {
		x1 = p.Sx1
	} else {
		x1, err = common.NewPrivKey(p.Cfg.Q3)
		if err != nil {
			return nil, err
		}
	}

	// TODO(conner): append sid?
	X1PoK, err := common.NewDLogPK(keyGenPhase1Msg, x1)
	if err != nil {
		return nil, err
	}
	// X1Nonce：对应的nonce
	X1Comm, X1Nonce, err := common.Commit(X1PoK.Bytes())
	if err != nil {
		return nil, err
	}

	p.Sx1 = x1
	p.X1 = x1.PublicKey()
	p.X1PoK = X1PoK
	p.X1Nonce = X1Nonce

	return &KeyGenMsg1{
		X1PoKComm: X1Comm,
	}, nil
}

// 生成PSK
func (p *Party1) KeyGenPhase3(sid uint64, m2 *KeyGenMsg2) (*KeyGenMsg3, error) {

	err := m2.X2PoK.Verify(keyGenPhase2Msg) // 校验
	if err != nil {
		return nil, err
	}

	psk, err := paillier.GenerateKey(rand.Reader, p.Cfg.NPaillierBits) // p1:PSK
	if err != nil {
		return nil, err
	}

	ckey, ckeyNonce, err := paillier.EncryptAndNonce(&psk.PublicKey, p.Sx1[:])
	if err != nil {
		return nil, err
	}

	proof, err := common.ProvePaillierNthRoot(&psk.PublicKey, p.Cfg.NthRootSecBits)
	if err != nil {
		return nil, err
	}

	X2, err := m2.X2PoK.PK.Uncompress()
	if err != nil {
		return nil, err
	}

	x1 := new(big.Int).SetBytes(p.Sx1[:])
	rpProver, err := common.NewRangeProofProver(
		x1, ckeyNonce, p.Cfg.Q, p.Cfg.Q3, psk, m2.RPChalComm,
		p.Cfg.RangeSecBits,
	)
	if err != nil {
		return nil, err
	}

	p.X2 = X2
	p.PSK = psk
	p.CKey = new(big.Int).SetBytes(ckey)
	p.CKeyNonce = ckeyNonce
	p.RPProver = rpProver

	return &KeyGenMsg3{
		X1PoK:       p.X1PoK,
		X1PoKNonce:  p.X1Nonce,
		PProof:      proof,
		Ckey:        ckey,
		RPCtxtPairs: p.RPProver.CtxtPairs,
	}, nil
}

func (p *Party1) KeyGenPhase5(sid uint64, m4 *KeyGenMsg4) (*KeyGenMsg5, error) {

	proofPairs, err := p.RPProver.Prove(m4.RPChallenge, &m4.RPChalNonce)
	if err != nil {
		return nil, err
	}

	alphaBytes, err := paillier.Decrypt(p.PSK, m4.CPrime.Bytes())
	if err != nil {
		return nil, err
	}

	// add comment later
	alphaSk := new(big.Int).SetBytes(alphaBytes)
	alphaSk.Mod(alphaSk, p.Cfg.Q)

	alpha, err := eckey.NewSecretKeyInt(alphaSk)
	if err != nil {
		return nil, err
	}

	alphaPK := alpha.PublicKey().Compress()

	alphaComm, alphaNonce, err := common.Commit(alphaPK[:])
	if err != nil {
		return nil, err
	}

	p.Alpha = new(big.Int).SetBytes(alphaBytes)
	p.AlphaPK = alphaPK
	p.AlphaNonce = alphaNonce
	p.ABComm = m4.ABComm

	return &KeyGenMsg5{
		RPProofPairs: proofPairs,
		AlphaComm:    alphaComm,
	}, nil
}

func (p *Party1) KeyGenPhase7(sid uint64, m6 *KeyGenMsg6) (*KeyGenMsg7, error) {

	var data []byte
	data = append(data, m6.A.Bytes()...)
	data = append(data, m6.B.Bytes()...)
	err := p.ABComm.Verify(data, &m6.ABNonce)
	if err != nil {
		return nil, err
	}

	var x1Int big.Int
	x1Int.SetBytes(p.Sx1[:])

	// Compute a' = a * x1 + b.
	var alphaPrime big.Int
	alphaPrime.Mul(m6.A, &x1Int)
	alphaPrime.Add(&alphaPrime, m6.B)

	if alphaPrime.Cmp(p.Alpha) != 0 {
		return nil, ErrInvalidOTMac
	}

	// 获取PK2的公钥
	X2x, X2y := p.X2.Coords()
	// 计算总的公钥
	Qx, Qy := btcec.S256().ScalarMult(X2x, X2y, p.Sx1[:])

	p.Q, err = eckey.NewPublicKeyCoords(Qx, Qy)
	if err != nil {
		return nil, err
	}

	return &KeyGenMsg7{
		AlphaPK:    p.AlphaPK,
		AlphaNonce: p.AlphaNonce,
	}, nil
}

func (p *Party1) PrivateKey() (*Party1PrivateKey, error) {
	switch {
	case p.PSK == nil:
		return nil, ErrKeyNotGenerated
	case p.CKey == nil:
		return nil, ErrKeyNotGenerated
	case p.Sx1 == nil:
		return nil, ErrKeyNotGenerated
	case p.Q == nil:
		return nil, ErrKeyNotGenerated
	}

	Qcpk := p.Q.Compress()
	Q, err := btcec.ParsePubKey(Qcpk[:], btcec.S256())
	if err != nil {
		return nil, err
	}

	return &Party1PrivateKey{
		Cfg:       p.Cfg, // 通用
		PSK:       p.PSK, // KeyGenPhase3生成
		X1SK:      p.Sx1, // KeyGenPhase1生成
		PublicKey: Q,     // 公钥
	}, nil
}
