// Package server
//
// @author: xwc1125
// @date: 2019/9/25
package server

import (
	"crypto/rand"
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

type Party2SignCtx struct {
	// Input
	msg []byte
	sk  *Party2PrivateKey

	// Sign phase 2
	R1PoKComm common.Comm
	k2        *eckey.SecretKey
	R2        *eckey.PublicKey
	R2PoK     *common.DLogPoK

	// Sign phase 4
	R1 *eckey.PublicKey
}

func (sk *Party2PrivateKey) NewSignCtx(msg []byte) *Party2SignCtx {
	return &Party2SignCtx{
		msg: msg,
		sk:  sk,
	}
}

func (c *Party2SignCtx) Zero() {
	c.k2.Zero()
}

func (p *Party2SignCtx) SignMsgPhase2(sid uint64, m1 *SignMsg1) (*SignMsg2, error) {

	// TODO check sid

	k2, err := common.NewPrivKey(p.sk.Cfg.Q)
	if err != nil {
		return nil, err
	}

	R2PoK, err := common.NewDLogPK(signPhase2Msg, k2)
	if err != nil {
		return nil, err
	}

	p.R1PoKComm = m1.R1PoKComm
	p.k2 = k2
	p.R2 = k2.PublicKey()
	p.R2PoK = R2PoK

	return &SignMsg2{
		R2PoK: R2PoK,
	}, nil
}

func (p *Party2SignCtx) SignMsgPhase4(sid uint64, m3 *SignMsg3) (*SignMsg4, error) {

	m := new(big.Int).SetBytes(p.msg)

	// Sample rho in q^2.
	rho, err := rand.Int(rand.Reader, p.sk.Cfg.QSquared)
	if err != nil {
		return nil, err
	}

	// Compute rho * q.
	var rhoq big.Int
	rhoq.Mul(rho, p.sk.Cfg.Q)
	rhoq.Mod(&rhoq, p.sk.Cfg.QSquared)

	// Compute k2^(-1).
	var k2Inv big.Int
	k2Inv.SetBytes(p.k2[:])
	k2Inv.ModInverse(&k2Inv, p.sk.Cfg.Q)

	// Compute pt = rho * q + [k2^(-1) * m mod q].
	var pt big.Int
	pt.Mul(&k2Inv, m)
	pt.Mod(&pt, p.sk.Cfg.Q)
	pt.Add(&pt, &rhoq)

	// Encrypt the plaintext to get c1 in parallel.
	c1Chan := make(chan *big.Int)
	go func() {
		c1Bytes, err := paillier.Encrypt(p.sk.PPK, pt.Bytes())
		if err != nil {
			panic(err)
		}

		c1 := new(big.Int).SetBytes(c1Bytes)
		c1Chan <- c1
	}()

	err = p.R1PoKComm.Verify(m3.R1PoK.Bytes(), &m3.R1PoKNonce)
	if err != nil {
		return nil, err
	}

	err = m3.R1PoK.Verify(signPhase1Msg)
	if err != nil {
		return nil, err
	}

	R1, err := m3.R1PoK.PK.Uncompress()
	if err != nil {
		return nil, err
	}

	R1x, R1y := R1.Coords()
	Rx, _ := btcec.S256().ScalarMult(R1x, R1y, p.k2[:])

	r := new(big.Int).Mod(Rx, p.sk.Cfg.Q)

	var x2Int big.Int
	x2Int.SetBytes(p.sk.X2SK[:])

	// Compute v = k2^(-1) * r * x2 mod q.
	var v big.Int
	v.Mul(&k2Inv, r)
	v.Mul(&v, &x2Int)
	v.Mod(&v, p.sk.Cfg.Q)

	// Compute c2 = ckey ^ v mod N^2, multiplying the decrypted value by v.
	var c2 big.Int
	c2.Exp(p.sk.CKey, &v, p.sk.PPK.NSquared)

	// Receive ciphertext c1 from background.
	c1 := <-c1Chan

	// Finally, compute c3 = c1 * c2 mod N^2, summing the decrypted
	// plaintexts.
	c3 := new(big.Int).Mul(c1, &c2)
	c3.Mod(c3, p.sk.PPK.NSquared)

	p.R1 = R1

	return &SignMsg4{
		C3: c3,
	}, nil
}
