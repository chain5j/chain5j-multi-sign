// Package kms
package kms

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"math/big"

	"github.com/chain5j/chain5j-multi-sign/eckey"
)

var (
	invalidCommitments = errors.New("invalid commitments")
	invalidDlogProof   = errors.New("invalid dlog proof")
	invalidOTMac       = errors.New("invalid one-time MAC")
	finalKeyMismatch   = errors.New("final one-time key doesn't match")
	invalidRangeProof  = errors.New("invalid range proof")
	invalidProofPair   = errors.New("cannot prove for invalid proof pair")
	invalidCKProop     = errors.New("invalid correct key proof")
)

type KenGenParams struct {
	Curve         elliptic.Curve
	Q             *big.Int
	Q3            *big.Int
	QSquared      *big.Int
	NPaillierBits int
	RangeSecBits  int
}

var (
	defaultKeyParams *KenGenParams
	one              = big.NewInt(1)
	secp256k1N, _    = new(big.Int).SetString("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)
	secp256k1halfN   = new(big.Int).Div(secp256k1N, big.NewInt(2))
)

func init() {
	params := eckey.S256().Params()
	q := new(big.Int).Set(params.N)
	q3 := new(big.Int).Div(q, big.NewInt(3))
	qSquared := new(big.Int).Mul(q, q)

	defaultKeyParams = &KenGenParams{
		Curve:         eckey.S256(),
		Q:             q,
		Q3:            q3,
		QSquared:      qSquared,
		NPaillierBits: 2048,
		RangeSecBits:  40, // TODO maybe need 128bit
	}
}

func newPrivKey(modulus *big.Int) (*ecdsa.PrivateKey, error) {
	x, err := rand.Int(rand.Reader, modulus)
	if err != nil {
		return nil, err
	}

	return eckey.ToECDSA(x.Bytes())
}

func hashToInt(hash []byte, c elliptic.Curve) *big.Int {
	orderBits := c.Params().N.BitLen()
	orderBytes := (orderBits + 7) / 8
	if len(hash) > orderBytes {
		hash = hash[:orderBytes]
	}

	ret := new(big.Int).SetBytes(hash)
	excess := len(hash)*8 - orderBits
	if excess > 0 {
		ret.Rsh(ret, uint(excess))
	}
	return ret
}

func fermatInverse(k, N *big.Int) *big.Int {
	two := big.NewInt(2)
	nMinus2 := new(big.Int).Sub(N, two)
	return new(big.Int).Exp(k, nMinus2, N)
}
