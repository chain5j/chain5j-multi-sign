// Package main
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/roasbeef/go-go-gadget-paillier"
)

var (
	secp256k1N, _  = new(big.Int).SetString("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)
	secp256k1halfN = new(big.Int).Div(secp256k1N, big.NewInt(2))

	curve         = crypto.S256()
	chainId int64 = 2018
)

func main() {
	// 生成两对秘钥对
	pk1, _ := ecdsa.GenerateKey(curve, rand.Reader)
	// pub1 := elliptic.Marshal(curve, pk1.X, pk1.Y)
	pk2, _ := ecdsa.GenerateKey(curve, rand.Reader)

	// 生成的最终公钥地址
	pubx, puby := curve.ScalarMult(pk2.X, pk2.Y, pk1.D.Bytes())
	// pub2x, pub2y := curve.ScalarMult(pk1.X, pk1.Y, pk2.D.Bytes())
	pub := ecdsa.PublicKey{
		Curve: curve,
		X:     pubx,
		Y:     puby,
	}
	pubKey := elliptic.Marshal(curve, pub.X, pub.Y)
	address := crypto.PubkeyToAddress(pub)
	fmt.Printf("Generate new public key: 0x%x, address: %s\n", pubKey, address.Hex())

	tx := types.NewTransaction(0, address, common.Big0, 21000, common.Big0, nil)
	signer := types.NewEIP155Signer(big.NewInt(chainId))
	hash := signer.Hash(tx)

	// message := "1234567"
	// hashM := crypto.Keccak256([]byte(message))
	hashM := hash[:]

	// sig1,_ := crypto.Sign(hashM, pk1)
	// sig2,_ := crypto.Sign(hashM, pk2)
	// fmt.Printf("sig1: %x\n", sig1)
	// fmt.Printf("sig2: %x\n", sig2)

	// 随机数算法、固定值
	rng1 := nonceRFC6979(pk1.D, hashM)
	rng2 := nonceRFC6979(pk2.D, hashM)
	// fmt.Printf("rng1: %x\n", rng1.Bytes())
	// fmt.Printf("rng2: %x\n", rng2.Bytes())

	// 签名 R值
	rx1, ry1 := signR(pk1, rng1)
	// fmt.Printf("rx1: %x, ry1: %x\n", rx1.Bytes(), ry1.Bytes())
	// rx2, ry2 := signR(pk1, hashM, rng1)

	// 最终R 值
	r, _ := curve.ScalarMult(rx1, ry1, rng2.Bytes())
	// r, _ := curve.ScalarMult(rx2, ry2, rng1.Bytes())
	fmt.Println("Sign Final:")
	fmt.Printf("r: %x\n", r.Bytes())

	// paillierKey 只能part1使用
	paillierKey, _ := paillier.GenerateKey(rand.Reader, 1024)
	epk1, _ := paillier.Encrypt(&paillierKey.PublicKey, pk1.D.Bytes())
	// fmt.Printf("epk1: %x\n", epk1)

	// 签名S 值
	s2 := part2SignS(&paillierKey.PublicKey, epk1, pk2, hashM, r, rng2)
	s := part1SignS(paillierKey, pk1, s2, rng1)
	fmt.Printf("s: %x\n", s.Bytes())

}

func signR(priv *ecdsa.PrivateKey, rng *big.Int) (rx, ry *big.Int) {
	c := priv.PublicKey.Curve
	N := c.Params().N

	for {
		rx, ry = priv.Curve.ScalarBaseMult(rng.Bytes())
		rx.Mod(rx, N)
		ry.Mod(ry, N)
		if rx.Sign() != 0 {
			return rx, ry
		}
	}
}

// s=(z+r⋅pk1⋅pk2)/k2/k1 核心算法，未加密

func part1SignS(paillierKey *paillier.PrivateKey, pk1 *ecdsa.PrivateKey, s2 []byte, rng1 *big.Int) *big.Int {
	c := pk1.PublicKey.Curve
	N := c.Params().N

	ps2, _ := paillier.Decrypt(paillierKey, s2)

	s := new(big.Int).SetBytes(ps2)

	var kInv1 *big.Int
	if in, ok := c.(invertible); ok {
		kInv1 = in.Inverse(rng1)
	} else {
		kInv1 = fermatInverse(rng1, N) // N != 0
	}

	s.Mul(s, kInv1)
	s.Mod(s, N) // N != 0

	if s.Cmp(secp256k1halfN) == 1 {
		s.Sub(N, s)
	}

	return s
}

// s’=(z+r⋅e(pk1)⋅pk2)/k2
func part2SignS(paillierKey *paillier.PublicKey, epk1 []byte, pk2 *ecdsa.PrivateKey, hash []byte, r, rng2 *big.Int) []byte {
	c := pk2.PublicKey.Curve
	N := c.Params().N

	var kInv2 *big.Int
	if in, ok := c.(invertible); ok {
		kInv2 = in.Inverse(rng2)
	} else {
		kInv2 = fermatInverse(rng2, N) // N != 0
	}

	e := hashToInt(hash, c)
	s := new(big.Int).Mul(pk2.D, r)

	sbytes := paillier.Mul(paillierKey, epk1, s.Bytes())
	sbytes = paillier.Add(paillierKey, sbytes, e.Bytes())
	sbytes = paillier.Mul(paillierKey, sbytes, kInv2.Bytes())

	return sbytes
}

var one = new(big.Int).SetInt64(1)

// A invertible implements fast inverse mod Curve.Params().N
type invertible interface {
	// Inverse returns the inverse of k in GF(P)
	Inverse(k *big.Int) *big.Int
}

func fermatInverse(k, N *big.Int) *big.Int {
	two := big.NewInt(2)
	nMinus2 := new(big.Int).Sub(N, two)
	return new(big.Int).Exp(k, nMinus2, N)
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
