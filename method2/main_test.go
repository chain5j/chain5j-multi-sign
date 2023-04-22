// Package main
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"testing"

	"github.com/btcsuite/btcd/btcec"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/roasbeef/go-go-gadget-paillier"
)

var (
	secp256k1N, _  = new(big.Int).SetString("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)
	secp256k1halfN = new(big.Int).Div(secp256k1N, big.NewInt(2))

	curve         = crypto.S256()
	chainId int64 = 2018
	rpc           = "http://106.75.27.25:22000"
)

func TestGen(t *testing.T) {
	// 生成两对秘钥对
	pk, _ := ecdsa.GenerateKey(curve, rand.Reader)
	P := pk.PublicKey
	fmt.Printf("import public key: 0x%x, address: %s\n", elliptic.Marshal(curve, P.X, P.Y), crypto.PubkeyToAddress(P).Hex())

	rng, _ := randFieldElement(curve, rand.Reader)
	rng.Mod(rng, curve.Params().N)
	// rngInv := fermatInverse(rng, curve.Params().N)

	d1 := rng
	d1Inv := fermatInverse(d1, curve.Params().N)

	d2 := new(big.Int).Mul(pk.D, d1Inv)
	d2.Mod(d2, curve.Params().N)

	// d := new(big.Int).Mul(d1, d2)
	// d.Mod(d, curve.Params().N)
	// if d.Cmp(pk.D) == 0 {
	//	fmt.Println("equal")
	// }

	pk1 := new(ecdsa.PrivateKey)
	pk1.PublicKey.Curve = curve
	pk1.D = d1
	pk1.PublicKey.X, pk1.PublicKey.Y = curve.ScalarBaseMult(d1.Bytes())

	pk2 := new(ecdsa.PrivateKey)
	pk2.PublicKey.Curve = curve
	pk2.D = d2
	pk2.PublicKey.X, pk2.PublicKey.Y = curve.ScalarBaseMult(d2.Bytes())

	// // 生成两对秘钥对
	// pk1, _ := ecdsa.GenerateKey(curve, rand.Reader)
	// //pub1 := elliptic.Marshal(curve, pk1.X, pk1.Y)
	// pk2, _ := ecdsa.GenerateKey(curve, rand.Reader)

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
	rng1 := nonceRFC6979(btcec.S256(), pk1.D, hashM)
	rng2 := nonceRFC6979(btcec.S256(), pk2.D, hashM)
	// fmt.Printf("rng1: %x\n", rng1.Bytes())
	// fmt.Printf("rng2: %x\n", rng2.Bytes())

	// 签名 R值
	rx1, ry1 := signR(pk1, rng1)
	// fmt.Printf("rx1: %x, ry1: %x\n", rx1.Bytes(), ry1.Bytes())
	// rx2, ry2 := signR(pk1, hashM, rng1)

	// 最终R 值
	r, ry := curve.ScalarMult(rx1, ry1, rng2.Bytes())
	// r, _ := curve.ScalarMult(rx2, ry2, rng1.Bytes())
	fmt.Println("Sign Final:")
	fmt.Printf("r: %x\n", r.Bytes())

	var v byte
	if new(big.Int).Mod(ry, common.Big2).Cmp(common.Big1) == 0 {
		v = 0x1
	} else {
		v = 0x0
	}

	// paillierKey 只能part1使用
	paillierKey, _ := paillier.GenerateKey(rand.Reader, 1024)
	epk1, _ := paillier.Encrypt(&paillierKey.PublicKey, pk1.D.Bytes())
	// fmt.Printf("epk1: %x\n", epk1)

	// 签名S 值
	s2 := part2SignS(&paillierKey.PublicKey, epk1, pk2, hashM, r, rng2)
	s, over := part1SignS(paillierKey, pk1, s2, rng1)
	if over {
		v ^= 0x1
	}
	fmt.Printf("s: %x\n", s.Bytes())
	fmt.Printf("v : %b\n", v)

	v2, err := computeV(r, s, hashM, address)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("v2 : %b\n", v2)

	// if ecdsa.Verify(&pub, hashM, r, s) {
	//	fmt.Println("Verify Success")
	// } else {
	//	fmt.Println("Verify fail")
	// }

	// 发送交易
	sig := make([]byte, 65)
	copy(sig[:32], r.Bytes())
	copy(sig[32:64], s.Bytes())
	sig[64] = v

	signtx, _ := tx.WithSignature(signer, sig)
	if err := sendTx(signtx); err != nil {
		log.Fatal(err)
	}
}

func sendTx(tx *types.Transaction) error {
	client, err := ethclient.Dial(rpc)
	defer client.Close()
	if err != nil {
		return err
	}

	fmt.Printf("Send Transaction %s\n", tx.Hash().Hex())
	err = client.SendTransaction(context.Background(), tx)
	if err != nil {
		return err
	}

	return nil
}

func computeV(r, s *big.Int, hash []byte, address common.Address) (byte, error) {
	sig := make([]byte, 65)
	copy(sig[:32], r.Bytes())
	copy(sig[32:64], s.Bytes())

	for i := 0; i < 4; i++ {
		v := byte(i)
		sig[64] = v
		pub, err := crypto.Ecrecover(hash, sig)
		if err != nil {
			return 0x0, err
		}
		if len(pub) == 0 || pub[0] != 4 {
			return 0x0, errors.New("invalid public key")
		}
		// fmt.Printf("recover pub: %x\n", pub)

		var recoverAddr common.Address
		copy(recoverAddr[:], crypto.Keccak256(pub[1:])[12:])
		// fmt.Printf("recover address: %s\n", recoverAddr.Hex())

		if recoverAddr == address {
			return v, nil
		}
	}

	return 0x0, errors.New("invalid signature")
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
func signS(pk1 *ecdsa.PrivateKey, pk2 *ecdsa.PrivateKey, hash []byte, r, rng1, rng2 *big.Int) *big.Int {
	c := pk1.PublicKey.Curve
	N := c.Params().N

	var kInv1, kInv2 *big.Int
	if in, ok := c.(invertible); ok {
		kInv1 = in.Inverse(rng1)
		kInv2 = in.Inverse(rng2)
	} else {
		kInv1 = fermatInverse(rng1, N) // N != 0
		kInv2 = in.Inverse(rng2)
	}

	e := hashToInt(hash, c)
	s := new(big.Int).Mul(pk1.D, r)
	s.Mul(s, pk2.D)
	s.Add(s, e)
	s.Mul(s, kInv1)
	s.Mul(s, kInv2)
	s.Mod(s, N) // N != 0

	return s
}

func part1SignS(paillierKey *paillier.PrivateKey, pk1 *ecdsa.PrivateKey, s2 []byte, rng1 *big.Int) (*big.Int, bool) {
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
		return s, true
	}

	return s, false
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

func randFieldElement(c elliptic.Curve, rand io.Reader) (k *big.Int, err error) {
	params := c.Params()
	b := make([]byte, params.BitSize/8+8)
	_, err = io.ReadFull(rand, b)
	if err != nil {
		return
	}

	k = new(big.Int).SetBytes(b)
	n := new(big.Int).Sub(params.N, one)
	k.Mod(k, n)
	k.Add(k, one)
	return
}

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
