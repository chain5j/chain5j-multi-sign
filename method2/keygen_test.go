// Package main
//
// @author: xwc1125
// @date: 2019/9/29
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"log"
	"math/big"
	"testing"
	"time"

	"github.com/NebulousLabs/hdkey/eckey"
	"github.com/btcsuite/btcd/btcec"
	"github.com/chain5j/chain5j-multi-sign/method2/client"
	"github.com/chain5j/chain5j-multi-sign/method2/common"
	"github.com/chain5j/chain5j-multi-sign/method2/server"
	paillier "github.com/roasbeef/go-go-gadget-paillier"
)

func TestKeyGen1(t *testing.T) {
	// ====================PK1====================
	params := btcec.S256().CurveParams       // 椭圆曲线参数
	q := new(big.Int).Set(params.N)          // q=N值
	q3 := new(big.Int).Div(q, big.NewInt(3)) // q3=q/3
	qSquared := new(big.Int).Mul(q, q)       // qSquared=q^2
	cfg := common.Config{
		Q:              q,
		Q3:             q3,
		QSquared:       qSquared,
		NPaillierBits:  NPaillierBits,
		NthRootSecBits: NthRootSecBits,
		RangeSecBits:   RangeSecBits,
	}

	Sx1, err := common.NewPrivKey(cfg.Q3)
	if err != nil {
		fmt.Println(err)
		return
	}
	psk, err := paillier.GenerateKey(rand.Reader, cfg.NPaillierBits) // p1:PSK

	sk1 := &client.Party1PrivateKey{
		Cfg:       &cfg,
		PSK:       psk,
		X1SK:      Sx1, // 主要的私钥（ecdsa）
		PublicKey: nil,
	}
	fmt.Println("PrivateKey1")
	fmt.Println(sk1)
	// ====================PK2====================
	x2, err := common.NewPrivKey(cfg.Q) // 产生新的私钥

	// 使用PK1私钥加密
	ckey, _, err := paillier.EncryptAndNonce(&sk1.PSK.PublicKey, Sx1[:])
	ckey1 := new(big.Int).SetBytes(ckey)

	sk2 := &server.Party2PrivateKey{
		PPK:       &sk1.PSK.PublicKey, // 用到了PK1 的paillier公钥
		CKey:      ckey1,
		X2SK:      x2, // 主要的私钥（ecdsa）
		PublicKey: nil,
	}
	fmt.Println("PrivateKey2")
	fmt.Println(sk2)

	// ====================公钥====================
	pu2 := x2.PublicKey() // 获取公钥
	// 获取PK2的公钥
	X2x, X2y := pu2.Coords()
	// 计算总的公钥
	Qx, Qy := btcec.S256().ScalarMult(X2x, X2y, Sx1[:])

	Q, err := eckey.NewPublicKeyCoords(Qx, Qy)
	Qcpk := Q.Compress()
	Q3, err := btcec.ParsePubKey(Qcpk[:], btcec.S256())

	sk1.PublicKey = Q3
	sk2.PublicKey = Q3
	fmt.Println("公钥")
	fmt.Printf("  Q: %x\n", Q3.SerializeCompressed())

	// ====================签名====================
	signStart := time.Now()
	fmt.Println("签名开始...")

	dgst := sha256.Sum256([]byte("Hello"))
	fmt.Printf("Digest: %x\n", dgst)
	msg := dgst[:]
	// p1第1次签名
	p1Ctx := sk1.NewSignCtx(msg)
	defer p1Ctx.Zero()

	sm1, err := p1Ctx.SignMsgPhase1(0)
	if err != nil {
		log.Println(err.Error())
		return
	}
	// p2签名
	sk2.Cfg = &cfg
	p2Ctx := sk2.NewSignCtx(msg)
	defer p2Ctx.Zero()

	sm2, err := p2Ctx.SignMsgPhase2(0, &server.SignMsg1{R1PoKComm: sm1.R1PoKComm})
	if err != nil {
		log.Println(err.Error())
		return
	}
	// p1第2次签名
	sm3, err := p1Ctx.SignMsgPhase3(0, &client.SignMsg2{R2PoK: sm2.R2PoK})
	if err != nil {
		log.Println(err.Error())
		return
	}
	// p2签名
	sm4, err := p2Ctx.SignMsgPhase4(0, &server.SignMsg3{
		R1PoK:      sm3.R1PoK,
		R1PoKNonce: sm3.R1PoKNonce,
	})
	if err != nil {
		log.Println(err.Error())
		return
	}
	// p1第3次签名
	sig, err := p1Ctx.SignMsgPhase5(0, &client.SignMsg4{C3: sm4.C3})
	if err != nil {
		log.Println(err.Error())
		return
	}
	fmt.Printf(" 签名结束: %v\n", time.Since(signStart))

	fmt.Printf("Signature:\n")
	fmt.Printf("  R: %x\n", sig.R)
	fmt.Printf("  S: %x\n", sig.S)

	// 校验
	fmt.Println("校验开始")
	valid1 := sig.Verify(dgst[:], sk1.PublicKey)
	fmt.Println("p1校验结果：", valid1)
	valid2 := sig.Verify(dgst[:], sk2.PublicKey)
	fmt.Println("p2校验结果：", valid2)
}
