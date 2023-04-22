// Package main
//
// @author: xwc1125
// @date: 2019/9/25
package main

import (
	"crypto/sha256"
	"fmt"
	"log"
	"math/big"
	"time"

	"github.com/btcsuite/btcd/btcec"
	"github.com/chain5j/chain5j-multi-sign/method2/client"
	"github.com/chain5j/chain5j-multi-sign/method2/common"
	"github.com/chain5j/chain5j-multi-sign/method2/server"
)

const (
	NPaillierBits  = 2048
	NthRootSecBits = 128
	RangeSecBits   = 40
)

func main() {
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

	fmt.Printf("KeyGen parameters:\n")
	fmt.Printf("  paillier key bits:        %d\n", cfg.NPaillierBits)
	fmt.Printf("  nth-root proof soundness: %d\n", cfg.NthRootSecBits)
	fmt.Printf("  range proof soundness:    %d\n", cfg.RangeSecBits)
	fmt.Println()

	var p1 = client.NewParty1(&cfg)
	var p2 = server.NewParty2(&cfg)

	keyGenStart := time.Now()
	fmt.Printf("私钥生成开始...")

	// p1:第1次交互
	m1, err := p1.KeyGenPhase1(0)
	if err != nil {
		log.Println(err.Error())
		return
	}
	// p2:交互

	m2, err := p2.KeyGenPhase2(0, &server.KeyGenMsg1{
		X1PoKComm: m1.X1PoKComm,
	})
	if err != nil {
		log.Println(err.Error())
		return
	}
	// p1:第2次交互
	m3, err := p1.KeyGenPhase3(0, &client.KeyGenMsg2{
		X2PoK:      m2.X2PoK,
		RPChalComm: m2.RPChalComm,
	})
	if err != nil {
		log.Println(err.Error())
		return
	}
	// p2:交互
	m4, err := p2.KeyGenPhase4(0, &server.KeyGenMsg3{
		X1PoK:       m3.X1PoK,
		X1PoKNonce:  m3.X1PoKNonce,
		Ckey:        m3.Ckey,
		PProof:      m3.PProof,
		RPCtxtPairs: m3.RPCtxtPairs,
	})
	if err != nil {
		log.Println(err.Error())
		return
	}
	// p1:第3次交互
	m5, err := p1.KeyGenPhase5(0, &client.KeyGenMsg4{
		RPChallenge: m4.RPChallenge,
		RPChalNonce: m4.RPChalNonce,
		CPrime:      m4.CPrime,
		ABComm:      m4.ABComm,
	})
	if err != nil {
		log.Println(err.Error())
		return
	}
	// p2:交互
	m6, err := p2.KeyGenPhase6(0, &server.KeyGenMsg5{
		RPProofPairs: m5.RPProofPairs,
		AlphaComm:    m5.AlphaComm,
	})
	if err != nil {
		log.Println(err.Error())
		return
	}
	// p1:第3次交互
	m7, err := p1.KeyGenPhase7(0, &client.KeyGenMsg6{
		A:       m6.A,
		B:       m6.B,
		ABNonce: m6.ABNonce,
	})
	if err != nil {
		log.Println(err.Error())
		return
	}
	// p2:交互
	err = p2.KeyGenPhase8(0, &server.KeyGenMsg7{
		AlphaPK:    m7.AlphaPK,
		AlphaNonce: m7.AlphaNonce,
	})
	if err != nil {
		log.Println(err.Error())
		return
	}

	fmt.Printf(" 私钥生成结束: %v\n", time.Since(keyGenStart))
	// p1的私钥
	sk1, err := p1.PrivateKey()
	if err != nil {
		log.Println("unable to generate 2p-ecdsa key: ", err)
	}

	fmt.Printf("Keys:\n")
	fmt.Printf("  x1: %x\n", *sk1.X1SK)
	sk2, err := p2.PrivateKey()
	if err != nil {
		log.Println("unable to generate 2p-ecdsa key: ", err)
	}
	fmt.Printf("  x2: %x\n", *sk2.X2SK)
	fmt.Printf("  Q: %x\n", sk1.PublicKey.SerializeCompressed())
	fmt.Printf("  Q: %x\n", sk2.PublicKey.SerializeCompressed())
	fmt.Println()

	// 开始签名
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
