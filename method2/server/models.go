// Package server
//
// @author: xwc1125
// @date: 2019/9/25
package server

import (
	"math/big"

	"github.com/NebulousLabs/hdkey/eckey"
	"github.com/chain5j/chain5j-multi-sign/method2/common"
)

type KeyGenMsg1 struct {
	X1PoKComm common.Comm
}

type KeyGenMsg2 struct {
	X2PoK      *common.DLogPoK
	RPChalComm common.Comm
}

type KeyGenMsg3 struct {
	X1PoK       *common.DLogPoK
	X1PoKNonce  common.Nonce
	PProof      *common.PaillierNthRootProof
	Ckey        []byte
	RPCtxtPairs []common.CiphertextPair
}

type KeyGenMsg4 struct {
	RPChallenge common.BitSlice
	RPChalNonce common.Nonce
	CPrime      *big.Int
	ABComm      common.Comm
}

type KeyGenMsg5 struct {
	RPProofPairs []common.ProofPair
	AlphaComm    common.Comm
}

type KeyGenMsg6 struct {
	A       *big.Int
	B       *big.Int
	ABNonce common.Nonce
}

type KeyGenMsg7 struct {
	AlphaPK    *eckey.CompressedPublicKey
	AlphaNonce common.Nonce
}

// =================sign================

type SignMsg1 struct {
	R1PoKComm common.Comm
}

type SignMsg2 struct {
	R2PoK *common.DLogPoK
}

type SignMsg3 struct {
	R1PoK      *common.DLogPoK
	R1PoKNonce common.Nonce
}

type SignMsg4 struct {
	C3 *big.Int
}
