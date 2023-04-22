// Package client
//
// @author: xwc1125
// @date: 2019/9/25
package client

import (
	"math/big"

	"github.com/NebulousLabs/hdkey/eckey"
	"github.com/btcsuite/btcd/btcec"
	"github.com/chain5j/chain5j-multi-sign/method2/common"
	paillier "github.com/roasbeef/go-go-gadget-paillier"
)

type Party1 struct {
	Cfg *common.Config

	// Keygen phase 1
	Sx1     *eckey.SecretKey // 私钥
	X1      *eckey.PublicKey // 公钥
	X1PoK   *common.DLogPoK  // DlogPoK 2P-ECDSA-KEYGEN-1的sign和公钥内容
	X1Nonce common.Nonce     // nonce值

	// Keygen phase 3
	X2        *eckey.PublicKey // 公钥
	PSK       *paillier.PrivateKey
	CKey      *big.Int
	CKeyNonce *big.Int
	RPProver  *common.RangeProofProver

	// Keygen phase 5
	ABComm     common.Comm
	Alpha      *big.Int
	AlphaPK    *eckey.CompressedPublicKey
	AlphaNonce common.Nonce

	// Keygen phase 7
	Q *eckey.PublicKey
}
type Party1PrivateKey struct {
	Cfg       *common.Config
	PSK       *paillier.PrivateKey
	X1SK      *eckey.SecretKey
	PublicKey *btcec.PublicKey
}

func NewParty1(cfg *common.Config) *Party1 {
	return &Party1{
		Cfg: cfg,
	}
}
