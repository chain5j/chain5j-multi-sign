// Package server
//
// @author: xwc1125
// @date: 2019/9/25
package server

import (
	"math/big"

	"github.com/NebulousLabs/hdkey/eckey"
	"github.com/btcsuite/btcd/btcec"
	"github.com/chain5j/chain5j-multi-sign/method2/common"
	paillier "github.com/roasbeef/go-go-gadget-paillier"
)

type Party2 struct {
	cfg *common.Config

	// Keygen phase 2
	X1PoKComm  common.Comm
	x2         *eckey.SecretKey           // 私钥
	X2         *eckey.PublicKey           // 公钥
	X2PoK      *common.DLogPoK            // 2P-ECDSA-KEYGEN-2 对应的sign和公钥
	RPVerifier *common.RangeProofVerifier // 随机证明的校验者

	// Keygen phase 4
	X1      *eckey.PublicKey
	PPK     *paillier.PublicKey
	CKey    *big.Int
	CPrime  *big.Int
	A       *big.Int
	B       *big.Int
	ABNonce common.Nonce

	// Keygen phase 6
	AlphaComm common.Comm

	// Keygen phase 8
	Q *eckey.PublicKey
}

type Party2PrivateKey struct {
	Cfg       *common.Config
	PPK       *paillier.PublicKey
	CKey      *big.Int
	X2SK      *eckey.SecretKey
	PublicKey *btcec.PublicKey
}

func NewParty2(cfg *common.Config) *Party2 {
	return &Party2{
		cfg: cfg,
	}
}
