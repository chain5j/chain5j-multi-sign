// Package common
//
// @author: xwc1125
// @date: 2019/9/25
package common

import (
	"crypto/rand"
	"math/big"

	"github.com/NebulousLabs/hdkey/eckey"
)

// 新的私钥
func NewPrivKey(modulus *big.Int) (*eckey.SecretKey, error) {
	x, err := rand.Int(rand.Reader, modulus)
	if err != nil {
		return nil, err
	}

	return eckey.NewSecretKeyInt(x)
}
