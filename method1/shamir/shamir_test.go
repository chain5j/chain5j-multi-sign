// Package shamir
// 
// @author: xwc1125
// @date: 2020/6/6
package shamir

import (
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"
)

func TestShamir(t *testing.T) {
	secret := big.NewInt(1024)
	threshold := 3
	modulus := big.NewInt(1000003)

	shamirSecret := New(secret, threshold, modulus)

	shares := make([]*big.Int, 6)
	for idx := 1; idx < 6; idx++ {
		val, err := shamirSecret.Shares(idx)
		assert.Nil(t, err)
		shares[idx] = val
	}

	selectedShares := make(map[int]*big.Int, 3)
	selectedShares[1] = shares[1]
	selectedShares[4] = shares[4]
	selectedShares[5] = shares[5]

	computedSecret, err := ReconstructSecret(selectedShares, modulus)
	assert.Nil(t, err)
	assert.Equal(t, computedSecret, secret)
}

func TestS256(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(crypto.S256(), rand.Reader)
	x := privateKey.X
	fmt.Println("x", x)
	// y := privateKey.Y

	threshold := 2
	modulus := big.NewInt(1000003)
	shamirSecret := New(x, threshold, modulus)

	shares := make([]*big.Int, 6)
	for idx := 1; idx < 6; idx++ {
		val, err := shamirSecret.Shares(idx)
		assert.Nil(t, err)
		shares[idx] = val
	}

	selectedShares := make(map[int]*big.Int, 2)
	// selectedShares[1] = shares[1]
	selectedShares[3] = shares[3]
	selectedShares[4] = shares[4]
	// selectedShares[5] = shares[5]

	computedSecret, err := ReconstructSecret(selectedShares, modulus)
	if err != nil {
		panic(err)
	}
	if computedSecret.Cmp(x) != 0 {
		fmt.Println("还原失败")
	} else {
		fmt.Println("还原成功")
	}
}
