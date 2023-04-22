// Package common
//
// @author: xwc1125
// @date: 2019/9/25
package common

import "math/big"

type Uint256 [32]byte

type Config struct {
	Q        *big.Int // q=N值
	Q3       *big.Int // q3=q/3
	QSquared *big.Int // qSquared=q^2

	NPaillierBits  int
	NthRootSecBits int
	RangeSecBits   int
}
