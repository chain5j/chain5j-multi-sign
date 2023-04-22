/*Package shamirssgo
 * is a Shamir's Secret Sharing implementation in Go
 * Copyright (C) 2019  Prahesa Kusuma Setia (prahesa at yahoo dot com)
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.*/
package shamir

import (
	"crypto/rand"
	"math/big"

	"github.com/pkg/errors"
)

const primeCertainty = 128

// ShamirSecret is a type struct of the package
type ShamirSecret struct {
	secret            *big.Int
	threshold         int
	modulus           *big.Int
	reconstructVector []*big.Int
}

// New initialize a pointer of ShamirSecret based on the given parameters
func New(secret *big.Int, threshold int, modulus *big.Int) *ShamirSecret {
	if !modulus.ProbablyPrime(primeCertainty) {
		panic("modulus fails prime test by ProbablePrime(), try to use prime (or prime enough)")
	}

	modulusBitLen := modulus.BitLen()
	max := new(big.Int)
	max.Exp(
		big.NewInt(2),
		big.NewInt(int64(modulusBitLen)),
		nil,
	).Sub(max, big.NewInt(1))

	rv := make([]*big.Int, threshold) // number of coefficient = number of polynomial degree
	rv[0] = big.NewInt(1)             // first coefficient is for the secret

	// randomly generate polynomial P(x) by randomly generate reconstruction vector
	for i := 1; i <= threshold-1; i++ {
		randNum, _ := rand.Int(rand.Reader, max)
		rv[i] = randNum.Mod(randNum, modulus)
	}

	return &ShamirSecret{
		secret:            secret.Mod(secret, modulus),
		threshold:         threshold,
		modulus:           modulus,
		reconstructVector: rv,
	}
}

// Shares computes a share based on the index given, index
// need to be greater than 0
func (ss *ShamirSecret) Shares(index int) (share *big.Int, err error) {
	if index <= 0 {
		err = errors.New("shares index need to be greater or equal than 0")
		return
	}
	// compute polynomial P(x) from secret and reconstruction vector
	share = big.NewInt(0)
	share.Add(share, ss.secret)
	for i := 1; i <= ss.threshold-1; i++ {
		xPowi := big.NewInt(int64(index))
		xPowi.Exp(xPowi, big.NewInt(int64(i)), ss.modulus)

		recVerMul := new(big.Int)
		recVerMul.Mul(ss.reconstructVector[i], xPowi)
		recVerMul.Mod(recVerMul, ss.modulus)

		share.Add(share, recVerMul)
		share.Mod(share, ss.modulus)
	}
	return
}

// ReconstructSecret is used to reconstruct the original secret based on the shares given
// in the sharesMap parameter. The number of shares given need to be greater than or equal to
// the threshold, otherwise the result of this function is undefined
func ReconstructSecret(sharesMap map[int]*big.Int, modulus *big.Int) (secret *big.Int, err error) {
	secret = big.NewInt(0)
	keySet := make(map[int]bool, len(sharesMap))
	for k := range sharesMap {
		keySet[k] = true
	}
	for k, v := range sharesMap {
		langrangeCoeff, err := langrangeCoeff(k, keySet, modulus)
		if err != nil {
			err = errors.Wrap(err, "fail getting lagrange coefficient in index "+string(k))
		}
		share := v

		lagrangeCoeffMult := new(big.Int)
		lagrangeCoeffMult.Mul(langrangeCoeff, share).Mod(lagrangeCoeffMult, modulus)
		secret.Add(secret, lagrangeCoeffMult).Mod(secret, modulus)
	}
	return
}

func langrangeCoeff(i int, setIndices map[int]bool, modulus *big.Int) (coeff *big.Int, err error) {
	coeff = big.NewInt(1)
	for t := range setIndices {
		if i == t {
			continue
		}
		numerator := big.NewInt(0)
		numerator.Sub(numerator, big.NewInt(int64(t))).Mod(numerator, modulus)

		denumerator := big.NewInt(int64(i - t))
		denumerator.Mod(denumerator, modulus)

		currVal := new(big.Int)
		denumeratorInverse := new(big.Int)
		denumeratorInverse.ModInverse(denumerator, modulus)
		currVal.Mul(numerator, denumeratorInverse)

		coeff.Mul(coeff, currVal).Mod(coeff, modulus)
	}
	return
}
