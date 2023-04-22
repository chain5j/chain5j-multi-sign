// Package eckey
package eckey

import (
	"crypto/ecdsa"
	"errors"
	"math/big"
)

var (
	// ErrPublicKeyNotOnCurve indicates that the public key's (X, Y) coordinates do
	// not lie on the secp256k1 curve.
	ErrPublicKeyNotOnCurve = errors.New("Public key is not on secp256k1 curve")
)

// PublicKeyFromCoordinates serializes an (X, Y) coordinate pair into a public
// key. Returns nil if X or Y are nil.
func NewPublicKeyCoords(x, y *big.Int) (*ecdsa.PublicKey, error) {
	if x == nil || y == nil {
		return nil, ErrPublicKeyNotOnCurve
	}

	if !S256().IsOnCurve(x, y) {
		return nil, ErrPublicKeyNotOnCurve
	}

	return newPublicKeyCoords(x, y), nil
}

func newPublicKeyCoords(x, y *big.Int) *ecdsa.PublicKey {
	pk := new(ecdsa.PublicKey)

	pk.X = x
	pk.Y = y
	pk.Curve = S256()

	return pk
}
