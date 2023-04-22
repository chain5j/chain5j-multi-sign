// Package paillier
package paillier

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"math/big"
)

var one = big.NewInt(1)

// ErrMessageTooLong is returned when attempting to encrypt a message which is
// too large for the size of the public key.
var ErrMessageTooLong = errors.New("paillier: message too long for Paillier public key size")

// GenerateKey generates an Paillier keypair of the given bit size using the
// random source random (for example, crypto/rand.Reader).
func GenerateKey(random io.Reader, bits int) (*PrivateKey, error) {
	p, err := rand.Prime(random, bits/2)
	if err != nil {
		return nil, err
	}

	// Now, find a prime q in the foreground.
	q, err := rand.Prime(random, bits/2)
	if err != nil {
		return nil, err
	}

	n := new(big.Int).Mul(p, q)
	pp := new(big.Int).Mul(p, p)
	qq := new(big.Int).Mul(q, q)

	return &PrivateKey{
		PublicKey: PublicKey{
			N:        n,
			NSquared: new(big.Int).Mul(n, n),
			G:        new(big.Int).Add(n, one), // g = n + 1
		},
		p:         p,
		pp:        pp,
		pminusone: new(big.Int).Sub(p, one),
		q:         q,
		qq:        qq,
		qminusone: new(big.Int).Sub(q, one),
		pinvq:     new(big.Int).ModInverse(p, q),
		hp:        h(p, pp, n),
		hq:        h(q, qq, n),
		n:         n,
	}, nil

}

// PrivateKey represents a Paillier key.
type PrivateKey struct {
	PublicKey
	p         *big.Int
	pp        *big.Int
	pminusone *big.Int
	q         *big.Int
	qq        *big.Int
	qminusone *big.Int
	pinvq     *big.Int
	hp        *big.Int
	hq        *big.Int
	n         *big.Int
}

func (p *PrivateKey) MarshalJSON() ([]byte, error) {
	type pq struct {
		P *big.Int `json:"p"`
		Q *big.Int `json:"q"`
	}

	var enc pq
	enc.P = p.p
	enc.Q = p.q

	return json.Marshal(&enc)
}

func (p *PrivateKey) UnmarshalJSON(input []byte) error {
	type pq struct {
		P *big.Int `json:"p"`
		Q *big.Int `json:"q"`
	}
	var dec pq

	err := json.Unmarshal(input, &dec)
	if err != nil {
		return err
	}

	n := new(big.Int).Mul(dec.P, dec.Q)
	pp := new(big.Int).Mul(dec.P, dec.P)
	qq := new(big.Int).Mul(dec.Q, dec.Q)

	p.PublicKey = PublicKey{
		N:        n,
		NSquared: new(big.Int).Mul(n, n),
		G:        new(big.Int).Add(n, one), // g = n + 1
	}

	p.p = dec.P
	p.pp = pp
	p.pminusone = new(big.Int).Sub(dec.P, one)
	p.q = dec.Q
	p.qq = qq
	p.qminusone = new(big.Int).Sub(dec.Q, one)
	p.pinvq = new(big.Int).ModInverse(dec.P, dec.Q)
	p.hp = h(dec.P, pp, n)
	p.hq = h(dec.Q, qq, n)
	p.n = n

	return nil
}

// PublicKey represents the public part of a Paillier key.
type PublicKey struct {
	N        *big.Int `json:"N"` // modulus
	G        *big.Int `json:"G"` // n+1, since p and q are same length
	NSquared *big.Int `json:"N^2"`
}

func h(p *big.Int, pp *big.Int, n *big.Int) *big.Int {
	gp := new(big.Int).Mod(new(big.Int).Sub(one, n), pp)
	lp := l(gp, p)
	hp := new(big.Int).ModInverse(lp, p)
	return hp
}

// L(u) = (u-1)/n
func l(u *big.Int, n *big.Int) *big.Int {
	return new(big.Int).Div(new(big.Int).Sub(u, one), n)
}

// Encrypt encrypts a plain text represented as a byte array. The passed plain
// text MUST NOT be larger than the modulus of the passed public key.
func Encrypt(pubKey *PublicKey, plainText []byte) ([]byte, error) {
	c, _, err := EncryptAndNonce(pubKey, plainText)
	return c, err
}

// EncryptAndNonce encrypts a plain text represented as a byte array, and in
// addition, returns the nonce used during encryption. The passed plain text
// MUST NOT be larger than the modulus of the passed public key.
func EncryptAndNonce(pubKey *PublicKey, plainText []byte) ([]byte, *big.Int, error) {
	r, err := rand.Int(rand.Reader, pubKey.N)
	if err != nil {
		return nil, nil, err
	}

	c, err := EncryptWithNonce(pubKey, r, plainText)
	if err != nil {
		return nil, nil, err
	}

	return c.Bytes(), r, nil
}

// EncryptWithNonce encrypts a plain text represented as a byte array using the
// provided nonce to perform encryption. The passed plain text MUST NOT be
// larger than the modulus of the passed public key.
func EncryptWithNonce(pubKey *PublicKey, r *big.Int, plainText []byte) (*big.Int, error) {
	m := new(big.Int).SetBytes(plainText)
	if pubKey.N.Cmp(m) < 1 { // N < m
		return nil, ErrMessageTooLong
	}

	// c = g^m * r^n mod n^2 = ((m*n+1) mod n^2) * r^n mod n^2
	n := pubKey.N
	c := new(big.Int).Mod(
		new(big.Int).Mul(
			new(big.Int).Mod(new(big.Int).Add(one, new(big.Int).Mul(m, n)), pubKey.NSquared),
			new(big.Int).Exp(r, n, pubKey.NSquared),
		),
		pubKey.NSquared,
	)

	return c, nil
}

// Decrypt decrypts the passed cipher text.
func Decrypt(privKey *PrivateKey, cipherText []byte) ([]byte, error) {
	c := new(big.Int).SetBytes(cipherText)
	if privKey.NSquared.Cmp(c) < 1 { // c < n^2
		return nil, ErrMessageTooLong
	}

	cp := new(big.Int).Exp(c, privKey.pminusone, privKey.pp)
	lp := l(cp, privKey.p)
	mp := new(big.Int).Mod(new(big.Int).Mul(lp, privKey.hp), privKey.p)
	cq := new(big.Int).Exp(c, privKey.qminusone, privKey.qq)
	lq := l(cq, privKey.q)

	mqq := new(big.Int).Mul(lq, privKey.hq)
	mq := new(big.Int).Mod(mqq, privKey.q)
	m := crt(mp, mq, privKey)

	return m.Bytes(), nil
}

// crt menas chinese remainder theorem
func crt(mp *big.Int, mq *big.Int, privKey *PrivateKey) *big.Int {
	u := new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Sub(mq, mp), privKey.pinvq), privKey.q)
	m := new(big.Int).Add(mp, new(big.Int).Mul(u, privKey.p))
	return new(big.Int).Mod(m, privKey.n)
}

// AddCipher homomorphically adds together two cipher texts.
// To do this we multiply the two cipher texts, upon decryption, the resulting
// plain text will be the sum of the corresponding plain texts.
func AddCipher(pubKey *PublicKey, cipher1, cipher2 []byte) []byte {
	x := new(big.Int).SetBytes(cipher1)
	y := new(big.Int).SetBytes(cipher2)

	// x * y mod n^2
	return new(big.Int).Mod(
		new(big.Int).Mul(x, y),
		pubKey.NSquared,
	).Bytes()
}

// Add homomorphically adds a passed constant to the encrypted integer
// (our cipher text). We do this by multiplying the constant with our
// ciphertext. Upon decryption, the resulting plain text will be the sum of
// the plaintext integer and the constant.
func Add(pubKey *PublicKey, cipher, constant []byte) []byte {
	c := new(big.Int).SetBytes(cipher)
	x := new(big.Int).SetBytes(constant)

	// c * g ^ x mod n^2
	return new(big.Int).Mod(
		new(big.Int).Mul(c, new(big.Int).Exp(pubKey.G, x, pubKey.NSquared)),
		pubKey.NSquared,
	).Bytes()
}

// Mul homomorphically multiplies an encrypted integer (cipher text) by a
// constant. We do this by raising our cipher text to the power of the passed
// constant. Upon decryption, the resulting plain text will be the product of
// the plaintext integer and the constant.
func Mul(pubKey *PublicKey, cipher []byte, constant []byte) []byte {
	c := new(big.Int).SetBytes(cipher)
	x := new(big.Int).SetBytes(constant)

	// c ^ x mod n^2
	return new(big.Int).Exp(c, x, pubKey.NSquared).Bytes()
}

func (dk *PrivateKey) ExtractNroot(z *big.Int) *big.Int {
	phi := new(big.Int).Mul(dk.pminusone, dk.qminusone)
	dn := new(big.Int).ModInverse(dk.N, phi)
	dp, dq := crtDecompose(dn, dk.pminusone, dk.qminusone)
	zp, zq := crtDecompose(z, dk.p, dk.q)

	rp := new(big.Int).Exp(zp, dp, dk.p)
	rq := new(big.Int).Exp(zq, dq, dk.q)

	return crtCombine(rp, rq, dk.p, dk.q, dk.pinvq)
}

func crtDecompose(x *big.Int, m1 *big.Int, m2 *big.Int) (*big.Int, *big.Int) {
	return new(big.Int).Mod(x, m1), new(big.Int).Mod(x, m2)
}

func crtCombine(x1 *big.Int, x2 *big.Int, m1 *big.Int, m2 *big.Int, m1Inv *big.Int) *big.Int {
	diff := new(big.Int).Sub(x2, x1)
	diff.Mod(diff, m2)

	u := new(big.Int).Mul(diff, m1Inv)
	u.Mod(u, m2)

	return new(big.Int).Add(x1, new(big.Int).Mul(u, m1))
}
