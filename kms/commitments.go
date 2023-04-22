// Package kms
package kms

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"

	"github.com/chain5j/chain5j-multi-sign/eckey"
)

// Avoid Rogue Key Attacks
type Commitments [32]byte
type Nonce [32]byte

func NewCommit(data []byte) (Commitments, Nonce, error) {
	var nonce Nonce
	_, err := io.ReadFull(rand.Reader, nonce[:])
	if err != nil {
		return Commitments{}, nonce, err
	}

	return commitWithNonce(data, &nonce), nonce, nil
}

func (c *Commitments) Verify(data []byte, nonce *Nonce) error {
	if *c == commitWithNonce(data, nonce) {
		return nil
	}

	return invalidCommitments
}

func (c *Commitments) MarshalText() ([]byte, error) {
	dst := make([]byte, hex.EncodedLen(len(c)))
	hex.Encode(dst, c[:])
	return dst, nil
}

func (n *Nonce) UnmarshalText(input []byte) error {
	if len(input) < hex.EncodedLen(len(n)) {
		return errors.New("invalid commit length")
	}

	hex.Decode(n[:], input)
	return nil
}

func (n *Nonce) MarshalText() ([]byte, error) {
	dst := make([]byte, hex.EncodedLen(len(n)))
	hex.Encode(dst, n[:])
	return dst, nil
}

func (c *Commitments) UnmarshalText(input []byte) error {
	if len(input) < hex.EncodedLen(len(c)) {
		return errors.New("invalid commit length")
	}

	hex.Decode(c[:], input)
	return nil
}

// data: the content of DLokPoK
func commitWithNonce(data []byte, nonce *Nonce) Commitments {
	h := sha256.New()
	h.Write(data)
	h.Write(nonce[:])

	var comm Commitments
	copy(comm[:], h.Sum(nil))
	return comm
}

type KeyGenCommWitness struct {
	PkCommitNonce Nonce
	ZkPokNonce    Nonce
	PublicShare   []byte // Party1 publicKey
	Proof         *DLogProof
}

func createKeyGenCommitments(g *Party1Generator) (Commitments, Commitments, *KeyGenCommWitness, error) {
	proof := dlogProve(g.sk1)

	pkbytes := eckey.FromECDSAPub(&g.sk1.PublicKey)

	pkComm, pkCommNonce, err := NewCommit(pkbytes)
	if err != nil {
		return Commitments{}, Commitments{}, nil, err
	}

	zkPokComm, zkPokNonce, err := NewCommit(proof.PkRandComm)
	if err != nil {
		return Commitments{}, Commitments{}, nil, err
	}

	return pkComm, zkPokComm, &KeyGenCommWitness{
		PkCommitNonce: pkCommNonce,
		ZkPokNonce:    zkPokNonce,
		PublicShare:   pkbytes,
		Proof:         proof,
	}, nil
}

func verifyKeyGenCommitments(pkCommit Commitments, zkPokCommit Commitments, witness *KeyGenCommWitness) bool {
	if pkCommit.Verify(witness.PublicShare, &witness.PkCommitNonce) != nil {
		return false
	}

	if zkPokCommit.Verify(witness.Proof.PkRandComm, &witness.ZkPokNonce) != nil {
		return false
	}

	if witness.Proof.Verify() != nil {
		return false
	}

	return true
}

type SignRCommWitness struct {
	R2CommNonce Nonce
	R2PokNonce  Nonce
	R2Share     []byte
	Proof       *DLogProof
}

func createRCommitments(k2 *ecdsa.PrivateKey) (Commitments, Commitments, *SignRCommWitness, error) {
	proof := dlogProve(k2)

	r2Pk := eckey.FromECDSAPub(&k2.PublicKey)
	r2Comm, r2CommNonce, err := NewCommit(r2Pk)
	if err != nil {
		return Commitments{}, Commitments{}, nil, err
	}

	r2PokComm, r2PokNonce, err := NewCommit(proof.PkRandComm)
	if err != nil {
		return Commitments{}, Commitments{}, nil, err
	}

	return r2Comm, r2PokComm, &SignRCommWitness{
		R2CommNonce: r2CommNonce,
		R2PokNonce:  r2PokNonce,
		R2Share:     r2Pk,
		Proof:       proof,
	}, nil
}

func verifySignCommitments(r2Comm Commitments, r2PokComm Commitments, witness *SignRCommWitness) bool {
	if r2Comm.Verify(witness.R2Share, &witness.R2CommNonce) != nil {
		return false
	}

	if r2PokComm.Verify(witness.Proof.PkRandComm, &witness.R2PokNonce) != nil {
		return false
	}

	if witness.Proof.Verify() != nil {
		return false
	}

	return true
}
