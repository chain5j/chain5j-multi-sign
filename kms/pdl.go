// Package kms
package kms

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"math/big"

	"github.com/chain5j/chain5j-multi-sign/eckey"
	"github.com/chain5j/chain5j-multi-sign/paillier"
)

// Proof of knowledge of the discrete log of an elliptic curve (PDL)

type Party2PDLFirstMsg struct {
	CPrime []byte      `json:"cprime"`
	ABComm Commitments `json:"abcomm"`
}

type PDLChallenge struct {
	CPrime  []byte
	ABComm  Commitments
	A       *big.Int
	B       *big.Int
	ABNonce Nonce
	Q       []byte
}

type Party2PDLDecommit struct {
	A       *big.Int `json:"a"`
	B       *big.Int `json:"b"`
	ABNonce Nonce    `json:"abnonce"`
}

type Party2Paillier struct {
	paillierPk *paillier.PublicKey // paillier公钥
	ckey       *big.Int
}

func (p *Party2Paillier) PDLChallenge(pubShare *ecdsa.PublicKey) (*Party2PDLFirstMsg, *PDLChallenge, error) {

	a, err := rand.Int(rand.Reader, defaultKeyParams.Q)
	if err != nil {
		return nil, nil, err
	}

	b, err := rand.Int(rand.Reader, defaultKeyParams.QSquared)
	if err != nil {
		return nil, nil, err
	}
	b.Mod(b, defaultKeyParams.Curve.Params().N)

	ac := paillier.Mul(p.paillierPk, p.ckey.Bytes(), a.Bytes())
	cPrime := paillier.Add(p.paillierPk, ac, b.Bytes()) // zengo c_tag

	var abConcat []byte
	abConcat = append(abConcat, a.Bytes()...)
	abConcat = append(abConcat, b.Bytes()...)

	abComm, abNonce, err := NewCommit(abConcat) // zengo c_tag_tag
	if err != nil {
		return nil, nil, err
	}

	// Q = a * X1 + b * G
	aQx, aQy := defaultKeyParams.Curve.ScalarMult(pubShare.X, pubShare.Y, a.Bytes())
	bx, by := defaultKeyParams.Curve.ScalarBaseMult(b.Bytes())
	qx, qy := defaultKeyParams.Curve.Add(aQx, aQy, bx, by)
	q, err := eckey.NewPublicKeyCoords(qx, qy)
	if err != nil {
		return nil, nil, err
	}

	return &Party2PDLFirstMsg{
			CPrime: cPrime,
			ABComm: abComm,
		}, &PDLChallenge{
			CPrime:  cPrime,
			ABComm:  abComm,
			A:       a,
			B:       b,
			ABNonce: abNonce,
			Q:       eckey.FromECDSAPub(q),
		}, nil
}

func (p *Party2Paillier) PDLDecommit(challenge *PDLChallenge) *Party2PDLDecommit {
	return &Party2PDLDecommit{
		A:       challenge.A,
		B:       challenge.B,
		ABNonce: challenge.ABNonce,
	}
}

func (p *Party2Paillier) VerifyPDL(alphaComm *Commitments, pdlDecomm *Party1PDLDecommit, challenge *PDLChallenge) error {
	if err := alphaComm.Verify(pdlDecomm.AlphaPk, &pdlDecomm.AlphaNonce); err != nil {
		return err
	}

	if bytes.Compare(challenge.Q, pdlDecomm.AlphaPk) != 0 {
		return finalKeyMismatch
	}

	return nil
}

type Party1Paillier struct {
	paillierKey *paillier.PrivateKey
	// paillier 对sk1私钥的加密
	ckey     []byte
	ckeyRand []byte
}

type Party1PDLFirstMsg struct {
	AlphaComm Commitments `json:"alphacomm"`
}

type Party1PDLDecommit struct {
	AlphaNonce Nonce  `json:"alphanonce"`
	AlphaPk    []byte `json:"alphapk"`
}

func (p *Party1Paillier) PDLFirstStage(pdlMsg1 *Party2PDLFirstMsg) (*Party1PDLFirstMsg, *Party1PDLDecommit, *ecdsa.PrivateKey, error) {
	alphaBytes, err := paillier.Decrypt(p.paillierKey, pdlMsg1.CPrime)
	if err != nil {
		return nil, nil, nil, err
	}

	alphaInt := new(big.Int).SetBytes(alphaBytes)
	alphaInt.Mod(alphaInt, defaultKeyParams.Q)
	alpha, err := eckey.ToECDSA(alphaInt.Bytes())
	if err != nil {
		return nil, nil, nil, err
	}

	alphaComm, alphaNonce, err := NewCommit(eckey.FromECDSAPub(&alpha.PublicKey))
	if err != nil {
		return nil, nil, nil, err
	}

	return &Party1PDLFirstMsg{
			AlphaComm: alphaComm, // zengo c_hat
		}, &Party1PDLDecommit{
			AlphaNonce: alphaNonce,
			AlphaPk:    eckey.FromECDSAPub(&alpha.PublicKey),
		}, alpha, nil
}

func (p *Party1Paillier) PDLSecondStage(p2Decomm *Party2PDLDecommit, p2PdlMsg1 *Party2PDLFirstMsg, x1 *ecdsa.PrivateKey, alpha *ecdsa.PrivateKey) error {
	var abConcat []byte
	abConcat = append(abConcat, p2Decomm.A.Bytes()...)
	abConcat = append(abConcat, p2Decomm.B.Bytes()...)

	if err := p2PdlMsg1.ABComm.Verify(abConcat, &p2Decomm.ABNonce); err != nil {
		return err
	}

	alphaTest := new(big.Int).Mul(p2Decomm.A, x1.D)
	alphaTest.Add(alphaTest, p2Decomm.B)

	if alphaTest.Cmp(alpha.D) == 0 {
		return invalidOTMac
	}

	return nil
}
