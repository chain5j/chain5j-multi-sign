// Package kms
package kms

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/json"
	"math/big"

	"github.com/chain5j/chain5j-multi-sign/eckey"
	"github.com/chain5j/chain5j-multi-sign/paillier"
)

type KeyGenParty1FirstMsg struct {
	PkCommit    Commitments `json:"pkcommit"`
	ZkPokCommit Commitments `json:"zkpokcommit"`
}

type KeyGenParty1SecondMsg struct {
	Witness     *KeyGenCommWitness `json:"witness"`
	Ckey        *big.Int           `json:"ckey"`
	CKProof     *NICorrectKeyProof `json:"ckproof"`
	RPCtxtPairs []CiphertextPair   `json:"rpctx"`
}

type KeyGenParty1ThirdMsg struct {
	Party1PdlMsg1 *Party1PDLFirstMsg `json:"pdlmsg1"`
	RPProofPairs  []ProofPair        `json:"rpproof"`
}

type KeyGenParty1FourthMsg struct {
	PdlDecommit *Party1PDLDecommit `json:"pdldecommit"`
}

type Party1Generator struct {
	sk1    *ecdsa.PrivateKey // ecdsa 私钥
	Sk1Puk ecdsa.PublicKey

	X2 *ecdsa.PublicKey

	// phase1
	witness *KeyGenCommWitness

	// paillier
	paillier *Party1Paillier

	// PDL
	pdlDecommit   *Party1PDLDecommit
	alphaSk       *ecdsa.PrivateKey
	party2PdlMsg1 *Party2PDLFirstMsg

	// Range Proof
	RPProver *RangeProofProver
}

func (g *Party1Generator) KeyGenPhase1() ([]byte, error) {
	err := g.createMasterKey()
	if err != nil {
		return nil, err
	}

	pkCommit, zkPokCommit, witeness, err := createKeyGenCommitments(g)
	if err != nil {
		return nil, err
	}

	g.witness = witeness

	return json.Marshal(&KeyGenParty1FirstMsg{
		PkCommit:    pkCommit,
		ZkPokCommit: zkPokCommit,
	})
}

func (g *Party1Generator) KeyGenPhase2(msg []byte) ([]byte, error) {
	var party2Msg1 KeyGenParty2FirstMsg
	if err := json.Unmarshal(msg, &party2Msg1); err != nil {
		return nil, err
	}

	if err := party2Msg1.Proof.Verify(); err != nil {
		return nil, err
	}

	x2, err := eckey.UnmarshalPubkey(party2Msg1.Proof.PublicShare)
	if err != nil {
		return nil, err
	}

	paillierKey, err := paillier.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	// 加密x1
	ckeyRand, err := rand.Int(rand.Reader, paillierKey.N)
	if err != nil {
		return nil, err
	}
	ckey, err := paillier.EncryptWithNonce(&paillierKey.PublicKey, ckeyRand, g.sk1.D.Bytes())
	if err != nil {
		return nil, err
	}

	// Range Proof
	rpProver, err := NewRangeProofProver(
		g.sk1.D,
		ckeyRand,
		defaultKeyParams.Q,
		defaultKeyParams.Q3,
		paillierKey,
		party2Msg1.RPChalComm,
		defaultKeyParams.RangeSecBits,
	)
	if err != nil {
		return nil, err
	}

	g.paillier = &Party1Paillier{
		paillierKey: paillierKey,
		ckey:        ckey.Bytes(),
		ckeyRand:    ckeyRand.Bytes(),
	}

	ckProof, err := NewCorrectKeyProof(g.paillier)
	if err != nil {
		return nil, err
	}

	g.X2 = x2
	g.RPProver = rpProver

	return json.Marshal(&KeyGenParty1SecondMsg{
		Witness:     g.witness,
		Ckey:        ckey,
		CKProof:     ckProof,
		RPCtxtPairs: rpProver.CtxtPairs,
	})
}

func (g *Party1Generator) KeyGenPhase3(msg []byte) ([]byte, error) {
	var party2Msg2 KeyGenParty2SecondMsg
	if err := json.Unmarshal(msg, &party2Msg2); err != nil {
		return nil, err
	}

	proofPairs, err := g.RPProver.Prove(party2Msg2.RPChallenge, &party2Msg2.RPChalNonce)
	if err != nil {
		return nil, err
	}

	pdlMsg1, pdlDecommit, alpha, err := g.paillier.PDLFirstStage(party2Msg2.Pdl1stMsg)
	if err != nil {
		return nil, err
	}

	g.pdlDecommit = pdlDecommit
	g.alphaSk = alpha
	g.party2PdlMsg1 = party2Msg2.Pdl1stMsg

	return json.Marshal(&KeyGenParty1ThirdMsg{
		Party1PdlMsg1: pdlMsg1,
		RPProofPairs:  proofPairs,
	})
}

func (g *Party1Generator) KeyGenPhase4(msg []byte) ([]byte, error) {
	var party2Msg3 KeyGenParty2SThirdMsg
	if err := json.Unmarshal(msg, &party2Msg3); err != nil {
		return nil, err
	}

	if err := g.paillier.PDLSecondStage(party2Msg3.PdlDecomm, g.party2PdlMsg1, g.sk1, g.alphaSk); err != nil {
		return nil, err
	}

	return json.Marshal(&KeyGenParty1FourthMsg{
		g.pdlDecommit,
	})
}

func (g *Party1Generator) KeyGenMaster() (*MasterKey1, error) {
	x, y := defaultKeyParams.Curve.ScalarMult(g.X2.X, g.X2.Y, g.sk1.D.Bytes())
	pub, err := eckey.NewPublicKeyCoords(x, y)
	if err != nil {
		return nil, err
	}

	return &MasterKey1{
		Sk1: g.sk1,
		Pk:  pub,
		Pk2: g.X2,
		PSk: g.paillier.paillierKey,
	}, nil
}

func (g *Party1Generator) createMasterKey() error {
	sk1, err := newPrivKey(defaultKeyParams.Q3)
	if err != nil {
		return err
	}

	g.sk1 = sk1
	g.Sk1Puk = sk1.PublicKey

	return nil
}
