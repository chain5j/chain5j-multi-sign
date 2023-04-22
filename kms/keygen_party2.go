// Package kms
package kms

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/json"

	"github.com/chain5j/chain5j-multi-sign/eckey"
)

type KeyGenParty2FirstMsg struct {
	Proof      *DLogProof  `json:"dlogproof"`
	RPChalComm Commitments `json:"rpchalcomm"`
}

type KeyGenParty2SecondMsg struct {
	Pdl1stMsg   *Party2PDLFirstMsg `json:"pdlmsg1"`
	RPChallenge BitSlice           `json:"rpchallenge"`
	RPChalNonce Nonce              `json:"rpchalnonce"`
}

type KeyGenParty2SThirdMsg struct {
	PdlDecomm *Party2PDLDecommit `json:"pdldecomm"`
}

type Party2Generator struct {
	sk2    *ecdsa.PrivateKey // ecdsa 私钥
	Sk2Puk ecdsa.PublicKey

	// Party2 公钥
	X1 *ecdsa.PublicKey
	// KeyGenParty1FirstMsg
	pkCommit    Commitments
	zkPokCommit Commitments

	paillier *Party2Paillier

	// range proof
	rpVerifier *RangeProofVerifier

	pdlChall    *PDLChallenge
	p1AlphaComm *Commitments
	p1PdlDecomm *Party1PDLDecommit
}

func (g *Party2Generator) KeyGenPhase1(msg []byte) ([]byte, error) {
	var party1Msg1 KeyGenParty1FirstMsg
	if err := json.Unmarshal(msg, &party1Msg1); err != nil {
		return nil, err
	}

	err := g.createMasterKey()
	if err != nil {
		return nil, err
	}

	proof := dlogProve(g.sk2)

	rpVerifier, err := NewRangeProofVerifier(defaultKeyParams.Q3, defaultKeyParams.RangeSecBits)
	if err != nil {
		return nil, err
	}

	g.rpVerifier = rpVerifier
	g.pkCommit = party1Msg1.PkCommit
	g.zkPokCommit = party1Msg1.ZkPokCommit

	return json.Marshal(&KeyGenParty2FirstMsg{
		Proof:      proof,
		RPChalComm: rpVerifier.Comm,
	})
}

func (g *Party2Generator) KeyGenPhase2(msg []byte) ([]byte, error) {
	var party1Msg2 KeyGenParty1SecondMsg
	if err := json.Unmarshal(msg, &party1Msg2); err != nil {
		return nil, err
	}

	if !verifyKeyGenCommitments(g.pkCommit, g.zkPokCommit, party1Msg2.Witness) {
		return nil, invalidCommitments
	}

	paillier := &Party2Paillier{
		paillierPk: party1Msg2.CKProof.PPk,
		ckey:       party1Msg2.Ckey,
	}

	pubShare, err := eckey.UnmarshalPubkey(party1Msg2.Witness.PublicShare)
	if err != nil {
		return nil, err
	}

	pdl1stMsg, challenge, err := paillier.PDLChallenge(pubShare)
	if err != nil {
		return nil, err
	}

	// verify correctKey proof
	if err := party1Msg2.CKProof.Verify(); err != nil {
		return nil, err
	}

	g.rpVerifier.ReceiveCtxt(party1Msg2.Ckey, party1Msg2.CKProof.PPk, party1Msg2.RPCtxtPairs)

	g.paillier = paillier
	g.X1 = pubShare
	g.pdlChall = challenge

	return json.Marshal(&KeyGenParty2SecondMsg{
		Pdl1stMsg:   pdl1stMsg,
		RPChallenge: g.rpVerifier.Challenge,
		RPChalNonce: g.rpVerifier.Nonce,
	})
}

func (g *Party2Generator) KeyGenPhase3(msg []byte) ([]byte, error) {
	var party1Msg3 KeyGenParty1ThirdMsg
	if err := json.Unmarshal(msg, &party1Msg3); err != nil {
		return nil, err
	}

	err := g.rpVerifier.Verify(party1Msg3.RPProofPairs)
	if err != nil {
		return nil, err
	}

	deComm := g.paillier.PDLDecommit(g.pdlChall)

	g.p1AlphaComm = &party1Msg3.Party1PdlMsg1.AlphaComm
	return json.Marshal(&KeyGenParty2SThirdMsg{
		PdlDecomm: deComm,
	})
}

func (g *Party2Generator) KeyGenPhase4(msg []byte) error {
	var party1Msg4 KeyGenParty1FourthMsg
	if err := json.Unmarshal(msg, &party1Msg4); err != nil {
		return err
	}

	if err := g.paillier.VerifyPDL(g.p1AlphaComm, party1Msg4.PdlDecommit, g.pdlChall); err != nil {
		return err
	}

	g.p1PdlDecomm = party1Msg4.PdlDecommit

	return nil
}

func (g *Party2Generator) KeyGenMaster() (*MasterKey2, error) {
	x, y := defaultKeyParams.Curve.ScalarMult(g.X1.X, g.X1.Y, g.sk2.D.Bytes())
	pub, err := eckey.NewPublicKeyCoords(x, y)
	if err != nil {
		return nil, err
	}

	return &MasterKey2{
		Sk2:  g.sk2,
		Pk:   pub,
		Pk1:  g.X1,
		Ckey: g.paillier.ckey,
		PPK:  g.paillier.paillierPk,
	}, nil
}

func (g *Party2Generator) createMasterKey() error {
	sk2, err := ecdsa.GenerateKey(eckey.S256(), rand.Reader)
	if err != nil {
		return err
	}

	g.sk2 = sk2
	g.Sk2Puk = sk2.PublicKey

	return nil
}
