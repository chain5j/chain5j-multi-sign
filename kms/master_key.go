// Package kms
package kms

import (
	"crypto/ecdsa"
	"encoding/json"
	"math/big"

	"github.com/chain5j/chain5j-multi-sign/eckey"
	"github.com/chain5j/chain5j-multi-sign/paillier"
)

// MasterKey1 the privatekey for the server
type MasterKey1 struct {
	Sk1 *ecdsa.PrivateKey //
	Pk  *ecdsa.PublicKey
	Pk2 *ecdsa.PublicKey
	PSk *paillier.PrivateKey // the privateKey for paillier
}

func (k *MasterKey1) MarshalJSON() ([]byte, error) {
	type data struct {
		SK1 *big.Int             `json:"sk1"`
		Pk  []byte               `json:"publickey"`
		Pk2 []byte               `json:"pk2"`
		PSK *paillier.PrivateKey `json:"paillier"`
	}

	var enc data
	enc.SK1 = k.Sk1.D
	enc.Pk = eckey.FromECDSAPub(k.Pk)
	enc.Pk2 = eckey.FromECDSAPub(k.Pk2)
	enc.PSK = k.PSk

	return json.Marshal(&enc)
}

func (k *MasterKey1) UnmarshalJSON(input []byte) error {
	var err error
	type data struct {
		SK1 *big.Int             `json:"sk1"`
		Pk  []byte               `json:"publickey"`
		Pk2 []byte               `json:"pk2"`
		PSK *paillier.PrivateKey `json:"paillier"`
	}

	var dec data
	if err := json.Unmarshal(input, &dec); err != nil {
		return err
	}

	k.Sk1, err = eckey.ToECDSA(dec.SK1.Bytes())
	if err != nil {
		return err
	}
	k.Pk, err = eckey.UnmarshalPubkey(dec.Pk)
	if err != nil {
		return err
	}
	k.Pk2, err = eckey.UnmarshalPubkey(dec.Pk2)
	if err != nil {
		return err
	}
	k.PSk = dec.PSK

	return nil
}

// MasterKey2 the privateKey for client
type MasterKey2 struct {
	Sk2 *ecdsa.PrivateKey // ecdsa privateKey

	Pk *ecdsa.PublicKey

	Pk1  *ecdsa.PublicKey
	Ckey *big.Int

	PPK *paillier.PublicKey // the publicKey for paillier
}

func (k *MasterKey2) MarshalJSON() ([]byte, error) {
	type data struct {
		SK2  *big.Int            `json:"sk2"`
		Pk   []byte              `json:"publickey"`
		Pk1  []byte              `json:"pk1"`
		Ckey *big.Int            `json:"ckey"`
		PPK  *paillier.PublicKey `json:"paillier"`
	}

	var enc data
	enc.SK2 = k.Sk2.D
	enc.Pk = eckey.FromECDSAPub(k.Pk)
	enc.Pk1 = eckey.FromECDSAPub(k.Pk1)
	enc.Ckey = k.Ckey
	enc.PPK = k.PPK

	return json.Marshal(&enc)
}

func (k *MasterKey2) UnmarshalJSON(input []byte) error {
	var err error
	type data struct {
		SK2  *big.Int            `json:"sk2"`
		Pk   []byte              `json:"publickey"`
		Pk1  []byte              `json:"pk1"`
		Ckey *big.Int            `json:"ckey"`
		PPK  *paillier.PublicKey `json:"paillier"`
	}

	var dec data
	if err := json.Unmarshal(input, &dec); err != nil {
		return err
	}

	k.Sk2, err = eckey.ToECDSA(dec.SK2.Bytes())
	if err != nil {
		return err
	}
	k.Pk, err = eckey.UnmarshalPubkey(dec.Pk)
	if err != nil {
		return err
	}
	k.Pk1, err = eckey.UnmarshalPubkey(dec.Pk1)
	if err != nil {
		return err
	}
	k.Ckey = dec.Ckey
	k.PPK = dec.PPK

	return nil
}
