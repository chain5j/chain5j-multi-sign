// Package common
package common

import (
	"crypto/sha256"
	"errors"

	"github.com/NebulousLabs/hdkey/eckey"
	"github.com/NebulousLabs/hdkey/schnorr"
)

var ErrInvalidPoK = errors.New("invalid proof of knowledge")

type DLogPoK struct {
	PK  eckey.CompressedPublicKey
	Sig schnorr.Signature
}

// 生成DLogPok(公钥和签名内容)
func NewDLogPK(plaintext []byte, sk *eckey.SecretKey) (*DLogPoK, error) {
	pk := sk.PublicKey().Compress() // 获取公钥

	msg := dlogPokMsg(plaintext, pk)  // 获取明文的sha256内容
	sig, err := schnorr.Sign(sk, msg) // 签名
	if err != nil {
		return nil, err
	}

	return &DLogPoK{
		PK:  *pk,
		Sig: *sig,
	}, nil
}

// DLogPoK 的校验
func (p *DLogPoK) Verify(plaintext []byte) error {
	pk, err := p.PK.Uncompress()
	if err != nil {
		return err
	}

	msg := dlogPokMsg(plaintext, &p.PK)
	return schnorr.Verify(&p.Sig, pk, msg)
}

// 对象转换成bytes
func (p *DLogPoK) Bytes() []byte {
	var b = make([]byte, len(p.PK)+len(p.Sig))
	offset := copy(b, p.PK[:])
	copy(b[offset:], p.Sig[:])
	return b
}

// 使用公钥进行明文的sha256
func dlogPokMsg(plaintext []byte, pk *eckey.CompressedPublicKey) []byte {
	h := sha256.New()
	h.Write(pk[:])
	h.Write(plaintext)
	return h.Sum(nil)
}
