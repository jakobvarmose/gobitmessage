package crypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/asn1"
	"errors"
	"math/big"

	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	// Another possibility: https://github.com/btcsuite/btcd/blob/master/btcec/btcec.go
)

type PublicKey []byte

func (p PublicKey) Verify(data, signature []byte) error {
	curve := secp256k1.S256()
	rs := make([]*big.Int, 2)
	rest, err := asn1.Unmarshal(signature, &rs)
	if err != nil {
		return err
	}
	if len(rest) > 0 {
		return errors.New("Extra data after signature")
	}
	key := new(ecdsa.PublicKey)
	key.Curve = curve
	key.X = new(big.Int).SetBytes(p[1:33])
	key.Y = new(big.Int).SetBytes(p[33:])
	hash := sha1.Sum(data)
	if !ecdsa.Verify(key, hash[:], rs[0], rs[1]) {
		hash2 := sha256.Sum256(data)
		if !ecdsa.Verify(key, hash2[:], rs[0], rs[1]) {
			return errors.New("Invalid signature")
		}
	}
	return nil
}

func aesEncrypt(message, key1, key2, iv []byte) []byte {
	//FIXME compute mac on entire object
	block, _ := aes.NewCipher(key1)
	padded := pad(message, block.BlockSize())
	encrypted := make([]byte, len(padded))
	c := cipher.NewCBCEncrypter(block, iv)
	c.CryptBlocks(encrypted, padded)
	return encrypted
}

func (p PublicKey) Encrypt(message []byte) []byte {
	curve := secp256k1.S256()
	pX, pY := elliptic.Unmarshal(curve, p)
	ePriv, eX, eY, _ := elliptic.GenerateKey(curve, rand.Reader)
	sX, _ := curve.ScalarMult(pX, pY, ePriv)
	h := sha512.New()
	h.Write(make([]byte, 32-len(sX.Bytes())))
	h.Write(sX.Bytes())
	sha := h.Sum(nil)
	iv := make([]byte, 16)
	rand.Read(iv)
	encrypted := aesEncrypt(message, sha[:32], sha[32:], iv)

	var res []byte
	res = append(res, iv...)
	res = append(res, 0x02, 0xca)
	res = append(res, 0, byte(len(eX.Bytes())))
	res = append(res, eX.Bytes()...)
	res = append(res, 0, byte(len(eY.Bytes())))
	res = append(res, eY.Bytes()...)
	res = append(res, encrypted...)
	h = hmac.New(sha256.New, sha[32:])
	h.Write(res)
	return h.Sum(res)
}
