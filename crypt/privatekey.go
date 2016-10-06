package crypt

import (
	"bytes"
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

	"github.com/jakobvarmose/gobitmessage/base58"

	"github.com/Sirupsen/logrus"

	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	// Another possibility: https://github.com/btcsuite/btcd/blob/master/btcec/btcec.go
)

type PrivateKey []byte

func RandomPrivateKey() PrivateKey {
	curve := secp256k1.S256()
	priv, _, _, err := elliptic.GenerateKey(curve, rand.Reader)
	if err != nil {
		logrus.Fatal(err.Error())
	}
	return priv
}

func NewPrivateKey(text string) (PrivateKey, error) {
	data, err := base58.DecodeBTC(text)
	if err != nil {
		return nil, err
	}
	b := bytes.NewBuffer(data)
	version, err := b.ReadByte()
	if err != nil {
		return nil, err
	}
	if version != 0x80 {
		return nil, errors.New("Invalid private key version")
	}
	priv := make([]byte, 32)
	_, err = b.Read(priv)
	if err != nil {
		return nil, err
	}
	return priv, nil
}

func (p PrivateKey) String() string {
	var b bytes.Buffer
	b.WriteByte(0x80)
	b.Write(p)
	return base58.EncodeBTC(b.Bytes())
}

func (p PrivateKey) PublicKey() PublicKey {
	curve := secp256k1.S256()
	x, y := secp256k1.S256().ScalarBaseMult(p)
	return elliptic.Marshal(curve, x, y)
}

func (p PrivateKey) Sign(data []byte) []byte {
	curve := secp256k1.S256()
	hash := sha1.Sum(data)
	key := new(ecdsa.PrivateKey)
	key.D = new(big.Int).SetBytes(p)
	key.PublicKey.Curve = curve
	key.PublicKey.X, key.PublicKey.Y = curve.ScalarBaseMult(p)
	r, s, err := ecdsa.Sign(rand.Reader, key, hash[:])
	if err != nil {
		panic(err)
	}
	signature, err := asn1.Marshal([]*big.Int{r, s})
	if err != nil {
		panic(err)
	}
	return signature
}
func aesDecrypt(encrypted, key1, key2, iv, full []byte) ([]byte, error) {
	if len(encrypted) < 32 {
		return nil, errors.New("Cannot read mac")
	}
	h := hmac.New(sha256.New, key2)
	h.Write(full)
	if !hmac.Equal(encrypted[len(encrypted)-32:], h.Sum(nil)) {
		return nil, errors.New("Invalid mac")
	}
	block, _ := aes.NewCipher(key1)
	padded := make([]byte, len(encrypted)-32)
	c := cipher.NewCBCDecrypter(block, iv)
	c.CryptBlocks(padded, encrypted[:len(encrypted)-32])
	message, err := unpad(padded, block.BlockSize())
	if err != nil {
		return nil, errors.New("Invalid padding")
	}
	return message, nil

}

func (p PrivateKey) Decrypt(encrypted []byte) ([]byte, error) {
	curve := secp256k1.S256()
	if len(encrypted) < 16 {
		return nil, errors.New("Cannot read iv")
	}
	iv := encrypted[:16]
	if len(encrypted) < 18 {
		return nil, errors.New("Cannot read curve")
	}
	if encrypted[16] != 0x02 || encrypted[17] != 0xca {
		return nil, errors.New("Invalid curve")
	}
	if len(encrypted) < 20 {
		return nil, errors.New("Cannot read x length")
	}
	xLen := int(encrypted[18])*256 + int(encrypted[19])
	if xLen > 32 {
		return nil, errors.New("Invalid x length")
	}
	if len(encrypted) < 20+xLen {
		return nil, errors.New("Cannot read x")
	}
	x := new(big.Int).SetBytes(encrypted[20 : 20+xLen])
	if len(encrypted) < 20+xLen+2 {
		return nil, errors.New("Cannot read y length")
	}
	yLen := int(encrypted[20+xLen])*256 + int(encrypted[20+xLen+1])
	if yLen > 32 {
		return nil, errors.New("Invalid y length")
	}
	if len(encrypted) < 20+xLen+2+yLen {
		return nil, errors.New("Cannot read y")
	}
	y := new(big.Int).SetBytes(encrypted[20+xLen+2 : 20+xLen+2+yLen])
	data := encrypted[20+xLen+2+yLen:]
	sX, _ := curve.ScalarMult(x, y, p)
	if sX == nil {
		return nil, errors.New("Invalid result")
	}
	h := sha512.New()
	h.Write(make([]byte, 32-len(sX.Bytes())))
	h.Write(sX.Bytes())
	sha := h.Sum(nil)
	message, err := aesDecrypt(data, sha[:32], sha[32:], iv, encrypted[:len(encrypted)-32])
	if err != nil {
		return nil, err
	}
	return message, nil
}
