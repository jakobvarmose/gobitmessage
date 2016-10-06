package crypt

import (
	"crypto/elliptic"
	"crypto/sha512"

	"github.com/decred/dcrd/dcrec/secp256k1"
	"github.com/jakobvarmose/gobitmessage/varint"
	"golang.org/x/crypto/ripemd160"
)

type PrivateCombo struct {
	SigningKey    PrivateKey
	EncryptionKey PrivateKey
}

func RandomPrivateCombo() *PrivateCombo {
	signingKey := RandomPrivateKey()
	encryptionKey := RandomPrivateKey()
	return &PrivateCombo{
		SigningKey:    signingKey,
		EncryptionKey: encryptionKey,
	}
}

func DeterministicPrivateCombo(name string) *PrivateCombo {
	curve := secp256k1.S256()
	for i := uint64(0); ; i += 2 {
		h1 := sha512.New()
		h1.Write([]byte(name))
		varint.Write(h1, i)
		x1, y1 := secp256k1.S256().ScalarBaseMult(h1.Sum(nil)[:32])
		key1 := elliptic.Marshal(curve, x1, y1)

		h2 := sha512.New()
		h2.Write([]byte(name))
		varint.Write(h2, i+1)
		x2, y2 := secp256k1.S256().ScalarBaseMult(h2.Sum(nil)[:32])
		key2 := elliptic.Marshal(curve, x2, y2)

		h3 := sha512.New()
		h3.Write(key1)
		h3.Write(key2)

		h4 := ripemd160.New()
		h4.Write(h3.Sum(nil))
		ripe := h4.Sum(nil)
		if ripe[0] == 0 {
			return &PrivateCombo{
				h1.Sum(nil)[:32],
				h2.Sum(nil)[:32],
			}
		}
	}
}

func (c *PrivateCombo) PublicCombo() *PublicCombo {
	return &PublicCombo{
		c.SigningKey.PublicKey(),
		c.EncryptionKey.PublicKey(),
	}
}

func (c *PrivateCombo) Ripe() Ripe {
	return c.PublicCombo().Ripe()
}
