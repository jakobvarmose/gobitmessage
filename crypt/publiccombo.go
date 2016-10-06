package crypt

import (
	"crypto/sha512"

	"golang.org/x/crypto/ripemd160"
)

type PublicCombo struct {
	SigningKey    PublicKey
	EncryptionKey PublicKey
}

func (c *PublicCombo) Ripe() Ripe {
	h3 := sha512.New()
	h3.Write(c.SigningKey)
	h3.Write(c.EncryptionKey)

	h4 := ripemd160.New()
	h4.Write(h3.Sum(nil))
	return h4.Sum(nil)
}
