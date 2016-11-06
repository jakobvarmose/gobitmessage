package crypt

import (
	"bytes"
	"crypto/sha512"
	"encoding/hex"

	"github.com/jakobvarmose/gobitmessage/varint"
)

func (a Address) XKey() PrivateKey {
	var b bytes.Buffer
	varint.Write(&b, a.Version)
	varint.Write(&b, a.Stream)
	b.Write(a.Ripe)
	h1 := sha512.New()
	h1.Write(b.Bytes())
	h2 := sha512.New()
	h2.Write(h1.Sum(nil))
	return h2.Sum(nil)[:32]
}

func (a Address) Tag() Tag {
	var b bytes.Buffer
	varint.Write(&b, a.Version)
	varint.Write(&b, a.Stream)
	b.Write(a.Ripe)
	h1 := sha512.New()
	h1.Write(b.Bytes())
	h2 := sha512.New()
	h2.Write(h1.Sum(nil))
	return h2.Sum(nil)[32:]
}

type Tag []byte

func (t Tag) String() string {
	return hex.EncodeToString(t)
}
