package crypt

import (
	"bytes"
	"errors"
	"strings"

	"github.com/jakobvarmose/gobitmessage/base58"
	"github.com/jakobvarmose/gobitmessage/varint"
)

type Ripe []byte

type Address struct {
	Version uint64
	Stream  uint64
	Ripe    Ripe
}

func NewAddress(text string) (*Address, error) {
	//FIXME support versions and stream over 252
	text = strings.TrimPrefix(text, "BM-")
	data, err := base58.DecodeBM(text)
	if err != nil {
		return nil, err
	}
	if len(data) < 2 || len(data) > 22 {
		return nil, errors.New("Invalid address")
	}
	version := uint64(data[0])
	stream := uint64(data[1])
	ripe := make([]byte, 20)
	copy(ripe[22-len(data):], data[2:])
	a := &Address{version, stream, ripe}
	return a, nil
}

func (a Address) String() string {
	var b bytes.Buffer
	varint.Write(&b, a.Version)
	varint.Write(&b, a.Stream)
	if a.Version == 2 || a.Version == 3 {
		b.Write(bytes.TrimLeft(a.Ripe[:2], "\x00"))
		b.Write(a.Ripe[2:])
	} else if a.Version == 4 {
		b.Write(bytes.TrimLeft(a.Ripe, "\x00"))
	} else {
		b.Write(a.Ripe)
	}
	return "BM-" + base58.EncodeBM(b.Bytes())
}
