package types

import (
	"bytes"
	"encoding/binary"
	"errors"
)

type Pubkey2 struct {
	Behavior      uint32
	SigningKey    []byte
	EncryptionKey []byte
}

func UnmarshalPubkey2(data []byte) (*Pubkey2, error) {
	if len(data) < 132 {
		return nil, errors.New("Invalid Pubkey2 data")
	}
	pubkey2 := new(Pubkey2)
	r := bytes.NewBuffer(data)
	binary.Read(r, binary.BigEndian, &pubkey2.Behavior)
	pubkey2.SigningKey = make([]byte, 64)
	r.Read(pubkey2.SigningKey)
	pubkey2.EncryptionKey = make([]byte, 64)
	r.Read(pubkey2.EncryptionKey)
	return pubkey2, nil
}

type Pubkey34 struct {
	Pubkey2
	Trials    uint64
	Extra     uint64
	Signature []byte
}
