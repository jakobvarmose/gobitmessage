package types

import (
	"errors"
)

type Getpubkey struct {
	Ripe []byte
	Tag  []byte
}

func UnmarshalGetpubkey(data []byte) (*Getpubkey, error) {
	switch len(data) {
	case 20:
		getpubkey := new(Getpubkey)
		getpubkey.Ripe = make([]byte, 20)
		copy(getpubkey.Ripe, data)
		return getpubkey, nil
	case 32:
		getpubkey := new(Getpubkey)
		getpubkey.Tag = make([]byte, 32)
		copy(getpubkey.Tag, data)
		return getpubkey, nil
	default:
		return nil, errors.New("Invalid Getpubkey data")
	}
}
