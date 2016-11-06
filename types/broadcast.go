package types

import (
	"bytes"
	"encoding/binary"
	"io"

	"github.com/jakobvarmose/gobitmessage/crypt"
	"github.com/jakobvarmose/gobitmessage/varint"
)

type Broadcast struct {
	Version   uint64
	Stream    uint64
	Behavior  Behavior
	Combo     crypt.PublicCombo
	Trials    uint64
	Extra     uint64
	Encoding  Encoding
	Contents  []byte
	Signature []byte
}

func (b *Broadcast) Sign(header, sigkey []byte) {
	w := new(bytes.Buffer)
	w.Write(header)
	varint.Write(w, b.Version)
	varint.Write(w, b.Stream)
	binary.Write(w, binary.BigEndian, b.Behavior)
	w.Write(b.Combo.SigningKey[1:])
	w.Write(b.Combo.EncryptionKey[1:])
	if b.Version >= 3 {
		varint.Write(w, b.Trials)
		varint.Write(w, b.Extra)
	}
	varint.Write(w, uint64(b.Encoding))
	varint.Write(w, uint64(len(b.Contents)))
	w.Write(b.Contents)

	b.Signature = crypt.PrivateKey(sigkey).Sign(w.Bytes())
}

func (b *Broadcast) VerifyWithAlgorithm(header []byte) (string, error) {
	w := new(bytes.Buffer)
	w.Write(header)
	varint.Write(w, b.Version)
	varint.Write(w, b.Stream)
	binary.Write(w, binary.BigEndian, b.Behavior)
	w.Write(b.Combo.SigningKey[1:])
	w.Write(b.Combo.EncryptionKey[1:])
	if b.Version >= 3 {
		varint.Write(w, b.Trials)
		varint.Write(w, b.Extra)
	}
	varint.Write(w, uint64(b.Encoding))
	varint.Write(w, uint64(len(b.Contents)))
	w.Write(b.Contents)

	return b.Combo.SigningKey.VerifyWithAlgorithm(w.Bytes(), b.Signature)
}

func (b *Broadcast) Verify(header []byte) bool {
	_, err := b.VerifyWithAlgorithm(header)
	return err != nil
}

func (b *Broadcast) Marshal() []byte {
	w := new(bytes.Buffer)
	varint.Write(w, b.Version)
	varint.Write(w, b.Stream)
	binary.Write(w, binary.BigEndian, b.Behavior)
	w.Write(b.Combo.SigningKey[1:])
	w.Write(b.Combo.EncryptionKey[1:])
	if b.Version >= 3 {
		varint.Write(w, b.Trials)
		varint.Write(w, b.Extra)
	}
	varint.Write(w, uint64(b.Encoding))
	varint.Write(w, uint64(len(b.Contents)))
	w.Write(b.Contents)
	varint.Write(w, uint64(len(b.Signature)))
	w.Write(b.Signature)
	return w.Bytes()
}
func (b *Broadcast) Unmarshal(data []byte) {
	r := bytes.NewBuffer(data)
	b.Version, _ = varint.Read(r)
	b.Stream, _ = varint.Read(r)
	binary.Read(r, binary.BigEndian, &b.Behavior)
	b.Combo.SigningKey = make([]byte, 65)
	b.Combo.SigningKey[0] = 0x04
	io.ReadFull(r, b.Combo.SigningKey[1:])
	b.Combo.EncryptionKey = make([]byte, 65)
	b.Combo.EncryptionKey[0] = 0x04
	io.ReadFull(r, b.Combo.EncryptionKey[1:])
	if b.Version >= 3 {
		b.Trials, _ = varint.Read(r)
		b.Extra, _ = varint.Read(r)
	} else {
		b.Trials = 1000
		b.Extra = 1000
	}
	encoding, _ := varint.Read(r)
	b.Encoding = Encoding(encoding)
	contentsSize, _ := varint.Read(r)
	b.Contents = make([]byte, contentsSize)
	io.ReadFull(r, b.Contents)
	signatureSize, _ := varint.Read(r)
	b.Signature = make([]byte, signatureSize)
	io.ReadFull(r, b.Signature)
}
