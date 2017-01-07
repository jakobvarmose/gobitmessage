package types

import (
	"bytes"
	"crypto/sha512"
	"encoding/binary"
	"io"

	"github.com/jakobvarmose/gobitmessage/crypt"
	"github.com/jakobvarmose/gobitmessage/varint"
)

type Message struct {
	Version   uint64
	Stream    uint64
	Behavior  Behavior
	Combo     crypt.PublicCombo
	Trials    uint64
	Extra     uint64
	Ripe      crypt.Ripe
	Encoding  Encoding
	Contents  []byte
	Ack       []byte
	Signature []byte
}

func (m *Message) Sign(header, sigkey []byte) {
	w := new(bytes.Buffer)
	w.Write(header)
	varint.Write(w, m.Version)
	varint.Write(w, m.Stream)
	binary.Write(w, binary.BigEndian, m.Behavior)
	w.Write(m.Combo.SigningKey[1:])
	w.Write(m.Combo.EncryptionKey[1:])
	if m.Version >= 3 {
		varint.Write(w, m.Trials)
		varint.Write(w, m.Extra)
	}
	w.Write(m.Ripe)
	varint.Write(w, uint64(m.Encoding))
	varint.Write(w, uint64(len(m.Contents)))
	w.Write(m.Contents)
	varint.Write(w, uint64(len(m.Ack)))
	w.Write(m.Ack)

	m.Signature = crypt.PrivateKey(sigkey).Sign(w.Bytes())
}

func (m *Message) VerifyWithAlgorithm(header []byte) (string, error) {
	w := new(bytes.Buffer)
	w.Write(header)
	varint.Write(w, m.Version)
	varint.Write(w, m.Stream)
	binary.Write(w, binary.BigEndian, m.Behavior)
	w.Write(m.Combo.SigningKey[1:])
	w.Write(m.Combo.EncryptionKey[1:])
	if m.Version >= 3 {
		varint.Write(w, m.Trials)
		varint.Write(w, m.Extra)
	}
	w.Write(m.Ripe)
	varint.Write(w, uint64(m.Encoding))
	varint.Write(w, uint64(len(m.Contents)))
	w.Write(m.Contents)
	varint.Write(w, uint64(len(m.Ack)))
	w.Write(m.Ack)

	return m.Combo.SigningKey.VerifyWithAlgorithm(w.Bytes(), m.Signature)
}

func (m *Message) Verify(header []byte) bool {
	_, err := m.VerifyWithAlgorithm(header)
	return err != nil
}

func (m *Message) Marshal() []byte {
	w := new(bytes.Buffer)
	varint.Write(w, m.Version)
	varint.Write(w, m.Stream)
	binary.Write(w, binary.BigEndian, m.Behavior)
	w.Write(m.Combo.SigningKey[1:])
	w.Write(m.Combo.EncryptionKey[1:])
	if m.Version >= 3 {
		varint.Write(w, m.Trials)
		varint.Write(w, m.Extra)
	}
	w.Write(m.Ripe)
	varint.Write(w, uint64(m.Encoding))
	varint.Write(w, uint64(len(m.Contents)))
	w.Write(m.Contents)
	varint.Write(w, uint64(len(m.Ack)))
	w.Write(m.Ack)
	varint.Write(w, uint64(len(m.Signature)))
	w.Write(m.Signature)
	return w.Bytes()
}
func (m *Message) Unmarshal(data []byte) {
	r := bytes.NewBuffer(data)
	m.Version, _ = varint.Read(r)
	m.Stream, _ = varint.Read(r)
	binary.Read(r, binary.BigEndian, &m.Behavior)
	m.Combo.SigningKey = make([]byte, 65)
	m.Combo.SigningKey[0] = 0x04
	io.ReadFull(r, m.Combo.SigningKey[1:])
	m.Combo.EncryptionKey = make([]byte, 65)
	m.Combo.EncryptionKey[0] = 0x04
	io.ReadFull(r, m.Combo.EncryptionKey[1:])
	if m.Version >= 3 {
		m.Trials, _ = varint.Read(r)
		m.Extra, _ = varint.Read(r)
	} else {
		m.Trials = 1000
		m.Extra = 1000
	}
	m.Ripe = make([]byte, 20)
	io.ReadFull(r, m.Ripe)
	encoding, _ := varint.Read(r)
	m.Encoding = Encoding(encoding)
	contentsSize, _ := varint.Read(r)
	m.Contents = make([]byte, contentsSize)
	io.ReadFull(r, m.Contents)
	ackSize, _ := varint.Read(r)
	m.Ack = make([]byte, ackSize)
	io.ReadFull(r, m.Ack)
	signatureSize, _ := varint.Read(r)
	m.Signature = make([]byte, signatureSize)
	io.ReadFull(r, m.Signature)
}

func (m *Message) SigHash() []byte {
	h1 := sha512.New()
	h1.Write(m.Signature)
	h2 := sha512.New()
	h2.Write(h1.Sum(nil))
	return h2.Sum(nil)[32:]
}
