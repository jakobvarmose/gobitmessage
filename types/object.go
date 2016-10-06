package types

import (
	"bytes"
	"encoding/binary"

	"github.com/jakobvarmose/gobitmessage/varint"
)

type Header struct {
	Nonce   uint64
	Expires uint64
	Type    uint32
	Version uint64
	Stream  uint64
}

func (h *Header) Marshal() []byte {
	w := new(bytes.Buffer)
	binary.Write(w, binary.BigEndian, h.Nonce)
	binary.Write(w, binary.BigEndian, h.Expires)
	binary.Write(w, binary.BigEndian, h.Type)
	varint.Write(w, h.Version)
	varint.Write(w, h.Stream)
	return w.Bytes()
}

type Object struct {
	Header  Header
	Payload []byte
}

func UnmarshalObject(data []byte) (*Object, error) {
	var err error
	obj := new(Object)
	r := bytes.NewBuffer(data)
	obj.Payload = make([]byte, len(data))
	binary.Read(r, binary.BigEndian, &obj.Header.Nonce)
	binary.Read(r, binary.BigEndian, &obj.Header.Expires)
	binary.Read(r, binary.BigEndian, &obj.Header.Type)
	obj.Header.Version, err = varint.Read(r)
	if err != nil {
		return nil, err
	}
	obj.Header.Stream, err = varint.Read(r)
	if err != nil {
		return nil, err
	}
	obj.Payload = make([]byte, len(data))
	n, _ := r.Read(obj.Payload)
	obj.Payload = obj.Payload[:n]
	return obj, nil
}

func (o *Object) Marshal() []byte {
	w := new(bytes.Buffer)
	binary.Write(w, binary.BigEndian, o.Header.Nonce)
	binary.Write(w, binary.BigEndian, o.Header.Expires)
	binary.Write(w, binary.BigEndian, o.Header.Type)
	varint.Write(w, o.Header.Version)
	varint.Write(w, o.Header.Stream)
	w.Write(o.Payload)
	return w.Bytes()
}
