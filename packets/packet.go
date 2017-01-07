package packets

import (
	"bytes"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"io"
	"net"

	"github.com/jakobvarmose/gobitmessage/varint"
)

type Command string

const (
	Command_Version = "version"
	Command_Verack  = "verack"
	Command_Addr    = "addr"
	Command_Inv     = "inv"
	Command_Getdata = "getdata"
	Command_Object  = "object"
)

type Packet struct {
	Command Command
	Payload []byte
}

func Write(w2 io.Writer, p Packet) {
	w := new(bytes.Buffer)
	binary.Write(w, binary.BigEndian, uint32(0xe9beb4d9))
	command := make([]byte, 12)
	copy(command, p.Command)
	w.Write(command)
	binary.Write(w, binary.BigEndian, uint32(len(p.Payload)))
	h := sha512.New()
	h.Write(p.Payload)
	w.Write(h.Sum(nil)[:4])
	w.Write(p.Payload)
	w2.Write(w.Bytes())
}

func Read(r io.Reader) (*Packet, error) {
	p := new(Packet)
	var magic uint32
	err := binary.Read(r, binary.BigEndian, &magic)
	if err != nil {
		return nil, err
	}
	if magic != 0xe9beb4d9 {
		return nil, errors.New("Wrong magic value")
	}
	command := make([]byte, 12)
	_, err = io.ReadFull(r, command)
	if err != nil {
		return nil, err
	}
	p.Command = Command(bytes.TrimRight(command, "\x00"))
	var size uint32
	err = binary.Read(r, binary.BigEndian, &size)
	if err != nil {
		return nil, err
	}
	checksum := make([]byte, 4)
	_, err = io.ReadFull(r, checksum)
	if err != nil {
		return nil, err
	}
	// There's no point in verifying the checksum
	p.Payload = make([]byte, size)
	_, err = io.ReadFull(r, p.Payload)
	if err != nil {
		return nil, err
	}
	return p, nil
}

type Version struct {
	Version   int32
	Services  uint64
	Timestamp int64

	SrcServices uint64
	SrcIP       net.IP
	SrcPort     uint16

	DstServices uint64
	DstIP       net.IP
	DstPort     uint16

	Nonce     uint64
	UserAgent string
	Streams   []uint64
}

func (v *Version) Marshal() []byte {
	w := new(bytes.Buffer)
	binary.Write(w, binary.BigEndian, v.Version)
	binary.Write(w, binary.BigEndian, v.Services)
	binary.Write(w, binary.BigEndian, v.Timestamp)

	binary.Write(w, binary.BigEndian, v.SrcServices)
	w.Write(v.SrcIP)
	binary.Write(w, binary.BigEndian, v.SrcPort)

	binary.Write(w, binary.BigEndian, v.DstServices)
	w.Write(v.DstIP)
	binary.Write(w, binary.BigEndian, v.DstPort)

	binary.Write(w, binary.BigEndian, v.Nonce)
	varint.WriteString(w, v.UserAgent)
	varint.Write(w, uint64(len(v.Streams)))
	for _, stream := range v.Streams {
		varint.Write(w, stream)
	}
	return w.Bytes()
}

func (v *Version) Unmarshal(b []byte) error {
	r := bytes.NewBuffer(b)
	binary.Read(r, binary.BigEndian, &v.Version)
	binary.Read(r, binary.BigEndian, &v.Services)
	binary.Read(r, binary.BigEndian, &v.Timestamp)

	binary.Read(r, binary.BigEndian, &v.SrcServices)
	v.SrcIP = make([]byte, 16)
	io.ReadFull(r, v.SrcIP)
	binary.Read(r, binary.BigEndian, &v.SrcPort)

	binary.Read(r, binary.BigEndian, &v.DstServices)
	v.DstIP = make([]byte, 16)
	io.ReadFull(r, v.DstIP)
	binary.Read(r, binary.BigEndian, &v.DstPort)

	binary.Read(r, binary.BigEndian, &v.Nonce)
	userAgent, err := varint.ReadString(r, 5000)
	if err != nil {
		return err
	}
	v.UserAgent = userAgent
	streamsSize, err := varint.Read(r)
	if err != nil {
		return err
	}
	if streamsSize > 160000 {
		return errors.New("Too many streams")
	}
	v.Streams = make([]uint64, streamsSize)
	for i := uint64(0); i < streamsSize; i++ {
		stream, err := varint.Read(r)
		if err != nil {
			return err
		}
		v.Streams[i] = stream
	}
	return nil
}

type Address struct {
	Time     uint64
	Stream   uint32
	Services uint64
	IP       net.IP
	Port     uint16
}

type Addr []Address

func (a *Addr) Marshal() []byte {
	w := new(bytes.Buffer)
	varint.Write(w, uint64(len(*a)))
	for _, address := range *a {
		binary.Write(w, binary.BigEndian, address.Time)
		binary.Write(w, binary.BigEndian, address.Stream)
		binary.Write(w, binary.BigEndian, address.Services)
		w.Write(address.IP)
		binary.Write(w, binary.BigEndian, address.Port)
	}
	return w.Bytes()
}
func (a *Addr) Unmarshal(b []byte) error {
	r := bytes.NewBuffer(b)
	size, err := varint.Read(r)
	if err != nil {
		return err
	}
	if size > 1000 {
		return errors.New("Too many addresses")
	}
	*a = make([]Address, size)
	for i := uint64(0); i < size; i++ {
		address := Address{}
		binary.Read(r, binary.BigEndian, &address.Time)
		binary.Read(r, binary.BigEndian, &address.Stream)
		binary.Read(r, binary.BigEndian, &address.Services)
		address.IP = make([]byte, 16)
		io.ReadFull(r, address.IP)
		binary.Read(r, binary.BigEndian, &address.Port)
		(*a)[i] = address
	}
	return nil
}

type Collection []string

func (in *Collection) Marshal() []byte {
	w := new(bytes.Buffer)
	varint.Write(w, uint64(len(*in)))
	for _, hash := range *in {
		w.Write([]byte(hash))
	}
	return w.Bytes()
}
func (in *Collection) Unmarshal(b []byte) error {
	r := bytes.NewBuffer(b)
	size, err := varint.Read(r)
	if err != nil {
		return err
	}
	if size > 50000 {
		return errors.New("Too many hashes")
	}
	*in = make([]string, size)
	for i := uint64(0); i < size; i++ {
		hash := make([]byte, 32)
		io.ReadFull(r, hash)
		(*in)[i] = string(hash)
	}
	return nil
}
