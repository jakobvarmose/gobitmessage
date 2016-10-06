package varint

import (
	"encoding/binary"
	"errors"
	"io"
)

func Write(w io.Writer, i uint64) error {
	if i <= 252 {
		return binary.Write(w, binary.BigEndian, uint8(i))
	} else if i <= 0xffff {
		err := binary.Write(w, binary.BigEndian, uint8(253))
		if err != nil {
			return err
		}
		return binary.Write(w, binary.BigEndian, uint16(i))
	} else if i <= 0xffffffff {
		err := binary.Write(w, binary.BigEndian, uint8(254))
		if err != nil {
			return err
		}
		return binary.Write(w, binary.BigEndian, uint32(i))
	} else {
		err := binary.Write(w, binary.BigEndian, uint8(255))
		if err != nil {
			return err
		}
		return binary.Write(w, binary.BigEndian, uint64(i))
	}
}

func Read(r io.Reader) (uint64, error) {
	var i uint8
	err := binary.Read(r, binary.BigEndian, &i)
	if err != nil {
		return 0, err
	}
	if i <= 252 {
		return uint64(i), nil
	} else if i == 253 {
		var j uint16
		err = binary.Read(r, binary.BigEndian, &j)
		if err != nil {
			return 0, err
		}
		return uint64(j), nil
	} else if i == 254 {
		var j uint32
		err = binary.Read(r, binary.BigEndian, &j)
		if err != nil {
			return 0, err
		}
		return uint64(j), nil
	} else {
		var j uint64
		err = binary.Read(r, binary.BigEndian, &j)
		if err != nil {
			return 0, err
		}
		return uint64(j), nil
	}
}

func WriteString(w io.Writer, str string) error {
	if err := Write(w, uint64(len(str))); err != nil {
		return err
	}
	if _, err := w.Write([]byte(str)); err != nil {
		return err
	}
	return nil
}

func ReadString(r io.Reader, max int) (string, error) {
	size, err := Read(r)
	if err != nil {
		return "", err
	}
	if size > uint64(max) {
		return "", errors.New("String too long")
	}
	str := make([]byte, size)
	if _, err := io.ReadFull(r, str); err != nil {
		return "", err
	}
	return string(str), nil
}
