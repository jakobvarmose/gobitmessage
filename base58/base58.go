package base58

import (
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"math/big"
	"reflect"
	"strings"
)

func encode(input []byte) string {
	chars := "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	x := big.NewInt(0)
	x.SetBytes(input)
	result := ""
	m := big.NewInt(0)
	for x.BitLen() > 0 {
		x.DivMod(x, big.NewInt(58), m)
		result = chars[m.Uint64():m.Uint64()+1] + result
	}
	for _, b := range input {
		if b != 0 {
			break
		}
		result = "1" + result
	}
	return result
}

func decode(input string) ([]byte, bool) {
	chars := "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	x := big.NewInt(0)
	for _, c := range input {
		x.Mul(x, big.NewInt(58))
		i := strings.IndexRune(chars, c)
		if i < 0 {
			return nil, false
		}
		x.Add(x, big.NewInt(int64(i)))
	}
	result := x.Bytes()
	for _, c := range input {
		if strings.IndexRune(chars, c) != 0 {
			break
		}
		result = append([]byte{0}, result...)
	}
	return result, true
}

func EncodeBM(input []byte) string {
	sha := sha512.Sum512(input)
	checksum := sha512.Sum512(sha[:])
	data := make([]byte, len(input)+4)
	copy(data[:len(input)], input)
	copy(data[len(input):], checksum[:4])
	return encode(data)
}

func DecodeBM(text string) ([]byte, error) {
	data, ok := decode(text)
	if !ok {
		return nil, errors.New("Invalid base58")
	}
	if len(data) < 4 {
		return nil, errors.New("Missing checksum")
	}
	sha := sha512.Sum512(data[:len(data)-4])
	checksum := sha512.Sum512(sha[:])
	if !reflect.DeepEqual(checksum[:4], data[len(data)-4:]) {
		return nil, errors.New("Invalid checksum")
	}
	return data[:len(data)-4], nil
}

func EncodeBTC(input []byte) string {
	sha := sha256.Sum256(input)
	checksum := sha256.Sum256(sha[:])
	data := make([]byte, len(input)+4)
	copy(data[:len(input)], input)
	copy(data[len(input):], checksum[:4])
	return encode(data)
}

func DecodeBTC(text string) ([]byte, error) {
	data, ok := decode(text)
	if !ok {
		return nil, errors.New("Invalid base58")
	}
	if len(data) < 4 {
		return nil, errors.New("Missing checksum")
	}
	sha := sha256.Sum256(data[:len(data)-4])
	checksum := sha256.Sum256(sha[:])
	if !reflect.DeepEqual(checksum[:4], data[len(data)-4:]) {
		return nil, errors.New("Invalid checksum")
	}
	return data[:len(data)-4], nil
}
