package crypt

import "errors"

func pad(data []byte, size int) []byte {
	count := size - len(data)%size
	for i := 0; i < count; i++ {
		data = append(data, byte(count))
	}
	return data
}

func unpad(data []byte, size int) ([]byte, error) {
	if len(data) == 0 || len(data)%size != 0 {
		return nil, errors.New("Invalid data length")
	}
	count := data[len(data)-1]
	if count == 0 || int(count) > size {
		return nil, errors.New("Invalid padding size")
	}
	for i := len(data) - int(count); i < len(data)-1; i++ {
		if data[i] != count {
			return nil, errors.New("Invalid padding")
		}
	}
	return data[:len(data)-int(count)], nil
}
