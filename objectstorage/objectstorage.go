package objectstorage

import "errors"

type ObjectStorage interface {
	Put(hash []byte, obj []byte) error
	Get(hash []byte) ([]byte, error)
	Exists(hash []byte) (bool, error)
	Delete(hash []byte) error
	Hashes() ([][]byte, error)
	Len() (int, error)
	Memory() (int64, error)
}

type mapObjectStorage map[string][]byte

func NewMap() ObjectStorage {
	return mapObjectStorage(make(map[string][]byte))
}

func (m mapObjectStorage) Put(hash []byte, obj []byte) error {
	m[string(hash)] = obj
	return nil
}

func (m mapObjectStorage) Get(hash []byte) ([]byte, error) {
	obj, ok := m[string(hash)]
	if !ok {
		return nil, errors.New("Not found")
	}
	return obj, nil
}

func (m mapObjectStorage) Exists(hash []byte) (bool, error) {
	_, ok := m[string(hash)]
	return ok, nil
}

func (m mapObjectStorage) Delete(hash []byte) error {
	delete(m, string(hash))
	return nil
}

func (m mapObjectStorage) Hashes() ([][]byte, error) {
	var hashes [][]byte
	for hash := range m {
		hashes = append(hashes, []byte(hash))
	}
	return hashes, nil
}

func (m mapObjectStorage) Len() (int, error) {
	return len(m), nil
}

func (m mapObjectStorage) Memory() (int64, error) {
	memory := int64(0)
	for _, obj := range m {
		memory += int64(len(obj))
	}
	return memory, nil
}
