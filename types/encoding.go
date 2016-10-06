package types

type Encoding uint64

const (
	Encoding_Ignore Encoding = iota
	Encoding_Trivial
	Encoding_Simple
	Encoding_Extended
)
