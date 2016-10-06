package types

type Tagged struct {
	Tag       [32]byte
	Encrypted []byte
}

const (
	Type_Getpubkey uint32 = iota
	Type_Pubkey
	Type_Msg
	Type_Broadcast
)
