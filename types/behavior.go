package types

type Behavior uint32

const (
	Behavior_DoesAck Behavior = 1 << iota
	Behavior_IncludeDestination
	Behavior_ExtendedEncoding
)
