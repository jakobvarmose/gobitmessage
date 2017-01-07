package pow

import (
	"context"
	"crypto/sha512"
	"encoding/binary"
	"math"
	"time"
)

func ComputeDefault(ctx context.Context, data []byte) error {
	return Compute(ctx, data, 1000, 1000)
}

func Compute(ctx context.Context, data []byte, trials int, extra int) error {
	ttl := int64(binary.BigEndian.Uint64(data[8:16])) - time.Now().Unix()
	println(ttl)
	target := uint64(math.Pow(2, 64) / (float64(trials) * (float64(len(data)) + float64(extra) + (float64(ttl)*(float64(len(data))+float64(extra)))/math.Pow(2, 16))))
	buffer := make([]byte, 8+64)
	initial := sha512.Sum512(data[8:])
	copy(buffer[8:], initial[:])
	stop := false
	ch := make(chan struct{})
	i := uint64(0)
	go func() {
		for !stop {
			binary.BigEndian.PutUint64(buffer[:8], i)
			hash1 := sha512.Sum512(buffer)
			hash2 := sha512.Sum512(hash1[:])
			value := binary.BigEndian.Uint64(hash2[:8])
			if value <= target {
				break
			}
			i++
		}
		ch <- struct{}{}
	}()
	select {
	case <-ctx.Done():
		stop = true
		<-ch
		return ctx.Err()
	case <-ch:
		binary.BigEndian.PutUint64(data[:8], i)
		return nil
	}
}

func Verify(data []byte, trials int, extra int) bool {
	ttl := int64(binary.BigEndian.Uint64(data[8:16])) - (time.Now().Unix() + 3600 /*PyBitmessage does not add this, but I think it should*/)
	if ttl < 300 {
		ttl = 300
	}
	target := uint64(math.Pow(2, 64) / (float64(trials) * (float64(len(data)) + float64(extra) + (float64(ttl)*(float64(len(data))+float64(extra)))/math.Pow(2, 16))))
	initial := sha512.Sum512(data[8:])
	buffer := make([]byte, 8+64)
	copy(buffer[:8], data[:8])
	copy(buffer[8:], initial[:])
	hash1 := sha512.Sum512(buffer)
	hash2 := sha512.Sum512(hash1[:])
	value := binary.BigEndian.Uint64(hash2[:8])
	if value <= target {
		return true
	}
	return false
}
