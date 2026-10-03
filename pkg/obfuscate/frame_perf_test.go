package obfuscate

import (
	"encoding/binary"
	"fmt"
	"testing"

	"p2ptap/pkg/config"
)

func BenchmarkPaddingPack(b *testing.B) {
	for _, size := range []int{64, 512, 1400} {
		for _, mode := range []string{"none", "fixed", "block", "dynamic"} {
			b.Run(fmt.Sprintf("%s/%d", mode, size), func(b *testing.B) {
				fp := NewFramePackerFull(&config.ObfuscationConfig{Enable: mode != "none", Mode: mode, FixedSize: 1500, BlockSize: 256, MaxSize: 1500})
				payload := make([]byte, size)
				out := make([]byte, MaxFrameSize)
				b.SetBytes(int64(size))
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if _, err := fp.Pack(uint64(i), payload, out); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}

func BenchmarkFrameSeal(b *testing.B) {
	for _, algo := range []byte{ObfAlgoAESGCM, ObfAlgoChaCha20} {
		for _, reuse := range []bool{false, true} {
			b.Run(fmt.Sprintf("%s/reuse=%t", AlgoName(algo), reuse), func(b *testing.B) {
				cipher, err := NewObfCipher(algo, make([]byte, 32))
				if err != nil {
					b.Fatal(err)
				}
				fp := NewFramePackerFull(&config.ObfuscationConfig{Enable: true, Mode: "fixed", FixedSize: 1500})
				fp.SetSendAlgo(algo)
				frame := make([]byte, MaxSealedFrameSize)
				n, err := fp.Pack(1, make([]byte, 1200), frame)
				if err != nil {
					b.Fatal(err)
				}
				var dst []byte
				if reuse {
					dst = make([]byte, 0, MaxSealedFrameSize)
				}
				b.SetBytes(1200)
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					binary.BigEndian.PutUint64(frame[2:10], uint64(i))
					if _, err := EncryptPayloadRegionInto(dst, frame[:n], cipher); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}
func BenchmarkPaddingParallel(b *testing.B) {
	b.SetBytes(1500)
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		buf := make([]byte, 1500)
		for pb.Next() {
			fillRandom(buf)
		}
	})
}
