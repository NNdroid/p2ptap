package obfuscate

import (
	"bytes"
	"fmt"
	"sync"
	"testing"

	"p2ptap/pkg/config"
)

func TestFrameDestinationCapacity(t *testing.T) {
	for _, algo := range []byte{ObfAlgoAESGCM, ObfAlgoChaCha20} {
		for _, size := range []int{0, 64, 1400, 65000} {
			t.Run(fmt.Sprintf("%s/%d", AlgoName(algo), size), func(t *testing.T) {
				cipher, err := NewObfCipher(algo, make([]byte, 32))
				if err != nil {
					t.Fatal(err)
				}
				fp := NewFramePackerFull(&config.ObfuscationConfig{Enable: true, Mode: "fixed", FixedSize: 1500})
				fp.SetSendAlgo(algo)
				plain := make([]byte, MaxFrameSize)
				n, err := fp.Pack(42, bytes.Repeat([]byte{0x5a}, size), plain)
				if err != nil {
					t.Fatal(err)
				}
				original := bytes.Clone(plain[:n])
				dst := make([]byte, n+cipher.Overhead())
				sealed, err := EncryptPayloadRegionInto(dst[:0], plain[:n], cipher)
				if err != nil {
					t.Fatal(err)
				}
				if &sealed[0] != &dst[0] {
					t.Fatal("seal did not reuse exact capacity")
				}
				opened, err := DecryptPayloadRegionInto(plain[:0:n], sealed, cipher)
				if err != nil {
					t.Fatal(err)
				}
				if &opened[0] != &plain[0] {
					t.Fatal("open did not reuse plaintext capacity")
				}
				if !bytes.Equal(opened, original) {
					t.Fatal("header, payload or padding changed")
				}
				sealed[HeaderLen] ^= 1
				if _, err := DecryptPayloadRegionInto(nil, sealed, cipher); err == nil {
					t.Fatal("accepted altered ciphertext")
				}
			})
		}
	}
}

func TestFillRandomConcurrentBoundaries(t *testing.T) {
	var wg sync.WaitGroup
	for worker := 0; worker < 16; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for _, size := range []int{0, 1, 7, 8, 255, 256, 257, 1500, MaxFrameSize} {
				buf := bytes.Repeat([]byte{0xa5}, size+2)
				fillRandom(buf[1 : 1+size])
				if buf[0] != 0xa5 || buf[len(buf)-1] != 0xa5 {
					t.Error("random fill crossed destination boundary")
				}
				if size >= 256 && bytes.Equal(buf[1:1+size], bytes.Repeat([]byte{0xa5}, size)) {
					t.Error("padding was not filled")
				}
			}
		}()
	}
	wg.Wait()
}
