package node

import (
	"bytes"
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	"p2ptap/pkg/config"
	"p2ptap/pkg/logger"
	"p2ptap/pkg/obfuscate"
)

type sealCountingCipher struct {
	obfuscate.ObfCipher
	seals int
}

func (c *sealCountingCipher) SealTo(dst, nonce, plaintext []byte) []byte {
	c.seals++
	return c.ObfCipher.SealTo(dst, nonce, plaintext)
}

func BenchmarkEncryptStreamFrame(b *testing.B) {
	logger.SetGlobalLevel(logger.LevelInfo)
	defer logger.SetGlobalLevel(logger.LevelDebug)
	cfg := config.DefaultConfig()
	packer := obfuscate.NewFramePackerFull(nil)
	n := &Node{Config: cfg, Packer: packer, fragRX: newFragReassembler()}
	n.SetConfig(cfg)
	sd := NewStrategyDispatcher(nil, "best_path")
	sd.SetNode(n)
	pid := peer.ID("stream-frag-bench")
	original := makePackedFragmentTestFrame(b, packer, 1500)
	baseCipher, err := obfuscate.NewObfCipher(obfuscate.ObfAlgoChaCha20, make([]byte, 32))
	if err != nil {
		b.Fatal(err)
	}
	for _, limit := range []struct {
		name string
		size int
	}{{"udp_mtu", n.maxFragPayload()}, {"reliable_stream", 65400}} {
		b.Run(limit.name, func(b *testing.B) {
			cipher := &sealCountingCipher{ObfCipher: baseCipher}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				frags, _, pooled, err := sd.encryptAndFragment(pid, cipher, original, limit.size)
				if err != nil {
					b.Fatal(err)
				}
				if pooled {
					releaseFragmentBuffers(frags)
				}
			}
			b.ReportMetric(float64(cipher.seals)/float64(b.N), "seals/frame")
		})
	}
}

func TestStreamFragmentPolicyPreservesExplicitLimit(t *testing.T) {
	cfg := config.DefaultConfig()
	packer := obfuscate.NewFramePackerFull(nil)
	n := &Node{Config: cfg, Packer: packer, fragRX: newFragReassembler()}
	n.SetConfig(cfg)
	sd := NewStrategyDispatcher(nil, "best_path")
	sd.SetNode(n)
	pid := peer.ID("stream-frag-peer")
	baseCipher, err := obfuscate.NewObfCipher(obfuscate.ObfAlgoChaCha20, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	original := makePackedFragmentTestFrame(t, packer, 1500)
	for _, transport := range []string{"/tcp/1234", "/udp/1234/quic-v1", "/udp/1234/webrtc-direct", "/udp/1234/quic-v1/webtransport", "/p2p-circuit"} {
		ps := NewPeerStreams(pid)
		ps.AddStream(transport, &strategyDeadlineStream{})
		for _, explicit := range []int{0, 512} {
			cfg.Obfuscation.MaxFragSize = explicit
			n.SetConfig(cfg)
			cipher := &sealCountingCipher{ObfCipher: baseCipher}
			frags, _, pooled, err := sd.encryptAndFragment(pid, cipher, original, n.maxFragPayloadForPS(ps))
			if err != nil {
				t.Fatal(err)
			}
			if pooled {
				defer releaseFragmentBuffers(frags)
			}
			if explicit == 0 {
				if len(frags) != 1 || cipher.seals != 1 {
					t.Fatalf("stream frame: fragments=%d seals=%d, want 1 each", len(frags), cipher.seals)
				}
				plain, err := obfuscate.DecryptPayloadRegion(frags[0], baseCipher)
				if err != nil || !bytes.Equal(plain, original) {
					t.Fatalf("unfragmented encrypted frame changed: %v", err)
				}
			} else if len(frags) < 2 || cipher.seals != len(frags)+1 {
				t.Fatal("explicit fragmentation bypassed, or encryption accounting lost")
			}
		}
	}
}
