package node

import (
	"bytes"
	"context"
	"fmt"
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	"p2ptap/pkg/config"
	"p2ptap/pkg/obfuscate"
	vswitch "p2ptap/pkg/switch"
	"p2ptap/pkg/tap"
)

type coalescedTestStream struct {
	strategyDeadlineStream
	writes int
}

func (s *coalescedTestStream) Write(p []byte) (int, error) {
	s.writes++
	return s.mockWriteStream.Write(p)
}

func TestStrategyBatchCoalescesWithoutLosingCopies(t *testing.T) {
	for _, count := range []int{1, 32, 65} {
		for _, mode := range []string{"best_path", "fallback", "redundant"} {
			t.Run(fmt.Sprintf("%s/%d", mode, count), func(t *testing.T) {
				sd := NewStrategyDispatcher(nil, mode)
				pid := peer.ID("batch-peer")
				streams := []*coalescedTestStream{{}, {}}
				for i, stream := range streams {
					sd.RegisterStream(pid, fmt.Sprint(i), stream)
				}
				frames := make([][]byte, count)
				for i := range frames {
					frames[i] = bytes.Repeat([]byte{byte(i)}, 100)
				}
				if err := sd.SendBatchToPeer(context.Background(), pid, frames); err != nil {
					t.Fatal(err)
				}
				copies := 0
				for _, stream := range streams {
					if stream.writes == 0 {
						continue
					}
					copies++
					if stream.writes != (count+31)/32 {
						t.Fatalf("transport writes=%d, want bounded batches", stream.writes)
					}
					for i, want := range frames {
						buf := make([]byte, 100)
						n, err := ReadFrame(&stream.buf, buf)
						if err != nil || !bytes.Equal(buf[:n], want) {
							t.Fatalf("frame %d differs: %v", i, err)
						}
					}
					if stream.buf.Len() != 0 {
						t.Fatal("unexpected trailing bytes")
					}
				}
				wantCopies := 1
				if mode == "redundant" {
					wantCopies = 2
				}
				if copies != wantCopies {
					t.Fatalf("copies=%d, want %d", copies, wantCopies)
				}
			})
		}
	}
}

type prefixFailBatchStream struct {
	strategyDeadlineStream
	prefix int
}

func (s *prefixFailBatchStream) Write(p []byte) (int, error) {
	n, _ := s.buf.Write(p[:min(s.prefix, len(p))])
	return n, timeoutReadError{}
}

func TestStrategyBatchPartialWriteRecoversWithoutDuplicateDelivery(t *testing.T) {
	pid := peer.ID("timeout-peer")
	packer := obfuscate.NewFramePackerFull(nil)
	var frames [][]byte
	for i := 1; i <= 3; i++ {
		payload := make([]byte, 64)
		payload[0], payload[5], payload[6], payload[63] = 2, 1, 2, byte(i)
		frame := make([]byte, packer.MaxPackedLen(len(payload)))
		n, err := packer.Pack(packer.MakeSeqID(uint64(i), 222), payload, frame)
		if err != nil {
			t.Fatal(err)
		}
		frames = append(frames, frame[:n])
	}
	for _, mode := range []string{"best_path", "fallback", "redundant"} {
		t.Run(mode, func(t *testing.T) {
			old := &prefixFailBatchStream{prefix: frameLenSize + len(frames[0])}
			fresh := &strategyReplacementStream{}
			sd := NewStrategyDispatcher(&strategyReplacementHost{stream: fresh}, mode)
			sd.RegisterStream(pid, "old", old)
			if err := sd.SendBatchToPeer(context.Background(), pid, frames); err != nil {
				t.Fatal(err)
			}
			if old.resets != 1 {
				t.Fatal("partially written stream not reset")
			}
			cfg := config.DefaultConfig()
			cfg.PSK = ""
			dev, pipe := tap.NewMemTAPPair("batch-rx", "batch-pipe")
			defer dev.Close()
			defer pipe.Close()
			rx := &Node{Config: cfg, TAP: dev, Collector: noopCollector{},
				Dispatcher: NewStrategyDispatcher(nil, mode), Packer: packer,
				dedupPeers: make(map[peer.ID]*obfuscate.Deduplicator),
				MACTable:   vswitch.NewMACTable(), IPTracker: NewIPTrafficTracker(),
				tapWriteCh: make(chan tapWriteJob, 8)}
			rx.SetConfig(cfg)
			rx.anchorDedupForPeer(pid, 0, 222)
			for _, wire := range [][]byte{old.buf.Bytes(), fresh.buf.Bytes()} {
				rx.handleStream(&epochInputStream{input: bytes.NewReader(wire)})
			}
			if len(rx.tapWriteCh) != 3 {
				t.Fatalf("TAP deliveries=%d, want 3 despite retrying delivered prefix", len(rx.tapWriteCh))
			}
			for i := 1; i <= 3; i++ {
				job := <-rx.tapWriteCh
				if len(job.data) != 64 || job.data[63] != byte(i) {
					t.Fatalf("delivery %d corrupted or out of order", i)
				}
				releaseFrameBuf(job.data)
			}
		})
	}
}

func TestStrategyBatchKeepsEncryptedFragmentsDistinct(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Obfuscation.MaxFragSize = 512
	packer := obfuscate.NewFramePackerFull(nil)
	n := &Node{Config: cfg, Packer: packer, fragRX: newFragReassembler()}
	n.SetConfig(cfg)
	sd := NewStrategyDispatcher(nil, "redundant")
	sd.SetNode(n)
	pid := peer.ID("fragment-batch-peer")
	ps := sd.GetOrCreatePeerStreams(pid)
	stream := &coalescedTestStream{}
	ps.AddStream("quic", stream)
	cipher, err := obfuscate.NewObfCipher(obfuscate.ObfAlgoChaCha20, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	var originals [][]byte
	for i := 1; i <= 3; i++ {
		payload := bytes.Repeat([]byte{byte(i)}, 1500)
		frame := make([]byte, packer.MaxPackedLen(len(payload)))
		size, err := packer.Pack(packer.NextSeqID(1), payload, frame)
		if err != nil {
			t.Fatal(err)
		}
		originals = append(originals, frame[:size])
	}
	ps.writeMu.Lock()
	err = sd.writePackedBatchLocked(pid, ps, cipher, originals)
	ps.writeMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	rx := newFragReassembler()
	complete := 0
	for stream.buf.Len() > 0 {
		wire := make([]byte, 4096)
		size, err := ReadFrame(&stream.buf, wire)
		if err != nil {
			t.Fatal(err)
		}
		outer, err := obfuscate.DecryptPayloadRegion(wire[:size], cipher)
		if err != nil {
			t.Fatal(err)
		}
		_, chunk, err := obfuscate.Unpack(outer)
		if err != nil {
			t.Fatal(err)
		}
		sealed, ok := rx.reassemble(pid, chunk, reasmChannelDirect)
		if !ok {
			continue
		}
		frame, err := obfuscate.DecryptPayloadRegion(sealed, cipher)
		if err != nil || complete >= len(originals) || !bytes.Equal(frame, originals[complete]) {
			t.Fatalf("completed frame %d corrupted: %v", complete, err)
		}
		complete++
	}
	if complete != len(originals) {
		t.Fatalf("completed frames=%d, want %d", complete, len(originals))
	}
}
