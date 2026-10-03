package node

import (
	"bytes"
	"testing"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"p2ptap/pkg/config"
	"p2ptap/pkg/obfuscate"
	vswitch "p2ptap/pkg/switch"
	"p2ptap/pkg/tap"
)

type epochInputStream struct {
	mockWriteStream
	input *bytes.Reader
}

func (s *epochInputStream) Conn() network.Conn         { return &timeoutReadConn{} }
func (s *epochInputStream) Read(p []byte) (int, error) { return s.input.Read(p) }

func TestReceiveEpochCannotResetReplayWindow(t *testing.T) {
	for _, path := range []string{"direct", "relay"} {
		t.Run(path, func(t *testing.T) {
			cfg := config.DefaultConfig()
			cfg.PSK = ""
			dev, pipe := tap.NewMemTAPPair("epoch-tap", "epoch-pipe")
			defer dev.Close()
			defer pipe.Close()
			n := &Node{
				Config: cfg, TAP: dev, Collector: noopCollector{},
				Dispatcher: NewStrategyDispatcher(nil, "redundant"),
				Packer:     obfuscate.NewFramePackerFull(&cfg.Obfuscation),
				dedupPeers: make(map[peer.ID]*obfuscate.Deduplicator),
				MACTable:   vswitch.NewMACTable(), IPTracker: NewIPTrafficTracker(),
				tapWriteCh: make(chan tapWriteJob, 8),
			}
			n.SetConfig(cfg)
			pid := peer.ID("timeout-peer")
			n.anchorDedupForPeer(pid, 0, 222)
			payload := make([]byte, 64)
			payload[0], payload[5], payload[6] = 2, 1, 2
			var wire bytes.Buffer
			for _, seq := range []uint64{n.Packer.MakeSeqID(1, 222), n.Packer.MakeSeqID(2, 111), n.Packer.MakeSeqID(1, 222), n.Packer.MakeSeqID(3, 222)} {
				if path == "relay" {
					n.deliverRelayedFrameToTAP(bytes.Clone(payload), pid, pid, seq)
					continue
				}
				buf := make([]byte, n.Packer.MaxPackedLen(len(payload)))
				count, err := n.Packer.Pack(seq, payload, buf)
				if err != nil {
					t.Fatal(err)
				}
				if err := WriteFrame(&wire, buf[:count]); err != nil {
					t.Fatal(err)
				}
			}
			if path == "direct" {
				n.handleStream(&epochInputStream{input: bytes.NewReader(wire.Bytes())})
			}
			if got := len(n.tapWriteCh); got != 2 {
				t.Fatalf("got %d accepted frames, want only current-epoch counters 1 and 3", got)
			}
			if epoch := n.dedupPeers[pid].ConnEpoch(); epoch != 222 {
				t.Fatalf("data changed negotiated epoch to %d", epoch)
			}
			for len(n.tapWriteCh) > 0 {
				job := <-n.tapWriteCh
				releaseFrameBuf(job.data)
			}
			// An actual control-plane epoch change must still allow new traffic.
			n.anchorDedupForPeer(pid, 0, 333)
			if n.dedupPeers[pid].IsDuplicate(n.Packer.MakeSeqID(1, 333)) {
				t.Fatal("control-plane epoch change failed")
			}
			if !n.dedupPeers[pid].IsDuplicate(n.Packer.MakeSeqID(4, 222)) {
				t.Fatal("previous epoch accepted after control-plane change")
			}
		})
	}
}
