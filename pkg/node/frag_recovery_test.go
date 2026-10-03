package node

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"p2ptap/pkg/config"
	"p2ptap/pkg/obfuscate"
	"p2ptap/pkg/routing"
	vswitch "p2ptap/pkg/switch"
	"p2ptap/pkg/tap"
)

func TestFragReassembleEpochAndChannelIsolation(t *testing.T) {
	f := newFragReassembler()
	pid := newTestPeerID(t)
	for _, channel := range []uint8{reasmChannelDirect, reasmChannelRelay} {
		for _, epoch := range []uint64{111, 222} {
			f.reassemble(pid, appendFragHeader(nil, 7, 0, 2, []byte{byte(channel), byte(epoch)}), channel, epoch)
		}
	}
	for _, channel := range []uint8{reasmChannelDirect, reasmChannelRelay} {
		for _, epoch := range []uint64{222, 111} {
			out, complete := f.reassemble(pid, appendFragHeader(nil, 7, 1, 2, []byte("tail")), channel, epoch)
			want := append([]byte{byte(channel), byte(epoch)}, []byte("tail")...)
			if !complete || !bytes.Equal(out, want) {
				t.Fatalf("epoch=%d channel=%d mixed fragments: %x", epoch, channel, out)
			}
		}
	}
}

func TestFragReassembleRejectsMalformedEnvelopeWithoutAllocation(t *testing.T) {
	pid := newTestPeerID(t)
	cases := map[string][]byte{
		"zero total":      appendFragHeader(nil, 1, 0, 0, []byte("x")),
		"single index":    appendFragHeader(nil, 1, 1, 1, []byte("x")),
		"multi index":     appendFragHeader(nil, 1, 2, 2, []byte("x")),
		"empty chunk":     appendFragHeader(nil, 1, 0, 2, nil),
		"length mismatch": appendFragHeader(nil, 1, 0, 2, []byte("x")),
	}
	binary.BigEndian.PutUint16(cases["length mismatch"][10:12], 2)
	for name, envelope := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFragReassembler()
			if out, complete := f.reassemble(pid, envelope, reasmChannelDirect, 1); complete || out != nil || len(f.bufs) != 0 {
				t.Fatal("malformed envelope delivered or allocated group state")
			}
		})
	}
	f := newFragReassembler()
	f.reassemble(pid, appendFragHeader(nil, 1, 0, 2, []byte("good")), reasmChannelDirect, 1)
	if _, complete := f.reassemble(pid, appendFragHeader(nil, 1, 1, 3, []byte("wrong")), reasmChannelDirect, 1); complete {
		t.Fatal("conflicting part count completed a group")
	}
	out, complete := f.reassemble(pid, appendFragHeader(nil, 1, 1, 2, []byte("tail")), reasmChannelDirect, 1)
	if !complete || string(out) != "goodtail" {
		t.Fatal("conflicting envelope poisoned valid recovery")
	}
}

func TestFragReassembleMaximumSealedFrameAtMinimumChunkSize(t *testing.T) {
	f := newFragReassembler()
	pid := newTestPeerID(t)
	original := bytes.Repeat([]byte{0x5a}, obfuscate.MaxSealedFrameSize)
	total := (len(original) + 255) / 256
	for i := 0; i < total; i++ {
		end := min((i+1)*256, len(original))
		out, complete := f.reassemble(pid, appendFragHeader(nil, 1, uint16(i), uint16(total), original[i*256:end]), reasmChannelDirect, 1)
		if complete != (i == total-1) || (complete && !bytes.Equal(out, original)) {
			t.Fatalf("full sealed-frame reassembly failed at part %d/%d", i, total)
		}
	}
}

func TestFragReassembleCumulativeBytesAbortAndRecover(t *testing.T) {
	f := newFragReassembler()
	pid := newTestPeerID(t)
	chunk := bytes.Repeat([]byte{0x5a}, (maxReasmBytes+1)/2)
	f.reassemble(pid, appendFragHeader(nil, 1, 0, 2, chunk), reasmChannelDirect, 1)
	if out, complete := f.reassemble(pid, appendFragHeader(nil, 1, 1, 2, chunk), reasmChannelDirect, 1); complete || out != nil || len(f.bufs) != 0 {
		t.Fatal("valid envelopes exceeded cumulative byte cap or retained corrupt state")
	}
	f.reassemble(pid, appendFragHeader(nil, 1, 0, 2, []byte("good")), reasmChannelDirect, 1)
	out, complete := f.reassemble(pid, appendFragHeader(nil, 1, 1, 2, []byte("tail")), reasmChannelDirect, 1)
	if !complete || string(out) != "goodtail" {
		t.Fatal("aborted group prevented subsequent recovery")
	}
}

type fragmentIDHost struct {
	host.Host
	pid peer.ID
}

func (h *fragmentIDHost) ID() peer.ID { return h.pid }

type fragmentIDConn struct {
	mockNetConn
	pid peer.ID
}

func (c *fragmentIDConn) RemotePeer() peer.ID { return c.pid }

type fragmentEpochStream struct {
	epochInputStream
	conn network.Conn
}

func (s *fragmentEpochStream) Conn() network.Conn { return s.conn }

// Exercise both production consumers, including replay rejection after a
// control-plane anchor. Old and new sessions reuse the same fragment group ID.
func TestReceiveFragmentEpochRecovery(t *testing.T) {
	for _, path := range []string{"direct", "relay"} {
		t.Run(path, func(t *testing.T) {
			cfg := config.DefaultConfig()
			cfg.PSK = ""
			dev, pipe := tap.NewMemTAPPair("frag-epoch", "frag-pipe")
			defer dev.Close()
			defer pipe.Close()
			pid, local := newTestPeerID(t), newTestPeerID(t)
			n := &Node{Config: cfg, Host: &fragmentIDHost{pid: local}, TAP: dev, Collector: noopCollector{},
				Dispatcher: NewStrategyDispatcher(nil, "redundant"), Packer: obfuscate.NewFramePackerFull(nil),
				fragRX: newFragReassembler(), dedupPeers: make(map[peer.ID]*obfuscate.Deduplicator),
				MACTable: vswitch.NewMACTable(), IPTracker: NewIPTrafficTracker(), tapWriteCh: make(chan tapWriteJob, 8)}
			n.SetConfig(cfg)
			n.anchorDedupForPeer(pid, 0, 222)
			pack := func(seq uint64, payload []byte) []byte {
				buf := make([]byte, n.Packer.MaxPackedLen(len(payload)))
				count, err := n.Packer.Pack(seq, payload, buf)
				if err != nil {
					t.Fatal(err)
				}
				return buf[:count]
			}
			var parts [2][][]byte
			for i, epoch := range []uint64{111, 222} {
				payload := bytes.Repeat([]byte{byte(i + 1)}, 64)
				payload[0], payload[5], payload[6] = 2, 1, 2
				inner := pack(n.Packer.MakeSeqID(1, epoch), payload)
				if path == "relay" {
					envelope, err := routing.PackRelayFrame(local, pid, 3, inner)
					if err != nil {
						t.Fatal(err)
					}
					inner = pack(n.Packer.MakeSeqID(2, epoch), envelope)
				}
				chunks := splitIntoChunks(inner, 2)
				for j, chunk := range chunks {
					parts[i] = append(parts[i], pack(n.Packer.MakeSeqID(uint64(3+j), epoch), appendFragHeader(nil, 7, uint16(j), 2, chunk)))
				}
			}
			var wire bytes.Buffer
			for _, frame := range [][]byte{parts[0][0], parts[1][0], parts[1][1], parts[0][1], parts[1][0], parts[1][1]} {
				if err := WriteFrame(&wire, frame); err != nil {
					t.Fatal(err)
				}
			}
			stream := &fragmentEpochStream{epochInputStream: epochInputStream{input: bytes.NewReader(wire.Bytes())}, conn: &fragmentIDConn{pid: pid}}
			if path == "direct" {
				n.handleStream(stream)
			} else {
				n.handleRelayStream(stream)
			}
			if len(n.tapWriteCh) != 1 {
				t.Fatalf("deliveries=%d, want current session once", len(n.tapWriteCh))
			}
			job := <-n.tapWriteCh
			defer releaseFrameBuf(job.data)
			if len(job.data) != 64 || job.data[63] != 2 {
				t.Fatal("current session corrupted by old fragment")
			}
		})
	}
}
