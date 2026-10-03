package node

import (
	"bytes"
	"context"
	"errors"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"
	"testing"
	"time"
)

type selectionTestConn struct {
	mockNetConn
	addr ma.Multiaddr
}

func (c *selectionTestConn) RemoteMultiaddr() ma.Multiaddr { return c.addr }

type selectionTestStream struct {
	strategyDeadlineStream
	conn network.Conn
}

func (s *selectionTestStream) Conn() network.Conn { return s.conn }

func newSelectionTestStream(t *testing.T, addr string) *selectionTestStream {
	t.Helper()
	m, err := ma.NewMultiaddr(addr)
	if err != nil {
		t.Fatal(err)
	}
	return &selectionTestStream{conn: &selectionTestConn{addr: m}}
}

func TestStreamSelectionStableTopologyOrder(t *testing.T) {
	ps := NewPeerStreams(peer.ID("selection-peer"))
	addrs := []string{"/ip4/10.0.0.2/tcp/1001", "/ip4/10.0.0.2/udp/1002/quic-v1", "/ip4/10.0.0.2/udp/1003/webrtc-direct"}
	for _, addr := range addrs {
		ps.AddStream(addr, newSelectionTestStream(t, addr))
	}
	first := ps.GetAllStreams()[0]
	for i := 0; i < 200; i++ {
		ps.mu.Lock()
		ps.rebuildLocked()
		ps.mu.Unlock()
		if ps.GetAllStreams()[0] != first {
			t.Fatal("unchanged topology changes tie winner")
		}
	}
}

func TestStreamSelectionUsesQualityAndBoundsExploration(t *testing.T) {
	slow := newSelectionTestStream(t, "/ip4/10.0.0.2/tcp/1")
	fast := newSelectionTestStream(t, "/ip4/10.0.0.2/udp/2/quic-v1")
	ps := NewPeerStreams(peer.ID("quality-peer"))
	ps.AddStream("a", slow)
	ps.AddStream("b", fast)
	streams := ps.GetAllStreams()
	now := time.Unix(1700000000, 0)
	if got := ps.selectStreamIndex(streams, now); got != 0 {
		t.Fatal("initial stable policy changed")
	}
	for i := 0; i < 3; i++ {
		ps.recordStreamWrite(slow, 32768, 20*time.Millisecond, now)
		ps.recordStreamWrite(fast, 32768, 2*time.Millisecond, now)
	}
	// No early switch or unbounded exploratory writes while the interval is active.
	for i := 0; i < 100; i++ {
		if ps.selectStreamIndex(streams, now.Add(100*time.Millisecond)) != 0 {
			t.Fatal("probe escaped interval")
		}
	}
	later := now.Add(4 * time.Second)
	ps.selectStreamIndex(streams, later) // one exploratory batch is allowed
	if ps.preferredStream != fast {
		t.Fatal("measured tenfold faster writer not selected")
	}
	for i := 0; i < 100; i++ {
		if ps.selectStreamIndex(streams, later.Add(time.Millisecond)) != 1 {
			t.Fatal("fast incumbent not retained")
		}
	}
	// A small change does not flap a healthy incumbent.
	ps.writeQuality[slow] = streamWriteQuality{nanosPerByte: ps.writeQuality[fast].nanosPerByte * .95, bytes: 65536, samples: 4, updated: later}
	ps.selectStreamIndex(streams, later.Add(4*time.Second))
	if ps.preferredStream != fast {
		t.Fatal("five percent noise caused transport flap")
	}
	// Removing the chosen stream takes effect without waiting for its hold time.
	ps.RemoveStream("b", fast)
	if got := ps.selectStreamIndex(ps.GetAllStreams(), later.Add(4*time.Second+time.Millisecond)); got != 0 || ps.preferredStream != slow {
		t.Fatal("dead incumbent survived")
	}
}

func TestStreamSelectionIgnoresTinyAndExpiredSamples(t *testing.T) {
	now := time.Unix(1700000000, 0)
	tiny := streamWriteQuality{nanosPerByte: 1, samples: 100, bytes: 100, updated: now}
	if tiny.usable(now) {
		t.Fatal("tiny control writes treated as bulk quality")
	}
	old := streamWriteQuality{nanosPerByte: 1, samples: 100, bytes: 65536, updated: now.Add(-streamQualityFreshFor - time.Second)}
	if old.usable(now) {
		t.Fatal("expired sample controls selection")
	}
}

func TestStreamSelectionFailedProbeRetainsDeliveryAndHealthyIncumbent(t *testing.T) {
	pid := peer.ID("probe-failure")
	good := newSelectionTestStream(t, "/ip4/10.0.0.2/tcp/1")
	bad := newSelectionTestStream(t, "/ip4/10.0.0.2/udp/2/quic-v1")
	bad.writeErr = errors.New("failed alternate")
	sd := NewStrategyDispatcher(nil, "best_path")
	sd.RegisterStream(pid, "a", good)
	sd.RegisterStream(pid, "b", bad)
	ps := sd.GetOrCreatePeerStreams(pid)
	ps.preferredStream = good
	ps.streamSelectedAt = time.Now().Add(-10 * time.Second)
	payload := []byte("delivered after exploratory failure")
	if err := sd.SendBatchToPeer(context.Background(), pid, [][]byte{payload}); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 100)
	count, err := ReadFrame(&good.buf, got)
	if err != nil || !bytes.Equal(got[:count], payload) {
		t.Fatalf("recovery lost payload: %v", err)
	}
	if bad.resets != 1 || len(ps.GetAllStreams()) != 1 {
		t.Fatal("failed probe not retired")
	}
	if ps.preferredStream != good {
		t.Fatal("failed exploration changed healthy incumbent")
	}
}
