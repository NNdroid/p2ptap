package node

import (
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
)

func TestPeerStreamsSnapshotReadsDoNotWaitForTopologyMutex(t *testing.T) {
	ps := NewPeerStreams(peer.ID("snapshot-peer"))
	ps.mu.Lock()
	ps.streams["/ip4/127.0.0.1/tcp/12345"] = nil
	ps.rebuildLocked()
	ps.mu.Unlock()

	ps.mu.Lock()
	done := make(chan struct{}, 1)
	go func() {
		streams := ps.GetAllStreams()
		if len(streams) != 1 {
			t.Errorf("GetAllStreams len = %d, want 1", len(streams))
		}
		if (&Node{}).maxFragPayloadForPS(ps) != maxFragPayloadStream {
			t.Error("stream fragment policy did not use snapshot")
		}
		done <- struct{}{}
	}()
	select {
	case <-done:
		ps.mu.Unlock()
	case <-time.After(500 * time.Millisecond):
		ps.mu.Unlock()
		t.Fatal("peer stream snapshot read blocked behind topology mutex")
	}
}

func TestPeerStreamsSnapshotTracksMixedTransport(t *testing.T) {
	ps := NewPeerStreams(peer.ID("mixed-peer"))
	ps.mu.Lock()
	ps.streams["/ip4/10.0.0.1/tcp/1234"] = nil
	ps.rebuildLocked()
	ps.mu.Unlock()
	if (&Node{}).maxFragPayloadForPS(ps) != maxFragPayloadStream {
		t.Fatal("TCP snapshot should use the reliable-stream limit")
	}

	ps.mu.Lock()
	ps.streams["/ip4/10.0.0.1/udp/1234/quic-v1"] = nil
	ps.rebuildLocked()
	ps.mu.Unlock()
	if (&Node{}).maxFragPayloadForPS(ps) != maxFragPayloadStream {
		t.Fatal("mixed TCP/QUIC snapshot should use the reliable-stream limit")
	}
}

func BenchmarkPeerStreamsSnapshotParallel(b *testing.B) {
	ps := NewPeerStreams(peer.ID("benchmark-peer"))
	ps.mu.Lock()
	ps.streams["/ip4/127.0.0.1/tcp/12345"] = nil
	ps.rebuildLocked()
	ps.mu.Unlock()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = ps.GetAllStreams()
			_ = (&Node{}).maxFragPayloadForPS(ps)
		}
	})
}
