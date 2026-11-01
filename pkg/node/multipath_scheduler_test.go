package node

import (
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"
)

// pathTestConn pins a remote multiaddr and remote peer so scoreStreamTransport
// classifies the path (loopback / LAN / WAN / circuit-relay) exactly like a real
// connection, including the relay signal: a relay path's underlying transport
// connection terminates at a HOP, so its RemotePeer() differs from the target
// peer (see connIsRelayForPeer). A direct path's RemotePeer() equals the target.
type pathTestConn struct {
	mockNetConn
	ma         ma.Multiaddr
	remotePeer peer.ID
}

func (c *pathTestConn) RemoteMultiaddr() ma.Multiaddr { return c.ma }
func (c *pathTestConn) RemotePeer() peer.ID           { return c.remotePeer }

// pathTestStream is a mock stream whose connection reports a fixed multiaddr.
type pathTestStream struct {
	mockWriteStream
	ma         ma.Multiaddr
	remotePeer peer.ID
}

func (s *pathTestStream) Conn() network.Conn {
	return &pathTestConn{ma: s.ma, remotePeer: s.remotePeer}
}

func TestMultipathSingleStreamFallsBack(t *testing.T) {
	ps := NewPeerStreams(peer.ID("mp-single"))
	streams := []network.Stream{&pathTestStream{ma: mustMA("/ip4/10.0.0.1/tcp/4001")}}
	if got := ps.pickMultipathStreamIndex(streams, time.Now()); got != 0 {
		t.Fatalf("single-stream pick = %d, want 0", got)
	}
}

func TestMultipathNoStreamsReturnsMinusOne(t *testing.T) {
	ps := NewPeerStreams(peer.ID("mp-none"))
	if got := ps.pickMultipathStreamIndex(nil, time.Now()); got != -1 {
		t.Fatalf("empty pick = %d, want -1", got)
	}
}

func TestMultipathFollowsTopologyNominal(t *testing.T) {
	// No write measurements yet: weights come from the topology-score nominal
	// capacity. A LAN path (5e8) should dominate a circuit-relay path (5e6), but
	// the 5% min-share floor must keep the slow path alive so its measurement
	// can accumulate.
	ps := NewPeerStreams(peer.ID("mp-topology"))
	lan := &pathTestStream{ma: mustMA("/ip4/192.168.1.5/tcp/4001"), remotePeer: peer.ID("mp-topology")}
	relay := &pathTestStream{ma: mustMA("/ip4/100.64.0.1/tcp/4002/p2p-circuit"), remotePeer: peer.ID("mp-hop")}
	streams := []network.Stream{lan, relay}

	const n = 4000
	counts := make([]int, len(streams))
	for i := 0; i < n; i++ {
		counts[ps.pickMultipathStreamIndex(streams, time.Now())]++
	}

	if counts[0] == 0 || counts[1] == 0 {
		t.Fatalf("both paths must carry traffic (min-share floor): counts=%v", counts)
	}
	// The LAN path must carry the majority.
	if counts[0] <= counts[1] {
		t.Fatalf("LAN path should dominate relay path: counts=%v", counts)
	}
	// The relay path must stay above ~2% of frames (floor is 5% of weight, not
	// frames, but a wide margin keeps the test robust against DWRR rounding).
	relayShare := float64(counts[1]) / float64(n)
	if relayShare < 0.02 {
		t.Fatalf("relay share = %.4f, want >= 0.02 (min-share floor not honored)", relayShare)
	}
}

func TestMultipathMeasuredCapacityDominates(t *testing.T) {
	// Both paths measured: the fast path (low nanosPerByte) should carry nearly
	// all traffic, while the slow path keeps a nonzero share.
	ps := NewPeerStreams(peer.ID("mp-measured"))
	fast := &pathTestStream{ma: mustMA("/ip4/192.168.1.5/tcp/4001"), remotePeer: peer.ID("mp-measured")}
	slow := &pathTestStream{ma: mustMA("/ip4/100.64.0.1/tcp/4002/p2p-circuit"), remotePeer: peer.ID("mp-hop")}
	streams := []network.Stream{fast, slow}
	now := time.Now()

	// Fast: 1ns/byte ≈ 1 GB/s. Slow: 20µs/byte ≈ 50 KB/s (well below the 5% floor
	// of the fast path, so the floor lifts it to keep it alive).
	ps.recordStreamWrite(fast, 64*1024, 64*1024*time.Nanosecond, now)     // 1 ns/B
	ps.recordStreamWrite(slow, 64*1024, 64*1024*20*time.Microsecond, now) // 20 µs/B
	// recordStreamWrite accumulates; pad to usable thresholds (>=3 samples, >=32KB).
	for i := 0; i < 4; i++ {
		ps.recordStreamWrite(fast, 32*1024, 32*1024*time.Nanosecond, now.Add(time.Duration(i)*time.Millisecond))
		ps.recordStreamWrite(slow, 32*1024, 32*1024*20*time.Microsecond, now.Add(time.Duration(i)*time.Millisecond))
	}

	const n = 4000
	counts := make([]int, len(streams))
	for i := 0; i < n; i++ {
		counts[ps.pickMultipathStreamIndex(streams, now)]++
	}

	if counts[0] == 0 || counts[1] == 0 {
		t.Fatalf("both paths must carry traffic: counts=%v", counts)
	}
	if counts[0] <= counts[1] {
		t.Fatalf("measured fast path should dominate: counts=%v", counts)
	}
}

func TestMultipathDeficitStaysBounded(t *testing.T) {
	// DWRR must keep deficits bounded (weights normalized to sum to 1), so no
	// single path accumulates an ever-growing lead.
	ps := NewPeerStreams(peer.ID("mp-bounded"))
	lan := &pathTestStream{ma: mustMA("/ip4/192.168.1.5/tcp/4001"), remotePeer: peer.ID("mp-bounded")}
	wan := &pathTestStream{ma: mustMA("/ip4/203.0.113.9/tcp/4001"), remotePeer: peer.ID("mp-bounded")}
	streams := []network.Stream{lan, wan}

	const n = 2000
	var maxDeficit float64
	for i := 0; i < n; i++ {
		ps.pickMultipathStreamIndex(streams, time.Now())
		for _, s := range streams {
			if d := ps.mpDeficit[s]; d > maxDeficit {
				maxDeficit = d
			}
		}
	}
	// Weights sum to 1, each step credits <=1 and debits exactly 1 from the
	// chosen stream, so deficit stays within a couple of units of a bounded
	// steady state. Anything above ~4 signals unbounded accumulation.
	if maxDeficit > 4 {
		t.Fatalf("DWRR deficit grew unbounded: max=%.4f", maxDeficit)
	}
}

// Congestion (writer queue full) must arm the SHORT fixed circuit, never the
// exponential one: a merely busy path is eligible again after pathBackoffBase,
// while a path whose writes actually fail keeps doubling up to pathBackoffMax.
// Success clears either circuit entirely.
func TestMpCongestionBackoffStaysAtBase(t *testing.T) {
	ps := NewPeerStreams(peer.ID("mp-congest"))
	s := &pathTestStream{ma: mustMA("/ip4/192.168.9.7/tcp/4001")}
	key := "/ip4/192.168.9.7/tcp/4001"
	now := time.Now()

	ps.writeMu.Lock()
	defer ps.writeMu.Unlock()

	// Two congestion events in a row: the cooldown re-arms from the LATEST one
	// and the failure counter is untouched, so nothing can grow exponentially.
	ps.notePathCongestedUnderLock(s, now)
	ps.notePathCongestedUnderLock(s, now.Add(time.Second))
	b := ps.pathBackoff[key]
	if b == nil {
		t.Fatal("congestion did not open a circuit")
	}
	if b.failures != 0 {
		t.Fatalf("congestion bumped the failure counter to %d; want 0", b.failures)
	}
	if got := b.until.Sub(now.Add(time.Second)); got != pathBackoffBase {
		t.Fatalf("congestion cooldown = %v; want exactly %v", got, pathBackoffBase)
	}

	// A real write failure keeps its own doubling on top: first failure cools
	// for base, the second for 2x base.
	t2 := now.Add(3 * time.Second)
	ps.notePathFailureUnderLock(s, t2)
	if got := ps.pathBackoff[key].until.Sub(t2); got != pathBackoffBase {
		t.Fatalf("first real failure cooled for %v; want %v", got, pathBackoffBase)
	}
	t3 := now.Add(6 * time.Second)
	ps.notePathFailureUnderLock(s, t3)
	if got := ps.pathBackoff[key].until.Sub(t3); got != 2*pathBackoffBase {
		t.Fatalf("second real failure cooled for %v; want %v", got, 2*pathBackoffBase)
	}

	// A successful write clears the whole circuit, congestion or not.
	ps.notePathSuccessUnderLock(s)
	if _, ok := ps.pathBackoff[key]; ok {
		t.Fatal("success did not clear the circuit")
	}
}
