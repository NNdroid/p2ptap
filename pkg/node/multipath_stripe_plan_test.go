package node

import (
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"
)

// stripeTestPeerStreams builds a PeerStreams with two mock paths whose measured
// write quality differs ~20x, mimicking "fast Wi-Fi + barely-alive relay" —
// the exact split where weighted shard spreading would concentrate a striped
// frame on the fast path and void the FEC parity bound.
func stripeTestPeerStreams(t *testing.T) (*PeerStreams, *mockStream, *mockStream, []network.Stream) {
	t.Helper()
	ps := NewPeerStreams(peer.ID("12D3KooWStripeTarget"))
	fast := newMockStream(&mockConn{remote: peer.ID("12D3KooWStripeVia"), addr: ma.StringCast("/ip4/127.0.0.1/tcp/10001")})
	slow := newMockStream(&mockConn{remote: peer.ID("12D3KooWStripeVia"), addr: ma.StringCast("/ip4/127.0.0.1/tcp/10002")})
	ps.AddStream("path-fast", fast)
	ps.AddStream("path-slow", slow)
	streams := ps.GetAllStreams()
	if len(streams) != 2 {
		t.Fatalf("expected 2 registered streams, got %d", len(streams))
	}

	now := time.Now()
	// usable() requires >= 3 samples and >= 32 KiB accumulated per stream.
	for i := 0; i < 3; i++ {
		ps.recordStreamWrite(fast, 16*1024, 1*time.Millisecond, now)  // ~33 MB/s
		ps.recordStreamWrite(slow, 16*1024, 20*time.Millisecond, now) // ~20x slower
	}
	return ps, fast, slow, streams
}

func stripeFrags(n int) [][]byte {
	frags := make([][]byte, n)
	for i := range frags {
		frags[i] = make([]byte, 16)
	}
	return frags
}

func planPathCounts(plans []mpFragPlan) map[network.Stream]int {
	counts := make(map[network.Stream]int, len(plans))
	for _, p := range plans {
		counts[p.s] += len(p.frags)
	}
	return counts
}

// TestPlanFragsOnPathsStripeSpreadsEvenly pins the premise fecParityFor's
// parity sizing depends on: a multi-fragment (striped) frame spreads its
// shards EVENLY over the eligible paths, so a single dead path costs at most
// ~total/paths shards — exactly what the parity rebuilds. Under the previous
// per-fragment DWRR pick, the 20x weight split concentrated ~95% of the frame
// on the fast path; a post-write death of that path stranded more shards than
// the parity could rebuild.
func TestPlanFragsOnPathsStripeSpreadsEvenly(t *testing.T) {
	ps, fast, slow, streams := stripeTestPeerStreams(t)
	ps.writeMu.Lock()
	defer ps.writeMu.Unlock()

	plans := ps.planFragsOnPaths(streams, stripeFrags(8))
	counts := planPathCounts(plans)
	if counts[fast] != 4 || counts[slow] != 4 {
		t.Fatalf("stripe not spread evenly over a 20x weight split: fast=%d slow=%d, want 4/4", counts[fast], counts[slow])
	}
}

// TestPlanFragsOnPathsSingleFragmentKeepsWeightedPick pins the other half of
// the contract: the single-fragment common case still rides the DWRR choice,
// which under a 20x weight split is the fast path.
func TestPlanFragsOnPathsSingleFragmentKeepsWeightedPick(t *testing.T) {
	ps, fast, _, streams := stripeTestPeerStreams(t)
	ps.writeMu.Lock()
	defer ps.writeMu.Unlock()

	plans := ps.planFragsOnPaths(streams, stripeFrags(1))
	if len(plans) != 1 || plans[0].s != fast {
		t.Fatalf("single fragment should ride the weighted (fast) path")
	}
}

// TestPlanFragsOnPathsStripeRoutesAroundCoolingPaths pins that a striped frame
// avoids a path inside its post-failure cooldown, and that a stripe spread
// over a SINGLE eligible path still delivers (all shards on the survivor).
func TestPlanFragsOnPathsStripeRoutesAroundCoolingPaths(t *testing.T) {
	ps, fast, slow, streams := stripeTestPeerStreams(t)
	ps.writeMu.Lock()
	defer ps.writeMu.Unlock()

	ps.notePathFailureUnderLock(fast, time.Now())
	plans := ps.planFragsOnPaths(streams, stripeFrags(8))
	counts := planPathCounts(plans)
	if len(plans) != 1 || plans[0].s != slow || counts[slow] != 8 {
		t.Fatalf("stripe should route around the cooling fast path: plans=%d counts=%v", len(plans), counts)
	}
}
