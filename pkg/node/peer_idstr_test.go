package node

import (
	"sync"
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
)

// TestPeerIDStringCache verifies the per-peer base58 cache returns the same
// rendering as pid.String() and keeps it stable across calls. This is the
// correctness half of a performance change: the receive path feeds this string
// to string-keyed collector/ACL calls, so a wrong or unstable value would
// corrupt per-peer stats and ACL identity.
func TestPeerIDStringCache(t *testing.T) {
	n := &Node{}
	pid := newTestPeerID(t)

	want := pid.String()
	if got := n.peerIDString(pid); got != want {
		t.Fatalf("first call: got %q want %q", got, want)
	}
	// Second call must hit the published snapshot — same value, no re-render.
	if got := n.peerIDString(pid); got != want {
		t.Fatalf("cached call: got %q want %q", got, want)
	}

	// Distinct peers must not collide in the cache.
	other := newTestPeerID(t)
	if got := n.peerIDString(other); got != other.String() {
		t.Fatalf("second peer: got %q want %q", got, other.String())
	}
	if n.peerIDString(pid) != want {
		t.Fatalf("first peer's rendering changed after caching another peer")
	}
}

// TestPeerIDStringCacheConcurrent is the race-detector companion: many
// goroutines render a small set of peers concurrently, forcing the slow
// publish path to interleave with hot-path snapshot reads.
func TestPeerIDStringCacheConcurrent(t *testing.T) {
	n := &Node{}
	const peers = 8
	ids := make([]peer.ID, peers)
	wants := make([]string, peers)
	for i := range ids {
		ids[i] = newTestPeerID(t)
		wants[i] = ids[i].String()
	}

	var wg sync.WaitGroup
	for g := 0; g < 32; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for r := 0; r < 200; r++ {
				i := (g + r) % peers
				if got := n.peerIDString(ids[i]); got != wants[i] {
					t.Errorf("peer %d: got %q want %q", i, got, wants[i])
					return
				}
			}
		}(g)
	}
	wg.Wait()
}
