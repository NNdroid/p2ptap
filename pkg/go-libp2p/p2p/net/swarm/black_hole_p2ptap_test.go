package swarm

import "testing"

// p2ptap installs a UDP counter with MinSuccesses = 0, i.e. the filter can
// never block. See the SwarmOpts wiring in pkg/node for why: blocking public
// UDP would strip every direct address from every peer, while hole punching
// and DCUtR are the only way to reach a symmetric-NAT peer at all — and
// p2ptap always has a relay fallback, so the cost of a genuinely blocked UDP
// path is wasted dial time, not lost connectivity.
func TestBlackHoleSuccessCounterZeroMinNeverBlocks(t *testing.T) {
	c := &BlackHoleSuccessCounter{N: 100, MinSuccesses: 0, Name: "UDP"}
	for i := 0; i < c.N*3; i++ {
		c.RecordResult(false)
	}
	if st := c.State(); st != blackHoleStateAllowed {
		t.Fatalf("state = %v, want Allowed", st)
	}
	if st := c.HandleRequest(); st != blackHoleStateAllowed {
		t.Fatalf("HandleRequest = %v, want Allowed", st)
	}
}

// The stock threshold does block, which is the hazard behind the p2ptap
// override. Combined with NoDelayDialRanker — which fires every address of a
// peer at delay 0, so one peer round yields six results instead of one — a
// fleet containing a handful of relay-only peers sinks the success ratio below
// 5% and the filter strips public UDP for every peer on the node for 99 of
// every 100 dial attempts.
func TestBlackHoleSuccessCounterStockThresholdBlocksOnFailures(t *testing.T) {
	c := &BlackHoleSuccessCounter{N: 100, MinSuccesses: 5, Name: "UDP"}
	for i := 0; i < c.N*2; i++ {
		c.RecordResult(false)
	}
	if st := c.State(); st != blackHoleStateBlocked {
		t.Fatalf("state = %v, want Blocked", st)
	}

	// Blocked must be reported to callers: this is what wastes the dial
	// budget, 99 of every 100 requests refused before a single dial starts.
	if st := c.HandleRequest(); st != blackHoleStateBlocked {
		t.Fatalf("HandleRequest = %v, want Blocked", st)
	}

	// A single success does NOT restore Allowed: reset() empties the sample
	// window — and the triggering success is consumed by the reset rather than
	// recorded — so an under-sized window is Probing. FilterAddrs still allows
	// public addresses while probing, so the probe runs and rebuilds a full
	// window before the state can clear.
	c.RecordResult(true)
	if st := c.State(); st != blackHoleStateProbing {
		t.Fatalf("state after one success = %v, want Probing", st)
	}
	for i := 0; i < c.N; i++ {
		c.RecordResult(true)
	}
	if st := c.State(); st != blackHoleStateAllowed {
		t.Fatalf("state after a full window of successes = %v, want Allowed", st)
	}
}
