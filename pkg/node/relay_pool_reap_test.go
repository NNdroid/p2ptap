package node

import (
	"context"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
)

// TestRelayPoolReapOrphanedConn proves the idle reaper tears down a relay conn
// whose hop is permanently orphaned (circuit-broken AND disconnected), but leaves
// a healthy/connected hop's conn alone. Reaping is what stops the pool from
// leaking a goroutine + 128-slot queue per permanently-dead hop.
func TestRelayPoolReapOrphanedConn(t *testing.T) {
	// nil host => relayHopConnected always false (hop treated as disconnected).
	// fakeRelayNode gives us the blacklist map + methods.
	pool := newRelayStreamPool(context.Background(), nil, fakeRelayNode())
	defer pool.shutdown()

	deadHop := peer.ID("dead-hop")
	aliveHop := peer.ID("alive-hop")

	// Two conns with no running goroutine (manually crafted rc): teardownConn
	// must be safe on them (no-op cancel, empty wg, nil stream).
	mkConn := func(p peer.ID) *relayConn {
		return &relayConn{
			peer:    p,
			cancel:  func() {}, // must NOT panic if nil func — replaced below
			writeCh: make(chan relayJob, relayPoolMaxQueue),
		}
	}

	// Use real cancels that set a flag so we can assert teardown ran.
	deadCancelled := false
	aliveCancelled := false
	deadRC := mkConn(deadHop)
	deadRC.cancel = func() { deadCancelled = true }
	aliveRC := mkConn(aliveHop)
	aliveRC.cancel = func() { aliveCancelled = true }

	pool.mu.Lock()
	pool.conns[deadHop] = deadRC
	pool.conns[aliveHop] = aliveRC
	pool.mu.Unlock()

	// Circuit-break the dead hop so it is blacklisted.
	pool.node.blacklistOverlayRelay(deadHop)

	// Backdate the dead hop's orphan-candidate window so the reap threshold
	// (a full overlayRelayBlacklistTTL) is already met on the first scan.
	pool.mu.Lock()
	pool.candidateSince[deadHop] = time.Now().Add(-2 * overlayRelayBlacklistTTL)
	pool.mu.Unlock()

	pool.reapOrphaned()

	if !deadCancelled {
		t.Fatal("expected orphaned (blacklisted+disconnected) conn to be reaped, but its cancel was not called")
	}
	if _, stillPresent := pool.getMapEntry(deadHop); stillPresent {
		t.Fatal("expected dead hop conn removed from pool.conns after reap")
	}
	if aliveCancelled {
		t.Fatal("expected healthy/connected-hop conn NOT to be reaped, but its cancel was called")
	}
	if _, stillPresent := pool.getMapEntry(aliveHop); !stillPresent {
		t.Fatal("expected alive-hop conn to remain in pool.conns")
	}
	t.Logf("✓ orphaned conn reaped (cancel=%v, removed=%v); connected-hop conn kept (cancel=%v)",
		deadCancelled, !poolHas(pool, deadHop), aliveCancelled)
}

func (p *relayStreamPool) getMapEntry(h peer.ID) (*relayConn, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	rc, ok := p.conns[h]
	return rc, ok
}

func poolHas(p *relayStreamPool, h peer.ID) bool {
	_, ok := p.getMapEntry(h)
	return ok
}

// TestRelayPoolHealthyConnNotReapedOnFirstScan ensures a conn that just became an
// orphan candidate (candidateSince set this scan) is NOT reaped yet — it must
// persist a full overlayRelayBlacklistTTL so a transiently-broken hop that is
// about to recover is not needlessly dropped.
func TestRelayPoolHealthyConnNotReapedOnFirstScan(t *testing.T) {
	pool := newRelayStreamPool(context.Background(), nil, fakeRelayNode())
	defer pool.shutdown()

	hop := peer.ID("transient-hop")
	rc := &relayConn{peer: hop, cancel: func() {}}
	cancelled := false
	rc.cancel = func() { cancelled = true }

	pool.mu.Lock()
	pool.conns[hop] = rc
	pool.mu.Unlock()
	pool.node.blacklistOverlayRelay(hop)

	// First scan: hop is orphaned now, but candidateSince was just recorded —
	// the reap threshold has NOT elapsed, so it must survive.
	pool.reapOrphaned()
	if cancelled {
		t.Fatal("expected conn not reaped on first orphan observation")
	}

	// Second scan immediately after (still within the TTL window) must also keep it.
	pool.reapOrphaned()
	if cancelled {
		t.Fatal("expected conn not reaped before a full overlayRelayBlacklistTTL elapsed")
	}

	t.Log("✓ conn survives until it has been orphaned for a full TTL")
}
