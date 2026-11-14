package node

import (
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"
)

// Tests for the connectivity-recovery fixes:
//
//   - ClearPathBreakers: an echo round trip re-admits a path the exponential
//     per-path breaker was still exiling (the old reset condition — a
//     successful WRITE — could never fire while the path was cooling).
//   - pathReturnStale: the return-side blackhole signal that feeds the DWRR
//     weight demotion.
//   - filterRecentlyFailedAddrs: direct addresses of a fully-failed dial are
//     skipped for dialAddrFailTTL, never leaving a peer undialable.
//   - peerUnicastRxWithin / resetPingPongFailCountForPeer: broadcast floods no
//     longer keep a broken unicast return path immune to reconnect.
//   - scheduleStreamRepair: single-flight repair is skipped for bare
//     dispatchers (no node back-reference) instead of dereferencing a stub host.

const recoveryTestWANMA = "/ip4/203.0.113.7/tcp/4001" // TEST-NET-3, WAN tier

func TestClearPathBreakersReadmitsCoolingPath(t *testing.T) {
	ps := NewPeerStreams(peer.ID("breaker-clear"))
	s := &pathTestStream{ma: mustMA(recoveryTestWANMA), remotePeer: peer.ID("breaker-clear")}

	ps.writeMu.Lock()
	ps.notePathFailureUnderLock(s, time.Now())
	ps.notePathFailureUnderLock(s, time.Now().Add(3*time.Second)) // escalate to 4s
	cooling := ps.pathCoolingLocked(s, time.Now().Add(6*time.Second))
	ps.writeMu.Unlock()
	if !cooling {
		t.Fatal("path should be cooling after repeated failures")
	}

	ps.ClearPathBreakers()
	ps.writeMu.Lock()
	stillCooling := ps.pathCoolingLocked(s, time.Now().Add(7*time.Second))
	ps.writeMu.Unlock()
	if stillCooling {
		t.Fatal("ClearPathBreakers must re-admit the path immediately")
	}
}

func TestClearPathBreakersNilSafe(t *testing.T) {
	ps := NewPeerStreams(peer.ID("breaker-empty"))
	ps.ClearPathBreakers() // must not panic with no breakers armed
}

func TestPathReturnStaleBlackholeDetection(t *testing.T) {
	n := &Node{}
	p := peer.ID("blackhole")
	path := recoveryTestWANMA

	// Never written: no verdict, weight untouched.
	if n.pathReturnStale(p, path, time.Now()) {
		t.Fatal("a path with no recorded traffic must not be judged stale")
	}

	// Actively written, nothing back: stale (the blackhole case).
	n.recordPeerTxBytesOnPath(p, path, 100, 1)
	if !n.pathReturnStale(p, path, time.Now()) {
		t.Fatal("actively written path with zero return traffic must be stale")
	}

	// Return traffic arrives: not stale.
	n.recordPeerRxBytesOnPath(p, path, 100)
	if n.pathReturnStale(p, path, time.Now()) {
		t.Fatal("path with fresh return traffic must not be stale")
	}

	// Return goes quiet while writes continue: stale again (synthetic times —
	// the counters are in-package state, so age them directly).
	tv, _ := n.pathTx.Load(pathKey{peer: p, path: path})
	tv.(*pathTxCounters).last.Store(time.Now().UnixNano())
	rv, _ := n.pathRx.Load(pathKey{peer: p, path: path})
	rv.(*pathRxCounters).last.Store(time.Now().Add(-2 * pathReturnStaleFor).UnixNano())
	if !n.pathReturnStale(p, path, time.Now()) {
		t.Fatal("actively written path whose return went quiet must be stale")
	}

	// Writes stop: dormant, no verdict.
	tv.(*pathTxCounters).last.Store(time.Now().Add(-2 * pathReturnStaleFor).UnixNano())
	if n.pathReturnStale(p, path, time.Now()) {
		t.Fatal("dormant path must keep its weight (no verdict)")
	}
}

func TestMultipathWeightDemotesBlackholePath(t *testing.T) {
	n := &Node{}
	p := peer.ID("weight-demote")
	ps := NewPeerStreams(p)
	ps.node = n

	fast := &pathTestStream{ma: mustMA("/ip4/198.51.100.5/tcp/4001"), remotePeer: p} // TEST-NET-2 WAN
	bad := &pathTestStream{ma: mustMA(recoveryTestWANMA), remotePeer: p}

	now := time.Now()
	// Both paths measured at the same capacity: equal shares before the signal.
	for i := 0; i < 4; i++ {
		ps.recordStreamWrite(fast, 32*1024, 32*1024*time.Nanosecond, now)
		ps.recordStreamWrite(bad, 32*1024, 32*1024*time.Nanosecond, now)
	}
	// Only the healthy path carries return traffic; the bad path is actively
	// written but silent on the return side.
	n.recordPeerRxBytesOnPath(p, fast.Conn().RemoteMultiaddr().String(), 100)
	n.recordPeerTxBytesOnPath(p, bad.Conn().RemoteMultiaddr().String(), 100, 1)

	ps.writeMu.Lock()
	wFast := ps.mpWeightFor(fast, now)
	wBad := ps.mpWeightFor(bad, now)
	ps.writeMu.Unlock()

	if wBad*wFast <= 0 {
		t.Fatalf("weights must stay positive: fast=%v bad=%v", wFast, wBad)
	}
	if wBad >= wFast {
		t.Fatalf("blackhole path must be demoted below its sibling: fast=%v bad=%v", wFast, wBad)
	}
	if got := wBad * pathReturnDemotion; got < wFast*0.99 || got > wFast*1.01 {
		t.Fatalf("demotion must be the configured divisor: fast=%v bad=%v", wFast, wBad)
	}
}

func TestFilterRecentlyFailedAddrs(t *testing.T) {
	n := &Node{}
	p := peer.ID("dialfail")
	direct := mustMA("/ip4/203.0.113.8/tcp/4001")
	// Built from components: a synthetic peer.ID string is not a parseable
	// /p2p component, and the filter only needs the /p2p-circuit marker.
	circuit := ma.Join(ma.StringCast("/ip4/203.0.113.9/tcp/4002"), ma.StringCast("/p2p-circuit"))
	other := mustMA("/ip4/203.0.113.10/tcp/4003")

	// Nothing marked: everything passes.
	if got := n.filterRecentlyFailedAddrs(p, []ma.Multiaddr{direct, circuit}); len(got) != 2 {
		t.Fatalf("unmarked addrs must pass: got %d, want 2", len(got))
	}

	// Marking skips circuit addrs entirely: only the direct one is marked.
	n.markDialFailedAddrs(p, []ma.Multiaddr{direct, circuit})
	got := n.filterRecentlyFailedAddrs(p, []ma.Multiaddr{direct, circuit, other})
	if len(got) != 2 {
		t.Fatalf("marked direct addr must be filtered, circuit and fresh kept: got %d", len(got))
	}
	for _, a := range got {
		if a.String() == direct.String() {
			t.Fatal("marked direct addr must not survive the filter")
		}
	}

	// The filter must never leave a peer with zero dialable addresses.
	if got := n.filterRecentlyFailedAddrs(p, []ma.Multiaddr{direct}); len(got) != 1 {
		t.Fatalf("all-marked set must fall back to the full set: got %d", len(got))
	}

	// Clearing (success, rediscovery) re-admits everything.
	n.clearDialFailedAddrs(p)
	if got := n.filterRecentlyFailedAddrs(p, []ma.Multiaddr{direct, circuit}); len(got) != 2 {
		t.Fatalf("cleared marks must pass everything: got %d", len(got))
	}

	// Aged-out marks expire on their own.
	n.markDialFailedAddrs(p, []ma.Multiaddr{direct})
	n.dialFailAddrsMu.Lock()
	n.dialFailAddrs[p][direct.String()] = time.Now().Add(-2 * dialAddrFailTTL)
	n.dialFailAddrsMu.Unlock()
	if got := n.filterRecentlyFailedAddrs(p, []ma.Multiaddr{direct}); len(got) != 1 {
		t.Fatalf("aged-out mark must expire: got %d", len(got))
	}
}

func TestPeerUnicastRxWithinFallback(t *testing.T) {
	n := &Node{}
	p := peer.ID("unicast")

	// No unicast ever seen: fall back to the any-frame tracker.
	n.notePeerRx(p)
	if !n.peerUnicastRxWithin(p, time.Minute) {
		t.Fatal("peer without any unicast history must fall back to any-frame liveness")
	}

	// Fresh unicast counts.
	n.notePeerUnicastRx(p)
	if !n.peerUnicastRxWithin(p, time.Minute) {
		t.Fatal("fresh unicast frame must count as return-path liveness")
	}

	// Once unicast history exists, only unicast counts: a stale unicast
	// timestamp must not be rescued by fresh broadcast traffic (notePeerRx).
	m := n.peerLastUnicastRx.Load()
	(*m)[p].Store(time.Now().Add(-2 * time.Minute).UnixNano())
	n.notePeerRx(p) // simulates a broadcast flood keeping peerLastRx fresh
	if n.peerUnicastRxWithin(p, time.Minute) {
		t.Fatal("stale unicast must not count once unicast history exists")
	}
}

func TestResetPingPongFailCountUnicastOnly(t *testing.T) {
	n := &Node{}
	p := peer.ID("reset")
	c := n.pingPongFailCounterFor(p)
	c.Store(1)

	n.resetPingPongFailCountForPeer(p, false)
	if c.Load() != 1 {
		t.Fatal("broadcast frame must not reset the echo-failure counter")
	}
	n.resetPingPongFailCountForPeer(p, true)
	if c.Load() != 0 {
		t.Fatal("unicast frame must reset the echo-failure counter")
	}
}

// repairTestNet is the minimal network view a repair goroutine can probe:
// ConnsToPeer reports no connections, so EnsureStreamsOnAllConns exits
// immediately. Other methods stay unimplemented (the embedded nil interface
// panics if one is ever reached — that is the signal, not silent success).
type repairTestNet struct {
	network.Network
}

func (n *repairTestNet) ConnsToPeer(peer.ID) []network.Conn { return nil }

// repairTestHost is a stub host whose Network() is usable by the repair path,
// unlike strategyReplacementHost whose embedded nil host.Host panics on it.
type repairTestHost struct {
	host.Host
}

func (h *repairTestHost) Network() network.Network { return &repairTestNet{} }

func TestScheduleStreamRepairSkipsBareDispatcher(t *testing.T) {
	// A bare dispatcher (no node back-reference) — strategy-layer unit tests
	// build these against stub hosts whose embedded nil host.Host panics on
	// Network(). The repair trigger must opt out instead of dereferencing it.
	sd := NewStrategyDispatcher(&strategyReplacementHost{}, "fallback")
	sd.scheduleStreamRepair(peer.ID("bare"))
	if len(sd.repairInFlight) != 0 {
		t.Fatal("bare dispatcher must not arm a repair")
	}

	// A dispatcher WITH a node arms the repair even on a nil-ctx node fake; the
	// eventual EnsureStreamsOnAllConns must survive a minimal host. Wait past
	// the coalescing delay so the repair goroutine actually runs here — a panic
	// inside it would fail this test via the deferred goexit, not silently.
	sd = NewStrategyDispatcher(&repairTestHost{}, "fallback")
	sd.SetNode(&Node{})
	sd.scheduleStreamRepair(peer.ID("nilctx"))
	if len(sd.repairInFlight) == 0 {
		t.Fatal("dispatcher with a node must arm the repair")
	}
	sd.ClearPathBreakers(peer.ID("nilctx")) // nil-safe read path while armed
	time.Sleep(3 * streamRepairDelay)
}
