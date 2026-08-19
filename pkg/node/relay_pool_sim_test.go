package node

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
)

// newSimHost spins up a real in-process libp2p host on loopback for relay-pool
// failure-mode simulation. It is heavyweight but lets us exercise the REAL
// NewStream / stream-flow-control path without mocking the entire host.Host
// interface — so the "peer accepts the stream but never reads" (B-class)
// failure reproduces exactly as in production.
func newSimHost(t *testing.T) (host.Host, peer.ID) {
	t.Helper()
	h, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatalf("libp2p.New: %v", err)
	}
	t.Cleanup(func() { h.Close() })
	return h, h.ID()
}

// fakeRelayNode returns a minimally-initialized *Node whose only wired behavior
// is the overlay-relay circuit-breaker (blacklist map + methods). All other
// Node fields stay zero-value; the blacklist methods touch nothing else.
func fakeRelayNode() *Node {
	n := &Node{}
	n.overlayRelayBlacklist = make(map[peer.ID]time.Time)
	return n
}

// TestRelayPoolCircuitBreaksStalledHop reproduces the 12D3KooWM9cR... "write
// queue full" class: a relay hop ACCEPTS the overlay-relay stream (NewStream
// succeeds) but NEVER reads it, so its flow-control window fills and every
// subsequent WriteFrame blocks until its 3s deadline and fails. The local write
// "succeeds" only while the window has room — so a naive failure-streak that is
// cleared on any successful buffered write would NEVER trip the breaker. The fix
// anchors "healthy" to independent return-path proof (we recently received a
// frame back from the hop); with none, the streak accumulates and the breaker
// trips, blacklisting the hop.
func TestRelayPoolCircuitBreaksStalledHop(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()

	sender, _ := newSimHost(t)
	receiver, recvID := newSimHost(t)

	// B-class: accept the stream and keep it open but NEVER read. The sender's
	// flow-control window fills, then every WriteFrame blocks to its 3s deadline
	// and fails. (Returning / closing early would let buffered writes "succeed"
	// and never exercise the window-full timeout.)
	receiver.SetStreamHandler(OverlayRelayProtocolID, func(s network.Stream) {
		<-ctx.Done() // hold the stream open for the whole test
		_ = s.Close()
	})

	if err := sender.Connect(ctx, peer.AddrInfo{ID: recvID, Addrs: receiver.Addrs()}); err != nil {
		t.Fatalf("connect sender→receiver: %v", err)
	}

	fn := fakeRelayNode()
	pool := newRelayStreamPool(ctx, sender, fn)

	// Top the queue up continuously with large frames so pumpFrames keeps
	// writing and the window actually fills (small payloads would all fit in the
	// send buffer and "succeed", never tripping the breaker).
	const frameSize = 32 * 1024
	payload := make([]byte, frameSize)
	var dropped int32
	deadline := time.Now().Add(30 * time.Second)
	blacklisted := false
	for time.Now().Before(deadline) {
		for i := 0; i < 256; i++ {
			pool.Submit(recvID, payload, nil, func() { atomic.AddInt32(&dropped, 1) })
		}
		if fn.isOverlayRelayBlacklisted(recvID) {
			blacklisted = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !blacklisted {
		t.Fatal("EXPECTED: stalled overlay-relay hop (accepts stream, never reads) " +
			"should be circuit-broken, but it was NEVER blacklisted — the breaker " +
			"cannot tell 'buffered write succeeded' from 'peer actually consumed'")
	}
	t.Logf("✓ stalled hop circuit-broken by breaker; %d frames dropped during stall", atomic.LoadInt32(&dropped))

	// Post-blacklist, Submit must fast-fail (return false) rather than pile onto
	// a dead queue that would pin full and re-flood the WARN.
	if pool.Submit(recvID, []byte("after-blacklist"), nil, func() {}) {
		t.Fatal("EXPECTED: Submit to fast-fail for a blacklisted hop")
	}
}

// TestRelayPoolUnsupportedHopFastFails covers the A-class: a relay hop that does
// NOT speak OverlayRelayProtocolID. NewStream fails with "protocols not
// supported", the hop is latched unsupported, and Submit rejects fast without
// blacklisting (a different, clean fallback path from a stalled/black-holed hop).
func TestRelayPoolUnsupportedHopFastFails(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	sender, _ := newSimHost(t)
	receiver, recvID := newSimHost(t)
	// A-class: receiver registers NO overlay-relay handler → NewStream returns
	// "protocols not supported".

	if err := sender.Connect(ctx, peer.AddrInfo{ID: recvID, Addrs: receiver.Addrs()}); err != nil {
		t.Fatalf("connect sender→receiver: %v", err)
	}

	fn := fakeRelayNode()
	pool := newRelayStreamPool(ctx, sender, fn)

	// First Submit kicks off stream-open in the write loop; let it latch unsupported.
	_ = pool.Submit(recvID, []byte("x"), nil, func() {})
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if pool.getOrCreate(recvID).unsupported.Load() {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !pool.getOrCreate(recvID).unsupported.Load() {
		t.Fatal("EXPECTED: hop without OverlayRelayProtocolID to be latched unsupported")
	}

	// Subsequent Submits must fast-fail (return false) and must NOT blacklist —
	// a protocol-mismatch peer is a clean fallback, not a stalled black-hole.
	if pool.Submit(recvID, []byte("y"), nil, func() {}) {
		t.Fatal("EXPECTED: Submit to fast-fail for an unsupported hop")
	}
	if fn.isOverlayRelayBlacklisted(recvID) {
		t.Fatal("unsupported hop must NOT be blacklisted (distinct path from stalled hop)")
	}
	t.Log("✓ unsupported hop latched; Submit fast-fails; no blacklist")
}
