package node

import (
	"context"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
)

// lsaStreamPool keeps ONE long-lived stream per peer for periodic, low-rate
// control traffic (LSA / Metadata / Echo). Previously broadcastLSA /
// broadcastMetadata / ping-pong opened a brand-new stream for EVERY peer on
// EVERY tick — O(N) NewStream calls per round, which thrashes the transport
// (TCP/QUIC handshake per cycle, libp2p muxed substream churn) and scales
// badly with peer count.
//
// We instead lazily open a persistent stream on first use and reuse it. If the
// peer disconnects or the stream breaks, the holder transparently re-opens on
// the next use. This collapses the periodic storm into zero new streams for
// steady-state peers.
//
// Concurrency model:
//   - The pool is shared by several goroutines that may target the SAME peer
//     stream concurrently (e.g. the LSA broadcast ticker vs. the LSA forwarding
//     path in handleLSAStream; the ping-pong ticker vs. a manual WebUI echo
//     probe). network.Stream.Write/Read is NOT safe for concurrent use, so two
//     goroutines must never touch the same stream at once.
//   - Each peer gets its OWN mutex (writeMu map), so unrelated peers never
//     serialize against each other — only same-peer operations serialize.
//   - Callers that only SEND use Submit; callers that must WRITE-then-READ a
//     response on the same stream use WithStream, which runs the callback while
//     holding that peer's lock so nothing else can interleave on the stream.
type lsaStreamPool struct {
	node *Node

	// mu guards the two maps below (never held across a blocking NewStream).
	mu       sync.Mutex
	streams  map[peer.ID]network.Stream
	writeMu  map[peer.ID]*sync.Mutex
	protocol protocol.ID // which control protocol this pool serves
}

func newLSAStreamPool(n *Node, proto protocol.ID) *lsaStreamPool {
	return &lsaStreamPool{
		node:     n,
		streams:  make(map[peer.ID]network.Stream),
		writeMu:  make(map[peer.ID]*sync.Mutex),
		protocol: proto,
	}
}

// peerMu returns the per-peer mutex, creating it on first use. Caller must hold mu.
func (p *lsaStreamPool) peerMuLocked(target peer.ID) *sync.Mutex {
	m, ok := p.writeMu[target]
	if !ok {
		m = &sync.Mutex{}
		p.writeMu[target] = m
	}
	return m
}

// Submit sends data to the given peer over its persistent stream. It returns
// true if the data was sent, false if the peer is unreachable after a reconnect
// attempt. The peer's lock is held for the whole send so no other goroutine can
// interleave on the same stream.
func (p *lsaStreamPool) Submit(target peer.ID, data []byte) bool {
	p.mu.Lock()
	m := p.peerMuLocked(target)
	p.mu.Unlock()

	m.Lock()
	defer m.Unlock()

	s := p.getOrOpenLocked(target)
	if s == nil {
		return false
	}
	if err := WriteFrame(s, data); err != nil {
		// Stream died mid-flight — drop it and try one reconnect.
		p.closeLocked(target)
		s = p.openLocked(target)
		if s == nil {
			return false
		}
		if err := WriteFrame(s, data); err != nil {
			p.closeLocked(target)
			return false
		}
	}
	return true
}

// WithStream obtains the peer's persistent stream and invokes fn while holding
// that peer's lock, so fn can safely WriteFrame AND ReadFrame a response on the
// same stream without another goroutine interleaving. fn must NOT call back into
// Submit/Invalidate/WithStream for the same peer (would deadlock). It should
// return a non-nil error to signal the stream is broken; WithStream then drops
// the cached stream so the next use re-opens.
func (p *lsaStreamPool) WithStream(target peer.ID, fn func(s network.Stream) error) bool {
	p.mu.Lock()
	m := p.peerMuLocked(target)
	p.mu.Unlock()

	m.Lock()
	defer m.Unlock()

	s := p.getOrOpenLocked(target)
	if s == nil {
		return false
	}
	if err := fn(s); err != nil {
		p.closeLocked(target)
		return false
	}
	return true
}

// getOrOpenLocked returns the cached stream or opens a new one. Caller MUST hold
// the peer's per-peer lock (via Submit/WithStream) — never called unlocked.
//
// The per-peer lock serializes operations on ONE peer's stream, but the streams
// map is shared across ALL peers, so every map access must additionally take mu
// (otherwise two different peers racing here = concurrent map write panic).
func (p *lsaStreamPool) getOrOpenLocked(target peer.ID) network.Stream {
	p.mu.Lock()
	s, ok := p.streams[target]
	p.mu.Unlock()
	if ok {
		return s
	}
	return p.openLocked(target)
}

func (p *lsaStreamPool) openLocked(target peer.ID) network.Stream {
	// Unified control-stream opener: prefer a direct connection, then an
	// overlay-relay hop (relay-ctrl tunnel), then the boot circuit relay. This
	// replaces the previous direct-then-circuit split so an LSA/Meta sync with a
	// peer reachable ONLY through another peer (e.g. A ↔ C via relay B) converges
	// instead of being abandoned. The relay-only fast-path's "skip the doomed
	// 10s direct dial" property is preserved: openControlStream only attempts a
	// direct NewStream when the peer IS directly connected, and otherwise goes
	// straight to the relay hop / circuit.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	s, err := p.node.openControlStream(ctx, target, p.protocol)
	if err != nil {
		log.Debug("stream open to %s (%s) failed: %v", target.ShortString(), p.protocol, err)
		return nil
	}
	p.cacheLocked(target, s)
	return s
}

// cacheLocked stores a freshly opened stream. Caller must NOT hold mu.
func (p *lsaStreamPool) cacheLocked(target peer.ID, s network.Stream) {
	p.mu.Lock()
	p.streams[target] = s
	p.mu.Unlock()
}

func (p *lsaStreamPool) closeLocked(target peer.ID) {
	p.mu.Lock()
	s, ok := p.streams[target]
	if ok {
		delete(p.streams, target)
	}
	p.mu.Unlock()
	if ok {
		s.Close()
	}
}

// Invalidate drops any cached stream for a peer (e.g. on disconnect) so the next
// use re-opens cleanly. Serialized with the peer's own lock.
func (p *lsaStreamPool) Invalidate(target peer.ID) {
	p.mu.Lock()
	m, ok := p.writeMu[target]
	p.mu.Unlock()
	if !ok {
		return
	}
	m.Lock()
	defer m.Unlock()
	p.closeLocked(target)
}

// InvalidateAll closes every cached stream (used on node shutdown).
func (p *lsaStreamPool) InvalidateAll() {
	p.mu.Lock()
	targets := make([]peer.ID, 0, len(p.streams))
	for id := range p.streams {
		targets = append(targets, id)
	}
	p.mu.Unlock()
	for _, id := range targets {
		p.Invalidate(id)
	}
}
