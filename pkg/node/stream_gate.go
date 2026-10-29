package node

import (
	"sync"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
)

// streamGate bounds concurrent inbound streams per peer for one handler.
//
// libp2p runs one handler goroutine per stream, and this node installs a
// NullResourceManager (no libp2p stream limit) because that manager's global
// caps would drop legitimate high-rate TAP forwarding frames. The consequence
// is that a hostile or buggy peer can open thousands of /p2ptap/... streams
// and pin a 65 KiB read buffer plus a goroutine each, growing memory without
// bound. Legitimate use opens one stream per path (a handful per peer even
// under multipath), so a per-peer bound far above that is invisible to healthy
// traffic and only stops a flood. Exceeding the bound resets the stream, which
// the remote opens and immediately learns about.
// Per-peer concurrent-stream bounds. Multipath opens one stream per live path
// (QUIC + TCP + WebRTC, typically <=4) plus the occasional replacement while a
// dead one is pruned, so 16 leaves ample headroom; echo is an unbuffered probe
// that should never pile up beyond a couple.
const (
	maxStreamsPerPeerData  = 16
	maxStreamsPerPeerRelay = 16
	maxStreamsPerPeerEcho  = 8
)

type streamGate struct {
	mu  sync.Mutex
	per map[peer.ID]int
	max int
}

func newStreamGate(max int) *streamGate {
	return &streamGate{per: make(map[peer.ID]int), max: max}
}

func (g *streamGate) acquire(p peer.ID) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.per[p] >= g.max {
		return false
	}
	g.per[p]++
	return true
}

func (g *streamGate) release(p peer.ID) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.per[p] <= 1 {
		delete(g.per, p)
	} else {
		g.per[p]--
	}
}

// gateStream wraps an inbound stream handler so each peer may hold at most
// max streams on it concurrently; beyond that the stream is reset. The gate is
// released when the handler returns (the handler owns the stream for exactly
// its own lifetime).
func (n *Node) gateStream(g *streamGate, h func(network.Stream)) func(network.Stream) {
	return func(s network.Stream) {
		p := s.Conn().RemotePeer()
		if !g.acquire(p) {
			log.Warn("refusing stream from %s: %d concurrent streams already open", p.ShortString(), g.max)
			_ = s.Reset()
			return
		}
		defer g.release(p)
		h(s)
	}
}
