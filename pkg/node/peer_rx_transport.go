package node

import (
	"sync/atomic"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"

	"p2ptap/pkg/maddrutil"
)

// transportLabelForConn classifies one live connection the way deriveConnSignals
// does: a circuit-relayed multiaddr is relayed, anything else is a direct
// transport (QUIC/TCP/WebRTC/WebTransport). Shared by deriveConnSignals' peers
// and the inbound-frame annotation below so the two never disagree on what a
// given connection *is*.
func transportLabelForConn(c network.Conn) string {
	if c == nil {
		return ""
	}
	if maddrutil.IsCircuitRelay(c.RemoteMultiaddr()) {
		return "circuit-relay"
	}
	return "direct"
}

// rxTransportInfo annotates one peer's most recent inbound frame. label and hop
// are copied into the map only when the PATH itself changes; lastTs is a
// per-peer atomic so a steady frame stream never forces a map copy.
type rxTransportInfo struct {
	label  string  // "direct" | "circuit-relay" | "overlay-relay"
	hop    peer.ID // carrier, non-empty only for overlay-relay
	lastTs atomic.Int64
}

// peerRxTransport records HOW the last inbound frame from each peer arrived:
// the transport label, plus the overlay hop that carried it when the frame was
// relayed.
//
// This is the return-side twin of describeTransportPath. That function classifies
// our OUTBOUND egress to a peer — computed from the route table and our live
// libp2p connections. This classifies the medium its frames actually arrive
// over — computed from the frames themselves. In an asymmetric-routing mesh
// (every node picks its own egress) the two routinely disagree: a peer can be
// sending us over an overlay relay while we send it over a live direct link.
// describeTransportPath's single label could only ever show one half of that,
// so "direct + relay" routing looked like a plain direct link. Only carrying
// both halves makes asymmetric paths readable instead of ambiguous.
//
// PERF: same copy-on-write shape as peerLastRx — one atomic load of the map
// pointer plus an atomic store on the peer's own counter per inbound frame; no
// global lock, no allocation on the steady-state path. Only a first sighting or
// an actual path change copies the map under peerRxTransportMu.
func (n *Node) notePeerRxTransport(p peer.ID, label string, hop peer.ID) {
	// notePeerRx keeps the pre-existing liveness semantics intact; this only adds
	// the transport annotation on top.
	n.notePeerRx(p)
	if p == "" || label == "" {
		return
	}
	now := time.Now().UnixNano()
	if m := n.peerRxTransport.Load(); m != nil {
		if v, ok := (*m)[p]; ok && v != nil && v.label == label && v.hop == hop {
			v.lastTs.Store(now)
			return
		}
	}
	n.peerRxTransportMu.Lock()
	defer n.peerRxTransportMu.Unlock()
	now = time.Now().UnixNano()
	if m := n.peerRxTransport.Load(); m != nil {
		if v, ok := (*m)[p]; ok && v != nil && v.label == label && v.hop == hop {
			v.lastTs.Store(now)
			return
		}
	}
	var next map[peer.ID]*rxTransportInfo
	if m := n.peerRxTransport.Load(); m != nil {
		next = make(map[peer.ID]*rxTransportInfo, len(*m)+1)
		for k, v := range *m {
			next[k] = v
		}
	} else {
		next = make(map[peer.ID]*rxTransportInfo, 1)
	}
	info := &rxTransportInfo{label: label, hop: hop}
	info.lastTs.Store(now)
	next[p] = info
	n.peerRxTransport.Store(&next)
}

// peerRxTransportPath returns the transport + hop of the last inbound frame
// from p, when that frame arrived within within. label is "" when nothing
// fresh has been observed — meaning we cannot claim anything about this peer's
// return medium, as opposed to having positively observed a direct one. hop is
// always "" when label is "".
//
// Callers gate on the same window as deriveReturnPath (returnPathAliveWindow),
// so the liveness verdict and the medium report agree on what counts as recent.
func (n *Node) peerRxTransportPath(p peer.ID, within time.Duration) (label string, hop peer.ID) {
	if p == "" || within <= 0 {
		return "", ""
	}
	m := n.peerRxTransport.Load()
	if m == nil {
		return "", ""
	}
	v, ok := (*m)[p]
	if !ok || v == nil {
		return "", ""
	}
	ns := v.lastTs.Load()
	if ns == 0 || time.Since(time.Unix(0, ns)) > within {
		return "", ""
	}
	return v.label, v.hop
}
