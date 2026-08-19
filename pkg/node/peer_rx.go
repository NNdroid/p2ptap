package node

import (
	"bytes"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"p2ptap/pkg/tap"
)

// notePeerRx records that we just received an inbound frame from p. In an
// asymmetric-routing mesh (each node selects its outbound and return paths
// independently) this is the ONLY local signal for return-path liveness: a
// healthy outbound path proves nothing about whether p can route frames back
// to us. The ping-pong probe uses lastRxFrom to distinguish "outbound dead"
// from "return dead at the peer".
//
// PERF: this runs once per inbound frame from EVERY peer, so it must not take
// a global lock. See the peerLastRx field comment in node.go for why the map
// is copy-on-write with per-peer atomic counters.
func (n *Node) notePeerRx(p peer.ID) {
	if m := n.peerLastRx.Load(); m != nil {
		if v, ok := (*m)[p]; ok {
			v.Store(time.Now().UnixNano())
			return
		}
	}
	// Slow path: first frame ever seen from this peer. Publish a new map under
	// the lock, re-checking inside it so two goroutines racing on the same new
	// peer cannot lose each other's update (double-checked locking).
	n.peerRxMu.Lock()
	defer n.peerRxMu.Unlock()
	now := time.Now().UnixNano()
	if m := n.peerLastRx.Load(); m != nil {
		if v, ok := (*m)[p]; ok {
			v.Store(now)
			return
		}
	}
	var next map[peer.ID]*atomic.Int64
	if m := n.peerLastRx.Load(); m != nil {
		next = make(map[peer.ID]*atomic.Int64, len(*m)+1)
		for k, v := range *m {
			next[k] = v
		}
	} else {
		next = make(map[peer.ID]*atomic.Int64, 1)
	}
	v := &atomic.Int64{}
	v.Store(now)
	next[p] = v
	n.peerLastRx.Store(&next)
}

// lastRxFrom returns the time we last received an inbound frame from p, or the
// zero time if none has ever arrived. Lock-free: it only reads the published
// map snapshot.
func (n *Node) lastRxFrom(p peer.ID) time.Time {
	m := n.peerLastRx.Load()
	if m == nil {
		return time.Time{}
	}
	v, ok := (*m)[p]
	if !ok {
		return time.Time{}
	}
	ns := v.Load()
	if ns == 0 {
		return time.Time{}
	}
	return time.Unix(0, ns)
}

// peerRxWithin reports whether we received an inbound frame from p within the
// last d. Called by the ping-pong probe after an echo timeout: if true, the
// outbound path clearly works (p is sending us frames), so the failed echo must
// be a RETURN-path break at p — not a local outbound failure.
func (n *Node) peerRxWithin(p peer.ID, d time.Duration) bool {
	last := n.lastRxFrom(p)
	if last.IsZero() {
		return false
	}
	return time.Since(last) <= d
}

// tapProbeOutcome is the cached result of the most recent end-to-end TAP
// forwarding probe toward a peer, exposed to the WebUI so the operator can see
// the peer's TAP up/down state without re-running a manual probe.
type tapProbeOutcome struct {
	Last    time.Time
	Ok      bool
	Reached bool
	Detail  string
}

// recordPeerObservedTapMAC stores the RAW source MAC observed on an inbound
// frame from p (captured before metadata-TapMAC normalization). It continuously
// tracks the MAC the peer actually emits on the wire, which may differ from its
// advertised TapMAC (e.g. Windows EUI-64 synthetic MACs).
func (n *Node) recordPeerObservedTapMAC(p peer.ID, mac net.HardwareAddr) {
	if len(mac) != 6 {
		return
	}
	// In steady state the peer's emitted MAC never changes, so skip the write
	// lock entirely once we've recorded it — avoids taking peerProbeMu on every
	// inbound frame destined for us.
	n.peerProbeMu.RLock()
	cur := n.peerObservedTapMAC[p]
	eq := len(cur) == 6 && bytes.Equal(cur, mac)
	n.peerProbeMu.RUnlock()
	if eq {
		return
	}
	cp := make(net.HardwareAddr, 6)
	copy(cp, mac)
	n.peerProbeMu.Lock()
	if n.peerObservedTapMAC == nil {
		n.peerObservedTapMAC = make(map[peer.ID]net.HardwareAddr)
	}
	n.peerObservedTapMAC[p] = cp
	n.peerProbeMu.Unlock()

	// Update local ARP index and MAC table immediately to use the true wire MAC!
	n.rebuildARPIndex()
	if n.MACTable != nil {
		n.MACTable.Learn(cp, p)
	}

	// Emit a Gratuitous ARP to the local OS TAP so Windows immediately updates its ARP cache
	if val, ok := n.peerMeta.Load(p); ok && n.TAP != nil {
		meta := val.(PeerMeta)
		if meta.TapIP != "" {
			ipStr := strings.Split(meta.TapIP, "/")[0]
			if ip := net.ParseIP(ipStr).To4(); ip != nil {
				garpFrame := tap.BuildARPReplyFrame(cp, net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, ip, ip)
				_, _ = n.tapWrite(garpFrame)
			}
		}
	}
}

// observedTapMACFrom returns the most recently observed raw TAP MAC for p, or
// nil if none has been seen yet.
func (n *Node) observedTapMACFrom(p peer.ID) net.HardwareAddr {
	n.peerProbeMu.RLock()
	defer n.peerProbeMu.RUnlock()
	m := n.peerObservedTapMAC[p]
	if len(m) != 6 {
		return nil
	}
	cp := make(net.HardwareAddr, 6)
	copy(cp, m)
	return cp
}

// recordTapProbe caches the outcome of an end-to-end TAP probe toward p so the
// WebUI can show TAP up/down without re-running it. reached reports whether the
// probe frame physically reached the peer's TAP (方案 B): when ok is false but
// reached is true the break is the peer OS (ICMP blocked / no return route);
// when reached is false the frame never arrived (overlay / relay path down).
func (n *Node) recordTapProbe(p peer.ID, ok bool, reached bool, detail string) {
	n.peerProbeMu.Lock()
	n.peerTapProbe[p] = tapProbeOutcome{Last: time.Now(), Ok: ok, Reached: reached, Detail: detail}
	n.peerProbeMu.Unlock()
}

// tapProbeFrom returns the cached outcome of the most recent TAP probe toward p,
// or the zero value if no probe has run.
func (n *Node) tapProbeFrom(p peer.ID) tapProbeOutcome {
	n.peerProbeMu.RLock()
	defer n.peerProbeMu.RUnlock()
	return n.peerTapProbe[p]
}
