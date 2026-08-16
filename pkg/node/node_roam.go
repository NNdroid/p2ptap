package node

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/p2p/net/swarm"
	"github.com/multiformats/go-multiaddr"
)

// roamDebounce collapses bursts of OS link/address events (a Wi-Fi
// reassociation can fire a dozen in under a second) into a single reconcile.
// It is a var (not const) so tests can shrink it.
var roamDebounce = 1500 * time.Millisecond

// roamDebouncer fires fn at most once per roamDebounce window. Each trigger()
// resets the window, so a storm of events coalesces into one call.
type roamDebouncer struct {
	mu     sync.Mutex
	timer  *time.Timer
	active bool
	fn     func()
}

func newRoamDebouncer(fn func()) *roamDebouncer {
	return &roamDebouncer{fn: fn}
}

func (d *roamDebouncer) start() {
	d.mu.Lock()
	d.active = true
	d.mu.Unlock()
}

func (d *roamDebouncer) trigger() {
	d.mu.Lock()
	if !d.active {
		d.mu.Unlock()
		return
	}
	if d.timer != nil {
		d.timer.Stop()
	}
	d.timer = time.AfterFunc(roamDebounce, d.fn)
	d.mu.Unlock()
}

func (d *roamDebouncer) stop() {
	d.mu.Lock()
	d.active = false
	if d.timer != nil {
		d.timer.Stop()
		d.timer = nil
	}
	d.mu.Unlock()
}

// listenerStore is the minimal surface reconcileRoam needs from the running
// node. Node satisfies it against the live libp2p host/swarm; tests inject a
// fake.
type listenerStore interface {
	CurrentListenAddrs() []multiaddr.Multiaddr
	AddListenAddrs(addrs ...multiaddr.Multiaddr) error
	CloseListenAddrs(addrs ...multiaddr.Multiaddr)
	RefreshEgress()
}

// reconcileRoam makes the running listener set match the NICs currently
// eligible for listening. It first refreshes the cached egress interface so
// new dialer sockets bind the new NIC, then diffs the desired per-NIC listen
// addresses against what is currently bound and applies only the delta.
// Listener removal is graceful: swarm.ListenClose only closes the listening
// socket; already-accepted connections survive, and libp2p's notifees
// auto-update the address book + push identify so peers re-learn reachable
// addresses and the mesh reconverges on its own.
// reconcileRoam returns true when the listener set actually changed (so the
// caller can, e.g., rebind the WebUI on a now-different NIC set).
func reconcileRoam(ls listenerStore, base []multiaddr.Multiaddr) bool {
	ls.RefreshEgress()

	desired := make([]multiaddr.Multiaddr, 0, len(base))
	for _, a := range base {
		desired = append(desired, expandListenAddr(a)...)
	}
	current := ls.CurrentListenAddrs()
	toAdd, toRemove := diffListeners(desired, current)
	if len(toAdd) > 0 {
		if err := ls.AddListenAddrs(toAdd...); err != nil {
			log.Debug("roam: failed to add listeners after NIC change: %v", err)
		}
	}
	if len(toRemove) > 0 {
		ls.CloseListenAddrs(toRemove...)
	}
	if len(toAdd) > 0 || len(toRemove) > 0 {
		log.Info("roam: reconciled listeners: +%d -%d (egress refreshed)", len(toAdd), len(toRemove))
		return true
	}
	return false
}

// diffListeners returns the add/remove delta. Desired addresses use port 0
// (expandListenAddr preserves the configured port, which is 0 so the OS assigns
// one); current addresses are the actually-bound ones with real ports. We
// compare on a normalized key that zeroes the port, so a freshly-expanded
// desired address matches an already-bound listener on the same NIC/transport.
func diffListeners(desired, current []multiaddr.Multiaddr) (toAdd, toRemove []multiaddr.Multiaddr) {
	curByKey := make(map[string]multiaddr.Multiaddr, len(current))
	for _, c := range current {
		cStr := c.String()
		if strings.Contains(cStr, "p2p-circuit") {
			continue
		}
		curByKey[normKey(c)] = c
	}
	desKeys := make(map[string]bool, len(desired))
	for _, d := range desired {
		k := normKey(d)
		desKeys[k] = true
		if _, ok := curByKey[k]; !ok {
			toAdd = append(toAdd, d)
		}
	}
	for k, c := range curByKey {
		if !desKeys[k] {
			toRemove = append(toRemove, c)
		}
	}
	return toAdd, toRemove
}

// normKey canonicalizes a listen multiaddr for comparison by zeroing its port,
// so a desired (port 0) address matches a bound (real-port) one on the same
// NIC + transport. It walks the multiaddr string: for a tcp/udp component the
// following token is the port, which we replace with 0.
func normKey(a multiaddr.Multiaddr) string {
	parts := strings.Split(a.String(), "/")
	out := make([]string, 0, len(parts))
	for i := 0; i < len(parts); i++ {
		p := parts[i]
		out = append(out, p)
		if (p == "tcp" || p == "udp") && i+1 < len(parts) {
			out = append(out, "0")
			i++ // skip the original port value
		}
	}
	return strings.Join(out, "/")
}

func parseListenAddrs(strs []string) []multiaddr.Multiaddr {
	out := make([]multiaddr.Multiaddr, 0, len(strs))
	for _, s := range strs {
		if m, err := multiaddr.NewMultiaddr(s); err == nil {
			out = append(out, m)
		} else {
			log.Warn("roam: invalid ListenAddr %q: %v", s, err)
		}
	}
	return out
}

// --- Node adapter for listenerStore ---

func (n *Node) CurrentListenAddrs() []multiaddr.Multiaddr {
	return n.Host.Network().ListenAddresses()
}

// AddListenAddrs adds the given listen addresses, tolerating per-address
// failures. NIC expansion (roam) can produce addresses that no transport can
// bind — e.g. an IPv6 address on which QUIC/TCP isn't enabled, or a protocol
// the host wasn't configured with. Such addresses are skipped (rather than
// aborting the whole batch and emitting spurious "no transport for protocol"
// warnings). A failed roam reconcile is non-fatal: the previously-bound
// listeners keep serving, so the method never returns an error.
func (n *Node) AddListenAddrs(addrs ...multiaddr.Multiaddr) error {
	s, ok := n.Host.Network().(*swarm.Swarm)
	if !ok {
		return n.Host.Network().Listen(addrs...)
	}
	// Drop addresses no transport can bind. Passing them to the swarm only
	// produces "no transport for protocol" warnings and aborts the batch.
	listenable := addrs[:0:len(addrs)]
	for _, a := range addrs {
		if s.TransportForListening(a) == nil {
			// Expected for addresses whose transport is not built into this node
			// (e.g. /webrtc-direct and /quic-v1/webtransport when only TCP+QUIC
			// are registered). The IP itself still listens on TCP/QUIC — only
			// this variant is dropped. Not an error.
			log.Debug("roam: skipping listen addr — no registered transport (only TCP/QUIC are active in this build): %s", a)
			continue
		}
		listenable = append(listenable, a)
	}
	if len(listenable) == 0 {
		return nil
	}
	if err := s.Listen(listenable...); err != nil {
		// Non-fatal: existing listeners stay up; surfaced at Debug, not Warn.
		log.Debug("roam: could not add %d listener(s) after NIC change (existing preserved): %v", len(listenable), err)
	}
	return nil
}

// CloseListenAddrs gracefully stops listeners for the given (exact,
// real-port) addresses. It uses the fork's swarm.ListenClose, which only
// closes the listening socket and leaves accepted connections running — so an
// in-flight peer session is never interrupted by a roam. No fork public-API
// change is needed: we type-assert the network to *swarm.Swarm.
func (n *Node) CloseListenAddrs(addrs ...multiaddr.Multiaddr) {
	if s, ok := n.Host.Network().(*swarm.Swarm); ok {
		s.ListenClose(addrs...)
		return
	}
	log.Warn("roam: host network is not *swarm.Swarm; cannot close stale listeners")
}

func (n *Node) RefreshEgress() {
	RefreshDefaultEgressInterface()
}

// startRoamWatcher wires the network-change monitor into the node lifecycle.
// It is called once from Start(), after the host (and its initial listeners)
// are up. A first reconcile is scheduled immediately so the initial NIC set is
// authoritative.
func (n *Node) startRoamWatcher() {
	n.parsedListenMu.Lock()
	if n.parsedListenAddrs == nil {
		n.parsedListenAddrs = parseListenAddrs(n.Config.ListenAddrs)
	}
	n.parsedListenMu.Unlock()

	deb := newRoamDebouncer(n.reconcile)
	deb.start()
	n.roamDeb = deb

	mon := NewNetMon(n.Config.TapName)
	n.netMon = mon
	ctx, cancel := context.WithCancel(n.ctx)
	n.roamCancel = cancel

	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		if err := mon.Watch(ctx, deb.trigger); err != nil {
			// Non-fatal: the initial scheduled reconcile still runs, and reconcile
			// can also be triggered externally.
			log.Warn("roam: failed to start network monitor: %v", err)
		}
	}()
}

// reconcile recomputes the desired listener set from the cached config and
// applies the delta. Guarded by the debouncer's active flag. When the listener
// set actually changes (a NIC appeared/disappeared), the WebUI server is
// rebound so the dashboard stays reachable if it was bound to a specific
// interface IP that went away.
func (n *Node) reconcile() {
	n.parsedListenMu.Lock()
	base := n.parsedListenAddrs
	n.parsedListenMu.Unlock()
	if len(base) == 0 {
		return
	}
	if changed := reconcileRoam(n, base); changed && n.WebSrv != nil {
		if err := n.WebSrv.Rebind(); err != nil {
			log.Warn("roam: WebUI rebind failed: %v", err)
		}
	}
}

// stopRoamWatcher tears down the monitor + debouncer. Called from Close().
func (n *Node) stopRoamWatcher() {
	if n.roamCancel != nil {
		n.roamCancel()
	}
	if n.netMon != nil {
		_ = n.netMon.Close()
	}
	if n.roamDeb != nil {
		n.roamDeb.stop()
	}
}
