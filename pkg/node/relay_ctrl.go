package node

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"

	"p2ptap/pkg/meta"
)

// relayCtrlMaxHops bounds how many relay hops a single control stream may
// traverse. Each intermediate hop increments RelayCtrlHeader.Hops; once it
// reaches this ceiling the frame is dropped instead of being forwarded again.
// This is the control-plane analogue of the data-plane MaxRelayTTL and guards
// against a routing loop wedging a handshake stream open forever.
const relayCtrlMaxHops = 8

// RelayCtrlHeader is the self-delimiting (length-prefixed) header carried on
// every RelayCtrlProtocolID stream. The initiator writes it once; each transit
// hop re-writes it (bumping Hops) before proxying the inner control bytes.
//
//	Origin  — the TRUE source peer (A). Preserved unchanged across every hop so
//	          the final destination can key the cipher / identity on A, not on
//	          the relay that happened to carry the bytes.
//	Target  — the final destination peer (C). When a hop sees Target == itself
//	          it stops forwarding and dispatches the inner protocol locally.
//	Proto   — the inner control protocol ID (SeqSync / LSA / Meta) to run once
//	          the tunnel reaches the final peer.
//	Hops    — relay-hop counter, incremented per transit hop (loop guard).
type RelayCtrlHeader struct {
	Origin peer.ID    `json:"o"`
	Target peer.ID    `json:"t"`
	Proto  string     `json:"p"`
	Hops   uint8      `json:"h"`
}

// openControlStream is the unified control-stream opener used by EVERY control
// protocol (SeqSync, LSA, Meta). It prefers, in order:
//  1. a direct libp2p connection to target;
//  2. an overlay-relay hop (relay-ctrl tunnel through a peer we can reach that
//     can in turn reach target);
//  3. the boot Circuit-Relay-v2 fall-back (openStreamViaRelay).
//
// The caller is agnostic to which path was taken: it simply writes/reads the
// inner control protocol on the returned stream. For path (2) the returned
// stream is the tunnel endpoint at the FIRST hop; the inner bytes are proxied
// transparently to target, which runs the inner protocol with its logical peer
// set to Origin. See handleRelayCtrl.
func (n *Node) openControlStream(ctx context.Context, target peer.ID, proto protocol.ID) (network.Stream, error) {
	if n.isDirectlyConnected(target) {
		return n.Host.NewStream(ctx, target, proto)
	}
	if hop := n.relayHopForTarget(target); hop != "" {
		if n.isBootstrapPeer(hop) {
			// Boot-relay control tunnel: the custom boot is a relay-over-backbone
			// bridge, NOT a Circuit-Relay v2 node, so it has no relay-ctrl
			// handler. Multiplex the inner control protocol onto the persistent
			// boot-relay uplink as kind=Control frames instead.
			return n.openBootRelayControlStream(hop, target, proto)
		}
		return n.openRelayCtrlStream(ctx, hop, n.Host.ID(), target, proto, 1)
	}
	// No overlay hop available: fall back to the boot circuit relay (Circuit
	// Relay v2). This is the classic path for a peer reachable only through a
	// bootstrap node that does not speak the application-level overlay relay.
	return n.openStreamViaRelay(target, proto)
}

// openRelayCtrlStream opens a RelayCtrlProtocolID stream to hop and writes the
// tunnel header. The caller then writes the inner control-protocol bytes on the
// returned stream; hop proxies them toward Target. hops is the relay-hop count
// to stamp into the header (initiator passes 1; a transit hop passes its own
// Hops+1 so the loop guard stays accurate across multi-hop tunnels).
func (n *Node) openRelayCtrlStream(ctx context.Context, hop, origin, target peer.ID, proto protocol.ID, hops uint8) (network.Stream, error) {
	s, err := n.Host.NewStream(ctx, hop, RelayCtrlProtocolID)
	if err != nil {
		return nil, fmt.Errorf("relay-ctrl: open stream to hop %s: %w", hop, err)
	}
	hdr := RelayCtrlHeader{Origin: origin, Target: target, Proto: string(proto), Hops: hops}
	hb, err := json.Marshal(hdr)
	if err != nil {
		s.Close()
		return nil, fmt.Errorf("relay-ctrl: marshal header: %w", err)
	}
	if err := WriteFrame(s, hb); err != nil {
		s.Close()
		return nil, fmt.Errorf("relay-ctrl: write header to hop %s: %w", hop, err)
	}
	return s, nil
}

// handleRelayCtrl is the RelayCtrlProtocolID stream handler. It runs on EVERY
// node that receives a relay-ctrl stream and serves two roles:
//
//   - FINAL HOP (hdr.Target == self): the tunnel has arrived. Dispatch the inner
//     control protocol with the stream's logical peer rewritten to hdr.Origin,
//     so the cipher / identity negotiated here is anchored on the TRUE origin
//     (A), not on the relay that carried the bytes.
//   - TRANSIT HOP (hdr.Target != self): forward the inner bytes toward Target,
//     either by opening a direct relay-ctrl stream to Target (when we are
//     directly connected to it) or by recursing through the next overlay hop
//     (relayHopForTarget). Bytes are proxied verbatim in both directions; the
//     transit hop never interprets the inner control protocol, so it can never
//     learn (or corrupt) the A↔C shared secret.
func (n *Node) handleRelayCtrl(s network.Stream) {
	defer s.Close()
	remotePeer := s.Conn().RemotePeer()

	hdrBuf := make([]byte, 4096)
	n0, err := ReadFrame(s, hdrBuf)
	if err != nil || n0 == 0 {
		log.Debug("RelayCtrl: header read error from %s: %v", remotePeer, err)
		return
	}
	var hdr RelayCtrlHeader
	if err := json.Unmarshal(hdrBuf[:n0], &hdr); err != nil {
		log.Warn("RelayCtrl: bad header from %s: %v", remotePeer, err)
		return
	}
	if hdr.Origin == "" || hdr.Target == "" {
		log.Warn("RelayCtrl: header missing origin/target from %s", remotePeer)
		return
	}

	// ---- FINAL HOP: deliver the inner control protocol locally ----
	if hdr.Target == n.Host.ID() {
		log.Debug("RelayCtrl: final hop for target %s (origin %s, proto %s)",
			hdr.Target, hdr.Origin, protocol.ID(hdr.Proto))
		n.dispatchRelayCtrlInner(s, hdr.Origin, protocol.ID(hdr.Proto))
		return
	}

	// ---- TRANSIT HOP: forward toward Target ----
	if hdr.Hops >= relayCtrlMaxHops {
		log.Warn("RelayCtrl: hop limit (%d) exceeded for target %s; dropping tunnel from %s",
			relayCtrlMaxHops, hdr.Target, hdr.Origin)
		return
	}

	sub, ferr := n.openRelayCtrlNextHop(hdr, remotePeer)
	if ferr != nil || sub == nil {
		log.Warn("RelayCtrl: cannot forward tunnel to %s (origin %s): %v",
			hdr.Target, hdr.Origin, ferr)
		return
	}
	defer sub.Close()

	// Bidirectional raw-byte proxy between the incoming tunnel stream and the
	// outgoing hop. The inner control protocol is NOT length-framed (SeqSync
	// uses newline-delimited JSON), so we copy bytes verbatim rather than
	// frame-by-frame. CloseWrite on each side signals EOF to the peer once the
	// opposite direction hits EOF, letting both ends tear the tunnel down.
	proxyStreams(s, sub)
}

// openRelayCtrlNextHop resolves the next leg of a transit tunnel and returns an
// open stream ready to receive the inner control bytes. Resolution order:
//  1. directly connected to Target → open a relay-ctrl stream and write the
//     FINAL header (Target == self on the far end dispatches locally);
//  2. an overlay-relay hop exists for Target → recurse (openRelayCtrlStream
//     re-writes the header with Hops+1);
//  3. boot circuit relay fall-back → circuit-dial Target on relay-ctrl and
//     write the final header.
func (n *Node) openRelayCtrlNextHop(hdr RelayCtrlHeader, fromPeer peer.ID) (network.Stream, error) {
	nextHops := hdr.Hops + 1

	if n.isDirectlyConnected(hdr.Target) {
		ctx, cancel := context.WithTimeout(n.ctx, 15*time.Second)
		defer cancel()
		sub, err := n.Host.NewStream(ctx, hdr.Target, RelayCtrlProtocolID)
		if err != nil {
			return nil, err
		}
		final := RelayCtrlHeader{Origin: hdr.Origin, Target: hdr.Target, Proto: hdr.Proto, Hops: nextHops}
		fb, _ := json.Marshal(final)
		if werr := WriteFrame(sub, fb); werr != nil {
			sub.Close()
			return nil, werr
		}
		return sub, nil
	}

	if hop := n.relayHopForTarget(hdr.Target); hop != "" && hop != fromPeer {
		ctx, cancel := context.WithTimeout(n.ctx, 15*time.Second)
		defer cancel()
		if n.isBootstrapPeer(hop) {
			if sub, err := n.openRelayCtrlStream(ctx, hop, hdr.Origin, hdr.Target, protocol.ID(hdr.Proto), nextHops); err == nil {
				return sub, nil
			}
			return n.openBootRelayControlStream(hop, hdr.Target, protocol.ID(hdr.Proto))
		}
		return n.openRelayCtrlStream(ctx, hop, hdr.Origin, hdr.Target, protocol.ID(hdr.Proto), nextHops)
	}


	// Boot circuit relay fall-back: dial Target through the circuit on the
	// relay-ctrl protocol; the far end dispatches it as a final hop.
	sub, err := n.openStreamViaRelay(hdr.Target, RelayCtrlProtocolID)
	if err != nil {
		return nil, err
	}
	final := RelayCtrlHeader{Origin: hdr.Origin, Target: hdr.Target, Proto: hdr.Proto, Hops: nextHops}
	fb, _ := json.Marshal(final)
	if werr := WriteFrame(sub, fb); werr != nil {
		sub.Close()
		return nil, werr
	}
	return sub, nil
}

// dispatchRelayCtrlInner runs the inner control protocol on the tunnel's final
// hop. The stream's logical peer is rewritten to origin so every consumer that
// keys state on s.Conn().RemotePeer() (cipher slot, dedup window, ready flag,
// meta identity) binds to the TRUE origin rather than the relay.
func (n *Node) dispatchRelayCtrlInner(s network.Stream, origin peer.ID, proto protocol.ID) {
	wrapped := &logicalPeerStream{Stream: s, logical: origin}
	switch proto {
	case SeqSyncProtocolID:
		n.handleSeqSync(wrapped)
	case LSAProtocolID:
		n.handleLSAStream(wrapped)
	case meta.MetaProtocolID:
		n.handleMetaStream(wrapped)
	case EchoProtocolID:
		// echoPool is built on newLSAStreamPool, so it opens through
		// openControlStream and therefore gets tunnelled for relay-only peers
		// too. Without this case the final hop would fall into default: and
		// close the stream, permanently breaking RTT measurement / keepalive
		// for exactly the peers that depend on the tunnel.
		n.handleEcho(wrapped)
	default:
		log.Warn("RelayCtrl: no inner handler for proto %s (origin %s); closing", proto, origin)
	}
}

// proxyStreams copies bytes bidirectionally between two libp2p streams until
// both hit EOF (or error). It is intentionally agnostic to any framing on the
// inner protocol: bytes are moved verbatim. CloseWrite on each direction lets
// the peer learn the tunnel is half-closed so it can tear down cleanly.
func proxyStreams(a, b network.Stream) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(b, a)
		_ = b.CloseWrite()
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(a, b)
		_ = a.CloseWrite()
	}()
	wg.Wait()
}

// logicalPeerStream wraps a network.Stream so that RemotePeer() (and
// Conn().RemotePeer()) report a LOGICAL peer instead of the physical transport
// peer. This is what lets a relayed control handshake bind its cipher / identity
// to the true origin peer rather than to the relay hop that carried the bytes.
// All other stream methods (Read/Write/Close/SetDeadline/Conn().RemoteMultiaddr)
// are delegated unchanged to the underlying stream.
type logicalPeerStream struct {
	network.Stream
	logical peer.ID
}

// RemotePeer reports the logical (true origin) peer.
func (l *logicalPeerStream) RemotePeer() peer.ID { return l.logical }

// Conn returns a connection view whose RemotePeer() is the logical peer. Every
// control handler resolves the counterpart via s.Conn().RemotePeer(), so this
// single override is enough to retarget all per-peer state.
func (l *logicalPeerStream) Conn() network.Conn {
	return &logicalPeerConn{Conn: l.Stream.Conn(), logical: l.logical}
}

// logicalPeerConn wraps network.Conn, overriding only RemotePeer().
type logicalPeerConn struct {
	network.Conn
	logical peer.ID
}

// RemotePeer reports the logical (true origin) peer.
func (c *logicalPeerConn) RemotePeer() peer.ID { return c.logical }

// relayControlReconciler periodically ensures that every peer which is reachable
// ONLY via a relay hop (not directly connected) has had its control plane
// brought up: an end-to-end SeqSync cipher and an identity (Meta) exchange.
// Without this, A and C (connected only through relay B) would learn each
// other's existence via flooded LSA but never establish the A↔C cipher, so
// every A→C frame would be dropped at C's AEAD gate — the exact "cannot connect
// to other peers" failure. We drive SyncSeqToPeer/Meta through the relay-ctrl
// tunnel (openControlStream) exactly as a directly-connected peer would.
func (n *Node) relayControlReconciler() {
	defer n.wg.Done()
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-n.ctx.Done():
			return
		case <-ticker.C:
			n.reconcileRelayControl()
			n.reconcileRelayControlOverBackbone()
		}
	}
}

// reconcileRelayControl scans the current route table for peers that are
// reachable only via a relay hop and brings their control plane up. A per-peer
// cooldown prevents re-triggering the (already self-rate-limited) SyncSeqToPeer
// every 5s tick while a handshake is still converging.
func (n *Node) reconcileRelayControl() {
	routes := n.getCachedRoutes()
	for pid, r := range routes {
		if pid == n.Host.ID() {
			continue
		}
		// Directly-connected peers bring their control plane up through the
		// normal connection-established path; skip them.
		if n.isDirectlyConnected(pid) {
			continue
		}
		// Only peers that have a relay next-hop (and are not us) need tunnelling.
		if r.NextHop == "" || r.NextHop == n.Host.ID() {
			continue
		}
		if n.isBootstrapPeer(pid) {
			continue
		}
		// Already converged (cipher + ready) → nothing to do.
		if n.isPeerReady(pid) && n.peerObf(pid) != nil {
			continue
		}
		// Cooldown: don't re-kick more often than every 20s per peer.
		if v, ok := n.relayCtrlSyncAt.Load(pid); ok {
			if time.Since(v.(time.Time)) < 20*time.Second {
				continue
			}
		}
		n.relayCtrlSyncAt.Store(pid, time.Now())

		target := pid
		go func() {
			// Cipher first; identity piggybacks on the same tunnel afterwards.
			// Respect the single-initiator (resync-leader) rule: only the LEADER
			// opens the handshake stream, the FOLLOWER nudges via rekeyReq (which
			// arrives over the relay-ctrl tunnel and makes the leader drive). This
			// is what stops BOTH relay-only peers from running SyncSeqToPeer at
			// once and deadlocking on the per-peer handshake mutex — each node
			// would be simultaneously the initiator (holding the lock for the
			// whole retry round) and the responder (blocked acquiring the same
			// lock), so the relayed "sync" is never answered and the A↔C cipher
			// never converges.
			n.triggerPeerRekey(target)
			// Meta exchange rides the same relay-ctrl tunnel; only attempt it once
			// the cipher is up so the session is authenticated. If not ready yet
			// the next reconciler tick will drive it.
			if n.isPeerReady(target) {
				n.syncMetadataToPeer(target)
			}
		}()
	}
}

// reconcileRelayControlOverBackbone scans the known-VPN-peer set (peerMeta) for
// peers that are reachable ONLY through a boot-relay uplink (relay-over-backbone)
// and brings their control plane up. These peers are learned via the boot's
// peek-map federation / meta, so they never appear in the LSA route table (the
// boot does not speak LSA) and the first loop above would never touch them — yet
// without a SeqSync cipher every frame to them dies at the AEAD gate. This is the
// exact gap that left two NAT'd nodes in the same PSK network (both behind a NAT,
// both connected to the same boot) unable to exchange a single ARP reply.
//
// The reconciliation reuses the SAME openControlStream path as a directly-
// connected peer: for a boot hop it opens the boot-relay control tunnel, which
// multiplexes the SeqSync handshake onto the persistent boot-relay uplink. The
// resync-leader rule still guarantees exactly one side initiates, so the
// simulator's (remote, proto) keying never collides on a simultaneous open.
func (n *Node) reconcileRelayControlOverBackbone() {
	n.peerMeta.Range(func(k, _ any) bool {
		pid, ok := k.(peer.ID)
		if !ok || pid == n.Host.ID() {
			return true
		}
		// Directly-connected peers bring their control plane up through the normal
		// connection-established path; bootstrap nodes are relays, not mesh peers.
		if n.isDirectlyConnected(pid) || n.isBootstrapPeer(pid) {
			return true
		}
		// No boot-relay path yet (uplink not established / peer on another PSK
		// network) → unreachable; skip until the uplink converges.
		if n.relayHopForTarget(pid) == "" {
			return true
		}
		// Already converged (cipher + ready) → nothing to do.
		if n.isPeerReady(pid) && n.peerObf(pid) != nil {
			return true
		}
		// Cooldown: don't re-kick more often than every 20s per peer.
		if v, ok := n.relayCtrlSyncAt.Load(pid); ok {
			if time.Since(v.(time.Time)) < 20*time.Second {
				return true
			}
		}
		n.relayCtrlSyncAt.Store(pid, time.Now())

		target := pid
		go func() {
			n.triggerPeerRekey(target)
			if n.isPeerReady(target) {
				n.syncMetadataToPeer(target)
			}
		}()
		return true
	})
}
