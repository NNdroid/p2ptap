package node

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"

	"p2ptap/pkg/obfuscate"
	"p2ptap/pkg/observer"
	"p2ptap/pkg/routing"
	"p2ptap/pkg/version"
	vswitch "p2ptap/pkg/switch"
)


// bootRelayMaxQueue is the per-boot write buffer depth for the boot-relay
// uplink. When full, Submit fails fast and the caller falls back to the circuit
// path (or drops, and the source retransmits).
const bootRelayMaxQueue = 128

// bootRelayBlacklistTTL is how long a boot stays blacklisted after its uplink
// repeatedly failed to establish. Expiry lets a boot that later comes up be
// retried instead of being permanently avoided.
const bootRelayBlacklistTTL = 5 * time.Minute

// bootRelayBlacklistMaxFailures is how many consecutive NewStream attempts to a
// boot must fail before we conclude it is not a real boot-relay server (e.g. a
// plain node mistakenly listed as a bootstrap peer) and blacklist it.
const bootRelayBlacklistMaxFailures = 5

// bootRelayJob is a single frame queued for the boot-relay uplink write loop.
type bootRelayJob struct {
	data   []byte
	onSent func()
	onFail func()
}

// bootRelayConn is the persistent boot-relay uplink to one boot. A single libp2p
// stream carries BOTH directions: the node writes relay envelopes UP (frames the
// boot must bridge) and reads relay envelopes DOWN (frames the boot bridged for
// this node). The write loop and the downlink reader run as two goroutines over
// the same stream; either ending tears the uplink down so it is reopened.
type bootRelayConn struct {
	boot    peer.ID
	ctx     context.Context
	cancel  context.CancelFunc
	mu      sync.Mutex
	stream  network.Stream
	writeCh chan bootRelayJob
}

// openBootRelayUplink establishes and maintains a persistent /p2ptap/boot-relay/
// 1.0.0 stream to boot. It is spawned once per connected boot right after the
// node authenticates with it (ensureRelayAuth). The loop reopens the stream on
// any disconnect, so transient boot link drops self-heal.
func (n *Node) openBootRelayUplink(boot peer.ID) {
	backoff := 2 * time.Second
	const maxBackoff = 30 * time.Second
	// readerBackoff spaces out reconnects AFTER a stream was established and then
	// died (reader returned). Without it a boot that accepts the stream and
	// immediately closes would cause a tight reconnect loop.
	readerBackoff := time.Second
	const maxReaderBackoff = 15 * time.Second
	failCount := 0
	for {
		if n.ctx.Err() != nil {
			return
		}
		// If this boot is blacklisted (its uplink repeatedly failed to
		// establish — it is likely not a real boot-relay server), throttle
		// reconnect attempts to one per TTL instead of hammering NewStream every
		// few seconds. The blacklist auto-expires, after which we retry.
		if n.isBootRelayBlacklisted(boot) {
			select {
			case <-n.ctx.Done():
				return
			case <-time.After(bootRelayBlacklistTTL):
			}
			continue
		}
		if n.Host.Network().Connectedness(boot) != network.Connected {
			select {
			case <-n.ctx.Done():
				return
			case <-time.After(2 * time.Second):
			}
			continue
		}
		s, err := n.Host.NewStream(n.ctx, boot, BootRelayProtocolID)
		if err != nil {
			failCount++
			log.Debug("[boot-relay] open uplink to %s failed (attempt %d, backoff=%v): %v", boot.ShortString(), failCount, backoff, err)
			if failCount >= bootRelayBlacklistMaxFailures {
				// The peer does not speak /p2ptap/boot-relay/1.0.0 — it is not a
				// real boot-relay server (e.g. a plain node mistakenly listed as
				// a bootstrap peer). Blacklist so relayHopForTarget stops trying
				// to egress through it and drops frames on every single packet.
				n.blacklistBootRelay(boot)
			}
			select {
			case <-n.ctx.Done():
				return
			case <-time.After(backoff):
			}
			if backoff < maxBackoff {
				backoff *= 2
			}
			continue
		}
		backoff = 2 * time.Second
		failCount = 0
		readerBackoff = time.Second
		log.Info("[boot-relay] uplink established to boot %s", boot.String())

		rcCtx, rcCancel := context.WithCancel(n.ctx)
		rc := &bootRelayConn{
			boot:    boot,
			ctx:     rcCtx,
			cancel:  rcCancel,
			stream:  s,
			writeCh: make(chan bootRelayJob, bootRelayMaxQueue),
		}
		n.bootRelayRegister(boot, rc)

		// Write loop (one goroutine) + downlink reader over the same stream.
		go n.bootRelayWriteLoop(rc)
		n.handleBootRelayDownlink(s, boot)

		// Downlink reader returned (stream dead): tear down, cancel writeLoop, and
		// reopen. Space the reopen out so a boot that accepts-then-closes does
		// not tight-loop.
		n.bootRelayUnregister(boot, rc)
		rcCancel()
		s.Close()
		log.Debug("[boot-relay] uplink to %s closed; reopening after %v", boot.ShortString(), readerBackoff)
		select {
		case <-n.ctx.Done():
			return
		case <-time.After(readerBackoff):
		}
		if readerBackoff < maxReaderBackoff {
			readerBackoff *= 2
		}
	}
}

func (n *Node) bootRelayRegister(boot peer.ID, rc *bootRelayConn) {
	n.bootRelayMu.Lock()
	n.bootRelayConns[boot] = rc
	n.bootRelayMu.Unlock()
}

func (n *Node) bootRelayUnregister(boot peer.ID, rc *bootRelayConn) {
	n.bootRelayMu.Lock()
	if n.bootRelayConns[boot] == rc {
		delete(n.bootRelayConns, boot)
	}
	n.bootRelayMu.Unlock()
}

// hasBootRelayUplink reports whether a persistent boot-relay uplink to boot is
// currently established. It is the gate used by canEgressToPeer and
// relayHopForTarget for the relay-over-backbone path: a peer is reachable
// through boot B iff the uplink to B is alive (the boot itself is a relay, not a
// mesh peer, so we hold no cipher / "ready" flag for it).
func (n *Node) hasBootRelayUplink(boot peer.ID) bool {
	n.bootRelayMu.Lock()
	_, ok := n.bootRelayConns[boot]
	n.bootRelayMu.Unlock()
	return ok
}

// isBootRelayBlacklisted reports whether boot is currently blacklisted (its
// relay-over-backbone uplink repeatedly failed to establish). Expired entries
// are purged on access so a boot that later comes up is retried.
func (n *Node) isBootRelayBlacklisted(boot peer.ID) bool {
	n.bootRelayBlacklistMu.Lock()
	defer n.bootRelayBlacklistMu.Unlock()
	exp, ok := n.bootRelayBlacklist[boot]
	if !ok {
		return false
	}
	if time.Now().After(exp) {
		delete(n.bootRelayBlacklist, boot)
		return false
	}
	return true
}

// blacklistBootRelay marks boot as unusable for relay-over-backbone until
// bootRelayBlacklistTTL elapses. It is called when the uplink NewStream fails
// too many times in a row (the peer is not a real boot-relay server).
func (n *Node) blacklistBootRelay(boot peer.ID) {
	n.bootRelayBlacklistMu.Lock()
	n.bootRelayBlacklist[boot] = time.Now().Add(bootRelayBlacklistTTL)
	n.bootRelayBlacklistMu.Unlock()
	log.Warn("[boot-relay] blacklisted boot %s: relay-over-backbone uplink could not be established (is it actually running p2ptap-boot?)", boot.ShortString())
}

// isOverlayRelayBlacklisted reports whether hop is circuit-broken as an
// overlay-relay next-hop (its relay stream could not be opened / kept stalling).
// Expired entries are purged on access so a hop that later recovers is retried.
// Mirrors isBootRelayBlacklisted but for ordinary mesh relay peers.
func (n *Node) isOverlayRelayBlacklisted(hop peer.ID) bool {
	n.overlayRelayBlacklistMu.Lock()
	defer n.overlayRelayBlacklistMu.Unlock()
	exp, ok := n.overlayRelayBlacklist[hop]
	if !ok {
		return false
	}
	if time.Now().After(exp) {
		delete(n.overlayRelayBlacklist, hop)
		return false
	}
	return true
}

// blacklistOverlayRelay marks hop as unusable as an overlay-relay next-hop until
// overlayRelayBlacklistTTL elapses. Called by the relay pool when its write loop
// fails to open or keep the relay stream alive after overlayRelayBlacklistMaxFailures
// consecutive attempts, so relayHopForTarget stops selecting it and frames fall
// through to a different hop instead of being blackholed. Already-active
// (non-expired) entries are not refreshed/extended.
func (n *Node) blacklistOverlayRelay(hop peer.ID) {
	n.overlayRelayBlacklistMu.Lock()
	exp, ok := n.overlayRelayBlacklist[hop]
	if ok && time.Now().Before(exp) {
		n.overlayRelayBlacklistMu.Unlock()
		return // already blacklisted and still active — do not extend
	}
	n.overlayRelayBlacklist[hop] = time.Now().Add(overlayRelayBlacklistTTL)
	n.overlayRelayBlacklistMu.Unlock()
	relayLog.Warn("[relay-pool] circuit-broke overlay relay hop %s: stream could not be opened/kept alive; routing around it for %s",
		hop.ShortString(), overlayRelayBlacklistTTL)
}

// bootRelaySubmit queues a boot-relay envelope for delivery on the persistent
// uplink to boot. Returns false (and calls onFail) if the uplink is not yet
// established or its queue is full, so the caller can fall back.
func (n *Node) bootRelaySubmit(boot peer.ID, env []byte, onSent, onFail func()) bool {
	n.bootRelayMu.Lock()
	rc := n.bootRelayConns[boot]
	n.bootRelayMu.Unlock()
	if rc == nil {
		if onFail != nil {
			onFail()
		}
		return false
	}
	select {
	case rc.writeCh <- bootRelayJob{data: env, onSent: onSent, onFail: onFail}:
		return true
	default:
		if onFail != nil {
			onFail()
		}
		return false
	}
}

// bootRelayWriteLoop pumps queued envelopes onto the uplink stream. It exits on
// context cancellation or a stream write error, draining the queue (calling
// onFail) so no frame is left silently queued on a dead uplink.
func (n *Node) bootRelayWriteLoop(rc *bootRelayConn) {
	for {
		select {
		case <-rc.ctx.Done():
			n.bootRelayDrain(rc)
			return
		case job, ok := <-rc.writeCh:
			if !ok {
				return
			}
			_ = rc.stream.SetWriteDeadline(time.Now().Add(3 * time.Second))
			if err := WriteFrame(rc.stream, job.data); err != nil {
				log.Debug("[boot-relay] uplink write to %s failed: %v", rc.boot.ShortString(), err)
				if job.onFail != nil {
					job.onFail()
				}
				n.bootRelayDrain(rc)
				return
			}
			if job.onSent != nil {
				job.onSent()
			}
		}
	}
}

func (n *Node) bootRelayDrain(rc *bootRelayConn) {
	for {
		select {
		case job := <-rc.writeCh:
			if job.onFail != nil {
				job.onFail()
			}
		default:
			return
		}
	}
}

// handleBootRelayDownlink reads relay envelopes the boot bridged FOR this node
// (finalDst == self) off the uplink stream and injects them into the local TAP.
// The envelope's inner TAP payload is end-to-end encrypted for us by the origin,
// so we decrypt with the cipher negotiated for the TRUE origin (srcPeer) — the
// boot itself never holds that key.
func (n *Node) handleBootRelayDownlink(s network.Stream, boot peer.ID) {
	defer s.Close()
	buf := make([]byte, obfuscate.MaxSealedFrameSize)
	for {
		readN, err := ReadFrame(s, buf)
		if err != nil || readN == 0 {
			return
		}
		data := buf[:readN]
		netID, kind, proto, finalDst, srcPeer, _, innerPayload, uerr := routing.UnpackBootRelayFrame(data)
		if uerr != nil {
			// A truncation / layout error here almost always means the boot is
			// running a DIFFERENT envelope version than this node (the historical
			// 0x8000 "proto field len 32768 > 163" class of bug). Surface it as a
			// WARN with both commits so the operator can immediately see the
			// version skew instead of silently dropped frames — the auth-handshake
			// version gate (P0) should normally have rejected this peer already.
			log.Warn("[boot-relay] downlink unpack error from %s (local commit=%s): %v", boot.String(), version.ShortCommit(), uerr)
			continue
		}
		if finalDst != n.Host.ID() {
			// The boot only sends us frames destined for us; a misrouted frame
			// is harmless to ignore.
			continue
		}
		// Control-plane frames (SeqSync / LSA / Meta / Echo for a relay-only
		// peer) carry the raw inner protocol bytes and must NOT be decrypted with
		// a per-peer cipher — that cipher is exactly what the handshake is trying
		// to establish, so it does not exist yet. They are multiplexed onto the
		// same boot-relay uplink as data frames and dispatched to the matching
		// local control handler with the logical peer set to srcPeer.
		if kind == routing.BootRelayKindControl {
			n.deliverBootRelayControl(finalDst, srcPeer, proto, boot, innerPayload)
			continue
		}
		_ = netID
		// Decrypt the inner payload with the cipher negotiated for srcPeer.
		if cipher := n.obfDecryptCipherForPeer(srcPeer); cipher != nil {
			dec, derr := obfuscate.DecryptPayloadRegion(innerPayload, cipher)
			if derr != nil {
				log.Debug("[boot-relay] downlink decrypt error from origin %s (via %s): %v",
					srcPeer.String(), boot.String(), derr)
				n.recordPeerRxDecrypt(srcPeer, false)
				continue
			}
			innerPayload = dec
		}
		seqID, unpacked, uerr := obfuscate.Unpack(innerPayload)
		if uerr != nil {
			log.Debug("[boot-relay] downlink Unpack err=%v from origin=%s; dropping", uerr, srcPeer.String())
			continue
		}
		n.deliverRelayedFrameToTAP(unpacked, srcPeer, boot, seqID)
	}
}

// sendToPeerViaBootRelay delivers packedData to a peer reachable only through a
// boot (relay-over-backbone). It mirrors sendToPeerViaOverlayRelay but targets
// the boot-relay uplink instead of the overlay relay pool:
//
//  1. END-TO-END seal the inner TAP frame for the final destination (boot cannot read it).
//  2. Wrap in a routing.PackBootRelayFrame envelope carrying our network ID in-band.
//  3. Submit to the persistent boot-relay uplink for the connected boot, which
//     bridges the frame to the destination (across the boot backbone if needed).
func (sd *StrategyDispatcher) sendToPeerViaBootRelay(target, bootHop peer.ID, packedData []byte) error {
	n := sd.node
	if n == nil {
		return fmt.Errorf("boot-relay send to %s requires node", target.String())
	}
	txBytes := len(packedData)

	// 1. End-to-end seal for the final destination.
	inner := packedData
	if cipher := n.obfCipherForPeer(target); cipher != nil {
		enc, eerr := n.sealPeerFrame(target, cipher, inner)
		if eerr != nil {
			return fmt.Errorf("boot-relay end-to-end seal for %s failed: %w", target.String(), eerr)
		}
		inner = enc
	}

	// 2. Wrap in a boot-relay envelope with the in-band network ID. kind=Data
	//    means the inner payload is an end-to-end-encrypted TAP frame.
	env, err := routing.PackBootRelayFrame(n.bootRelayNetID, routing.BootRelayKindData, "", target, n.Host.ID(), routing.MaxRelayTTL, inner)
	if err != nil {
		return fmt.Errorf("boot-relay pack for %s failed: %w", target.String(), err)
	}

	// 3. Submit to the persistent boot-relay uplink.
	if !n.bootRelaySubmit(bootHop, env,
		func() { n.recordPeerTxBytes(target, txBytes) },
		func() {
			log.Debug("[boot-relay] send to peer %s via %s permanently failed", target.String(), bootHop.String())
		},
	) {
		return fmt.Errorf("boot-relay send to %s via %s: uplink unavailable", target.String(), bootHop.String())
	}
	return nil
}

// deliverRelayedFrameToTAP writes a decrypted, unpacked relayed Ethernet frame
// into the local TAP device, applying the same dedup / ACL / MAC-learn /
// exit-node / dst-MAC-fixup steps as the overlay-relay receive path. srcPeer is
// the TRUE origin (used for the cipher, dedup window and ACL); viaPeer is the
// transport peer the frame arrived FROM (the overlay relay hop or the boot for
// relay-over-backbone). Centralising this stops the two relay paths from
// drifting apart.
func (n *Node) deliverRelayedFrameToTAP(tapPayload []byte, srcPeer, viaPeer peer.ID, seqID uint64) {
	// Valid end-to-end frame: record success so the recent-error window resets
	// and readiness self-heals, matching the direct-frame RX path.
	n.recordPeerRxDecrypt(srcPeer, true)
	n.maybeMarkReadyOnDecrypt(srcPeer, true)

	n.dedupPeersMu.RLock()
	peerDedup, ok := n.dedupPeers[srcPeer]
	n.dedupPeersMu.RUnlock()
	if !ok {
		n.dedupPeersMu.Lock()
		peerDedup = n.dedupPeers[srcPeer]
		if peerDedup == nil {
			peerDedup = obfuscate.NewDeduplicator()
			n.dedupPeers[srcPeer] = peerDedup
		}
		n.dedupPeersMu.Unlock()
	}
	if peerDedup.IsDuplicate(seqID) {
		n.Collector.RecordDedup()
		n.Collector.RecordPeerDedup(srcPeer.String())
		log.Debug("Duplicate relayed frame seq=%d from peer %s", seqID, srcPeer.String())
		return
	}
	n.Collector.RecordRxSeq(srcPeer.String(), seqID, peerDedup.MaxSeq(), peerDedup.ReplayDrops(), peerDedup.WindowResets(), peerDedup.WindowUtilization())

	// ACL check — evaluate against the TRUE origin (srcPeer), not the relay
	// transport peer. The relay only forwards the frame; the security policy is
	// about which mesh member may inject traffic into our TAP.
	if !n.checkACL(tapPayload, srcPeer.String(), false) {
		log.Debug("ACL blocked relayed frame from origin %s (via %s)", srcPeer.String(), viaPeer.String())
		return
	}

	// Learn source MAC — key on srcPeer so replies route back through the relay
	// path (not directly to the relay forwarder, which would drop them).
	if dstMAC, srcMAC, ok := vswitch.ExtractEthernetMACs(tapPayload); ok {
		if realMAC := n.lookupPeerTapMAC(srcPeer); realMAC != nil {
			srcMAC = realMAC
		}
		n.MACTable.Learn(srcMAC, srcPeer)
		log.Debug("Rx relayed frame: len=%d src=%s dst=%s from_peer=%s",
			len(tapPayload), net.HardwareAddr(srcMAC[:]).String(), net.HardwareAddr(dstMAC[:]).String(), viaPeer.String())
	}

	// Content-based frame dedup ONLY for broadcast/multicast relayed frames.
	// Unicast frames are handled by per-peer SeqID sliding window deduplication.
	if len(tapPayload) >= 6 && isBroadcastOrMulticastMAC(net.HardwareAddr(tapPayload[0:6])) {
		contentHash := fnvHash64(tapPayload)
		if n.bcastDedup.isDuplicate(contentHash) {
			n.Collector.RecordDedup()
			log.Debug("Content-dup relayed broadcast frame hash=0x%x from peer %s dropped", contentHash, srcPeer.String())
			return
		}
	}


	// Routing arbitration for relayed transit (mirrors the direct-Rx decision
	// table): an Exit Node client only sinks frames genuinely for us.
	if n.isExitNodeActive() {
		dstV4, dstV6 := frameDstIPs(tapPayload)
		if dstV4 != nil && !dstV4.Equal(n.localV4IP) && n.lookupPeerMACByAdvertisedSubnet(dstV4) == nil {
			log.Debug("Dropping relayed transit dstIP=%s: would mis-egress via local Exit Node", dstV4.String())
			return
		}
		if dstV6 != nil && n.localV6IP != nil && !dstV6.Equal(n.localV6IP) && n.lookupPeerMACByAdvertisedSubnet(dstV6) == nil {
			log.Debug("Dropping relayed transit dstIP=%s: would mis-egress via local Exit Node", dstV6.String())
			return
		}
	}

	// L2 MAC fixup so the kernel TAP accepts the frame as addressed to us.
	n.rewriteRxDstMAC(tapPayload)

	// Write packet to local TAP device.
	if n.TAP != nil {
		if n.Collector != nil {
			n.Collector.CaptureFrameWithPeers(observer.DirRx, tapPayload, srcPeer.String(), "self")
		}
		_, _ = n.tapWrite(tapPayload)
		n.recordPeerRxBytes(srcPeer, len(tapPayload))
		n.Collector.RecordRecv(len(tapPayload))
		n.Collector.RecordPacketDir(tapPayload, false)
		n.IPTracker.ExtractAndRecord(tapPayload, false)
		if len(tapPayload) >= 14 {
			ethType := binary.BigEndian.Uint16(tapPayload[12:14])
			n.Collector.RecordProtocol(ethType)
		}
	}

}
