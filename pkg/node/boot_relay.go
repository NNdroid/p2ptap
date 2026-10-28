package node

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"

	"p2ptap/pkg/obfuscate"
	"p2ptap/pkg/observer"
	"p2ptap/pkg/routing"
	vswitch "p2ptap/pkg/switch"
	"p2ptap/pkg/version"
)

// bootRelayMaxQueue is the per-boot write buffer depth for the boot-relay
// uplink. When full, Submit fails fast and the caller falls back to the circuit
// path (or drops, and the source retransmits).
const bootRelayMaxQueue = 128

// maxBootRelayEnvelope is the largest boot-relay frame on the wire:
//
//	obfuscate.MaxSealedFrameSize (65551) + relay header (~98B for two
//	46-char peer.IDs) + boot-relay prefix (21B) = 65670 bytes.
//
// ReadFrame rejects any frame larger than its destination buffer ("frame too
// large") and drops it SILENTLY, so every relay read path MUST allocate at
// least this much or max-size envelopes are lost. 64 KiB (65536) is 134 bytes
// too small for the envelope alone — the boot-relay downlink used to size its
// buffer to exactly obfuscate.MaxSealedFrameSize and dropped the largest valid
// frames. Rounded up to 66000 for headroom, matching p2ptap-boot's own
// constant so the two sides cannot drift apart again.
const maxBootRelayEnvelope = 66000

// bootRelayBlacklistTTL is how long a boot stays blacklisted after its uplink
// repeatedly failed to establish. 30s allows rapid self-healing recovery from transient blips.
const bootRelayBlacklistTTL = 30 * time.Second

// bootRelayBlacklistMaxFailures is how many consecutive NewStream attempts to a
// boot must fail before we conclude it is not a real boot-relay server (e.g. a
// plain node mistakenly listed as a bootstrap peer) and blacklist it.
const bootRelayBlacklistMaxFailures = 8

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

// bootRelayUplinkAbortAfter is how long a boot may be unreachable before the
// uplink loop gives up and retires its bootRelayStarted slot. Transient drops
// run for seconds; a boot that has been gone this long has left the mesh, and
// leaving the loop running means the slot is never reclaimed, so a later
// reconnect would find a stale entry and never restart the uplink. ConnectedF
// starts a fresh loop as soon as the boot comes back.
const bootRelayUplinkAbortAfter = 15 * time.Minute

// openBootRelayUplink establishes and maintains a persistent /p2ptap/boot-relay/
// 1.0.0 stream to boot. It is spawned once per connected boot right after the
// node authenticates with it (ensureRelayAuth). The loop reopens the stream on
// any disconnect, so transient boot link drops self-heal; after a sustained
// absence it exits instead of polling forever, handing the slot back so a
// future connection can reopen the uplink.
func (n *Node) openBootRelayUplink(boot peer.ID, gen uint64) {
	backoff := 2 * time.Second
	const maxBackoff = 30 * time.Second
	// readerBackoff spaces out reconnects AFTER a stream was established and then
	// died (reader returned). Without it a boot that accepts the stream and
	// immediately closes would cause a tight reconnect loop.
	readerBackoff := time.Second
	const maxReaderBackoff = 15 * time.Second
	failCount := 0
	// goneSince marks the first poll that found the boot unreachable. Any
	// reconnection resets it, so a boot that flaps but keeps coming back never
	// triggers the abort.
	var goneSince time.Time
	for {
		if n.ctx.Err() != nil {
			return
		}
		if n.Host.Network().Connectedness(boot) == network.NotConnected {
			// Connectivity is checked BEFORE the blacklist throttle: a
			// blacklisted boot that is also offline would otherwise spend its
			// 30s blacklist sleep first and keep resetting goneSince, so the
			// loop could never reach the abort condition at all.
			if goneSince.IsZero() {
				goneSince = time.Now()
			} else if time.Since(goneSince) >= bootRelayUplinkAbortAfter {
				log.Info("[boot-relay] boot %s unreachable for %v; giving up on its uplink and releasing the slot for a fresh start when it returns",
					boot.ShortString(), time.Since(goneSince).Round(time.Second))
				n.forgetBootRelayStarted(boot, gen)
				return
			}
			select {
			case <-n.ctx.Done():
				return
			case <-time.After(2 * time.Second):
			}
			continue
		}
		goneSince = time.Time{}
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
		// Start the writer BEFORE publishing rc. bootRelayRegister is what makes
		// rc visible to bootRelaySubmit, and registering first left a window in
		// which a submit could enqueue into a channel no writer had started yet.
		// The writer itself does not read anything gated on registration.
		go n.bootRelayWriteLoop(rc)
		n.bootRelayRegister(boot, rc)

		// Downlink reader over the same stream.
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

// maybeSpawnBootRelayUplink starts the boot-relay uplink loop for boot when no
// one is running already, and reports whether it started one. Both
// authentication paths call it (ConnectedF and ensureRelayAuth), which is why
// the once-only guard lives here instead of being duplicated at each call site.
func (n *Node) maybeSpawnBootRelayUplink(boot peer.ID) bool {
	n.bootRelayMu.Lock()
	if _, ok := n.bootRelayStarted[boot]; ok {
		n.bootRelayMu.Unlock()
		return false
	}
	gen := n.bootRelayUplinkGen.Add(1)
	n.bootRelayStarted[boot] = gen
	n.bootRelayMu.Unlock()
	go n.openBootRelayUplink(boot, gen)
	return true
}

// forgetBootRelayStarted retires boot's uplink slot only if this loop still
// owns it. A boot that comes back before a stale loop has noticed its absence
// gets a fresh entry and a fresh loop, and the stale loop must not delete the
// newcomer's entry and leave it orphaned.
func (n *Node) forgetBootRelayStarted(boot peer.ID, gen uint64) {
	n.bootRelayMu.Lock()
	if cur, ok := n.bootRelayStarted[boot]; ok && cur == gen {
		delete(n.bootRelayStarted, boot)
	}
	n.bootRelayMu.Unlock()
}

// hasBootRelayUplink reports whether a persistent boot-relay uplink to boot is
// currently established AND still usable. It is the gate used by canEgressToPeer
// and relayHopForTarget for the relay-over-backbone path: a peer is reachable
// through boot B iff the uplink to B is alive (the boot itself is a relay, not a
// mesh peer, so we hold no cipher / "ready" flag for it).
//
// A map entry alone is not enough — registration tracks ownership, not
// deliverability. bootRelayWriteLoop removes its own entry on every exit path,
// but a conn whose context has been cancelled is unusable the instant it is
// cancelled, so this re-checks ctx too. Without it a dead boot would keep being
// selected as a hop for the whole re-open backoff, so in a multi-boot
// deployment traffic would stall against the dead boot instead of falling over
// to a healthy sibling.
func (n *Node) hasBootRelayUplink(boot peer.ID) bool {
	n.bootRelayMu.Lock()
	rc, ok := n.bootRelayConns[boot]
	n.bootRelayMu.Unlock()
	if !ok {
		return false
	}
	// rc.ctx is written once at construction and never reassigned, so reading
	// it outside the lock is safe; the map lookup above is what publishes the
	// pointer.
	//
	// A nil context is the bare &bootRelayConn{boot: ...} stub several routing
	// tests register to fake a live uplink. It has no writer and no context,
	// and a nil context interface panics on Done(), so it is reported alive
	// rather than read.
	if rc.ctx == nil {
		return true
	}
	return rc.ctx.Err() == nil
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
		// writeCh is buffered and never closed, so a successful send is not proof
		// the job will be consumed. bootRelayWriteLoop drains once on
		// rc.ctx.Done() and then exits, so a submit that races that exit enqueues
		// into a channel nobody reads and returns success for a lost frame. Drain
		// it — the channel hands each job out exactly once, so onFail fires at
		// most once even if the writer is still draining — and report failure so
		// the caller falls back.
		//
		// rc.ctx is compared to nil rather than read through a select case:
		// a nil context interface panics on Done(), and unit tests register
		// bare &bootRelayConn{boot: ...} stubs to exercise the dispatch paths.
		if rc.ctx != nil && rc.ctx.Err() != nil {
			n.bootRelayDrain(rc)
			return false
		}
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
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	// Unregister on EVERY exit path, declared before stream.Close so the close
	// (which wakes the downlink reader) runs first. A failed write drains,
	// cancels rc and returns: without this bootRelayConns[boot] kept pointing
	// at a dead conn, so hasBootRelayUplink reported a live uplink for the
	// whole re-open backoff and relayHopForTarget kept sending every frame for
	// the target to this boot. The frames were not lost — bootRelaySubmit
	// rejects the cancelled conn — but nothing fell over to a healthy sibling
	// boot until the entry was replaced by a successful re-open. unregister is
	// guarded, so the reader path's unregister for the same rc is a no-op.
	defer n.bootRelayUnregister(rc.boot, rc)
	// Close the stream on exit so the downlink reader wakes immediately
	// instead of parking until its 60 s read deadline.
	defer rc.stream.Close()

	for {
		select {
		case <-rc.ctx.Done():
			n.bootRelayDrain(rc)
			return
		case <-ticker.C:
			// Send a periodic loopback heartbeat frame (finalDst == self)
			// to keep intermediate NAT / firewall UDP/TCP translations alive
			// and detect broken uplinks promptly.
			hbFrame, err := routing.PackBootRelayFrame(n.bootRelayNetID, routing.BootRelayKindControl, "", n.Host.ID(), n.Host.ID(), 1, []byte("ping"))
			if err == nil {
				_ = rc.stream.SetWriteDeadline(time.Now().Add(3 * time.Second))
				if err := WriteFrame(rc.stream, hbFrame); err != nil {
					log.Debug("[boot-relay] heartbeat to %s failed: %v, tearing down uplink", rc.boot.ShortString(), err)
					n.bootRelayDrain(rc)
					rc.cancel()
					return
				}
			}
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
				rc.cancel()
				return
			}
			// Attribute the relay-over-backbone bytes to the BootRelay channel so
			// the unified Datapath card's "Relayed" split is honest.
			if n.protoTracker != nil {
				n.protoTracker.BootRelay.RecordTx(1, uint64(len(job.data)))
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
	// n.ctx is the node's shutdown context: without a reset hook this reader
	// parks in ReadFrame until its 60s deadline, so shutdown can hang that long
	// on each boot uplink. Reset on shutdown and let the guard goroutine exit
	// with the reader (mirrors the mux data channel's teardown).
	streamDone := make(chan struct{})
	defer close(streamDone)
	go func() {
		select {
		case <-n.ctx.Done():
			_ = s.Reset()
		case <-streamDone:
		}
	}()
	buf := make([]byte, maxBootRelayEnvelope)
	for {
		// The write loop sends a loopback heartbeat every 15s, so the boot
		// echoes at least one frame down this stream per interval. A 60s
		// read deadline (4× the heartbeat) detects a half-open connection
		// (the boot or transport silently died but TCP didn't notice) and
		// tears down the uplink for reconnect. Without it, a silently dead
		// connection pins this goroutine and the stream forever.
		_ = s.SetReadDeadline(time.Now().Add(60 * time.Second))
		readN, err := ReadFrame(s, buf)
		if err != nil || readN == 0 {
			return
		}
		n.handleBootRelayFrame(boot, buf[:readN])
	}
}

// handleBootRelayFrame processes one boot-relay downlink frame: unpack the
// envelope, verify the destination and network, then either dispatch a
// control-plane frame or decrypt + unpack the end-to-end TAP payload and write
// it to the local TAP. Shared by the dedicated boot-relay uplink
// (handleBootRelayDownlink) and the unified mux data channel
// (handleDataMuxBootRelay) so the two RX paths cannot drift.
//
// data must belong exclusively to the calling goroutine: for the uplink it is
// the per-stream read buffer, for the mux path it is a private per-frame copy.
func (n *Node) handleBootRelayFrame(boot peer.ID, data []byte) {
	// Boot-relay downlink bytes count toward the BootRelay channel (folded
	// into the unified Datapath card's "Relayed" split).
	if n.protoTracker != nil {
		n.protoTracker.BootRelay.RecordRx(1, uint64(len(data)))
	}
	netID, kind, proto, finalDst, srcPeer, _, innerPayload, uerr := routing.UnpackBootRelayFrame(data)
	if uerr != nil {
		hexLen := len(data)
		if hexLen > 32 {
			hexLen = 32
		}
		log.Warn("[boot-relay] downlink unpack error from %s (local commit=%s): %v, raw_hex=%x", boot.String(), version.ShortCommit(), uerr, data[:hexLen])
		return

	}
	if finalDst != n.Host.ID() {
		// The boot only sends us frames destined for us; a misrouted frame
		// is harmless to ignore.
		return
	}
	// Defense in depth: the boot already enforces that a local delivery's
	// netID equals the receiver's network, but re-verify here so a frame that
	// slipped through (e.g. a misconfigured/permissive boot) cannot inject
	// traffic tagged for a different PSK network into this node. Data AND
	// control frames are both gated; a control handshake is exactly what an
	// attacker would forge to establish a bogus cipher.
	if netID != n.bootRelayNetID {
		log.Debug("[boot-relay] downlink drop netID mismatch from %s (frame net=%s, local net=%s)",
			boot.ShortString(), netID, n.bootRelayNetID)
		return
	}

	// Control-plane frames (SeqSync / LSA / Meta / Echo for a relay-only
	// peer) carry the raw inner protocol bytes and must NOT be decrypted with
	// a per-peer cipher — that cipher is exactly what the handshake is trying
	// to establish, so it does not exist yet. They are multiplexed onto the
	// same boot-relay uplink as data frames and dispatched to the matching
	// local control handler with the logical peer set to srcPeer.
	if kind == routing.BootRelayKindControl {
		n.deliverBootRelayControl(finalDst, srcPeer, proto, boot, innerPayload)
		return
	}
	// Decrypt the inner payload with the cipher negotiated for srcPeer.
	if cipher := n.obfDecryptCipherForPeer(srcPeer); cipher != nil {
		dec, derr := obfuscate.DecryptPayloadRegion(innerPayload, cipher)
		if derr != nil {
			log.Debug("[boot-relay] downlink decrypt error from origin %s (via %s): %v",
				srcPeer.String(), boot.String(), derr)
			n.relayDiag.finalDecFail()
			n.recordPeerRxDecrypt(srcPeer, false)
			// Self-heal parity with the overlay-relay path (handleRelayFrame):
			// a persistent inner-open failure means srcPeer↔us keys diverged.
			// Without the throttled resync nudge, a boot-relay-only peer had to
			// wait for the reconciler's next full round — minutes of one-way
			// blackhole that looked exactly like "connects but no data", and
			// with no direct path the peer never resyncs on its own.
			n.maybeResyncOnDecryptFail(srcPeer)
			return
		}
		n.recordPeerRxDecrypt(srcPeer, true)
		n.maybeMarkReadyOnDecrypt(srcPeer, true)
		innerPayload = dec
	}
	seqID, unpacked, uerr := obfuscate.Unpack(innerPayload)
	if uerr != nil {
		log.Debug("[boot-relay] downlink Unpack err=%v from origin=%s; dropping", uerr, srcPeer.String())
		n.relayDiag.finalUnpack()
		n.recordPeerRxDecrypt(srcPeer, false)
		return
	}
	// Return-path liveness and provenance are recorded by
	// deliverRelayedFrameToTAP, and only AFTER its PSK gate — recording them
	// here too would double-count every boot-relay frame, and would stamp
	// liveness on a frame that then fails the PSK check. Decrypt+unpack
	// success alone is not enough to keep a peer connection alive.
	n.deliverRelayedFrameToTAP(unpacked, srcPeer, boot, seqID)
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
	// Keep the topology rate in original TAP bytes. The boot-relay envelope,
	// fixed-size padding, and encryption overhead belong to wire telemetry, not
	// to the user-facing upload/download rate.
	txBytes := tapPayloadLenFromPackedFrame(packedData)

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
		n.relayDiag.uplinkGone()
		return fmt.Errorf("boot-relay send to %s via %s: uplink unavailable", target.String(), bootHop.String())
	}
	return nil
}

// forwardRelayEnvelopeViaBootRelay hands a relay-transit frame whose route
// resolved to a p2ptap-boot to the relay-over-backbone uplink, instead of the
// overlay relay pool (which refuses boot hops outright). innerPayload is
// already END-TO-END sealed for finalDst by srcPeer, so it is wrapped directly
// in the boot-relay envelope — it must NOT be re-sealed. Re-sealing would wrap
// the frame in the (us ↔ finalDst) cipher, which finalDst cannot open, and the
// destination's Unpack would still succeed on the cleartext header, writing
// garbage to the TAP with no error anywhere: the classic "link healthy, no
// replies" failure. The envelope carries srcPeer, not our own ID, as its source
// so finalDst picks the (srcPeer ↔ finalDst) cipher.
func (n *Node) forwardRelayEnvelopeViaBootRelay(finalDst, bootHop, srcPeer peer.ID, innerPayload []byte) {
	env, err := routing.PackBootRelayFrame(n.bootRelayNetID, routing.BootRelayKindData, "",
		finalDst, srcPeer, routing.MaxRelayTTL, innerPayload)
	if err != nil {
		log.Warn("Relay forward to %s via boot %s aborted: boot-relay pack failed: %v",
			finalDst.String(), bootHop.String(), err)
		n.relayDiag.sealFail()
		return
	}
	// MaxRelayTTL (not the decremented overlay ttl) is deliberate: the boot
	// router floods the backbone only when ttl > 1, and a boot-relay bridge is
	// one hop regardless of how many overlay hops the origin budgeted. The
	// backbone flood is single-hop and fromMesh frames are never re-flooded, so
	// this cannot loop.
	if !n.bootRelaySubmit(bootHop, env,
		nil, // onSent — forwarding does not double-count the origin's tx bytes
		func() {
			log.Debug("Relay forward to %s via boot %s permanently failed",
				finalDst.String(), bootHop.String())
		},
	) {
		n.relayDiag.uplinkGone()
	}
}

// deliverRelayedFrameToTAP writes a decrypted, unpacked relayed Ethernet frame
// into the local TAP device, applying the same dedup / ACL / MAC-learn /
// exit-node / dst-MAC-fixup steps as the overlay-relay receive path. srcPeer is
// the TRUE origin (used for the cipher, dedup window and ACL); viaPeer is the
// transport peer the frame arrived FROM (the overlay relay hop or the boot for
// relay-over-backbone). Centralising this stops the two relay paths from
// drifting apart.
func (n *Node) deliverRelayedFrameToTAP(tapPayload []byte, srcPeer, viaPeer peer.ID, seqID uint64) {
	// PSK-required fail-closed (RX twin of canEgressToPeer + the direct-path
	// gate in handleStream): a relayed frame from an origin we have NOT
	// negotiated an end-to-end cipher with carries no proof the sender knows the
	// PSK, so it must never be sunk into the TAP — otherwise a non-PSK peer
	// could inject plaintext via a relay hop even though the direct path is
	// gated. Only overlay-relay / boot-relay transit reaches here, so this
	// single choke point covers both relay paths.
	if n.pskRequired() && !n.hasNegotiatedCipher(srcPeer) {
		if log.IsDebug() {
			log.Debug("Rx: dropping relayed frame from origin %s — PSK network requires a negotiated cipher", srcPeer.String())
		}
		n.relayDiag.originPsk()
		return
	}
	// Valid end-to-end frame: record return-path liveness and success. Via peer
	// is the carrier of this frame, so it is the hop the return side used.
	// isBootstrapPeer derives the peek-map IsBoot bit here rather than at each
	// call site: this helper is reached from BOTH the overlay-relay and the
	// boot-relay path, and hard-coding false (as it used to) recorded a frame
	// that demonstrably came through a boot as if it came from an ordinary hop.
	n.notePeerRxTransport(srcPeer, "overlay-relay", viaPeer)
	if viaPeer != "" && viaPeer != srcPeer {
		n.recordPeekMapOrigin(srcPeer, viaPeer, 1, n.isBootstrapPeer(viaPeer))
	}
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
	// Keep the same epoch/replay contract as the direct receive path.
	if dup, reason := peerDedup.IsDuplicateReason(seqID); dup {
		n.Collector.RecordDedup()
		// PERF: cached base58 — this is on every relayed frame (see peer_idstr.go).
		n.Collector.RecordPeerDedup(n.peerIDString(srcPeer))
		log.Debug("Duplicate relayed frame seq=%d from peer %s", seqID, srcPeer.String())
		// Same classification as the direct path: only SameSeq is benign. The
		// relay path runs the SAME dedup window, so it sees the same desync and
		// must be able to heal it there too.
		if reason != obfuscate.DedupDropSameSeq {
			n.recordPeerDedupDesync(srcPeer, true)
			n.maybeResyncOnDedupDesync(srcPeer)
		}
		return
	}
	n.recordPeerDedupDesync(srcPeer, false)
	n.Collector.RecordRxSeq(n.peerIDString(srcPeer), seqID, peerDedup.MaxSeq(), peerDedup.ReplayDrops(), peerDedup.WindowResets(), peerDedup.WindowUtilization())

	// ACL check — evaluate against the TRUE origin (srcPeer), not the relay
	// transport peer. The relay only forwards the frame; the security policy is
	// about which mesh member may inject traffic into our TAP.
	if !n.checkACL(tapPayload, n.peerIDString(srcPeer), false) {
		log.Debug("ACL blocked relayed frame from origin %s (via %s)", srcPeer.String(), viaPeer.String())
		return
	}

	// Learn source MAC — key on srcPeer so replies route back through the relay
	// path (not directly to the relay forwarder, which would drop them).
	// GUARD: same minEthernetFrameLen check as the direct-Rx path in
	// handleStream — ExtractEthernetMACs only needs 12 bytes, so a short
	// control payload would otherwise be learned as a bogus src MAC here too.
	if dstMAC, srcMAC, ok := vswitch.ExtractEthernetMACs(tapPayload); ok && len(tapPayload) >= minEthernetFrameLen {
		if rawSrc := net.HardwareAddr(srcMAC); len(rawSrc) == 6 {
			if n.isFrameFromPeerSelf(srcPeer, tapPayload) {
				n.recordPeerObservedTapMAC(srcPeer, rawSrc)
			}
		}
		if realMAC := n.lookupPeerTapMAC(srcPeer); realMAC != nil {
			srcMAC = realMAC
		}
		n.MACTable.Learn(srcMAC, srcPeer)

		// Auto-learn peer IPv4 / IPv6 into ARP/NDP index and inject GARP/NA into local TAP
		// ensuring the local OS can immediately return unicast replies without unproxied broadcast delay.
		n.learnPeerAddressFromFrame(srcPeer, srcMAC, tapPayload)

		// Guarded: this is the per-relay-frame path, and Go evaluates the three
		// .String() calls at the call site regardless of level — two MAC
		// format-and-allocate plus one base58 peer encode on every frame, even
		// at info. Roughly 3 allocations and 3 µs per frame that never print.
		if log.IsDebug() {
			log.Debug("Rx relayed frame: len=%d src=%s dst=%s from_peer=%s",
				len(tapPayload), net.HardwareAddr(srcMAC[:]).String(), net.HardwareAddr(dstMAC[:]).String(), viaPeer.String())
		}
	}

	// Content-based frame dedup ONLY for broadcast/multicast relayed frames.
	// Unicast frames are handled by per-peer SeqID sliding window deduplication.
	if len(tapPayload) >= 6 && isBroadcastOrMulticastMAC(net.HardwareAddr(tapPayload[0:6])) {
		contentHash := fnvHash64(tapPayload)
		// srcPeer is the true originator, so a broadcast that reaches us directly
		// and again relayed through another peer carries the same key and is
		// still deduplicated.
		if n.bcastDedup.isDuplicate(srcPeer, contentHash) {
			n.Collector.RecordDedup()
			log.Debug("Content-dup relayed broadcast frame hash=0x%x from peer %s dropped", contentHash, srcPeer.String())
			return
		}
	}

	// Routing arbitration for relayed transit (mirrors the direct-Rx decision
	// table): an Exit Node client only sinks frames genuinely for us.
	if n.isExitNodeActive() {
		// isMeshLocalIP is the single predicate, as on the direct path. The old
		// check was "not our IP and not an advertised subnet", which made every
		// group-addressed frame that arrived via a relay unreachable: mDNS,
		// LLMNR, SSDP, MLD, DHCPv6 and IPv6 NS multicast are destinations that
		// are never our own address and never sit in an advertised subnet, so
		// service discovery died on the relay path even where the direct path
		// delivered the same frame fine.
		dstV4, dstV6 := frameDstIPs(tapPayload)
		if dstV4 != nil && !n.isMeshLocalIP(dstV4) {
			log.Debug("Dropping relayed transit dstIP=%s: would mis-egress via local Exit Node", dstV4.String())
			return
		}
		if dstV6 != nil && !n.isMeshLocalIP(dstV6) {
			log.Debug("Dropping relayed transit dstIP=%s: would mis-egress via local Exit Node", dstV6.String())
			return
		}
	}

	// L2 MAC fixup so the kernel TAP accepts the frame as addressed to us.
	n.rewriteRxDstMAC(tapPayload)

	// TAP-probe hooks on the RELAYED receive path. Probe requests stay on the
	// synchronous boundary so their ack is emitted only after kernel delivery.
	n.maybeDeliverProbeReply(tapPayload)
	n.observeTapICMPEchoReply(srcPeer, tapPayload, time.Now())
	tapProbeFrame := false
	var probePID peer.ID
	var probeTok uint64
	if pid, tok, ok := n.isTapProbeRequest(tapPayload); ok {
		tapProbeFrame = true
		probePID, probeTok = pid, tok
		dstIP := net.IP(tapPayload[14+16 : 14+20])
		ackFlag := tapProbeAckFlagIPMismatch
		if n.localV4IP != nil && dstIP.Equal(n.localV4IP) {
			ackFlag = tapProbeAckFlagIPMatched
		}
		n.queueDeferredProbeAck(deferredProbeAck{prober: pid, token: tok, flag: ackFlag})
	}

	if n.TAP == nil {
		if tapProbeFrame {
			n.takeDeferredProbeAck(probePID, probeTok)
		}
		return
	}
	if n.Collector != nil {
		n.Collector.CaptureFrameWithPeers(observer.DirRx, tapPayload, n.peerIDString(srcPeer), "self")
	}

	if !tapProbeFrame {
		// Reorder gate (multipath): relayed and direct frames share the same
		// per-peer counter space, so both feed the same per-peer reorder queue.
		// The path key names the hop that actually carried the frame; the
		// buffered job carries it so per-path RX is attributed on TAP delivery.
		n.reorderTapWrite(srcPeer, seqID, tapPayload, false, srcPeer, "relay://"+viaPeer.String())
		return
	}

	// Synchronous probe path: complete accounting and ack only on write success.
	wn, werr := n.tapWrite(tapPayload)
	if werr != nil || wn != len(tapPayload) {
		n.takeDeferredProbeAck(probePID, probeTok)
		return
	}
	if deferred := n.takeDeferredProbeAck(probePID, probeTok); len(deferred) > 0 {
		for _, d := range deferred {
			go n.sendTapProbeAck(d.prober, d.token, d.flag)
		}
	}
	n.recordRelayedTapDelivery(srcPeer, tapPayload, "relay://"+viaPeer.String())

}
