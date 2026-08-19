package node

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/libp2p/go-libp2p/p2p/net/swarm"
	"github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr/net"

	"p2ptap/pkg/version"
)

func (n *Node) connectWithRetry(pi peer.AddrInfo, peerType string, baseDelay time.Duration, maxRetries int) {
	for attempt := 1; attempt <= maxRetries; attempt++ {
		select {
		case <-n.ctx.Done():
			return
		default:
		}

		// Every attempt uses parallel direct+relay race.
		// For NAT'd peers direct dial often fails, so relay is the only option.
		log.Debug("Connecting to %s peer %s (attempt %d/%d with parallel direct+relay race)...",
			peerType, pi.ID.String(), attempt, maxRetries)
		err := n.dialInParallel(n.ctx, pi, peerType)

		if err != nil {
			delay := baseDelay * time.Duration(attempt)
			if delay > 60*time.Second {
				delay = 60 * time.Second
			}
			log.Debug("%s peer %s connect failed (attempt %d): %v, retrying in %v", peerType, pi.ID.String(), attempt, err, delay)
			select {
			case <-n.ctx.Done():
				return
			case <-time.After(delay):
			}
		} else {
			return
		}
	}
	log.Warn("Failed to connect to %s peer %s after %d attempts", peerType, pi.ID.String(), maxRetries)
	// Final failure: trigger an immediate DHT rediscovery so we do not have to
	// wait up to 20s for the next discovery tick to learn fresh addresses for a
	// peer whose stored addrs may have gone stale (e.g. it changed networks).
	go n.rediscoverPeer(pi.ID)
}

// rediscoverPeer performs a one-shot DHT lookup for a peer whose connection
// attempts were exhausted, then re-dials using any fresh addresses learned. This
// shortens the time a peer stays unreachable after its stored addresses go stale
// (instead of waiting for the periodic 20s discovery loop).
func (n *Node) rediscoverPeer(pid peer.ID) {
	if n.DHT == nil {
		return
	}
	ctx, cancel := context.WithTimeout(n.ctx, 8*time.Second)
	defer cancel()
	info, err := n.DHT.FindPeer(ctx, pid)
	if err != nil {
		log.Debug("Rediscovery for %s found no addresses: %v", pid.String(), err)
		return
	}
	if len(info.Addrs) == 0 {
		log.Debug("Rediscovery for %s returned no addresses", pid.String())
		return
	}
	log.Info("Rediscovery learned %d fresh address(es) for %s", len(info.Addrs), pid.String())
	n.Host.Peerstore().AddAddrs(pid, info.Addrs, 10*time.Minute)
	// Re-dial through the normal path (self-limited by semaphore + in-flight guard).
	_ = n.dialInParallel(n.ctx, info, "rediscover")
}

const relayAuthProtocol = "/p2ptap/auth/1.0.0"

// authenticateWithRelay performs PSK challenge-response with a relay/bootstrap server.
// isRefresh=true marks a periodic keep-alive refresh (logs at DEBUG); the initial
// handshake on (re)connect logs at INFO.
func (n *Node) authenticateWithRelay(peerID peer.ID, isRefresh bool) bool {
	// Probe the relay auth stream
	s, err := n.Host.NewStream(n.ctx, peerID, relayAuthProtocol)
	if err != nil {
		// Bootstrap server does NOT have PSK enabled (open mode)
		log.Debug("Relay peer %s does not require PSK auth (open relay)", peerID.ShortString())
		return true
	}
	defer s.Close()

	// If the auth stream opened successfully, the bootstrap server REQUIRES PSK authentication!
	if n.Config.PSK == "" {
		log.Warn("Bootstrap peer %s requires PSK authentication, but no PSK is configured on this node! Relay access and discovery denied.", peerID.ShortString())
		return false
	}

	log.Debug("Authenticating with relay peer %s using PSK...", peerID.String())

	// Compute auth token: SHA-256("p2ptap-relay-auth:" + PSK)
	token := sha256.Sum256([]byte("p2ptap-relay-auth:" + n.Config.PSK))

	// Send 32-byte auth token, then our version/capability record. An OLD boot
	// simply ignores the trailing record; a NEW boot reads it and replies with
	// its own record so we can reject envelope/commit mismatches up-front
	// (the historical 0x8000 "proto field len 32768" silent-corruption bug).
	if _, err := s.Write(token[:]); err != nil {
		log.Debug("Relay auth write failed for peer %s: %v", peerID.String(), err)
		return false
	}
	if err := version.CurrentRecord().WriteRecord(s); err != nil {
		log.Debug("Relay auth version write failed for peer %s: %v", peerID.String(), err)
		return false
	}

	// Read 1-byte response
	var resp [1]byte
	if _, err := io.ReadFull(s, resp[:]); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			log.Debug("Relay peer %s closed auth stream (relay does not require PSK auth)", peerID.String())
			return true
		}
		log.Debug("Relay auth response read info for peer %s: %v", peerID.String(), err)
		return false
	}

	if resp[0] != 0x01 {
		log.Warn("Relay auth FAILED with peer %s — PSK mismatch, relay access denied", peerID.String())
		return false
	}

	// Auth succeeded: best-effort read the boot's version record. An OLD boot
	// closed the stream after the 1-byte response, so a short read means
	// "unknown version" — warn and proceed rather than fail the whole link.
	var peerRec version.Record
	if err := peerRec.ReadRecord(s); err != nil {
		log.Warn("Relay peer %s did not report a version record (old build?) — cannot verify envelope compatibility", peerID.String())
	} else {
		// Compatibility is a tri-state: OK (safe), Warn (differs but safe to
		// connect), Danger (incompatible envelope — corruption risk). We NEVER
		// reject on Warn; on Danger we only reject when StrictVersionCheck is on
		// (default off), so two peers that CAN interoperate are never blocked.
		switch lvl, reason := version.CurrentRecord().CompatibleWith(peerRec); lvl {
		case version.CompatOK:
			// identical build or unknown peer — nothing to report
		case version.CompatWarn:
			log.Warn("Relay peer %s version differs but safe to connect: %s (local commit=%s, peer commit=%s)",
				peerID.String(), reason, version.ShortCommit(), peerRec.Commit)
		case version.CompatDanger:
			log.Error("Relay peer %s version INCOMPATIBLE — risk of silent relay corruption: %s (local commit=%s, peer commit=%s)",
				peerID.String(), reason, version.ShortCommit(), peerRec.Commit)
			if version.StrictVersionCheck {
				log.Error("Relay peer %s rejected (StrictVersionCheck=true) to avoid silent relay corruption", peerID.String())
				return false
			}
			log.Warn("Relay peer %s StrictVersionCheck is off — proceeding despite incompatibility", peerID.String())
		}
	}

	if isRefresh {
		log.Debug("Relay auth SUCCESS with peer %s — relay access granted (refresh)", peerID.String())
	} else {
		log.Info("Relay auth SUCCESS with peer %s — relay access granted", peerID.String())
	}
	return true
}

// bootstrapKeepAliveLoop periodically reconnects to bootstrap/static peers that have disconnected
func (n *Node) bootstrapKeepAliveLoop() {
	defer n.wg.Done()
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-n.ctx.Done():
			return
		case <-ticker.C:
			// Check if physical egress gateway IP changed (Wi-Fi <-> Ethernet switch)
			if n.Gateway != nil {
				n.Gateway.CheckAndUpdatePhysicalGateway()
			}

			// Check and reconnect to bootstrap peers
			for _, bStr := range n.Config.BootstrapPeers {
				ma, err := multiaddr.NewMultiaddr(bStr)
				if err != nil {
					continue
				}
				info, err := peer.AddrInfoFromP2pAddr(ma)
				if err != nil {
					continue
				}
				if n.Host.Network().Connectedness(info.ID) != network.Connected {
					log.Debug("Bootstrap peer %s disconnected, reconnecting...", info.ID.String())
					go n.connectWithRetry(*info, "bootstrap", 5*time.Second, 3)
				}
			}

			// Check and reconnect to static peers
			for _, sStr := range n.Config.StaticPeers {
				ma, err := multiaddr.NewMultiaddr(sStr)
				if err != nil {
					continue
				}
				info, err := peer.AddrInfoFromP2pAddr(ma)
				if err != nil {
					continue
				}
				// Inspired by official libp2p chat example: permanently register static peer addrs in Peerstore
				n.Host.Peerstore().AddAddrs(info.ID, info.Addrs, peerstore.PermanentAddrTTL)

				if n.Host.Network().Connectedness(info.ID) != network.Connected {
					log.Debug("Static peer %s disconnected, reconnecting...", info.ID.String())
					go n.connectWithRetry(*info, "static", 5*time.Second, 3)
				}
			}
		}
	}
}

// clearSwarmBackoff aggressively clears the libp2p Swarm dial backoff for a peer
func (n *Node) clearSwarmBackoff(pid peer.ID) {
	if sw, ok := n.Host.Network().(*swarm.Swarm); ok {
		sw.Backoff().Clear(pid)
	}
}

// reconnectPeer disconnects and reconnects to a peer using its known multiaddrs.
func (n *Node) reconnectPeer(pid peer.ID) {
	// Aggressively clear dial backoff
	n.clearSwarmBackoff(pid)

	// Get stored addresses from peerstore, dropping loopback (127.0.0.0/8,
	// ::1) — dialing loopback would target THIS host, not the peer.
	addrs := filterLoopbackAddrs(n.Host.Peerstore().Addrs(pid))
	// A peer may be known only by PeerID (learned via LSA / peek-map) or its
	// stored circuit address may have expired, leaving no dialable address in
	// the peerstore. In that case synthesize relay circuit addresses from any
	// connected bootstrap relay so we can STILL reach it — this is exactly what
	// dialInParallel already does for the initial dial. Without this,
	// handleUnicastFailure's "no addresses" path calls reconnectPeer and we
	// give up here, permanently orphaning a peer that is actually reachable
	// through the relay (both ends attached to the same boot). We only give up
	// when there is genuinely no connected relay to bridge through.
	if len(addrs) == 0 {
		if relayAddrs := n.SynthesizeRelayCircuitAddrs(pid); len(relayAddrs) > 0 {
			addrs = relayAddrs
			n.Host.Peerstore().AddAddrs(pid, relayAddrs, peerstore.AddressTTL)
			log.Debug("Reconnect %s: no stored addrs, synthesized %d relay circuit addr(s) from connected bootstrap", pid.ShortString(), len(relayAddrs))
		}
	}
	if len(addrs) == 0 {
		log.Warn("No stored (non-loopback) addrs for peer %s and no connected relay available, cannot reconnect", pid.String())
		return
	}

	// Disconnect first
	if err := n.Host.Network().ClosePeer(pid); err != nil {
		log.Debug("ClosePeer %s: %v", pid.String(), err)
	}

	addrInfo := peer.AddrInfo{ID: pid, Addrs: addrs}
	go n.connectWithRetry(addrInfo, "healthcheck", 3*time.Second, 3)
}

// openStreamViaRelay establishes a control stream to target through a circuit
// relay. It is used for peers that are only reachable via relay (their direct
// addresses are private/unreachable), so we do NOT waste the dial budget trying
// the dead direct address first. SynthesizeRelayCircuitAddrs returns fresh
// "/p2p/<relay>/p2p-circuit/p2p/<target>" addresses from the relays we are
// currently connected to; adding them to the peerstore makes libp2p dial the
// peer through the relay instead of only the unreachable direct address.
//
// For relay-only peers we additionally clear the dead direct addresses so the
// swarm dials exclusively the circuit path (avoids a 10s hang on a black-holed
// direct address). For peers that merely *failed* direct this round we keep
// their addresses and let libp2p race circuit vs. direct.
func (n *Node) openStreamViaRelay(target peer.ID, proto protocol.ID) (network.Stream, error) {
	// Bug A fix: if the target is already connected (e.g. a boot-relay circuit
	// link we established earlier is still live), reuse that connection directly
	// instead of insisting on (re)synthesizing a fresh circuit address. This is
	// what lets the relay-priority control path recognize and reuse a live
	// circuit link instead of always failing with "no connected relay".
	if n.Host.Network().Connectedness(target) == network.Connected {
		ctx, cancel := context.WithTimeout(n.ctx, 10*time.Second)
		defer cancel()
		return n.Host.NewStream(ctx, target, proto)
	}

	relayAddrs := n.SynthesizeRelayCircuitAddrs(target)
	if len(relayAddrs) == 0 {
		return nil, fmt.Errorf("no connected relay available for circuit dial to %s", target)
	}

	if n.isRelayOnlyPeer(target) {
		// Drop the unreachable direct addresses so the swarm only tries the
		// circuit path for this peer.
		n.Host.Peerstore().ClearAddrs(target)
	}
	n.Host.Peerstore().AddAddrs(target, relayAddrs, peerstore.AddressTTL)

	ctx, cancel := context.WithTimeout(n.ctx, 10*time.Second)
	defer cancel()
	return n.Host.NewStream(ctx, target, proto)
}

// handleUnicastFailure centralizes unicast send-error handling. When the failure
// is caused by a peer having no dialable addresses (typically an offline/stale
// mesh peer still present in the MAC table), we act as a circuit-breaker:
//  1. Forget the stale MAC -> peer mapping so subsequent frames to that L2
//     destination fall back to broadcast/flood instead of repeatedly dialing a
//     dead peer (which produces a per-frame "no addresses" storm and starves
//     the dispatch workers / bootstrap connection).
//  2. Only then attempt a throttled reconnect (already 5s cooldown), which will
//     re-learn the peer's addresses via DHT if it comes back online.
func (n *Node) handleUnicastFailure(pid peer.ID, dstMAC net.HardwareAddr, err error) {
	if err != nil && strings.Contains(err.Error(), "no addresses") {
		if len(dstMAC) == 6 && !isBroadcastOrMulticastMAC(dstMAC) {
			n.MACTable.Forget(dstMAC)
			log.Info("Unicast target peer %s has no addresses; forgot MAC %s mapping, will flood instead",
				pid.String(), dstMAC.String())
		}
	}
	n.triggerThrottledReconnect(pid)
}

// triggerThrottledReconnect triggers peer reconnection on send failures with a 5-second cooldown
func (n *Node) triggerThrottledReconnect(pid peer.ID) {
	n.reconnectTimeMu.Lock()
	if n.lastReconnectTime == nil {
		n.lastReconnectTime = make(map[peer.ID]time.Time)
	}
	last, exists := n.lastReconnectTime[pid]
	if exists && time.Since(last) < 5*time.Second {
		n.reconnectTimeMu.Unlock()
		return
	}
	n.lastReconnectTime[pid] = time.Now()
	n.reconnectTimeMu.Unlock()

	log.Warn("Send failure to peer %s detected, triggering automatic hole-punching / reconnection...", pid.String())
	n.Dispatcher.RemovePeer(pid)
	n.reconnectPeer(pid)
}

// PingPongKeepaliveInterval defines how often we send echo-based liveness probes.
// Unified with the old HealthCheck loop, so 10s is plenty (was 5s) and halves the
// probe frequency vs. the previous 5s+30s dual-storm.
const PingPongKeepaliveInterval = 10 * time.Second
const pingPongStreamTimeout = 3 * time.Second // stream creation timeout (reduced from 5s)
const pingPongWriteTimeout = 2 * time.Second  // write "PING" timeout (reduced from 3s)
const pingPongReadTimeout = 3 * time.Second   // read echo timeout (reduced from 8s; was > tick interval)
const pingPongMaxFailures = 3
const pingPongMaxConcurrent = 8 // max concurrent peer probes per tick

// resetPingPongFailCountForPeer resets the ping-pong failure counter for a peer.
// This is called from handleStream when data is actively flowing, preventing false
// positives where yamux flow control delays echo streams but the connection is healthy.
func (n *Node) resetPingPongFailCountForPeer(pid peer.ID) {
	n.pingPongFailMu.Lock()
	if count, ok := n.pingPongFailCount[pid]; ok && count > 0 {
		n.pingPongFailCount[pid] = 0
	}
	n.pingPongFailMu.Unlock()
	// Any inbound data from pid means its return path to us is alive.
	n.notePeerRx(pid)
}

// assertBootRelayUplinkHealth surfaces the "Connected but egress dead" failure
// mode that plain echo keepalive misses: a boot may be transport-Connected (so
// its echo stream passes) yet have NO live relay-over-backbone uplink, which
// silently blackholes every frame to relay-only peers. We warn within one
// keepalive tick (and re-trigger relay auth) so the operator sees it instead of
// via packet captures — this is what originally masked the WHBbjX / 92NZj class
// of relay-drop bug.
func (n *Node) assertBootRelayUplinkHealth() {
	for _, pid := range n.Host.Network().Peers() {
		if pid == n.Host.ID() {
			continue
		}
		if !n.isBootstrapPeer(pid) {
			continue
		}
		if n.Host.Network().Connectedness(pid) != network.Connected {
			continue
		}
		if n.isBootRelayBlacklisted(pid) || n.hasBootRelayUplink(pid) {
			continue
		}
		log.Warn("keepalive: boot %s is transport-Connected but has NO relay-over-backbone uplink — egress to relay-only peers via it is dead; re-triggering relay auth", pid.String())
		go n.ensureRelayAuth(peer.AddrInfo{ID: pid})
	}
}

// peerPingPongLoop sends echo-based keepalive pings to all connected non-bootstrap
// peers every 5 seconds.  After 3 consecutive timeouts the peer is forcibly
// disconnected and reconnected.  This provides fast dead-connection detection
// (5-15s) vs. the 30s health-check loop which also probes but more slowly.
//
// All peers are probed concurrently (capped at pingPongMaxConcurrent) to prevent
// a single slow peer from blocking the entire probe cycle and causing false
// positive failures on subsequent peers.
func (n *Node) peerPingPongLoop() {
	defer n.wg.Done()
	ticker := time.NewTicker(PingPongKeepaliveInterval)
	defer ticker.Stop()

	for {
		select {
		case <-n.ctx.Done():
			return
		case <-ticker.C:
			peers := n.Host.Network().Peers()
			connected := make(map[peer.ID]bool, len(peers))
			var probePeers []peer.ID
			for _, pid := range peers {
				if pid == n.Host.ID() {
					continue
				}
				connected[pid] = true
				// Include all peers (both normal P2P peers and Bootstrap Relay servers)
				// to maintain active UDP/TCP NAT hole-punch mapping.
				if n.Host.Network().Connectedness(pid) != network.Connected {
					n.pingPongFailMu.Lock()
					delete(n.pingPongFailCount, pid)
					n.pingPongFailMu.Unlock()
					continue
				}
				probePeers = append(probePeers, pid)
			}

			// Keepalive for relay-only peers that may have dropped out of
			// Network().Peers() because their circuit went idle. Probing them
			// re-establishes the end-to-end circuit via the relay
			// (openStreamViaRelay), so their link is not silently cut.
			n.relayOnlyMu.RLock()
			for pid := range n.relayOnlyPeers {
				if pid == n.Host.ID() || connected[pid] {
					continue
				}
				probePeers = append(probePeers, pid)
			}
			n.relayOnlyMu.RUnlock()

			// Data-plane health for boot-relay hops: a boot may be
			// transport-Connected (so its echo keepalive passes) yet have NO live
			// relay-over-backbone uplink, which silently blackholes every frame to
			// relay-only peers. Surface that fast instead of via packet captures.
			n.assertBootRelayUplinkHealth()

			// Probe all peers concurrently (capped by semaphore)
			var wg sync.WaitGroup
			sem := make(chan struct{}, pingPongMaxConcurrent)
			for _, pid := range probePeers {
				wg.Add(1)
				sem <- struct{}{}
				go func(pid peer.ID) {
					defer wg.Done()
					defer func() { <-sem }()
					n.pingPongProbePeer(pid)
				}(pid)
			}
			wg.Wait()

			// Cleanup stale entries (but keep relay-only peers so their
			// 3-strike count survives transient circuit drops).
			n.pingPongFailMu.Lock()
			for pid := range n.pingPongFailCount {
				if n.Host.Network().Connectedness(pid) == network.Connected {
					continue
				}
				if n.isRelayOnlyPeer(pid) {
					continue
				}
				delete(n.pingPongFailCount, pid)
			}
			n.pingPongFailMu.Unlock()
		}
	}
}

// pingPongProbePeer sends a single echo ping to one peer and handles failure counting.
// It reuses a persistent per-peer echo stream (echoPool) instead of opening a fresh
// NewStream on every tick — the old per-tick NewStream-per-peer storm is gone.
func (n *Node) pingPongProbePeer(pid peer.ID) {
	pingPayload := []byte{0x50, 0x49, 0x4E, 0x47} // "PING"
	start := time.Now()
	replyBuf := make([]byte, 16)

	// Reuse the persistent echo stream (WithStream runs write+read inside the
	// peer's lock so a concurrent manual WebUI probe can't interleave on it).
	ok := n.echoPool.WithStream(pid, func(s network.Stream) error {
		_ = s.SetWriteDeadline(time.Now().Add(pingPongWriteTimeout))
		if err := WriteFrame(s, pingPayload); err != nil {
			return err
		}
		_ = s.SetReadDeadline(time.Now().Add(pingPongReadTimeout))
		rn, rerr := ReadFrame(s, replyBuf)
		rtt := time.Since(start)
		isValidEcho := (rerr == nil || rerr == io.EOF) && rn >= 4 && bytes.Equal(replyBuf[:4], pingPayload)
		if !isValidEcho {
			log.Debug("Ping-pong echo read failed for %s rtt=%dms readBytes=%d err=%v",
				pid.String(), rtt.Milliseconds(), rn, rerr)
			return fmt.Errorf("bad echo: readBytes=%d err=%v", rn, rerr)
		}
		log.Debug("Ping-pong OK for %s RTT=%dms", pid.String(), rtt.Milliseconds())
		return nil
	})

	if ok {
		n.pingPongFailMu.Lock()
		n.pingPongFailCount[pid] = 0
		n.pingPongFailMu.Unlock()
		return
	}

	// WithStream returned false => stream open failed or bad echo (cache dropped).
	n.pingPongFailMu.Lock()
	n.pingPongFailCount[pid]++
	fc := n.pingPongFailCount[pid]
	n.pingPongFailMu.Unlock()
	if fc >= pingPongMaxFailures {
		if n.peerRxWithin(pid, pingPongReadTimeout*3) {
			// We have received OTHER inbound frames from pid recently, so our
			// outbound path to it clearly works — the failed echo means pid's
			// RETURN path to us is broken (asymmetric routing: its return hop
			// differs from our outbound hop and is stalled). A reconnect may not
			// fix a return-path break at the peer; the operator must check pid's
			// relay stream / TAP egress.
			log.Warn("Ping-pong keepalive failed %d times for %s — but return-path frames still arriving recently ⇒ OUTBOUND OK, RETURN dead at peer (asymmetric routing); forcing reconnect, but check %s's relay stream / TAP egress",
				fc, pid.String(), pid.ShortString())
		} else {
			log.Warn("Ping-pong keepalive failed %d times for %s — no recent inbound frames ⇒ OUTBOUND dead (or fully partitioned); forcing reconnect",
				fc, pid.String())
		}
		n.reconnectPeer(pid)
		n.pingPongFailMu.Lock()
		delete(n.pingPongFailCount, pid)
		n.pingPongFailMu.Unlock()
	} else {
		log.Debug("Ping-pong failed for %s (%d/%d)", pid.String(), fc, pingPongMaxFailures)
	}
}

// dialLimiter caps concurrent in-flight dials so a discovery/mDNS burst cannot
// turn into a connection storm (each dial also connects to every bootstrap relay).
var dialLimiter = make(chan struct{}, 16)

// dialingMu guards dialingDone. A peer with an entry is already being dialed;
// concurrent callers wait on the channel and reuse the result instead of
// launching a second competing dial (which can cause libp2p transport conflicts).
var dialingMu sync.Mutex
var dialingDone = make(map[peer.ID]chan struct{})

// isLocalAddr reports whether a multiaddr points at a LAN/loopback/link-local
// address — i.e. one that is directly reachable without a relay hop.
func isLocalAddr(a multiaddr.Multiaddr) bool {
	ip, err := manet.ToIP(a)
	if err != nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()
}

// allAddrsLocal reports whether every address is locally reachable. An empty
// slice is treated as "not local" so we still attempt the relay fallback.
func allAddrsLocal(addrs []multiaddr.Multiaddr) bool {
	if len(addrs) == 0 {
		return false
	}
	for _, a := range addrs {
		if !isLocalAddr(a) {
			return false
		}
	}
	return true
}

// allAddrsLoopback reports whether every address is loopback — i.e. the peer is
// ourselves. It is intentionally stricter than allAddrsLocal: private/ULA
// (RFC1918) addresses are NOT treated as loopback here, because a peer on a
// different NAT also carries a private IP that is not actually reachable from
// us. Using this (instead of allAddrsLocal) for the relay-skip decision ensures
// cross-NAT peers still attempt the circuit-relay race.
func allAddrsLoopback(addrs []multiaddr.Multiaddr) bool {
	if len(addrs) == 0 {
		return false
	}
	for _, a := range addrs {
		ip, err := manet.ToIP(a)
		if err != nil || !ip.IsLoopback() {
			return false
		}
	}
	return true
}

// dialInParallel attempts to dial a peer concurrently via direct connection and
// Circuit Relay, returning whichever succeeds first. This eliminates the sequential
// 3-10s latency penalty when falling back to relay.
// IMPORTANT: When the first goroutine wins, the losing goroutine is explicitly
// cancelled via raceCtx to prevent a second connection from being established
// and causing a libp2p transport conflict/disconnect.
func (n *Node) dialInParallel(ctx context.Context, pi peer.AddrInfo, peerType string) error {
	// Aggressive: Clear any dial backoff and refresh multiaddrs in Peerstore.
	// NOTE: we intentionally do NOT ClearAddrs here. Clearing would discard
	// addresses the peerstore already learned via DHT/mDNS/relay, forcing future
	// dials to fall back to relays or re-discover. AddAddrs merges and refreshes
	// TTL, which is exactly what we want across reconnect attempts.
	n.clearSwarmBackoff(pi.ID)
	if len(pi.Addrs) > 0 {
		n.Host.Peerstore().AddAddrs(pi.ID, pi.Addrs, 2*time.Hour)
	}

	// Coalesce concurrent dials to the same peer. If a dial is already in flight,
	// wait for it and reuse its outcome instead of launching a competing dial
	// (which can trigger libp2p transport conflicts / disconnects).
	dialingMu.Lock()
	if done, ok := dialingDone[pi.ID]; ok {
		dialingMu.Unlock()
		select {
		case <-done:
		case <-ctx.Done():
			return ctx.Err()
		}
		if n.Host.Network().Connectedness(pi.ID) == network.Connected {
			return nil
		}
		return fmt.Errorf("peer %s not connected after concurrent dial", pi.ID.String())
	}
	doneCh := make(chan struct{})
	dialingDone[pi.ID] = doneCh
	dialingMu.Unlock()
	defer func() {
		dialingMu.Lock()
		delete(dialingDone, pi.ID)
		close(doneCh)
		dialingMu.Unlock()
	}()

	// Bound concurrent dials globally so a discovery/mDNS burst cannot turn into a
	// connection storm (each dial also connects to every bootstrap relay).
	select {
	case dialLimiter <- struct{}{}:
		defer func() { <-dialLimiter }()
	case <-ctx.Done():
		return ctx.Err()
	}

	type result struct {
		err  error
		mode string
	}

	raceCtx, raceCancel := context.WithCancel(ctx)
	defer raceCancel() // ensure both child contexts are cancelled when we return

	ch := make(chan result, 2)

	// Race: direct connection
	go func() {
		directCtx, cancel := context.WithTimeout(raceCtx, 5*time.Second)
		defer cancel()
		err := n.Host.Connect(directCtx, pi)
		select {
		case ch <- result{err: err, mode: "direct"}:
		case <-raceCtx.Done():
			// Losing goroutine — winner already returned, don't send on closed path
		}
	}()

	// Only skip the relay race for genuinely loopback peers (i.e. ourselves).
	// We deliberately do NOT treat RFC1918/ULA private addresses as "local": two
	// peers behind *different* NATs both carry private IPs that are NOT mutually
	// reachable, so the old "all-private ⇒ local" rule suppressed the relay race
	// and left cross-NAT peers unable to connect. The parallel dial lets a fast
	// direct connection win for truly-LAN peers, so launching relay here is safe.
	localOnly := allAddrsLoopback(pi.Addrs)
	relayLaunched := false
	if !localOnly {
		// Race: Circuit Relay connection via known relay addresses
		// Relay path needs more time: connect to relay (1.5s) + auth (2s) + circuit connect
		relayLaunched = true
		go func() {
		relayCtx, cancel := context.WithTimeout(raceCtx, 15*time.Second)
		defer cancel()

		// Ensure each bootstrap relay is connected (best-effort, 3s each)
		// before we synthesize circuit addrs through it. SynthesizeRelayCircuitAddrs
		// is the single source of truth for circuit-addr composition and only
		// emits addrs for relays we are actually Connected to, so the initial dial
		// race and the relay-priority control path now use the exact same shape.
		for _, bStr := range n.Config.BootstrapPeers {
			bMA, berr := multiaddr.NewMultiaddr(bStr)
			if berr != nil {
				continue
			}
			bInfo, berr := peer.AddrInfoFromP2pAddr(bMA)
			if berr != nil {
				continue
			}
			if n.Host.Network().Connectedness(bInfo.ID) != network.Connected {
				bCtx, bCancel := context.WithTimeout(relayCtx, 3*time.Second)
				_ = n.Host.Connect(bCtx, *bInfo)
				bCancel()
			}
		}
		// Single source of truth for circuit-addr composition (shared with
		// openStreamViaRelay / reconnectPeer / LSA-meta path).
		relayAddrs := n.SynthesizeRelayCircuitAddrs(pi.ID)

		if len(relayAddrs) == 0 {
			select {
			case ch <- result{err: fmt.Errorf("no active relay available"), mode: "relay"}:
			case <-raceCtx.Done():
			}
			return
		}

		// Use the default peerstore TTL (10m), NOT a short 15s value: a
		// relay-only peer's circuit address must survive between reconnect
		// attempts, otherwise the address expires and every dial falls back
		// to re-synthesizing + re-dialing, causing reconnect churn.
		n.Host.Peerstore().AddAddrs(pi.ID, relayAddrs, peerstore.AddressTTL)
		// Connect with a relay-only AddrInfo so the relay race does not also fan
		// out direct dials to the destination's private/public addrs (that produced
		// the noisy "concurrent active dial through the same relay" dedup lines and
		// wasted dial budget — the direct race is already run by the parallel
		// goroutine above).
		relayInfo := peer.AddrInfo{ID: pi.ID, Addrs: relayAddrs}
		// Circuitv2 semantics (relay.go: NewStream with WithNoDial fails): the
		// relay holds a VALID reservation but has NO live connection to the
		// destination right now, so it returns 203 (CONNECTION_FAILED) and cannot
		// bridge. This is usually transient — the destination may be mid-reconnect
		// to the relay — so we retry once after a short backoff to self-heal
		// instead of giving up the relay leg immediately. The destination is the
		// one responsible for keeping its link to the relay warm; this retry only
		// absorbs the brief window while it does.
		var relayErr error
		const maxRelayRetries = 3
	relayRetry:
		for attempt := 0; attempt < maxRelayRetries; attempt++ {
			relayErr = n.Host.Connect(relayCtx, relayInfo)
			if relayErr == nil {
				break
			}
			// Transient relay errors: 203 (CONNECTION_FAILED) or PERMISSION_DENIED / relay_denied.
			// When the destination node has just connected and is in the middle of PSK authentication,
			// or is mid-reconnect, retry with exponential backoff (1s -> 2s -> 4s) so the dial
			// completes seamlessly once auth finishes.
			errLower := strings.ToLower(relayErr.Error())
			isTransient := strings.Contains(errLower, "203") ||
				strings.Contains(errLower, "connection_failed") ||
				strings.Contains(errLower, "permission_denied") ||
				strings.Contains(errLower, "relay_denied") ||
				strings.Contains(errLower, "denied")
			if !isTransient {
				break
			}
			if attempt+1 < maxRelayRetries {
				backoff := time.Duration(1<<uint(attempt)) * 1 * time.Second // 1s, 2s, 4s
				log.Debug("Relay circuit to %s returned transient rejection (%v): destination may still be handshaking/authenticating. Retrying in %v (attempt %d/%d)...", pi.ID.String(), relayErr, backoff, attempt+1, maxRelayRetries)
				select {
				case <-time.After(backoff):
				case <-raceCtx.Done():
					relayErr = raceCtx.Err()
					break relayRetry
				}
				n.clearSwarmBackoff(pi.ID) // drop any dial backoff accrued on the failed attempt
			}
		}
		if relayErr != nil {
			log.Debug("Relay circuit to %s failed: %v (the destination must hold an active connection to this relay — list it as a bootstrap/relay so its keep-alive re-reserves and keeps the link warm).", pi.ID.String(), relayErr)
		}
		select {
		case ch <- result{err: relayErr, mode: "circuit-relay"}:
		case <-raceCtx.Done():
		}
	}()
	}

	// Wait for first successful result
	var first result
	select {
	case first = <-ch:
	case <-ctx.Done():
		return ctx.Err()
	}

	if first.err == nil {
		log.Info("%s peer %s connected via %s (parallel race winner)", peerType, pi.ID.String(), first.mode)
		if peerType == "bootstrap" {
			go n.ensureRelayAuth(pi)
		}
		// Cancel losing goroutine — prevents double-connect and transport conflict
		raceCancel()
		return nil
	}

	// If relay was skipped (local-only peer) there is no fallback to wait for.
	if !relayLaunched {
		log.Debug("%s peer %s direct connect failed (local-only, no relay fallback): %v", peerType, pi.ID.String(), first.err)
		return first.err
	}

	// First attempt failed, wait for the other
	select {
	case second := <-ch:
		if second.err == nil {
			log.Info("%s peer %s connected via %s (parallel race fallback)", peerType, pi.ID.String(), second.mode)
		if peerType == "bootstrap" {
			go n.ensureRelayAuth(pi)
		}
		return nil
	}
		log.Debug("%s peer %s: direct=%v, relay=%v", peerType, pi.ID.String(), first.err, second.err)
		return fmt.Errorf("direct: %v | relay: %v", first.err, second.err)
	case <-ctx.Done():
		return ctx.Err()
	}
}

// ensureRelayAuth performs the one-time PSK handshake with a bootstrap/relay
// peer. It is guarded by the shared relayAuthInProgress map so the fan-out
// goroutines spawned by Start() (one per transport address of the SAME relay
// PeerID — e.g. QUIC/TCP/WebRTC × IPv4/IPv6) don't each run a full auth: that
// produced 7× "Relay auth SUCCESS" log lines for a single relay at startup. The
// relay connection itself is shared (the swarm dedupes connections per PeerID),
// so authenticating once is correct. bootstrapKeepAliveLoop and the ConnectedF
// handler reuse the same guard, so refreshes never collide with this either.
//
// NOTE: p2ptap's actual relay for VPN traffic is its OWN overlay relay
// (this PSK auth + relay_ctrl.go hop tunneling), which is independent of the
// standard libp2p Circuit Relay v2 service. The latter is intentionally NOT
// used here: p2ptap nodes never mount the libp2p relay /hop handler (the relay
// service only activates on Public reachability, and p2ptap forces Private via
// ForceReachabilityPrivate at node startup), so any explicit circuitv2
// reservation would permanently fail with PERMISSION_DENIED and spam the log.
// libp2p AutoRelay (enabled via EnableAutoRelayWithStaticRelays) remains the
// only standard-relay client path, and it handles its own reservation silently.
func (n *Node) ensureRelayAuth(pi peer.AddrInfo) {
	n.relayAuthMu.Lock()
	if n.relayAuthInProgress[pi.ID] {
		n.relayAuthMu.Unlock()
		return
	}
	n.relayAuthInProgress[pi.ID] = true
	n.relayAuthMu.Unlock()

	defer func() {
		n.relayAuthMu.Lock()
		delete(n.relayAuthInProgress, pi.ID)
		n.relayAuthMu.Unlock()
	}()

	if !n.authenticateWithRelay(pi.ID, false) {
		// PSK mismatch (or transport failure): do not open the boot-relay
		// uplink — the boot would drop our frames anyway.
		return
	}

	// Establish the boot-relay (relay-over-backbone) uplink. The uplink is
	// SELF-HEALING: its own loop reopens the stream whenever the boot link
	// drops, so we spawn it EXACTLY ONCE per boot (guarded here) and must NOT
	// re-spawn it on every reconnect, or we would leak orphaned reader goroutines
	// and clobber the live uplink entry. This is what lets us reach peers
	// attached to THIS boot OR a different boot in the same PSK network when no
	// direct / overlay-relay path exists. In open mode (no PSK) auth succeeds
	// trivially and the uplink is still opened so cross-boot bridging works.
	n.bootRelayMu.Lock()
	if _, ok := n.bootRelayStarted[pi.ID]; !ok {
		n.bootRelayStarted[pi.ID] = struct{}{}
		n.bootRelayMu.Unlock()
		go n.openBootRelayUplink(pi.ID)
	} else {
		n.bootRelayMu.Unlock()
	}
}
