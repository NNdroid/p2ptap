package node

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"p2ptap/pkg/mux"

	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/libp2p/go-libp2p/p2p/net/swarm"
	"github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr/net"

	"p2ptap/pkg/config"
	"p2ptap/pkg/maddrutil"
	"p2ptap/pkg/routing"
	"p2ptap/pkg/version"
)

// retryBootstrap retries DHT bootstrap with exponential backoff. The first attempt
// often fails because bootstrap peer connections haven't been established yet
// (the DialRanker needs time to connect to dnsaddr peers). Subsequent attempts
// succeed once those connections are up. Returns nil on first success.
func retryBootstrap(ctx context.Context, kdht *dht.IpfsDHT) error {
	const maxAttempts = 3
	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if err := kdht.Bootstrap(ctx); err != nil {
			lastErr = err
			log.Debug("DHT bootstrap attempt %d/%d failed: %v", attempt, maxAttempts, err)
			if attempt < maxAttempts {
				delay := time.Duration(2*(attempt)) * time.Second // 2s, 4s
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(delay):
				}
			}
			continue
		}
		if attempt > 1 {
			log.Info("DHT bootstrap succeeded on attempt %d", attempt)
		}
		return nil
	}
	return lastErr
}

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
			// Skip the backoff sleep on the final attempt — there is no
			// retry after this, so sleeping only delays the failure log and
			// extends the goroutine's lifetime (which matters because
			// connectWithRetry goroutines are not tracked by n.wg).
			if attempt < maxRetries {
				// Exponential backoff with jitter: base * 2^(attempt-1) + random[0, base/4]
				// This prevents thundering-herd when many peers fail simultaneously
				// and caps total retry window for bootstrap/static (3 attempts).
				delay := baseDelay * time.Duration(1<<uint(attempt-1))
				if delay > 60*time.Second {
					delay = 60 * time.Second
				}
				// Add jitter (0-25% of delay) to de-synchronize concurrent retries.
				// Guard against delay/4==0 which would make rand.Int63n(0) panic.
				if jitterBase := delay / 4; jitterBase > 0 {
					jitter := time.Duration(rand.Int63n(int64(jitterBase)))
					delay += jitter
				}
				log.Debug("%s peer %s connect failed (attempt %d): %v, retrying in %v", peerType, pi.ID.String(), attempt, err, delay)
				select {
				case <-n.ctx.Done():
					return
				case <-time.After(delay):
				}
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
	n.Host.Peerstore().AddAddrs(pid, info.Addrs, relayRediscoveryAddrTTL)
	// Re-dial through the normal path (self-limited by semaphore + in-flight guard).
	_ = n.dialInParallel(n.ctx, info, "rediscover")
}

const relayAuthProtocol = "/p2ptap/auth/1.0.0"

const (
	// relayUpgradeBaseBackoff is the first backoff step after a failed
	// direct-upgrade attempt; each further consecutive failure doubles it.
	relayUpgradeBaseBackoff = time.Minute
	// relayUpgradeMaxBackoff caps the exponential growth, so a peer that can
	// never be reached directly is retried roughly once per half hour instead
	// of once per tick.
	relayUpgradeMaxBackoff = 30 * time.Minute
	// relayRediscoveryAddrTTL is how long addresses learned from a DHT
	// rediscovery stay cached. Shorter than peerstore.AddressTTL (1h): a DHT
	// record is a point-in-time view of what the peer advertised, so a stale
	// mapping is rediscovered in 10 minutes instead of being re-dialled for an
	// hour.
	relayRediscoveryAddrTTL = 10 * time.Minute
	// relayUpgradeFlapWindow is how long a peer that just upgraded to direct is
	// held back from another upgrade attempt once it falls back to relay-only.
	// A success resets the failure backoff to zero, so a marginal path — one that
	// only sometimes survives a hole punch — would otherwise be redialled every
	// tick for its whole life, each success tearing down and rebuilding the
	// peer's circuit streams. The window bounds that churn; the peer keeps
	// sending data over the surviving circuit relay meanwhile.
	relayUpgradeFlapWindow = 5 * time.Minute
)

// resolveRelayUpgradeMaxBackoff refuses a cap outside config's accepted range.
// Validate() already rejects such a config, so this only guards a caller that
// bypasses validation.
func resolveRelayUpgradeMaxBackoff(v time.Duration) time.Duration {
	if v < config.RelayUpgradeMaxBackoffMin || v > config.RelayUpgradeMaxBackoffMax {
		return relayUpgradeMaxBackoff
	}
	return v
}

// resolveRelayUpgradeFlapWindow refuses a window outside config's accepted range.
// See resolveRelayUpgradeMaxBackoff for why this is belt-and-braces.
func resolveRelayUpgradeFlapWindow(v time.Duration) time.Duration {
	if v < config.RelayUpgradeFlapWindowMin || v > config.RelayUpgradeFlapWindowMax {
		return relayUpgradeFlapWindow
	}
	return v
}

// directCandidates keeps only addrs that are not circuit-relay hops. The
// relay-upgrade dial is forced direct, so a /p2p-circuit addr can never succeed
// there and would only be dialed before failing.
func directCandidates(addrs []multiaddr.Multiaddr) []multiaddr.Multiaddr {
	out := make([]multiaddr.Multiaddr, 0, len(addrs))
	for _, a := range addrs {
		if !maddrutil.IsCircuitRelay(a) {
			out = append(out, a)
		}
	}
	return out
}

// relayOnlyDirectUpgradeLoop periodically attempts to upgrade relay-only peers
// to a direct connection. It is the recovery path for the "pinned to relay"
// state: once a direct connection succeeds, the ConnectedF handler calls
// clearRelayOnlyPeer and the Router link flips from LinkCircuit to LinkDirect.
// The retry interval is Config.RelayUpgradeInterval (default 30s), the failure
// backoff is capped by Config.RelayUpgradeMaxBackoff (default 30m), and a peer
// that just upgraded is held back Config.RelayUpgradeFlapWindow (default 5m)
// after it falls back to relay-only, so a marginal path does not churn the loop
// every tick.
func (n *Node) relayOnlyDirectUpgradeLoop() {
	defer n.wg.Done()
	// The ticker cadence is frozen at loop start: time.NewTicker cannot be
	// resized, so relay_upgrade_interval needs a restart. The backoff cap and
	// the flap window are read per tick below and are live-reloadable instead.
	interval := n.config().RelayUpgradeInterval
	if interval < config.RelayUpgradeIntervalMin || interval > config.RelayUpgradeIntervalMax {
		interval = 30 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-n.ctx.Done():
			return
		case <-ticker.C:
			cfg := n.config()
			maxBackoff := cfg.RelayUpgradeMaxBackoff
			flapWindow := resolveRelayUpgradeFlapWindow(cfg.RelayUpgradeFlapWindow)
			relayOnly := n.relayUpgradeCandidates(time.Now(), flapWindow)

			// Parallel upgrades with a bounded semaphore: each attemptDirectUpgrade
			// can take ~23s (8s DHT + 15s dial), so a serial loop of N peers can
			// exceed the 30s tick interval. Cap at 4 concurrent to avoid dial storms.
			const maxConcurrent = 4
			sem := make(chan struct{}, maxConcurrent)
			var wg sync.WaitGroup
			for _, pid := range relayOnly {
				if pid == n.Host.ID() || n.isBootstrapPeer(pid) {
					continue
				}
				if n.isDirectlyConnected(pid) {
					n.clearRelayOnlyPeer(pid)
					continue
				}
				wg.Add(1)
				sem <- struct{}{}
				go func(pid peer.ID) {
					defer wg.Done()
					defer func() { <-sem }()
					upgraded := n.attemptDirectUpgrade(pid)
					n.noteRelayUpgradeResult(pid, upgraded, maxBackoff)
				}(pid)
			}
			wg.Wait()
		}
	}
}

// attemptDirectUpgrade performs one force-direct dial (no circuit addresses)
// to a relay-only peer using its stored or DHT-rediscovered direct addresses.
// It reports whether the peer is directly connected now, so the caller can
// back off peers that repeatedly fail instead of retrying every tick.
func (n *Node) attemptDirectUpgrade(pid peer.ID) bool {
	// Direct candidates: peerstore addrs minus loopback minus circuit addrs.
	direct := directCandidates(filterUndialableAddrs(n.Host.Peerstore().Addrs(pid)))

	// No usable direct addrs (expired TTL): rediscover via DHT. Only addrs that
	// came out of the DHT are re-registered below — the ones already in the
	// peerstore need no re-registration, and re-registering them would renew
	// their TTL on every failed attempt, so a dead NAT mapping would be cached
	// forever and this lookup could never run again.
	var fresh []multiaddr.Multiaddr
	if len(direct) == 0 && n.DHT != nil {
		ctx, cancel := context.WithTimeout(n.ctx, 8*time.Second)
		info, err := n.DHT.FindPeer(ctx, pid)
		cancel()
		if err == nil {
			fresh = directCandidates(filterUndialableAddrs(info.Addrs))
			direct = append(direct, fresh...)
		}
	}
	if len(direct) == 0 {
		// No usable direct address, but the peer may still sit behind a NAT that
		// full-ICE WebRTC can cross: candidates are exchanged via the signal
		// stream, so we do not need any direct multiaddr from the peerstore.
		n.maybeWebRTCSignalUpgrade(pid)
		return false
	}

	direct = prioritizeMultiaddrs(direct)
	if len(fresh) > 0 {
		n.Host.Peerstore().AddAddrs(pid, fresh, relayRediscoveryAddrTTL)
	}

	timeout := n.config().HolePunchTimeout
	if timeout <= 0 || timeout > 120*time.Second {
		timeout = 15 * time.Second
	}
	ctx, cancel := context.WithTimeout(n.ctx, timeout)
	defer cancel()
	// ForceDirectDial keeps the swarm from racing the peerstore's circuit addrs
	// (which would instantly "win" and report a false direct upgrade).
	if err := n.Host.Connect(network.WithForceDirectDial(ctx, "p2ptap-relay-upgrade"), peer.AddrInfo{ID: pid, Addrs: direct}); err != nil {
		log.Debug("Direct upgrade for relay-only peer %s failed this round: %v", pid.ShortString(), err)
		n.maybeWebRTCSignalUpgrade(pid)
		return false
	}
	if !n.isDirectlyConnected(pid) {
		return false
	}
	log.Info("Relay-only peer %s upgraded to DIRECT connection", pid.String())
	n.clearRelayOnlyPeer(pid)
	return true
}

// maybeWebRTCSignalUpgrade kicks off an async WebRTC signaling upgrade for a
// relay-only peer whose direct dial just failed. The full-ICE candidate exchange
// runs over the relay control channel, so this works even when the peer has no
// reachable direct multiaddr at all — the ICE agents discover each other's
// public/relay candidates via STUN/TURN and punch through the NAT. No-op when
// signaling is disabled or the peer is not relay-only. webrtcSignalUpgrade
// re-checks eligibility and the offerer role (higher peer.ID offers), so the
// goroutine is cheap and self-limiting.
func (n *Node) maybeWebRTCSignalUpgrade(pid peer.ID) {
	if !n.config().Transports.EnableWebRTCSignaling || !n.isRelayOnlyPeer(pid) {
		return
	}
	go n.webrtcSignalUpgrade(pid)
}

// relayTicketCache is a cached session ticket minted by one boot. expUnix is the
// embedded absolute expiry (unix seconds) so a stale entry is dropped without a
// network round trip.
type relayTicketCache struct {
	ticket  []byte
	expUnix int64
}

// storeRelayTicket caches the session ticket a boot minted for this node.
func (n *Node) storeRelayTicket(peerID peer.ID, ticket []byte) {
	if len(ticket) != routing.RelayTicketLen {
		return
	}
	exp := int64(binary.BigEndian.Uint64(ticket[32:40]))
	n.relayAuthTickets.Store(peerID, &relayTicketCache{ticket: ticket, expUnix: exp})
}

// loadRelayTicket returns a cached, unexpired ticket for a boot. Entries past
// their expiry are dropped.
func (n *Node) loadRelayTicket(peerID peer.ID) ([]byte, bool) {
	v, ok := n.relayAuthTickets.Load(peerID)
	if !ok {
		return nil, false
	}
	c := v.(*relayTicketCache)
	if time.Now().Unix() > c.expUnix {
		n.relayAuthTickets.Delete(peerID)
		return nil, false
	}
	return c.ticket, true
}

// authenticateWithRelay authenticates to a relay/bootstrap server with PSK. The
// protocol has two modes, selected by the first byte the node sends:
//
//   - RelayAuthModeFull (0x00): classic challenge-response. The node sends 0x00,
//     reads the boot's [0x02][31B] challenge, answers with
//     HMAC-SHA256(token, challenge) merged with its version record, and the
//     boot replies 0x01 ‖ newTicket ‖ its version record. A ticket is minted on
//     success so the next reconnect can take the fast path.
//   - RelayAuthModeTicket (0x01): the node replays a cached session ticket
//     (minted within RelayAuthTicketTTL) merged with its version record. The
//     boot verifies the ticket's HMAC with O(1) work — no per-PSK scan — and
//     replies 0x01 ‖ freshTicket ‖ its version record. If the ticket is
//     expired/corrupt the boot replies 0x00 and the node falls back to the full
//     challenge-response on the same stream using the challenge the boot sent.
//
// Both sides send their first packet immediately (full-duplex), so neither path
// waits on a read before writing: the full path is 1.5 RTT and the ticket path
// 1 RTT, versus 1.5 RTT for the old always-full handshake. The boot sends the
// challenge up front in both modes; a ticket-mode node reads and discards it
// (or keeps it for the 0x00 fallback).
//
// The PSK itself never appears on the wire in either mode: only
// HMAC-SHA256(HKDF(psk), challenge) and the ticket MAC (HMAC of an opaque,
// PSK-free ticket under a per-PSK HKDF-derived master key).
//
// isRefresh=true marks a periodic keep-alive refresh (logs at DEBUG); the
// initial handshake on (re)connect logs at INFO.
func (n *Node) authenticateWithRelay(peerID peer.ID, isRefresh bool) bool {
	// Probe the relay auth stream. Only "protocol not supported" means the
	// boot is in open mode (PSK disabled). Any other error — peer not
	// connected, transient transport failure, context deadline — must NOT be
	// treated as auth success, or a non-member peer gets relay access.
	s, err := n.Host.NewStream(n.ctx, peerID, relayAuthProtocol)
	if err != nil {
		if isProtocolNotSupported(err) {
			log.Debug("Relay peer %s does not require PSK auth (open relay)", peerID.ShortString())
			return true
		}
		log.Debug("Relay peer %s auth stream open failed: %v", peerID.ShortString(), err)
		return false
	}
	defer s.Close()

	// If the auth stream opened successfully, the bootstrap server REQUIRES PSK authentication!
	if n.Config.PSK == "" {
		log.Warn("Bootstrap peer %s requires PSK authentication, but no PSK is configured on this node! Relay access and discovery denied.", peerID.String())
		return false
	}

	log.Debug("Authenticating with relay peer %s using PSK...", peerID.String())

	// Compute the auth token. routing.RelayAuthToken is the one derivation the
	// boot server also calls, so the two sides cannot drift apart and a hex PSK
	// is treated case-insensitively on both.
	token := routing.RelayAuthToken(n.Config.PSK)

	// Set a read deadline BEFORE any read. Without this, if the boot accepts
	// the stream but never replies (stale boot, mid-restart), the goroutine
	// hangs forever while holding relayAuthInProgress[pID] — which permanently
	// suppresses every future auth attempt for that boot. The 5s deadline is
	// generous: auth completes in milliseconds on a healthy boot.
	_ = s.SetReadDeadline(time.Now().Add(5 * time.Second))

	// Fast path: a cached, unexpired session ticket authenticates with a single
	// short round trip and O(1) boot-side work.
	if ticket, ok := n.loadRelayTicket(peerID); ok {
		return n.relayAuthTicket(s, peerID, token, ticket, isRefresh)
	}
	// Slow path: no ticket — announce full mode, answer the challenge.
	if _, err := s.Write([]byte{routing.RelayAuthModeFull}); err != nil {
		log.Warn("Relay auth mode write failed for peer %s: %v", peerID.String(), err)
		return false
	}
	return n.relayAuthFull(s, peerID, token, isRefresh)
}

// relayAuthTicket replays a cached session ticket. It sends the ticket merged
// with the node's version record, reads (and keeps) the challenge the boot sent
// up front, then:
//   - 0x01: ticket accepted — read the fresh ticket and the boot's version
//     record, done.
//   - 0x00: ticket rejected (expired/corrupt) — fall back to the full
//     challenge-response using the challenge we just read.
func (n *Node) relayAuthTicket(s network.Stream, peerID peer.ID, token [32]byte, ticket []byte, isRefresh bool) bool {
	// Send [0x01] ‖ ticket ‖ nodeRecord in ONE write (merge optimization): the
	// boot reads mode, then ticket, then the record without a read-timeout gap.
	var recBuf bytes.Buffer
	_ = version.CurrentRecord().WriteRecord(&recBuf)
	buf := make([]byte, 0, 1+routing.RelayTicketLen+recBuf.Len())
	buf = append(buf, routing.RelayAuthModeTicket)
	buf = append(buf, ticket...)
	buf = append(buf, recBuf.Bytes()...)
	if _, err := s.Write(buf); err != nil {
		log.Debug("Relay auth ticket write failed for peer %s: %v", peerID.String(), err)
		return false
	}
	if n.protoTracker != nil {
		n.protoTracker.Auth.RecordTx(1, uint64(len(buf)))
	}

	challenge, ok := n.relayAuthReadChallenge(s, peerID)
	if !ok {
		return false
	}

	var b [1]byte
	if _, err := io.ReadFull(s, b[:]); err != nil {
		log.Debug("Relay auth ticket response read failed for peer %s: %v", peerID.String(), err)
		return false
	}
	switch b[0] {
	case 0x01:
		return n.relayAuthSuccess(s, peerID, isRefresh)
	case 0x00:
		// Ticket rejected — the boot now expects a full response to the
		// challenge it sent up front.
		return n.relayAuthSendFull(s, peerID, token, challenge, isRefresh)
	default:
		log.Warn("Relay peer %s sent unexpected auth byte %#x after ticket", peerID.String(), b[0])
		return false
	}
}

// relayAuthFull performs the classic challenge-response: read the boot's
// challenge (sent up front), answer it, and consume the success reply.
func (n *Node) relayAuthFull(s network.Stream, peerID peer.ID, token [32]byte, isRefresh bool) bool {
	challenge, ok := n.relayAuthReadChallenge(s, peerID)
	if !ok {
		return false
	}
	return n.relayAuthSendFull(s, peerID, token, challenge, isRefresh)
}

// relayAuthReadChallenge reads the [RelayChallengeByte][31B] challenge the boot
// sent up front, validating the fixed prefix so a 0x00 failure or 0x01 success
// byte cannot be mistaken for a challenge.
func (n *Node) relayAuthReadChallenge(s network.Stream, peerID peer.ID) ([]byte, bool) {
	challenge := make([]byte, routing.RelayAuthChallengeLen)
	if _, err := io.ReadFull(s, challenge); err != nil {
		log.Warn("Relay auth challenge read failed for peer %s: %v", peerID.String(), err)
		return nil, false
	}
	if challenge[0] != routing.RelayChallengeByte {
		log.Warn("Relay peer %s sent %#x where a challenge was expected", peerID.String(), challenge[0])
		return nil, false
	}
	return challenge, true
}

// relayAuthSendFull answers a challenge with the full response and consumes the
// success/ticket reply. The HMAC response is merged with the node's version
// record into one write so the boot never waits out its record read timeout.
func (n *Node) relayAuthSendFull(s network.Stream, peerID peer.ID, token [32]byte, challenge []byte, isRefresh bool) bool {
	authResp := routing.RelayAuthResponse(token, challenge)
	var recBuf bytes.Buffer
	_ = version.CurrentRecord().WriteRecord(&recBuf)
	buf := make([]byte, 0, len(authResp)+recBuf.Len())
	buf = append(buf, authResp[:]...)
	buf = append(buf, recBuf.Bytes()...)
	if _, err := s.Write(buf); err != nil {
		log.Warn("Relay auth response write failed for peer %s: %v", peerID.String(), err)
		return false
	}
	if n.protoTracker != nil {
		n.protoTracker.Auth.RecordTx(1, uint64(len(buf)))
	}
	return n.relayAuthSuccess(s, peerID, isRefresh)
}

// relayAuthSuccess reads the boot's 0x01, the freshly minted ticket, and the
// boot's version record, then runs the envelope-compatibility check.
func (n *Node) relayAuthSuccess(s network.Stream, peerID peer.ID, isRefresh bool) bool {
	var resp [1]byte
	if _, err := io.ReadFull(s, resp[:]); err != nil {
		// The auth stream was opened, so the boot REQUIRES PSK auth. An EOF
		// (boot closed without sending 0x01) means auth FAILED — treating it
		// as success would grant relay access to a non-member. Return false
		// so the caller does not open a boot-relay uplink to an unauthenticated
		// peer.
		log.Debug("Relay auth response read failed for peer %s: %v", peerID.String(), err)
		return false
	}
	if n.protoTracker != nil {
		n.protoTracker.Auth.RecordRx(1, 1)
	}
	if resp[0] != 0x01 {
		log.Warn("Relay auth FAILED with peer %s — PSK mismatch, relay access denied", peerID.String())
		return false
	}

	// Read the freshly minted session ticket and cache it for the next
	// reconnect. An old boot sends no ticket (just closes) — that is still a
	// successful auth, just without a fast path.
	ticket := make([]byte, routing.RelayTicketLen)
	if _, err := io.ReadFull(s, ticket); err != nil {
		log.Debug("Relay peer %s sent no session ticket — next auth will do a full handshake", peerID.String())
	} else {
		n.storeRelayTicket(peerID, ticket)
	}

	// Best-effort read the boot's version record. An OLD boot closed the stream
	// after the 1-byte response, so a short read means "unknown version" — warn
	// and proceed rather than fail the whole link. A corrupted record (non-EOF
	// error) means the peer sent a malformed or truncated JSON — log loudly so
	// an envelope-corruption attack is visible, but still proceed (the auth
	// already succeeded, and the compatibility check below will flag any
	// envelope mismatch).
	var peerRec version.Record
	if err := peerRec.ReadRecord(s); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			log.Warn("Relay peer %s did not report a version record (old build?) — cannot verify envelope compatibility", peerID.String())
		} else {
			log.Warn("Relay peer %s sent a corrupted version record — cannot verify envelope compatibility: %v", peerID.String(), err)
		}
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
	if n.protoTracker != nil {
		n.protoTracker.Auth.RecordSyncEvent()
	}
	return true
}

// isProtocolNotSupported checks whether err means the peer rejected our
// protocol because it does not advertise it. The go-multistream muxer
// returns ErrNotSupported (whose string is "protocols not supported: …"),
// and BasicHost.NewStream wraps it as "failed to negotiate protocol: …".
// This is the ONLY error that means "open mode / PSK disabled" — every
// other error (no conn, timeout, reset) must NOT be treated as success.
func isProtocolNotSupported(err error) bool {
	return err != nil && strings.Contains(err.Error(), "protocols not supported")
}

// bootstrapKeepAliveLoop periodically reconnects to bootstrap/static peers that have disconnected
func (n *Node) bootstrapKeepAliveLoop() {
	defer n.wg.Done()
	const period = 15 * time.Second
	// Jittered so bootstrap/relay reconnect probing has no fixed cadence tell.
	timer := newJitterTimer(period)
	defer timer.Stop()

	for {
		select {
		case <-n.ctx.Done():
			return
		case <-timer.C:
			timer.Reset(jitterInterval(period))
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
				if n.Host.Network().Connectedness(info.ID) == network.NotConnected {
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

				if n.Host.Network().Connectedness(info.ID) == network.NotConnected {
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

	// Get stored addresses from peerstore, dropping loopback (127.0.0.0/8, ::1)
	addrs := filterUndialableAddrs(n.Host.Peerstore().Addrs(pid))

	// Always synthesize fresh relay circuit addresses from any connected bootstrap relay
	// alongside direct addresses. This ensures NAT'd peers that cannot be dialed directly
	// can still be reached over circuit relays, preventing permanent "unreachable" disconnect deadlocks.
	if relayAddrs := n.SynthesizeRelayCircuitAddrs(pid); len(relayAddrs) > 0 {
		addrs = append(addrs, relayAddrs...)
		n.Host.Peerstore().AddAddrs(pid, relayAddrs, peerstore.AddressTTL)
		log.Debug("Reconnect %s: synthesized %d relay circuit addr(s)", pid.ShortString(), len(relayAddrs))
	}
	if len(addrs) == 0 {
		log.Warn("No stored (non-loopback) addrs for peer %s and no connected relay available, cannot reconnect", pid.String())
		return
	}

	// Invalidate stale streams and reset handshake state before reconnecting
	n.Dispatcher.RemovePeer(pid)
	n.echoPool.Invalidate(pid)
	n.clearCachedHandshakeEph(pid)
	n.peerReady.Delete(pid)
	n.forgetPeerTelemetry(pid)

	// Close any stale / hung swarm connections so libp2p doesn't treat the peer
	// as already connected and no-op the subsequent dial.
	if err := n.Host.Network().ClosePeer(pid); err != nil {
		log.Debug("ClosePeer %s: %v", pid.String(), err)
	}

	addrInfo := peer.AddrInfo{ID: pid, Addrs: addrs}
	go func() {
		_ = n.dialInParallel(n.ctx, addrInfo, "reconnect")
	}()
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
	return n.openStreamViaRelayContext(n.ctx, target, proto)
}

func (n *Node) hasPeerConnection(target peer.ID) bool {
	state := n.Host.Network().Connectedness(target)
	return state == network.Connected || state == network.Limited
}

func (n *Node) openStreamViaRelayContext(parent context.Context, target peer.ID, proto protocol.ID) (network.Stream, error) {
	if err := parent.Err(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	ctx = network.WithAllowLimitedConn(ctx, "p2ptap-control")
	// Bug A fix: if the target is already connected (e.g. a boot-relay circuit
	// link we established earlier is still live), reuse that connection directly
	// instead of insisting on (re)synthesizing a fresh circuit address. This is
	// what lets the relay-priority control path recognize and reuse a live
	// circuit link instead of always failing with "no connected relay".
	if n.hasPeerConnection(target) {
		s, err := n.Host.NewStream(ctx, target, proto)
		if err != nil {
			n.recordRelayControlFailure(target, err)
			return nil, err
		}
		n.clearRelayControlFailure(target)
		return s, nil
	}
	if err := n.relayPermissionCooldownError(target); err != nil {
		return nil, err
	}

	relayAddrs := n.SynthesizeRelayCircuitAddrs(target)
	if len(relayAddrs) == 0 {
		return nil, fmt.Errorf("no connected relay available for circuit dial to %s", target)
	}

	if n.isRelayOnlyPeer(target) {
		// Do NOT ClearAddrs here. Clearing permanently discarded the peer's
		// direct addresses, so nothing could ever dial it directly again — a
		// relay-only peer stayed relay-only forever. The circuit addr added
		// below wins the swarm's address race against any black-holed direct
		// address (circuit setup is near-instant on an already-connected relay
		// hop), so there is no hang cost in keeping the direct addrs around;
		// relayOnlyDirectUpgradeLoop uses them to periodically retry direct.
		log.Debug("Keeping direct addrs for relay-only peer %s (direct upgrade loop will retry them)", target.ShortString())
	}
	n.Host.Peerstore().AddAddrs(target, relayAddrs, peerstore.AddressTTL)

	s, err := n.Host.NewStream(ctx, target, proto)
	if err != nil {
		n.recordRelayControlFailure(target, err)
		return nil, err
	}
	n.clearRelayControlFailure(target)
	return s, nil
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
	n.forgetPeerTelemetry(pid)
	// reconnectPeer performs several synchronous libp2p operations (ClosePeer,
	// Clear backoff, SynthesizeRelayCircuitAddrs) that hold internal network
	// locks. Running it in the dispatch worker would block that worker for the
	// duration, starving healthy peers. The 5s cooldown above bounds the
	// goroutine count to one per peer per 5s.
	go n.reconnectPeer(pid)
}

// triggerOnDemandConnect triggers active connection or re-keying when egress traffic
// is blocked by canEgressToPeer, with a 5-second cooldown per peer.
func (n *Node) triggerOnDemandConnect(pid peer.ID) {
	if pid == "" || pid == n.Host.ID() {
		return
	}
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

	go func() {
		log.Debug("On-demand egress trigger for peer %s (connectedness=%v)", pid.ShortString(), n.Host.Network().Connectedness(pid))
		if n.Host.Network().Connectedness(pid) != network.NotConnected {
			// Already connected at transport layer, trigger rekey to unblock cipher / ready state
			n.triggerPeerRekey(pid)
		} else {
			// Not connected, attempt parallel dial with stored addrs + synthesized relay circuit addrs
			addrs := filterUndialableAddrs(n.Host.Peerstore().Addrs(pid))
			if relayAddrs := n.SynthesizeRelayCircuitAddrs(pid); len(relayAddrs) > 0 {
				addrs = append(addrs, relayAddrs...)
				n.Host.Peerstore().AddAddrs(pid, relayAddrs, peerstore.AddressTTL)
			}
			if len(addrs) > 0 {
				_ = n.dialInParallel(n.ctx, peer.AddrInfo{ID: pid, Addrs: addrs}, "on-demand")
			}
		}
	}()
}

// WebRTCConn is implemented by WebRTC connections so the ping-pong handler
// can detect WebRTC peers and reconnect faster (2s instead of 20s).
type WebRTCConn interface{ IsWebRTC() bool }

// PingPongKeepaliveInterval defines how often we send echo-based liveness probes.
// Unified with the old HealthCheck loop, so 10s is plenty (was 5s) and halves the
// probe frequency vs. the previous 5s+30s dual-storm.
const PingPongKeepaliveInterval = 10 * time.Second
const pingPongStreamTimeout = 5 * time.Second // stream creation timeout
const pingPongWriteTimeout = 4 * time.Second  // write "PING" timeout
const pingPongReadTimeout = 6 * time.Second   // read echo timeout (supports WAN/jitter)
const pingPongMaxFailures = 2
const pingPongMaxConcurrent = 8 // max concurrent peer probes per tick

// pingPongReconnectQuietWindow is how recently a peer must have sent us an
// inbound DATA frame for its echo failures to be treated as "the echo stream
// broke" (refresh the stream, keep the negotiated cipher) rather than "the peer
// is dead" (reconnectPeer).
//
// The window is deliberately wide because reconnectPeer is not a link teardown
// — it is a full state reset: Dispatcher.RemovePeer, echoPool.Invalidate,
// clearCachedHandshakeEph, peerReady.Delete and ClosePeer. That wipes the
// negotiated SeqSync cipher and forces a complete re-handshake, and for a
// relay-only peer that round trip costs the entire relay-upgrade latency. An
// echo stream fails for transient reasons (a GC pause, an unrelated burst)
// while the peer's data path is perfectly healthy, so a peer that has sent us
// even one frame inside this window is treated as live and we refresh only the
// echo stream.
//
// It deliberately equals returnPathAliveWindow, the same package constant the
// WebUI return-path verdict uses: there is one notion of "this peer's return
// path is dead" in the engine, so the UI never claims a peer is healthier than
// we are willing to assume on its behalf. A peer that has sent nothing inside
// the window AND whose echo fails twice is treated as genuinely dead — which is
// the failure mode this probe exists to detect.
const pingPongReconnectQuietWindow = returnPathAliveWindow

// pingPongShouldReconnect reports whether an echo failure may escalate to
// reconnectPeer, or must be satisfied by refreshing only the echo stream. See
// pingPongReconnectQuietWindow for why a peer with recent inbound data must
// never be re-handshaken just because its echo stream stalled.
func (n *Node) pingPongShouldReconnect(pid peer.ID) bool {
	return !n.peerRxWithin(pid, pingPongReconnectQuietWindow)
}

// pingPongFailCounter returns pid's fail counter from the current published
// snapshot, or nil if the peer has no entry yet. Lock-free (hot-path reader).
func (n *Node) pingPongFailCounter(pid peer.ID) *atomic.Int32 {
	if m := n.pingPongFailCount.Load(); m != nil {
		return (*m)[pid]
	}
	return nil
}

// pingPongFailCounterFor returns pid's fail counter, creating and publishing a
// new CoW snapshot if needed. Slow path — only the first failure for a peer
// reaches this; a missing entry already means "zero consecutive failures".
func (n *Node) pingPongFailCounterFor(pid peer.ID) *atomic.Int32 {
	if c := n.pingPongFailCounter(pid); c != nil {
		return c
	}
	n.pingPongFailMu.Lock()
	defer n.pingPongFailMu.Unlock()
	// Double-check: a concurrent prober may have published while we waited.
	if m := n.pingPongFailCount.Load(); m != nil {
		if c, ok := (*m)[pid]; ok {
			return c
		}
	}
	var next map[peer.ID]*atomic.Int32
	if m := n.pingPongFailCount.Load(); m != nil {
		next = make(map[peer.ID]*atomic.Int32, len(*m)+1)
		for k, v := range *m {
			next[k] = v
		}
	} else {
		next = make(map[peer.ID]*atomic.Int32, 1)
	}
	c := &atomic.Int32{}
	next[pid] = c
	n.pingPongFailCount.Store(&next)
	return c
}

// deletePingPongFailCount removes pid's fail counter via CoW republish.
// Structural change only (10s keepalive tick / post-reconnect cleanup).
func (n *Node) deletePingPongFailCount(pid peer.ID) {
	n.pingPongFailMu.Lock()
	defer n.pingPongFailMu.Unlock()
	m := n.pingPongFailCount.Load()
	if m == nil {
		return
	}
	if _, ok := (*m)[pid]; !ok {
		return
	}
	next := make(map[peer.ID]*atomic.Int32, len(*m))
	for k, v := range *m {
		if k == pid {
			continue
		}
		next[k] = v
	}
	n.pingPongFailCount.Store(&next)
}

// resetPingPongFailCountForPeer resets the ping-pong failure counter for a peer.
// This is called from handleStream when data is actively flowing, preventing false
// positives where yamux flow control delays echo streams but the connection is healthy.
//
// HOT PATH (once per inbound frame): lock-free snapshot read, and the per-peer
// Store(0) only fires while a counter is actually non-zero — a healthy steady
// state costs no writes at all. Missing entry == zero failures, so no creation.
func (n *Node) resetPingPongFailCountForPeer(pid peer.ID) {
	if c := n.pingPongFailCounter(pid); c != nil && c.Load() != 0 {
		c.Store(0)
	}
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
		if n.Host.Network().Connectedness(pid) == network.NotConnected {
			continue
		}
		if n.isBootRelayBlacklisted(pid) || n.hasBootRelayUplink(pid) {
			continue
		}
		log.Warn("keepalive: boot %s is transport-Connected but has NO relay-over-backbone uplink — egress to relay-only peers via it is dead; re-triggering relay auth", pid.String())
		go n.ensureRelayAuth(peer.AddrInfo{ID: pid})
	}
}

// peerPingPongLoop sends echo-based keepalive pings to all connected peers
// every PingPongKeepaliveInterval (10s, ±20% jitter). Bootstrap peers are
// included because without application-level echo pings, a half-open transport
// link to the boot could silently blackhole circuit-relay traffic for up to
// 30s (the boot's own relayKeepaliveLoop period) before either side notices.
// pingPongMaxFailures (2) consecutive timeouts the peer is reconnected — unless
// it has sent us inbound data within pingPongReconnectQuietWindow, in which case
// only the echo stream is refreshed. This provides fast dead-connection
// detection (~20-30s) vs. the 30s health-check loop which also probes but more
// slowly.
//
// All peers are probed concurrently (capped at pingPongMaxConcurrent) to prevent
// a single slow peer from blocking the entire probe cycle and causing false
// positive failures on subsequent peers.
func (n *Node) peerPingPongLoop() {
	defer n.wg.Done()
	// Jittered echo-keepalive cadence: a fixed 10s probe beat is a passive DPI
	// timing signature. ±20% stays well inside the failure-detection budget.
	timer := newJitterTimer(PingPongKeepaliveInterval)
	defer timer.Stop()

	for {
		select {
		case <-n.ctx.Done():
			return
		case <-timer.C:
			timer.Reset(jitterInterval(PingPongKeepaliveInterval))
			peers := n.Host.Network().Peers()
			connected := make(map[peer.ID]bool, len(peers))
			var probePeers []peer.ID
			for _, pid := range peers {
				if pid == n.Host.ID() {
					continue
				}
				connected[pid] = true
				// Probe all connected peers including bootstrap/relay peers.
				// Without this the client's link to the boot was never echo-probed
				// from the client side (only from the boot's 30s relayKeepaliveLoop),
				// so a half-open transport link to the boot could silently blackhole
				// circuit-relay traffic for up to 30s before the boot noticed.
				if n.Host.Network().Connectedness(pid) == network.NotConnected {
					n.deletePingPongFailCount(pid)
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

			// Also probe peers known in peerMeta that are reachable via relay/overlay
			// but don't have a direct libp2p swarm connection.
			n.peerMeta.Range(func(key, val any) bool {
				pid := key.(peer.ID)
				if pid == n.Host.ID() || connected[pid] || n.isRelayOnlyPeer(pid) || n.isBootstrapPeer(pid) {
					return true
				}
				meta := val.(PeerMeta)
				if meta.TapIP == "" && meta.TapIPv6 == "" {
					return true // skip pure signalling bootstrap nodes
				}
				if hop := n.relayHopForTarget(pid); hop != "" {
					probePeers = append(probePeers, pid)
				}
				return true
			})

			// Data-plane health for boot-relay hops: a boot may be
			// transport-Connected (so its echo keepalive passes) yet have NO live
			// relay-over-backbone uplink, which silently blackholes every frame to
			// relay-only peers. Surface that fast instead of via packet captures.
			n.assertBootRelayUplinkHealth()

			// Under multipath, repair per-connection streams BEFORE probing.
			// A path whose stream was retired (write failure, or a full writer
			// queue — see writeMultipathLocked) is never re-opened by the lazy
			// openStream path: that path reuses any surviving stream and only
			// dials when the peer has none left. Without this repair a single
			// transient failure permanently drops the peer to one path and the
			// strategy silently decays to best_path for the rest of the session.
			if n.Dispatcher.Mode() == "multipath" {
				for _, pid := range probePeers {
					if pid == n.Host.ID() || n.isBootstrapPeer(pid) {
						continue
					}
					if n.Host.Network().Connectedness(pid) == network.NotConnected {
						continue
					}
					go n.Dispatcher.EnsureStreamsOnAllConns(pid)
				}
			}

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
			if m := n.pingPongFailCount.Load(); m != nil {
				for pid := range *m {
					if n.Host.Network().Connectedness(pid) != network.NotConnected {
						continue
					}
					if n.isRelayOnlyPeer(pid) {
						continue
					}
					n.deletePingPongFailCount(pid)
				}
			}
		}
	}
}

// pingPongProbePeer sends a single echo ping to one peer and handles failure counting.
// It reuses a persistent per-peer echo stream (echoPool) instead of opening a fresh
// NewStream on every tick — the old per-tick NewStream-per-peer storm is gone.
func (n *Node) pingPongProbePeer(pid peer.ID) {
	if pid == "" || pid == n.Host.ID() {
		return
	}

	// Do not skip the measurement merely because application traffic is active.
	// Data proves liveness, but it says nothing about RTT, jitter, or loss.  The
	// old early-return left the WebUI permanently unmeasured during a continuous
	// ping/iperf run and then displayed the fabricated 10ms fallback.  This is a
	// four-byte probe once per interval on a persistent stream; failures still
	// consult recent data below before deciding whether to reconnect.

	pingPayload := []byte{0x50, 0x49, 0x4E, 0x47} // "PING"
	replyBuf := make([]byte, 16)
	var measuredRTT time.Duration

	// Try the unified mux control channel first.
	muxSucceeded := false
	if n.muxEngine != nil {
		frame := make([]byte, 4+len(pingPayload))
		binary.BigEndian.PutUint32(frame[:4], uint32(len(pingPayload)))
		copy(frame[4:], pingPayload)
		start := time.Now()
		resp, err := n.muxEngine.SendRecv(pid, mux.TagEcho, frame, pingPongReadTimeout)
		rtt := time.Since(start)
		if err == nil && len(resp) >= 8 {
			rn := binary.BigEndian.Uint32(resp[:4])
			if rn >= 4 && bytes.Equal(resp[4:4+min(4, rn)], pingPayload) {
				measuredRTT = rtt
				muxSucceeded = true
				log.Debug("Ping-pong OK (mux) for %s RTT=%dms", pid.String(), rtt.Milliseconds())
			}
		}
	}

	var ok bool
	if !muxSucceeded {
		// Legacy fallback: reuse the persistent echo stream.
		ok = n.echoPool.WithStream(pid, func(s network.Stream) error {
			// Exclude stream lookup/opening from the wire RTT. Cold connection setup
			// is a separate availability metric, not round-trip latency.
			start := time.Now()
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
			measuredRTT = rtt
			log.Debug("Ping-pong OK for %s RTT=%dms", pid.String(), rtt.Milliseconds())
			return nil
		})
	}

	if ok || measuredRTT > 0 {
		// Feed the real completed echo round trip into both libp2p's EWMA and
		// the source-labelled rolling WebUI window. Previously the RTT was only
		// printed at DEBUG and discarded.
		if measuredRTT > 0 {
			n.Host.Peerstore().RecordLatency(pid, measuredRTT)
			n.recordPeerRTTProbe(pid, rttSourceP2PEcho, measuredRTT, true)
		}
		// Success: reset if a counter exists and record return-path liveness
		if c := n.pingPongFailCounter(pid); c != nil {
			c.Store(0)
		}
		n.notePeerRx(pid)
		n.clearRelayControlFailure(pid)
		return
	}

	// WithStream returned false => stream open failed or bad echo (cache dropped).
	n.recordPeerRTTProbe(pid, rttSourceP2PEcho, 0, false)
	fc := n.pingPongFailCounterFor(pid).Add(1)
	if fc >= pingPongMaxFailures {
		if !n.pingPongShouldReconnect(pid) {
			// Inbound data frames are actively arriving or arrived recently from
			// pid! The data-plane return path is healthy — only the echo stream
			// had an issue. Do NOT tear down the working connection: reconnectPeer
			// would wipe the negotiated SeqSync cipher and force a full
			// re-handshake over a path that is demonstrably alive.
			log.Debug("Ping-pong echo stream failed for %s, but inbound data arrived within %s; refreshing echo stream instead of reconnecting",
				pid.ShortString(), pingPongReconnectQuietWindow)
			n.echoPool.Invalidate(pid)
			n.pingPongFailCounterFor(pid).Store(0)
			return
		}

		log.Warn("Ping-pong keepalive failed %d times for %s — no inbound frames within %s; triggering reconnect",
			fc, pid.String(), pingPongReconnectQuietWindow)
		if hop := n.relayHopForTarget(pid); hop != "" && n.isBootstrapPeer(hop) {
			log.Warn("Ping-pong keepalive failed %d times for relay peer %s via boot %s — re-verifying boot uplink",
				fc, pid.ShortString(), hop.ShortString())
			go n.ensureRelayAuth(peer.AddrInfo{ID: hop})
		}
		n.reconnectPeer(pid)
		n.deletePingPongFailCount(pid)
	} else if fc == 1 {
		// WebRTC connections recover faster: reconnect immediately on first
		// failure instead of waiting for 2 failures × 10s = 20s. But not when
		// the peer has demonstrably sent us data recently — then the WebRTC
		// leg that broke is the echo stream, and reconnectPeer's cipher wipe is
		// pure cost.
		if n.hasWebRTCConn(pid) && n.pingPongShouldReconnect(pid) {
			log.Debug("WebRTC ping-pong failed for %s — reconnecting immediately", pid.ShortString())
			n.reconnectPeer(pid)
			n.deletePingPongFailCount(pid)
			return
		}
		log.Debug("Ping-pong failed for %s (%d/%d)", pid.String(), fc, pingPongMaxFailures)
	} else {
		log.Debug("Ping-pong failed for %s (%d/%d)", pid.String(), fc, pingPongMaxFailures)
	}
}

// hasWebRTCConn returns true if pid has any WebRTC connections.
func (n *Node) hasWebRTCConn(pid peer.ID) bool {
	for _, conn := range n.Host.Network().ConnsToPeer(pid) {
		if _, ok := conn.(WebRTCConn); ok {
			return true
		}
	}
	return false
}

// dialLimiter caps concurrent in-flight dials so a discovery/mDNS burst cannot
// turn into a connection storm (each dial also connects to every bootstrap relay).
// 32 concurrent dials (up from 16) lets a DHT round that surfaces ~100 peers
// drain in ~10s instead of ~40s. Each dial still races direct vs relay under
// a 10s deadline, and the dialingDone coalescing guard drops duplicates.
var dialLimiter = make(chan struct{}, 32)

// directRaceGracePeriod is how long dialInParallel keeps waiting for the direct
// dial after the relay race has already succeeded. Relay circuits usually win
// the raw race (the bootstrap hop is already connected) while NAT traversal
// takes seconds; without this grace window every hole punch would be cancelled
// mid-flight and peers would stay pinned to relay forever.
const directRaceGracePeriod = 10 * time.Second

// dialingMu guards dialingDone. A peer with an entry is already being dialed;
// concurrent callers wait on the channel and reuse the result instead of
// launching a second competing dial (which can cause libp2p transport conflicts).
var dialingMu sync.Mutex
var dialingDone = make(map[peer.ID]chan struct{})

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

// prioritizeMultiaddrs sorts candidate multiaddrs by connectivity likelihood and performance:
//  1. Public Global Unicast IPv6 (2000::/3) with QUIC/UDP (score: 130) or TCP (score: 110)
//     -> Native public route, zero NAT traversal overhead, near 100% direct connect rate.
//  2. Public IPv4 with QUIC/UDP (score: 90)
//     -> 0-RTT and optimal UDP hole punching protocol for NAT traversal.
//  3. Public IPv4 with WebRTC (score: 80)
//  4. Public IPv4 with TCP (score: 70)
//  5. Private / CGNAT IPv4 / ULA IPv6 (score: 30-40)
//
// Loopback addresses are excluded.
func prioritizeMultiaddrs(addrs []multiaddr.Multiaddr) []multiaddr.Multiaddr {
	if len(addrs) <= 1 {
		return addrs
	}
	type scoredAddr struct {
		addr  multiaddr.Multiaddr
		score int
	}
	scored := make([]scoredAddr, 0, len(addrs))
	var passthrough []multiaddr.Multiaddr
	for _, a := range addrs {
		ip, err := manet.ToIP(a)
		if err != nil {
			// Non-IP addrs (dnsaddr, p2p-circuit) get score 0 but are
			// preserved — dropping them would remove circuit addrs from the
			// peerstore refresh, starving the relay race leg.
			passthrough = append(passthrough, a)
			continue
		}
		if ip.IsLoopback() {
			continue // loopback is never dialable across machines
		}
		// Drop overlay (TAP/mesh) addresses — dialing them routes through
		// our own tunnel, creating a libp2p-over-TAP recursion loop.
		if isOverlayMultiaddr(a) {
			continue
		}
		score := 0
		isV6 := ip.To4() == nil
		isPrivate := ip.IsPrivate() || ip.IsLinkLocalUnicast()

		if isV6 {
			if !isPrivate && ip.IsGlobalUnicast() {
				score += 100 // Public Global IPv6
			} else {
				score += 20 // ULA or Link-Local IPv6
			}
		} else {
			if !isPrivate {
				score += 60 // Public IPv4
			} else {
				score += 30 // Private RFC1918 / CGNAT IPv4
			}
		}

		switch TransportOf(a) {
		case "quic":
			score += 30
		case "webtransport":
			score += 25
		case "webrtc":
			score += 20
		case "tcp":
			score += 10
		}

		scored = append(scored, scoredAddr{addr: a, score: score})
	}

	sort.SliceStable(scored, func(i, j int) bool {
		return scored[i].score > scored[j].score
	})

	res := make([]multiaddr.Multiaddr, len(scored), len(scored)+len(passthrough))
	for i, sa := range scored {
		res[i] = sa.addr
	}
	res = append(res, passthrough...)
	return res
}

// dialInParallel attempts to dial a peer concurrently via direct connection and
// Circuit Relay, returning whichever succeeds first. This eliminates the sequential
// 3-10s latency penalty when falling back to relay.
// IMPORTANT: When the first goroutine wins, the losing goroutine is explicitly
// cancelled via raceCtx to prevent a second connection from being established
// and causing a libp2p transport conflict/disconnect.
func (n *Node) dialInParallel(ctx context.Context, pi peer.AddrInfo, peerType string) error {
	// Filter loopback addresses and prioritize high-success direct multiaddrs (IPv6/QUIC first)
	pi.Addrs = prioritizeMultiaddrs(filterUndialableAddrs(pi.Addrs))

	// Aggressive: Clear any dial backoff and refresh multiaddrs in Peerstore.
	// NOTE: we intentionally do NOT ClearAddrs here. Clearing would discard
	// addresses the peerstore already learned via DHT/mDNS/relay, forcing future
	// dials to fall back to relays or re-discover. AddAddrs merges and refreshes
	// TTL, which is exactly what we want across reconnect attempts.
	if len(pi.Addrs) > 0 {
		// Only clear backoff when we have real addresses to dial. Unconditionally
		// clearing on every dial (including retry loops) neutralizes libp2p's
		// exponential backoff and causes thundering-herd against unresponsive peers.
		n.clearSwarmBackoff(pi.ID)
		n.Host.Peerstore().AddAddrs(pi.ID, pi.Addrs, peerstore.AddressTTL)
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
		if n.hasPeerConnection(pi.ID) {
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
		// Slot acquired; released below after the first race result.
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

	// Race: direct connection. WithForceDirectDial keeps this leg TRULY direct:
	// circuit-relay addresses previously synthesized into the peerstore (10-min
	// AddressTTL) would otherwise be raced by the swarm inside this very call, so
	// a fast circuit win would be misreported as "connected via direct".
	go func() {
		directCtx, cancel := context.WithTimeout(raceCtx, n.config().HolePunchTimeout)

		defer cancel()
		err := n.Host.Connect(network.WithForceDirectDial(directCtx, "p2ptap-direct-race"), pi)
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
		// Prepare a context for the relay race with configurable timeout
		relayCtx, relayCancel := context.WithTimeout(raceCtx, n.config().HolePunchTimeout)
		defer relayCancel()

		// Relay path needs more time: connect to relay (1.5s) + auth (2s) + circuit connect
		relayLaunched = true
		go func() {
			if cooldownErr := n.relayPermissionCooldownError(pi.ID); cooldownErr != nil {
				select {
				case ch <- result{err: cooldownErr, mode: "circuit-relay"}:
				case <-raceCtx.Done():
				}
				return
			}
			// Connect to all bootstrap relays in parallel — sequential connects
			// burned up to 9s (3 boots × 3s) of the 15s HolePunchTimeout budget
			// before SynthesizeRelayCircuitAddrs even ran.
			var bootWg sync.WaitGroup
			for _, bStr := range n.Config.BootstrapPeers {
				bMA, berr := multiaddr.NewMultiaddr(bStr)
				if berr != nil {
					continue
				}
				bInfo, berr := peer.AddrInfoFromP2pAddr(bMA)
				if berr != nil {
					continue
				}
				if n.Host.Network().Connectedness(bInfo.ID) == network.NotConnected {
					bootWg.Add(1)
					go func(bi peer.AddrInfo) {
						defer bootWg.Done()
						bCtx, bCancel := context.WithTimeout(relayCtx, 3*time.Second)
						_ = n.Host.Connect(bCtx, bi)
						bCancel()
					}(*bInfo)
				}
			}
			bootWg.Wait()
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
				// 203/CONNECTION_FAILED is transient: the destination may be
				// reconnecting to the relay. A 202/PERMISSION_DENIED is an ACL
				// decision (authentication or PSK-network mismatch), so record it
				// and stop this immediate retry burst.
				errLower := strings.ToLower(relayErr.Error())
				if isRelayPermissionDenied(relayErr) {
					n.recordRelayControlFailure(pi.ID, relayErr)
					break
				}
				isTransient := strings.Contains(errLower, "203") ||
					strings.Contains(errLower, "connection_failed")
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
			if relayErr == nil {
				n.clearRelayControlFailure(pi.ID)
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
		<-dialLimiter // release slot on timeout
		return ctx.Err()
	}

	// Release the dial-limiter slot immediately — we have a connection (or
	// a definitive failure). Without this, a relay leg that wins in ~1s but a
	// black-holed direct leg that holds until HolePunchTimeout would pin one
	// of 32 slots for up to 10s, turning a 100-peer DHT round from ~3s into
	// ~30s. The race goroutines are bounded by their own contexts; raceCancel
	// below ensures they exit.
	<-dialLimiter

	if first.err == nil {
		// DIRECT-FIRST preference: when the relay race won (it usually starts
		// faster because the bootstrap hop is already connected), do NOT settle
		// immediately — keep waiting for the direct dial result up to a grace
		// window. The already-established relay connection costs nothing while we
		// wait, and a direct success here means NAT traversal actually worked and
		// we return it as the winning path instead of pinning the peer to relay.
		if first.mode == "circuit-relay" && relayLaunched {
			timer := time.NewTimer(directRaceGracePeriod)
			select {
			case second := <-ch:
				if second.err == nil && second.mode == "direct" {
					log.Info("%s peer %s connected via direct (direct preferred over relay winner)", peerType, pi.ID.String())
					timer.Stop()
					if peerType == "bootstrap" {
						go n.ensureRelayAuth(pi)
					}
					raceCancel()
					return nil
				}
				// Direct failed or was cancelled — accept the relay winner below.
			case <-timer.C:
				// Grace expired: NAT traversal is slow/black-holed; accept relay.
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			}
			timer.Stop()
		}
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
		log.Warn("PSK auth with bootstrap %s failed — relay access and discovery denied, boot-relay uplink NOT opened", pi.ID.ShortString())
		// PSK mismatch (or transport failure): do not open the boot-relay
		// uplink — the boot would drop our frames anyway.
		return
	}

	// Establish the boot-relay (relay-over-backbone) uplink. The uplink is
	// SELF-HEALING: its own loop reopens the stream whenever the boot link
	// drops, so we spawn it EXACTLY ONCE per boot (guarded in
	// maybeSpawnBootRelayUplink) and must NOT re-spawn it on every reconnect,
	// or we would leak orphaned reader goroutines and clobber the live uplink
	// entry. This is what lets us reach peers attached to THIS boot OR a
	// different boot in the same PSK network when no direct / overlay-relay path
	// exists. In open mode (no PSK) auth succeeds trivially and the uplink is
	// still opened so cross-boot bridging works.
	n.maybeSpawnBootRelayUplink(pi.ID)
}
