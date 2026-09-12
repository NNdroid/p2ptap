package libp2ptls

import (
	"crypto/sha256"
	"crypto/tls"
	"strings"
	"sync"
	"time"
)

// This file is a p2ptap LOCAL PATCH to go-libp2p's TLS security transport. It
// centralises the handshake server_name (SNI) so a single operator setting
// applies to BOTH TLS-over-TCP (SecureOutbound) and QUIC (whose transport builds
// its tls.Config from the same Identity.ConfigForPeer). See LOCAL_PATCHES.md.
//
// Why central: upstream libp2p leaves ServerName unset (QUIC/TLS dial by IP
// multiaddr, and real HTTP/3 clients always send SNI, so "no SNI" is itself a
// DPI tell). p2ptap lets the operator supply a plausible server_name to look like
// ordinary HTTP/3. Doing it per-transport (only QUIC) would be inconsistent, so
// it is done here where both transports share the client tls.Config.

// dialServerName / dialSNISuffix are the two SNI modes; suffix wins if set.
//   - suffix != "": per-peer SNI = "<label(remote PeerID)>.<suffix>" — a distinct,
//     stable DNS-safe label per link under one base domain.
//   - else name != "": static SNI for every dial.
//   - else: no SNI (upstream behaviour).
//
// Guarded like the other p2ptap runtime hooks; set once from config before dials.
var (
	sniMu          sync.RWMutex
	dialServerName string
	dialSNISuffix  string
)

// SetDialServerName registers the static SNI placed on outgoing TLS/QUIC
// ClientHellos. An empty value (the default) sends no server_name, preserving
// upstream behaviour and full interop with stock libp2p peers.
func SetDialServerName(name string) {
	sniMu.Lock()
	dialServerName = name
	sniMu.Unlock()
}

// SetDialSNISuffix enables per-peer derived SNI: outgoing ClientHellos carry
// "<label(remote PeerID)>.<suffix>". Takes precedence over SetDialServerName.
// An empty suffix disables it (falls back to the static name, or none).
func SetDialSNISuffix(suffix string) {
	suffix = strings.Trim(strings.TrimSpace(suffix), ".")
	sniMu.Lock()
	dialSNISuffix = suffix
	sniMu.Unlock()
}

// DialServerName returns the configured static outgoing SNI ("" = none).
func DialServerName() string {
	sniMu.RLock()
	defer sniMu.RUnlock()
	return dialServerName
}

// DialSNISuffix returns the configured per-peer SNI suffix ("" = disabled).
func DialSNISuffix() string {
	sniMu.RLock()
	defer sniMu.RUnlock()
	return dialSNISuffix
}

// peerSNILabel turns a remote Peer ID into a short, lowercase, DNS-label-safe
// prefix (RFC1123: [a-z0-9-], no leading/trailing '-'). Uses the first 8 bytes
// of SHA-256 hex — stable for a given peer, distinct across peers, no entropy
// beyond the peer identity already implied by the connection.
func peerSNILabel(remote string) string {
	if remote == "" {
		return ""
	}
	sum := sha256.Sum256([]byte("p2ptap-sni:" + remote))
	const hexdigits = "0123456789abcdef"
	var b [16]byte
	for i := range b {
		b[i] = hexdigits[sum[i]&0xf]
	}
	return string(b[:])
}

// resolveDialServerName computes the SNI for a dial to the given remote peer ID.
// Suffix mode wins; else static name; else empty (no SNI).
func resolveDialServerName(remote string) string {
	sniMu.RLock()
	name, suffix := dialServerName, dialSNISuffix
	sniMu.RUnlock()
	if suffix != "" {
		if label := peerSNILabel(remote); label != "" {
			return label + "." + suffix
		}
		// No peer id yet (rare): fall back to the static name if any.
		return name
	}
	return name
}

// applyDialServerName sets conf.ServerName for an outgoing (client) handshake to
// the resolved SNI (per-peer suffix or static name). remote is the peer ID being
// dialed (empty for the listener / unknown). Server-side configs ignore
// ServerName in crypto/tls, so it is harmless to apply on the shared clone.
func applyDialServerName(conf *tls.Config, remote string) {
	if conf == nil || conf.ServerName != "" {
		return
	}
	if sni := resolveDialServerName(remote); sni != "" {
		conf.ServerName = sni
	}
}

// --- Inbound SNI observation (operator visibility into what peers advertise) ---
//
// When a peer handshakes with US, its ClientHello server_name is visible in
// GetConfigForClient before the peer identity is known. We key it by the remote
// IP:port (the same string the node attributes connections by) — in a small
// bounded map — and expose it so the node can show, per connected peer, the SNI
// the peer actually presented. Keying by IP:port (not just IP) avoids conflating
// two peers behind one NAT egress. This lets an operator verify a tls_server_name
// rollout reached every node instead of assuming it.

type observedSNI struct {
	serverName string
	seenAt     time.Time
}

const (
	observedSNITTL        = 30 * time.Minute
	observedSNIMaxEntries = 2048
)

var (
	observedSNIMu    sync.Mutex
	observedServerNI map[string]observedSNI = make(map[string]observedSNI)
)

// ObserveInboundServerName is the exported entry point used by the QUIC
// transport's listener (which builds its tls.Config separately) to record the
// server_name a peer presented, keyed by its remote host, for WebUI display.
// No-op on empty inputs.
func ObserveInboundServerName(remoteHost, serverName string) {
	observeInboundServerName(remoteHost, serverName)
}

// observeInboundServerName records the server_name a peer presented, keyed by its
// remote host. Best-effort: an oversized map is pruned by age rather than
// growing unbounded (a connection flood must not turn this into a memory DoS).
func observeInboundServerName(remoteHost, serverName string) {
	if remoteHost == "" || serverName == "" {
		return
	}
	observedSNIMu.Lock()
	defer observedSNIMu.Unlock()
	if len(observedServerNI) >= observedSNIMaxEntries {
		// Opportunistic prune; if still too big, evict the oldest entries.
		now := time.Now()
		for k, v := range observedServerNI {
			if now.Sub(v.seenAt) > observedSNITTL {
				delete(observedServerNI, k)
			}
		}
		if len(observedServerNI) >= observedSNIMaxEntries {
			for k := range observedServerNI {
				delete(observedServerNI, k)
				if len(observedServerNI) < observedSNIMaxEntries/2 {
					break
				}
			}
		}
	}
	observedServerNI[remoteHost] = observedSNI{serverName: serverName, seenAt: time.Now()}
}

// InboundServerNames returns a snapshot of remote-host → last-presented SNI. The
// node uses each connection's remote IP to attribute it to a peer for display.
func InboundServerNames() map[string]string {
	observedSNIMu.Lock()
	defer observedSNIMu.Unlock()
	out := make(map[string]string, len(observedServerNI))
	for k, v := range observedServerNI {
		out[k] = v.serverName
	}
	return out
}
