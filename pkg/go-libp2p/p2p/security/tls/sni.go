package libp2ptls

import (
	"crypto/tls"
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

// dialServerName is the SNI we advertise on outgoing handshakes (both TCP-TLS and
// QUIC). Empty = no SNI (upstream behaviour). Guarded like the other p2ptap
// runtime hooks; set once from config before any dial.
var (
	sniMu          sync.RWMutex
	dialServerName string
)

// SetDialServerName registers the SNI placed on outgoing TLS/QUIC ClientHellos.
// An empty value (the default) sends no server_name, preserving upstream
// behaviour and full interop with stock libp2p peers.
func SetDialServerName(name string) {
	sniMu.Lock()
	dialServerName = name
	sniMu.Unlock()
}

// DialServerName returns the configured outgoing SNI ("" = none). Surfaced to the
// WebUI "本机信息" panel so the operator can confirm what this node advertises.
func DialServerName() string {
	sniMu.RLock()
	defer sniMu.RUnlock()
	return dialServerName
}

// applyDialServerName sets conf.ServerName for an outgoing (client) handshake
// when SNI is configured and the config does not already carry one. Called from
// ConfigForPeer. Server-side configs ignore ServerName in crypto/tls, so it is
// harmless to apply on the shared clone.
func applyDialServerName(conf *tls.Config) {
	if conf == nil || conf.ServerName != "" {
		return
	}
	if sni := DialServerName(); sni != "" {
		conf.ServerName = sni
	}
}

// --- Inbound SNI observation (operator visibility into what peers advertise) ---
//
// When a peer handshakes with US, its ClientHello server_name is visible in
// GetConfigForClient before the peer identity is known. We key it by the remote
// host (IP) — the same host the connection ends up attributed to — in a small
// bounded map, and expose it so the node can show, per connected peer, the SNI
// the peer actually presented. This lets an operator verify a tls_server_name
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
