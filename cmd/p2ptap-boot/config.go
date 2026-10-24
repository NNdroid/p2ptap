package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// BootConfig is the JSON configuration for the standalone p2ptap bootstrap /
// relay server. It mirrors the mesh node's config file approach (a single JSON
// document loaded with -c, default boot.json) so the two deploy artifacts share
// the same operational model. A missing config file is treated as "first run":
// a sensible default is written to disk so the operator can edit it in place
// rather than having to learn every key.
//
// Multi-network support: psks is a STRING ARRAY, one entry per isolated network.
// Each distinct PSK defines a network; peers authenticated under one PSK can
// only relay to and discover peers under the SAME PSK.
// WebUIConfig controls the embedded WebUI monitoring dashboard.
const (
	// DefaultPeerAddrFile is the peer-address cache sidecar written next to
	// boot.json.
	DefaultPeerAddrFile = "boot.addrs.json"
	// DefaultPeerAddrRebroadcastWindow bounds startup replay of cached records.
	DefaultPeerAddrRebroadcastWindow = 7 * 24 * time.Hour
)

type WebUIConfig struct {
	Enable    bool   `json:"enable"`     // enable web dashboard
	Listen    string `json:"listen"`     // e.g. "0.0.0.0:8080"
	AuthToken string `json:"auth_token"` // access token for login protection (auto-generated if empty)
}

type BootConfig struct {
	ListenAddrs []string    `json:"listen_addrs"` // Multiaddr listen addresses (REQUIRED)
	KeyFile     string      `json:"key_file"`     // persistent identity private key path
	PSKs        []string    `json:"psks"`         // multi-network: one PSK per isolated network
	NodeName    string      `json:"node_name"`    // display name in WebUI / discovery
	MeshPeers   []string    `json:"mesh_peers"`   // peer boot multiaddrs for backbone interconnect
	LogLevel    string      `json:"log_level"`    // debug | info | warn | error
	GeoIPPath   string      `json:"geoip_path"`   // path to GeoLite2-City.mmdb (optional, defaults to "GeoLite2-City.mmdb")
	WebUI       WebUIConfig `json:"web_ui"`       // optional embedded WebUI dashboard

	// STUN/TURN servers for NAT traversal. When a boot server is behind NAT,
	// these allow it to discover its public IP via STUN and allocate relay
	// ports via TURN so mesh peers can always reach it.
	// See pkg/config.DefaultConfig for the full server list.
	StunServers []string `json:"stun_servers,omitempty"`
	TurnServers []string `json:"turn_servers,omitempty"`

	// HolePunchTimeout bounds the direct dial the puncher makes after it has
	// exchanged hole-punch addresses with a peer. It must match the mesh node's
	// value, which defaults to 15s: the boot answers the punch, so a boot that
	// dials with a shorter timeout gives up before the peer behind symmetric NAT
	// finishes bringing its socket up. JSON serializes it as nanoseconds.
	HolePunchTimeout time.Duration `json:"hole_punch_timeout"`

	// PeerAddrFile is the sidecar JSON file holding the public source addresses
	// this boot observed from directly-connected peers, with the times they
	// were seen. It is deliberately separate from boot.json: it grows with the
	// peer population and is rewritten on every save, which would churn a file
	// the operator edits by hand.
	PeerAddrFile string `json:"peer_addr_file"`
	// EnablePeerAddrCache turns address observation on. When false the boot
	// behaves exactly as before — it just stops remembering peer addresses
	// across a disconnect or a restart.
	EnablePeerAddrCache bool `json:"enable_peer_addr_cache"`
	// PeerAddrRebroadcastWindow bounds how old a record may be when the boot
	// replays it after a restart. NAT mappings rarely survive a day, so replaying
	// everything would flood the mesh with unreachable endpoints; the on-disk
	// copy is still retained forever for operators.
	PeerAddrRebroadcastWindow time.Duration `json:"peer_addr_rebroadcast_window"`
}

// DefaultBootConfig returns the configuration used on first run / when fields
// are omitted from the JSON file.
func DefaultBootConfig() *BootConfig {
	return &BootConfig{
		ListenAddrs: []string{
			"/ip4/0.0.0.0/udp/4001/quic-v1",
			"/ip6/::/udp/4001/quic-v1",
			"/ip4/0.0.0.0/udp/4002/webrtc-direct",
			"/ip6/::/udp/4002/webrtc-direct",
			// WebTransport is QUIC-over-HTTP/3, so /quic-v1/ is mandatory. Without
			// it multiaddr still parses — the parser does not check transport
			// layering — but webtransport.Transport.Listen rejects the address
			// and swarm_listen only warns per address, so the listener silently
			// never comes up and libp2p.New returns success anyway.
			"/ip4/0.0.0.0/udp/4003/quic-v1/webtransport",
			"/ip6/::/udp/4003/quic-v1/webtransport",
			"/ip4/0.0.0.0/tcp/4001",
			"/ip6/::/tcp/4001",
		},
		KeyFile:   "boot.key",
		PSKs:      []string{},
		NodeName:  "Bootstrap-Relay",
		MeshPeers: []string{},
		LogLevel:  "info",
		GeoIPPath: "GeoLite2-City.mmdb",
		WebUI: WebUIConfig{
			Enable:    true,
			Listen:    "0.0.0.0:8080",
			AuthToken: "",
		},
		// Boot relays usually sit on stable infrastructure, so STUN needs only a
		// handful of fallbacks. Still kept: a relay behind NAT cannot serve as a
		// relay unless it can discover its own public address.
		StunServers: []string{
			"/udp/turn.cloudflare.com/3478",
			"/udp/stun.cloudflare.com/3478",
			"/udp/stun.l.google.com/19302",
			"/udp/stun1.l.google.com/19302",
			"/tcp/turn.cloudflare.com/80",
			"/tcp/stun.cloudflare.com/3478",
		},
		// Empty on purpose. TURN requires authentication, so anonymous entries
		// can never allocate a relay port and only burn an allocation cycle.
		// Fill this in with a real URL carrying ?username=...&credential=....
		TurnServers:      []string{},
		HolePunchTimeout: 15 * time.Second,

		PeerAddrFile:              DefaultPeerAddrFile,
		EnablePeerAddrCache:       true,
		PeerAddrRebroadcastWindow: DefaultPeerAddrRebroadcastWindow,
	}
}

// LoadBootConfig reads path, or — if it does not exist — writes DefaultBootConfig
// to path and returns that default. A malformed file is a hard error so the
// operator is not silently running an unintended configuration.
func LoadBootConfig(path string) (*BootConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		def := DefaultBootConfig()
		if werr := SaveBootConfig(path, def); werr == nil {
			fmt.Printf("[+] Created default boot config: %s (edit it, then restart)\n", path)
			return def, nil
		} else {
			return nil, fmt.Errorf("read %s: %w (also failed to write default: %v)", path, err, werr)
		}
	}
	cfg := DefaultBootConfig()
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	// BootConfig has no transports field, so a "transports" block in this file is
	// silently dropped — and it is easy to write one, because the mesh node's
	// config.json carries the same key and this binary now listens on every
	// protocol the mesh node can. Copying a setting across the two files would
	// look like it took effect while the boot keeps listening on all four.
	var probe struct {
		Transports json.RawMessage `json:"transports"`
	}
	if err := json.Unmarshal(data, &probe); err == nil && probe.Transports != nil {
		fmt.Printf("Warning: ignoring \"transports\" in %s — the boot server has no transport switches, so QUIC, WebRTC, WebTransport and TCP always listen. That key belongs in the mesh node's config.json.\n", path)
	}
	// Same guard as the mesh node's config: JSON encodes time.Duration as
	// nanoseconds, so an operator who meant "15 seconds" writes 15 and gets 15
	// nanoseconds — a punch that gives up before the socket is even open.
	if cfg.HolePunchTimeout < 100*time.Millisecond || cfg.HolePunchTimeout > 120*time.Second {
		cfg.HolePunchTimeout = 15 * time.Second
	}
	// The rebroadcast window must stay in the same ballpark. Too small and a
	// restart loses records that were recorded minutes ago; too large and a
	// restart replays mappings that have been dead for months.
	if cfg.PeerAddrRebroadcastWindow < 1*time.Hour || cfg.PeerAddrRebroadcastWindow > 365*24*time.Hour {
		cfg.PeerAddrRebroadcastWindow = DefaultPeerAddrRebroadcastWindow
	}
	// An empty name would silently fall back to "." and write the store next to
	// whatever the current directory happened to be.
	if cfg.PeerAddrFile == "" {
		cfg.PeerAddrFile = DefaultPeerAddrFile
	}
	// Trim and drop empty / whitespace-only PSK entries. Without this an
	// operator who writes `"psks": [""]` or leaves a trailing comma is not
	// asked for a PSK and does not realise the boot is running open relay
	// mode with zero networks configured. The empty-string case is worse
	// than "no PSKs at all": relayRes.pskEnabled flips to true, ACL
	// enforcement engages, and every subsequent PSK auth silently fails
	// against the zero-byte network key — the boot refuses every client
	// with no signal in the config that anything is misconfigured.
	if len(cfg.PSKs) > 0 {
		kept := cfg.PSKs[:0]
		for i, raw := range cfg.PSKs {
			trimmed := strings.TrimSpace(raw)
			if trimmed == raw {
				kept = append(kept, raw)
				continue
			}
			if trimmed == "" {
				fmt.Printf("Warning: dropping empty psks[%d] from %s\n", i, path)
				continue
			}
			fmt.Printf("Warning: trimming whitespace from psks[%d] in %s\n", i, path)
			kept = append(kept, trimmed)
		}
		cfg.PSKs = kept
	}
	// Require each retained PSK to have real entropy, matching the mesh node's
	// validatePSK policy. Anything below 8 bytes (16 hex chars) is guessable
	// with a single laptop; anything above 64 bytes is almost certainly a
	// key file pasted into the wrong field, and the PSK is fed to every
	// per-peer key derivation on connect, so a huge value is a self-inflicted
	// performance trap rather than extra security.
	for i, psk := range cfg.PSKs {
		if err := validateBootSecret("psks["+strconv.Itoa(i)+"]", psk, 16, 128); err != nil {
			return nil, err
		}
	}
	// web_ui.auth_token has the same trust model as a PSK on this machine:
	// anyone who knows the token can read every peer's identity, name, TAP IP,
	// geo location and version from /api/stats and /api/logs. An empty string
	// is fine (the boot generates a random one at startup), but a non-empty
	// token must have real entropy — "changeme" or a hardcoded short string
	// defeats the whole point of putting an auth token on a public listener.
	if tok := strings.TrimSpace(cfg.WebUI.AuthToken); tok != "" {
		if err := validateBootSecret("web_ui.auth_token", tok, 16, 256); err != nil {
			return nil, err
		}
		if tok != cfg.WebUI.AuthToken {
			cfg.WebUI.AuthToken = tok
		}
	}
	return cfg, nil
}

// validateBootSecret enforces a length window and a two-character-class
// requirement on a secret read from boot.json. It mirrors the semantics of
// validateSecretEntropy in pkg/config but lives here because the mesh-node
// version is unexported and the boot binary is a separate deployment artifact
// that must stay self-contained.
//
// The character-class check is what stops "changeme" and "abcdefgh12345678"
// from passing — a single-class secret of the right length is still trivially
// guessable.
func validateBootSecret(field, secret string, minLen, maxLen int) error {
	if len(secret) < minLen {
		return fmt.Errorf("invalid config: %s: %d characters is below the %d-character minimum for adequate entropy", field, len(secret), minLen)
	}
	if len(secret) > maxLen {
		return fmt.Errorf("invalid config: %s: %d characters exceeds the %d-character maximum", field, len(secret), maxLen)
	}
	classes := 0
	for _, ch := range secret {
		switch {
		case ch >= 'a' && ch <= 'z':
			classes |= 0x1
		case ch >= 'A' && ch <= 'Z':
			classes |= 0x2
		case ch >= '0' && ch <= '9':
			classes |= 0x4
		default:
			classes |= 0x8
		}
	}
	n := 0
	for x := classes; x > 0; x &= x - 1 {
		n++
	}
	if n < 2 {
		return fmt.Errorf("invalid config: %s: secret uses only one character class (lowercase/uppercase/digit/symbol); include at least two for adequate entropy", field)
	}
	return nil
}

// SaveBootConfig writes the config as pretty-printed JSON (0600).
func SaveBootConfig(path string, cfg *BootConfig) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}
