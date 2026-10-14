package main

import (
	"encoding/json"
	"fmt"
	"os"
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
	// Same guard as the mesh node's config: JSON encodes time.Duration as
	// nanoseconds, so an operator who meant "15 seconds" writes 15 and gets 15
	// nanoseconds — a punch that gives up before the socket is even open.
	if cfg.HolePunchTimeout < 100*time.Millisecond || cfg.HolePunchTimeout > 120*time.Second {
		cfg.HolePunchTimeout = 15 * time.Second
	}
	return cfg, nil
}

// SaveBootConfig writes the config as pretty-printed JSON (0600).
func SaveBootConfig(path string, cfg *BootConfig) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}
