package main

import (
	"encoding/json"
	"fmt"
	"os"
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
			"/ip4/0.0.0.0/udp/4003/webtransport",
			"/ip6/::/udp/4003/webtransport",
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
		// STUN/TURN defaults — a curated subset of the client's list.
		// Boot servers need fewer fallbacks since they are typically
		// deployed on stable infrastructure, but STUN is essential
		// for discovering the public IP behind NAT.
		StunServers: []string{
			"/udp/turn.cloudflare.com/3478",
			"/udp/stun.cloudflare.com/3478",
			"/udp/stun.l.google.com/19302",
			"/udp/stun1.l.google.com/19302",
			"/udp/stun2.l.google.com/19302",
			"/tcp/turn.cloudflare.com/80",
			"/tcp/stun.cloudflare.com/3478",
		},
		TurnServers: []string{
			"turn:turn.cloud-rtc.com:80",
			"turn:w1.xirsys.com:3478",
			"turn:u1.xirsys.com:3478",
			"turn:relay1.expressturn.com:3478",
			"turn:global.turn.twilio.com:3478",
		},
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
