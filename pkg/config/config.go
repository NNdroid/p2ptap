package config

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"
)

// WebUIConfig defines Web Dashboard options
type WebUIConfig struct {
	Enable     bool   `json:"enable"`
	ListenIP   string `json:"listen_ip"`
	ListenIPv6 string `json:"listen_ipv6"`
	Port       int    `json:"port"`
	// AuthToken is the bearer token required for every /api/* request.
	// When empty at startup, p2ptap generates a random token and prints it
	// to the log. Set this to a fixed value to use a known password.
	AuthToken string `json:"auth_token"`
	// PcapSampleEvery captures 1 of every N frames (1 = capture all). Lets an
	// operator bound the per-frame parse/memcopy cost of the live packet view
	// on a busy link. Higher = lower CPU but coarser capture.
	PcapSampleEvery int `json:"pcap_sample_every"`
	// PcapMaxRatePerSec caps captured frames per second (0 = unlimited). A
	// secondary safety net on top of PcapSampleEvery for extreme throughput.
	PcapMaxRatePerSec int `json:"pcap_max_rate_per_sec"`
}

// MaxNodeNameLen is the upper bound for a NodeName accepted by the WebUI.
const MaxNodeNameLen = 64

// validNodeNameChars restricts NodeName to a safe subset so it can never be
// used to inject HTML/JS into the dashboard (prevents stored XSS).
func validNodeName(name string) bool {
	if name == "" {
		return true
	}
	if len(name) > MaxNodeNameLen {
		return false
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '-' || r == '_' || r == '.' || r == ' ' || r == '@':
		default:
			return false
		}
	}
	return true
}

// TransportsConfig defines transport layer protocol options
type TransportsConfig struct {
	EnableQUICReuse    bool   `json:"enable_quic_reuse"`
	EnableWebRTC       bool   `json:"enable_webrtc"`
	EnableWebTransport bool   `json:"enable_webtransport"`
	EnableTCPReuse     bool   `json:"enable_tcp_reuse"`
	EnableTCPBrutal    bool   `json:"enable_tcp_brutal"`
	TCPBrutalRate      string `json:"tcp_brutal_rate"`
	// DisableRelay turns OFF libp2p circuit-relay client/service, AutoRelay
	// and DCUtR hole-punching. Use as a diagnostic: if a peer that was reachable
	// (but slow, e.g. hundreds of ms) becomes UNREACHABLE with this on, it was
	// being auto-relayed through a static relay peer. Does NOT affect p2ptap's
	// own overlay relay (OverlayRelayProtocolID) — that path is still visible
	// in the WebUI routes table.
	DisableRelay bool `json:"disable_relay"`
	// TLSServerName sets the TLS server_name (SNI) placed on OUTGOING handshakes —
	// both TLS-over-TCP (the default security module) and QUIC. Empty (default)
	// sends no server_name, matching upstream libp2p. Set it to a plausible
	// hostname to make the mesh resemble ordinary HTTP/3 to a DPI that inspects
	// the (public-salt-encrypted QUIC Initial / cleartext TCP) ClientHello. It
	// never affects authentication: libp2p verifies peers via the signed
	// certificate extension, not the SNI.
	TLSServerName string `json:"tls_server_name"`
	// TLSSNISuffix enables a per-peer derived SNI: the outgoing server_name
	// becomes "<label(remote PeerID)>.<suffix>" instead of the static
	// TLSServerName. The label is a lowercase, DNS-safe short hash of the peer
	// we are dialing, so every mesh link presents a distinct, stable SNI while
	// all still resolving under one operator-controlled base domain — avoiding
	// the "every p2ptap node sends the identical SNI" global-correlation tell.
	// Takes precedence over TLSServerName when non-empty. Requires restart.
	// NOTE: a high-entropy random subdomain under a single base is itself a
	// known tunnel/exfil shape; prefer a domain you actually own, and weigh
	// against the static TLSServerName option.
	TLSSNISuffix string `json:"tls_sni_suffix"`
}

// ExitNodeConfig defines options for node acting as an Exit Node gateway
type ExitNodeConfig struct {
	Enable        bool   `json:"enable"`         // Enable Exit Node functionality
	NATMasquerade bool   `json:"nat_masquerade"` // Enable SNAT/Masquerade NAT rules
	WANInterface  string `json:"wan_interface"`  // Physical egress interface name (e.g. "eth0" or "auto")
}

// ObfuscationConfig defines traffic obfuscation & padding options
type ObfuscationConfig struct {
	Enable      bool   `json:"enable"`
	Mode        string `json:"mode"`         // "fixed","block","random","dynamic","auto"
	FixedSize   int    `json:"fixed_size"`   // target total frame size (fixed/dynamic max)
	BlockSize   int    `json:"block_size"`   // block alignment granularity
	JitterRange int    `json:"jitter_range"` // ±N byte random jitter on fixed/block modes (0=off)
	MinSize     int    `json:"min_size"`     // minimum frame size for dynamic mode
	MaxSize     int    `json:"max_size"`     // maximum frame size for dynamic mode

	// Auto-detection
	AutoDetectInterval int  `json:"auto_detect_interval"` // seconds between re-evaluations (default 30)
	AutoThresholdBytes int  `json:"auto_threshold_bytes"` // bytes before evaluating switch
	AllowModeSwitch    bool `json:"allow_mode_switch"`    // allow engine to auto-switch mode

	// MaxFragSize caps the per-fragment inner size (bytes) used by the tunnel's
	// TAP-frame fragmentation layer. When 0, the node auto-derives a safe value
	// from the tunnel MTU and obfuscation overhead so each fragment fits under
	// the QUIC path MTU without IP fragmentation. Range: 256..1400.
	MaxFragSize int `json:"max_frag_size"`

	// Algorithm selects the payload encryption algorithm for the obfuscation
	// layer. "auto" (default) lets the SeqSync handshake negotiate a common
	// algorithm with each peer (preference: chacha20, aes-gcm, none). Other
	// accepted values: "none", "aes-gcm", "chacha20". The actual key is derived
	// per-peer via an ECDH(P256) handshake — never shared statically.
	Algorithm string `json:"algorithm"`

	// StrictKeyNegotiation (default false) enforces forward secrecy and per-peer
	// key isolation. During a SeqSync handshake each peer pair derives its own
	// cipher from a one-shot ECDH(P256) ephemeral key (PFS, unique per pair).
	// If no ephemeral key is available (e.g. a forced re-sync where the
	// pending handshake key was already consumed), the engine normally falls
	// back to the long-lived node key — which still yields a per-pair ECDH key
	// but loses PFS and reuses one static identity key across all peers. When
	// this flag is true, that fallback is forbidden: if a fresh ephemeral key
	// cannot be used, the peer pair is left at plaintext obfuscation rather
	// than degrading to the shared long-lived node key. Enable for maximum
	// key isolation; disable (default) for smoother interop with re-syncs.
	StrictKeyNegotiation bool `json:"strict_key_negotiation"`
}

// ACLRule defines a single access control rule for P2P mesh traffic (ZeroTier-style)
type ACLRule struct {
	RuleID    string `json:"rule_id"`   // Unique rule ID (e.g. "rule-1")
	Action    string `json:"action"`    // "accept" or "drop" (or "allow"/"deny")
	Direction string `json:"direction"` // "both", "inbound", "outbound"
	PeerID    string `json:"peer_id"`   // target Peer ID or "*" for all
	IPCIDR    string `json:"ip_cidr"`   // target IP CIDR or "*" for all
	Protocol  string `json:"protocol"`  // "any", "tcp", "udp", "icmp"
	Port      string `json:"port"`      // "0" (all), "80", or range "8000-9000"
	Comment   string `json:"comment"`   // human-readable description
}

// ACLConfig defines P2P mesh firewall rule options
type ACLConfig struct {
	Enable        bool      `json:"enable"`         // Default: false (mesh fully open)
	DefaultAction string    `json:"default_action"` // "allow" or "deny"
	Rules         []ACLRule `json:"rules"`
}

// Config represents the complete P2P TAP VPN configuration
type Config struct {
	LogLevel       string   `json:"log_level"` // "debug", "info", "warn", "error"
	ListenAddrs    []string `json:"listen_addrs"`
	BootstrapPeers []string `json:"bootstrap_peers"`
	StaticPeers    []string `json:"static_peers"`
	// DiscoverBootMesh lets this node attach to boot nodes it discovers through
	// a federated boot backbone (boots interconnected with p2ptap-boot -mesh),
	// in addition to the ones listed in BootstrapPeers. Attaching gives the two
	// clusters a shared relay anchor, which is what makes peers in the remote
	// cluster reachable — Circuit Relay v2 requires both ends on the same boot.
	// Disable it to keep this node pinned to its configured boots only.
	DiscoverBootMesh        bool              `json:"discover_boot_mesh"`
	EnableMDNS              bool              `json:"enable_mdns"`
	WebUI                   WebUIConfig       `json:"web_ui"`
	Transports              TransportsConfig  `json:"transports"`
	TransportStrategy       string            `json:"transport_strategy"` // "best_path", "redundant", "fallback"
	NodeName                string            `json:"node_name"`          // e.g. "my-node" or empty for os.Hostname()
	TapName                 string            `json:"tap_name"`
	TapIP                   string            `json:"tap_ip"`        // e.g. "10.0.0.1/24"
	TapIPv6                 string            `json:"tap_ipv6"`      // e.g. "fd00::1/64"
	TapMAC                  string            `json:"tap_mac"`       // e.g. "02:00:00:00:00:01"
	MTU                     int               `json:"mtu"`           // e.g. 1500 (default 1500)
	DriverType              string            `json:"driver_type"`   // "auto", "tap", or "wintun" (Windows only, default "auto")
	NodeKeyFile             string            `json:"node_key_file"` // e.g. "node.key"
	PSK                     string            `json:"psk"`
	Obfuscation             ObfuscationConfig `json:"obfuscation"`
	ExitNode                ExitNodeConfig    `json:"exit_node"`
	AdvertisedSubnets       []string          `json:"advertised_subnets"`        // e.g. ["192.168.1.0/24"]
	AcceptAdvertisedSubnets bool              `json:"accept_advertised_subnets"` // Default: false
	AllowedSubnetPeers      []string          `json:"allowed_subnet_peers"`      // Allowed Peer IDs or ["*"]
	ACL                     ACLConfig         `json:"acl"`
	ConfigPath              string            `json:"-"` // Path to config file (not persisted)
	HolePunchTimeout        time.Duration     `json:"hole_punch_timeout"`
	// ForcePrivateReachability forces the libp2p host to advertise itself as
	// private (relay-only). Default false: reachability is auto-detected via
	// AutoNAT, so nodes with a public IP still advertise direct addresses and
	// peers can dial them directly instead of always going through a relay.
	// Enable only when AutoNAT is known to be unreliable in your network.
	ForcePrivateReachability bool `json:"force_private_reachability"`
	// StunServers is a list of STUN server multiaddrs for WebRTC ICE candidate
	// gathering. Format: "/udp/stun.l.google.com/19302" or "stun:stun.l.google.com:19302".
	// Empty means no STUN servers (ICE relies on host/server-reflexive candidates only).
	// Adding reachable STUN servers significantly improves hole-punching success rate
	// for WebRTC connections by providing server-reflexive candidates.
	StunServers []string `json:"stun_servers"`
	// TurnServers is a list of TURN server URLs for NAT traversal fallback.
	// Format: "turn:host:port" (anonymous) or "turn:host:port?username=...&credential=..."
	// (authenticated). Empty means no TURN relay allocation.
	TurnServers []string `json:"turn_servers"`
	// RelayUpgradeInterval controls how often relay-only peers are retried for a
	// direct connection upgrade. Default: 30s. Shorter intervals improve direct
	// connection recovery speed but increase background dial activity.
	RelayUpgradeInterval time.Duration `json:"relay_upgrade_interval"`
}

// DefaultConfig returns a sane default configuration
func DefaultConfig() *Config {
	hostName, err := os.Hostname()
	if err != nil || hostName == "" {
		hostName = "p2ptap-node"
	}
	// Sanitize any characters outside allowed set and clamp to MaxNodeNameLen
	var sb strings.Builder
	for _, r := range hostName {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' || r == ' ' || r == '@':
			sb.WriteRune(r)
		default:
			sb.WriteRune('-')
		}
	}
	hostName = sb.String()
	if hostName == "" {
		hostName = "p2ptap-node"
	}
	if len(hostName) > MaxNodeNameLen {
		hostName = hostName[:MaxNodeNameLen]
	}

	return &Config{
		HolePunchTimeout: 15 * time.Second,
		ListenAddrs: []string{
			"/ip4/0.0.0.0/udp/0/quic-v1",
			"/ip6/::/udp/0/quic-v1",
			"/ip4/0.0.0.0/udp/0/webrtc-direct",
			"/ip6/::/udp/0/webrtc-direct",
			"/ip4/0.0.0.0/udp/0/quic-v1/webtransport",
			"/ip6/::/udp/0/quic-v1/webtransport",
			"/ip4/0.0.0.0/tcp/0",
			"/ip6/::/tcp/0",
		},
		BootstrapPeers: []string{
			"/dnsaddr/bootstrap.libp2p.io/p2p/QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN",
			"/dnsaddr/bootstrap.libp2p.io/p2p/QmQCU2EcMqAqQPR2i9bChDtGNJchTbq5TbXJJ16u19uLTa",
			"/dnsaddr/bootstrap.libp2p.io/p2p/QmbLHAnMoJPWSCR5Zhtx6BHJX9KiKNN6tpvbUcqanj75Nb",
			"/dnsaddr/bootstrap.libp2p.io/p2p/QmcZf59bWwK5XFi76CZX8cbJ4BhTzzA3gU1ZjYZcYW3dwt",
			"/dnsaddr/bootstrap.libp2p.io/p2p/QmaCpDMGvV2BGHeYERUEnRQAwe3N8SzbUtfsmvsqQLuvuJ",
		},
		StaticPeers: []string{},
		// On by default: a node that is told about a federated boot cannot reach
		// the remote cluster's peers unless it attaches to that boot.
		DiscoverBootMesh: true,
		EnableMDNS:       true,
		WebUI: WebUIConfig{
			Enable:     true,
			ListenIP:   "0.0.0.0",
			ListenIPv6: "::",
			Port:       80,
			PcapSampleEvery: 1,
		},
		Transports: TransportsConfig{
			EnableQUICReuse:    true,
			EnableWebRTC:       true,
			EnableWebTransport: true,
			EnableTCPReuse:     true,
			EnableTCPBrutal:    false,
			TCPBrutalRate:      "100Mbps",
			DisableRelay:       false,
		},
		TransportStrategy: "best_path",
		NodeName:          hostName,
		TapName:           "p2ptap0",
		TapIP:             "10.0.0.1/24",
		TapIPv6:           "fd00::1/64",
		TapMAC:            GenerateRandomMAC(),
		MTU:               1500,
		DriverType:        "auto", // TAP first, Wintun fallback on Windows
		NodeKeyFile:       "node.key",
		PSK:               "",
		StunServers: []string{
			// ── UDP STUN servers ──
			"/udp/turn.cloudflare.com/3478",
			"/udp/stun.cloudflare.com/3478",
			"/udp/stun.l.google.com/19302",
			"/udp/stun1.l.google.com/19302",
			"/udp/stun2.l.google.com/19302",
			"/udp/stun3.l.google.com/19302",
			"/udp/stun4.l.google.com/19302",
			"/udp/fwa.lifesizecloud.com/3478",
			"/udp/stun.isp.net.au/3478",
			"/udp/stun.freeswitch.org/3478",
			"/udp/stun.voip.blackberry.com/3478",
			"/udp/stun.nextcloud.com/3478",
			"/udp/stun.sipnet.com/3478",
			"/udp/stun.radiojar.com/3478",
			"/udp/stun.sonetel.com/3478",
			"/udp/stun.voipgate.com/3478",
			"/udp/stun.miwifi.com/3478",
			"/udp/stun.chat.bilibili.com/3478",
			"/udp/stun.douyucdn.cn/18000",
			"/udp/stun.hitv.com/3478",
			"/udp/stun.cdnbye.com/3478",
			"/udp/stun.relay.metered.ca/80",
			"/udp/stun.hivestreaming.com/3478",
			// ── Amazon Kinesis STUN servers (UDP) ──
			"/udp/stun.kinesisvideo.us-east-2.amazonaws.com/443",
			"/udp/stun.kinesisvideo.us-east-1.amazonaws.com/443",
			"/udp/stun.kinesisvideo.us-west-2.amazonaws.com/443",
			"/udp/stun.kinesisvideo.af-south-1.amazonaws.com/443",
			"/udp/stun.kinesisvideo.ap-east-1.amazonaws.com/443",
			"/udp/stun.kinesisvideo.ap-south-1.amazonaws.com/443",
			"/udp/stun.kinesisvideo.ap-northeast-2.amazonaws.com/443",
			"/udp/stun.kinesisvideo.ap-southeast-1.amazonaws.com/443",
			"/udp/stun.kinesisvideo.ap-southeast-2.amazonaws.com/443",
			"/udp/stun.kinesisvideo.ap-northeast-1.amazonaws.com/443",
			"/udp/stun.kinesisvideo.ca-central-1.amazonaws.com/443",
			"/udp/stun.kinesisvideo.eu-central-1.amazonaws.com/443",
			"/udp/stun.kinesisvideo.eu-west-1.amazonaws.com/443",
			"/udp/stun.kinesisvideo.eu-west-2.amazonaws.com/443",
			"/udp/stun.kinesisvideo.eu-west-3.amazonaws.com/443",
			"/udp/stun.kinesisvideo.sa-east-1.amazonaws.com/443",
			// ── TCP STUN servers (RFC 7675) ──
			"/tcp/turn.cloudflare.com/80",
			"/tcp/stun.cloudflare.com/3478",
			"/tcp/stun.l.google.com/3478",
			"/tcp/stun1.l.google.com/3478",
			"/tcp/fwa.lifesizecloud.com/3478",
			"/tcp/stun.isp.net.au/3478",
			"/tcp/stun.freeswitch.org/3478",
			"/tcp/stun.voip.blackberry.com/3478",
			"/tcp/stun.nextcloud.com/3478",
			"/tcp/stun.sipnet.com/3478",
			"/tcp/stun.radiojar.com/3478",
			"/tcp/stun.sonetel.com/3478",
			"/tcp/stun.voipgate.com/3478",
			"/tcp/stun.miwifi.com/3478",
			"/tcp/stun.chat.bilibili.com/3478",
			"/tcp/turn.cloud-rtc.com/80",
			"/tcp/w1.xirsys.com/3478",
			"/tcp/u1.xirsys.com/3478",
			"/tcp/relay1.expressturn.com/3478",
			"/tcp/relay2.expressturn.com/3478",
			"/tcp/relay3.expressturn.com/3478",
			"/tcp/relay4.expressturn.com/3478",
			"/tcp/relay5.expressturn.com/3478",
			"/tcp/relay6.expressturn.com/3478",
			"/tcp/relay7.expressturn.com/3478",
			"/tcp/relay8.expressturn.com/3478",
			"/tcp/global.turn.twilio.com/3478",
			"/tcp/stun.relay.metered.ca/80",
			// ── Amazon Kinesis STUN servers (TCP) ──
			"/tcp/stun.kinesisvideo.us-east-2.amazonaws.com/443",
			"/tcp/stun.kinesisvideo.us-east-1.amazonaws.com/443",
			"/tcp/stun.kinesisvideo.us-west-2.amazonaws.com/443",
			"/tcp/stun.kinesisvideo.af-south-1.amazonaws.com/443",
			"/tcp/stun.kinesisvideo.ap-east-1.amazonaws.com/443",
			"/tcp/stun.kinesisvideo.ap-south-1.amazonaws.com/443",
			"/tcp/stun.kinesisvideo.ap-northeast-2.amazonaws.com/443",
			"/tcp/stun.kinesisvideo.ap-southeast-1.amazonaws.com/443",
			"/tcp/stun.kinesisvideo.ap-southeast-2.amazonaws.com/443",
			"/tcp/stun.kinesisvideo.ap-northeast-1.amazonaws.com/443",
			"/tcp/stun.kinesisvideo.ca-central-1.amazonaws.com/443",
			"/tcp/stun.kinesisvideo.eu-central-1.amazonaws.com/443",
			"/tcp/stun.kinesisvideo.eu-west-1.amazonaws.com/443",
			"/tcp/stun.kinesisvideo.eu-west-2.amazonaws.com/443",
			"/tcp/stun.kinesisvideo.eu-west-3.amazonaws.com/443",
			"/tcp/stun.kinesisvideo.sa-east-1.amazonaws.com/443",
		},
		TurnServers: []string{
			"turn:turn.cloud-rtc.com:80",
			"turn:w1.xirsys.com:3478",
			"turn:u1.xirsys.com:3478",
			"turn:relay1.expressturn.com:3478",
			"turn:relay2.expressturn.com:3478",
			"turn:relay3.expressturn.com:3478",
			"turn:relay4.expressturn.com:3478",
			"turn:relay5.expressturn.com:3478",
			"turn:relay6.expressturn.com:3478",
			"turn:relay7.expressturn.com:3478",
			"turn:relay8.expressturn.com:3478",
			"turn:global.turn.twilio.com:3478",
		},
		RelayUpgradeInterval: 30 * time.Second,
		Obfuscation: ObfuscationConfig{
			Enable:               true,
			Mode:                 "random",
			FixedSize:            1500,
			BlockSize:            256,
			JitterRange:          64,
			MinSize:              512,
			MaxSize:              1500,
			AutoDetectInterval:   30,
			AutoThresholdBytes:   65536,
			AllowModeSwitch:      false,
			MaxFragSize:          0,
			Algorithm:            "auto",
			StrictKeyNegotiation: false,
		},
		ExitNode: ExitNodeConfig{
			Enable:        false,
			NATMasquerade: true,
			WANInterface:  "auto",
		},
		AdvertisedSubnets:       []string{},
		AcceptAdvertisedSubnets: false,
		AllowedSubnetPeers:      []string{},
		ACL: ACLConfig{
			Enable:        false,
			DefaultAction: "allow",
			Rules:         []ACLRule{},
		},
	}
}

// LoadConfigFromFile reads JSON config from path
func LoadConfigFromFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %s: %w", path, err)
	}

	cfg := DefaultConfig()
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse JSON config %s: %w", path, err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config %s: %w", path, err)
	}

	cfg.ConfigPath = path

	// Repair permissions on configs persisted by older builds, which wrote
	// 0644 unconditionally even when they carried a PSK.
	tightenExistingPerm(path, cfg)

	return cfg, nil
}

func GenerateRandomMAC() string {
	buf := make([]byte, 6)
	_, _ = rand.Read(buf)
	buf[0] = (buf[0] | 0x02) & 0xfe // Locally administered unicast MAC
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", buf[0], buf[1], buf[2], buf[3], buf[4], buf[5])
}

// Validate checks the configuration for correctness. Error messages follow
// the "invalid config: <field_name>: <details>" pattern so the Android UI can
// extract the offending field name via regex and show a localized hint.
func (c *Config) Validate() error {
	// --- Identity / naming ---
	if c.NodeName != "" && !validNodeName(c.NodeName) {
		return fmt.Errorf("invalid config: node_name: '%s' is invalid (max %d chars, allowed: a-z A-Z 0-9 - _ . @ space)", c.NodeName, MaxNodeNameLen)
	}
	if c.TapName != "" {
		if len(c.TapName) > 16 {
			return fmt.Errorf("invalid config: tap_name: too long (max 16 chars), got %d", len(c.TapName))
		}
		if strings.ContainsAny(c.TapName, " \t\n") {
			return fmt.Errorf("invalid config: tap_name: must not contain spaces in '%s'", c.TapName)
		}
	}

	// --- TAP address (host addresses are expected, e.g. 10.0.0.1/24) ---
	if c.TapIP != "" {
		if err := validateCIDR("tap_ip", c.TapIP, false, false); err != nil {
			return err
		}
	}
	if c.TapIPv6 != "" {
		if err := validateCIDR("tap_ipv6", c.TapIPv6, true, false); err != nil {
			return err
		}
	}
	if c.TapMAC == "" || c.TapMAC == "auto" {
		c.TapMAC = GenerateRandomMAC()
	} else {
		mac, err := net.ParseMAC(c.TapMAC)
		if err != nil || len(mac) != 6 {
			return fmt.Errorf("invalid config: tap_mac: '%s' must be a 6-octet MAC address", c.TapMAC)
		}
	}

	// --- Listen addresses ---
	for i, addr := range c.ListenAddrs {
		if addr == "" {
			continue
		}
		if _, err := ma.NewMultiaddr(addr); err != nil {
			return fmt.Errorf("invalid config: listen_addrs[%d]: '%s' is not a valid multiaddr", i, addr)
		}
	}

	// --- Peers ---
	staticPeers, err := normalizePeerAddresses("static_peers", c.StaticPeers)
	if err != nil {
		return wrapPeerErr("static_peers", err)
	}
	bootstrapPeers, err := normalizePeerAddresses("bootstrap_peers", c.BootstrapPeers)
	if err != nil {
		return wrapPeerErr("bootstrap_peers", err)
	}
	c.StaticPeers, c.BootstrapPeers = staticPeers, bootstrapPeers

	// --- Allowed subnet peers ---
	for i, p := range c.AllowedSubnetPeers {
		if p == "*" {
			continue
		}
		if _, err := peer.Decode(p); err != nil {
			return fmt.Errorf("invalid config: allowed_subnet_peers[%d]: '%s' is not a valid peer ID (use a peer ID or '*')", i, p)
		}
	}

	// --- Advertised subnets (must be network addresses, no host bits) ---
	for i, sub := range c.AdvertisedSubnets {
		if sub == "" {
			continue
		}
		if err := validateCIDR("advertised_subnets", sub, false, true); err != nil {
			return fmt.Errorf("invalid config: advertised_subnets[%d]: %v", i, err)
		}
	}

	// --- Transport strategy ---
	if c.TransportStrategy != "best_path" && c.TransportStrategy != "redundant" && c.TransportStrategy != "fallback" {
		return fmt.Errorf("invalid config: transport_strategy: '%s' must be 'best_path', 'redundant', or 'fallback'", c.TransportStrategy)
	}

	// --- Log level ---
	if err := validateLogLevel("log_level", c.LogLevel); err != nil {
		return err
	}

	// --- Node key file ---
	if c.NodeKeyFile != "" && strings.ContainsAny(c.NodeKeyFile, "\x00") {
		return fmt.Errorf("invalid config: node_key_file: must not contain null bytes")
	}

	// --- MTU ---
	if c.MTU <= 0 || c.MTU > 9000 {
		c.MTU = 1500
	}

	// --- Driver type ---
	if c.DriverType == "" {
		c.DriverType = "auto"
	}
	if c.DriverType != "auto" && c.DriverType != "tap" && c.DriverType != "wintun" {
		return fmt.Errorf("invalid config: driver_type: '%s' must be 'auto', 'tap', or 'wintun'", c.DriverType)
	}

	// --- Transports ---
	if err := validateRate("transports.tcp_brutal_rate", c.Transports.TCPBrutalRate); err != nil {
		return err
	}
	if c.Transports.TLSServerName != "" {
		if err := validateDNSName("transports.tls_server_name", c.Transports.TLSServerName); err != nil {
			return err
		}
	}
	if c.Transports.TLSSNISuffix != "" {
		if err := validateDNSName("transports.tls_sni_suffix", c.Transports.TLSSNISuffix); err != nil {
			return err
		}
	}

	// --- WebUI ---
	if c.WebUI.Port < 1 || c.WebUI.Port > 65535 {
		return fmt.Errorf("invalid config: web_ui.port: %d must be between 1 and 65535", c.WebUI.Port)
	}
	if c.WebUI.ListenIP != "" {
		if net.ParseIP(c.WebUI.ListenIP) == nil {
			return fmt.Errorf("invalid config: web_ui.listen_ip: '%s' is not a valid IP address", c.WebUI.ListenIP)
		}
	}
	if c.WebUI.ListenIPv6 != "" {
		if net.ParseIP(c.WebUI.ListenIPv6) == nil {
			return fmt.Errorf("invalid config: web_ui.listen_ipv6: '%s' is not a valid IP address", c.WebUI.ListenIPv6)
		}
	}
	if c.WebUI.PcapSampleEvery < 1 {
		return fmt.Errorf("invalid config: web_ui.pcap_sample_every: %d must be >= 1", c.WebUI.PcapSampleEvery)
	}
	if c.WebUI.PcapMaxRatePerSec < 0 {
		return fmt.Errorf("invalid config: web_ui.pcap_max_rate_per_sec: %d must be >= 0", c.WebUI.PcapMaxRatePerSec)
	}

	// --- Exit node ---
	if c.ExitNode.WANInterface != "" && c.ExitNode.WANInterface != "auto" {
		if err := validateInterfaceName("exit_node.wan_interface", c.ExitNode.WANInterface); err != nil {
			return err
		}
	}

	// --- Obfuscation ---
	validModes := map[string]bool{"fixed": true, "block": true, "random": true, "dynamic": true, "auto": true}
	if c.Obfuscation.Mode != "" && !validModes[c.Obfuscation.Mode] {
		return fmt.Errorf("invalid config: obfuscation.mode: '%s' must be fixed/block/random/dynamic/auto", c.Obfuscation.Mode)
	}
	if c.Obfuscation.Mode == "fixed" && c.Obfuscation.FixedSize <= 0 {
		return fmt.Errorf("invalid config: obfuscation.fixed_size: must be > 0 when mode is 'fixed', got %d", c.Obfuscation.FixedSize)
	}
	if c.Obfuscation.Mode == "block" && c.Obfuscation.BlockSize <= 0 {
		return fmt.Errorf("invalid config: obfuscation.block_size: must be > 0 when mode is 'block', got %d", c.Obfuscation.BlockSize)
	}
	if c.Obfuscation.JitterRange < 0 {
		return fmt.Errorf("invalid config: obfuscation.jitter_range: %d must be >= 0", c.Obfuscation.JitterRange)
	}
	if c.Obfuscation.MinSize > 0 && c.Obfuscation.MaxSize > 0 && c.Obfuscation.MinSize > c.Obfuscation.MaxSize {
		return fmt.Errorf("invalid config: obfuscation.min_size: %d must be <= max_size %d", c.Obfuscation.MinSize, c.Obfuscation.MaxSize)
	}
	if c.Obfuscation.MaxFragSize < 0 {
		return fmt.Errorf("invalid config: obfuscation.max_frag_size: %d must be >= 0 (0 = auto)", c.Obfuscation.MaxFragSize)
	}
	if c.Obfuscation.MaxFragSize > 1400 {
		return fmt.Errorf("invalid config: obfuscation.max_frag_size: %d must be <= 1400", c.Obfuscation.MaxFragSize)
	}
	if c.Obfuscation.MaxFragSize > 0 && c.Obfuscation.MaxFragSize < 256 {
		return fmt.Errorf("invalid config: obfuscation.max_frag_size: %d must be >= 256 or 0 (auto)", c.Obfuscation.MaxFragSize)
	}
	switch c.Obfuscation.Algorithm {
	case "", "auto", "none", "aes-gcm", "chacha20":
	default:
		return fmt.Errorf("invalid config: obfuscation.algorithm: '%s' must be one of: auto, none, aes-gcm, chacha20", c.Obfuscation.Algorithm)
	}
	if c.Obfuscation.AutoDetectInterval <= 0 {
		c.Obfuscation.AutoDetectInterval = 30
	}
	if c.Obfuscation.AutoThresholdBytes <= 0 {
		c.Obfuscation.AutoThresholdBytes = 65536
	}
	if c.Obfuscation.AutoDetectInterval > 3600 {
		return fmt.Errorf("invalid config: obfuscation.auto_detect_interval: %d must be 1-3600 (seconds)", c.Obfuscation.AutoDetectInterval)
	}
	if c.Obfuscation.AutoThresholdBytes > 1048576 {
		return fmt.Errorf("invalid config: obfuscation.auto_threshold_bytes: %d must be 1-1048576 (bytes)", c.Obfuscation.AutoThresholdBytes)
	}

	// --- ACL ---
	if c.ACL.Enable {
		if c.ACL.DefaultAction != "accept" && c.ACL.DefaultAction != "allow" && c.ACL.DefaultAction != "drop" && c.ACL.DefaultAction != "deny" {
			return fmt.Errorf("invalid config: acl.default_action: '%s' must be 'accept'/'allow' or 'drop'/'deny'", c.ACL.DefaultAction)
		}
		for i, r := range c.ACL.Rules {
			act := strings.ToLower(r.Action)
			if act != "accept" && act != "allow" && act != "drop" && act != "deny" {
				return fmt.Errorf("invalid config: acl.rules[%d].action: '%s' must be 'accept'/'allow' or 'drop'/'deny'", i, r.Action)
			}
			proto := strings.ToLower(r.Protocol)
			if proto != "" && proto != "any" && proto != "tcp" && proto != "udp" && proto != "icmp" {
				return fmt.Errorf("invalid config: acl.rules[%d].protocol: '%s' must be 'tcp', 'udp', 'icmp', or 'any'", i, r.Protocol)
			}
			dir := strings.ToLower(r.Direction)
			if dir != "" && dir != "both" && dir != "inbound" && dir != "outbound" {
				return fmt.Errorf("invalid config: acl.rules[%d].direction: '%s' must be 'both', 'inbound', or 'outbound'", i, r.Direction)
			}
			if r.IPCIDR != "" && r.IPCIDR != "*" {
				if _, _, err := net.ParseCIDR(r.IPCIDR); err != nil {
					return fmt.Errorf("invalid config: acl.rules[%d].ip_cidr: '%s' is not a valid CIDR", i, r.IPCIDR)
				}
			}
			if r.PeerID != "" && r.PeerID != "*" {
				if _, err := peer.Decode(r.PeerID); err != nil {
					return fmt.Errorf("invalid config: acl.rules[%d].peer_id: '%s' is not a valid peer ID (use a peer ID or '*')", i, r.PeerID)
				}
			}
			if err := validatePortSpec(fmt.Sprintf("acl.rules[%d].port", i), r.Port); err != nil {
				return err
			}
		}
	}

	// --- Durations ---
	// JSON serializes time.Duration as nanoseconds; accept only values
	// >= 100ms to reject accidental "15" (nanoseconds) from operators
	// who meant "15 seconds".
	if c.HolePunchTimeout < 100*time.Millisecond || c.HolePunchTimeout > 120*time.Second {
		c.HolePunchTimeout = 15 * time.Second
	}
	if c.RelayUpgradeInterval <= 0 {
		c.RelayUpgradeInterval = 30 * time.Second
	}

	// --- STUN servers ---
	for i, srv := range c.StunServers {
		if err := validateSTUNServer(fmt.Sprintf("stun_servers[%d]", i), srv); err != nil {
			return err
		}
	}

	// --- TURN servers ---
	for i, srv := range c.TurnServers {
		if err := validateTURNServer(fmt.Sprintf("turn_servers[%d]", i), srv); err != nil {
			return err
		}
	}

	return nil
}

// --- Validation helpers ---

// validateCIDR checks that s is a valid CIDR and optionally that it matches
// the expected IP family. When rejectHostBits is true, host bits being set
// are rejected (e.g. "192.168.1.5/24" is invalid for a subnet advertisement
// but is perfectly valid as a TAP host address).
func validateCIDR(field, s string, wantIPv6 bool, rejectHostBits bool) error {
	ip, ipnet, err := net.ParseCIDR(s)
	if err != nil {
		return fmt.Errorf("invalid config: %s: '%s' is not a valid CIDR (%v)", field, s, err)
	}
	if wantIPv6 {
		if ip.To4() != nil {
			return fmt.Errorf("invalid config: %s: '%s' is an IPv4 CIDR, expected IPv6", field, s)
		}
	} else {
		if ip.To4() == nil {
			return fmt.Errorf("invalid config: %s: '%s' is an IPv6 CIDR, expected IPv4", field, s)
		}
	}
	if rejectHostBits {
		ones, bits := ipnet.Mask.Size()
		if bits == 32 && ones == 32 {
			return fmt.Errorf("invalid config: %s: '%s' is a host address (/32), use a network CIDR like /24", field, s)
		}
		if bits == 128 && ones == 128 {
			return fmt.Errorf("invalid config: %s: '%s' is a host address (/128), use a network CIDR like /64", field, s)
		}
		// Reject host bits being set (e.g. 192.168.1.5/24 has host bits)
		if ip.Mask(ipnet.Mask).String() != ip.String() {
			return fmt.Errorf("invalid config: %s: '%s' has host bits set, use the network address (e.g. '%s')", field, s, ipnet.IP.String())
		}
	}
	return nil
}

func validateSTUNServer(field, server string) error {
	s := strings.TrimSpace(server)
	if s == "" {
		return fmt.Errorf("invalid config: %s: empty server address", field)
	}
	// Strip transport prefix: /udp/, /tcp/, stun:, turn:, tcp:
	if strings.HasPrefix(s, "/udp/") {
		s = strings.TrimPrefix(s, "/udp/")
	} else if strings.HasPrefix(s, "/tcp/") {
		s = strings.TrimPrefix(s, "/tcp/")
	} else if strings.HasPrefix(s, "stun:") {
		s = strings.TrimPrefix(s, "stun:")
	} else if strings.HasPrefix(s, "turn:") {
		s = strings.TrimPrefix(s, "turn:")
	} else if strings.HasPrefix(s, "tcp:") {
		s = strings.TrimPrefix(s, "tcp:")
	}
	// Parse host:port
	if idx := strings.LastIndex(s, ":"); idx >= 0 {
		host := s[:idx]
		portStr := s[idx+1:]
		if host == "" {
			return fmt.Errorf("invalid config: %s: empty host in '%s'", field, server)
		}
		p, err := strconv.Atoi(portStr)
		if err != nil || p < 1 || p > 65535 {
			return fmt.Errorf("invalid config: %s: invalid port in '%s' (must be 1-65535)", field, server)
		}
		return nil
	}
	// No port — accept bare host (defaults to 3478)
	if s == "" {
		return fmt.Errorf("invalid config: %s: empty host in '%s'", field, server)
	}
	return nil
}

func validateTURNServer(field, server string) error {
	s := strings.TrimSpace(server)
	if s == "" {
		return fmt.Errorf("invalid config: %s: empty server address", field)
	}
	if !strings.HasPrefix(s, "turn:") {
		return fmt.Errorf("invalid config: %s: '%s' must start with 'turn:'", field, server)
	}
	// Remove turn: prefix and query string for validation
	s = strings.TrimPrefix(s, "turn:")
	if idx := strings.Index(s, "?"); idx >= 0 {
		s = s[:idx]
	}
	// Parse host:port
	if idx := strings.LastIndex(s, ":"); idx >= 0 {
		host := s[:idx]
		portStr := s[idx+1:]
		if host == "" {
			return fmt.Errorf("invalid config: %s: empty host in '%s'", field, server)
		}
		p, err := strconv.Atoi(portStr)
		if err != nil || p < 1 || p > 65535 {
			return fmt.Errorf("invalid config: %s: invalid port in '%s' (must be 1-65535)", field, server)
		}
		return nil
	}
	// No port — accept bare host (defaults to 3478)
	if s == "" {
		return fmt.Errorf("invalid config: %s: empty host in '%s'", field, server)
	}
	return nil
}

func validateInterfaceName(field, name string) error {
	if name == "" {
		return fmt.Errorf("invalid config: %s: empty interface name", field)
	}
	if len(name) > 16 {
		return fmt.Errorf("invalid config: %s: too long (max 16 chars), got %d", field, len(name))
	}
	for _, c := range name {
		if !unicode.IsLetter(c) && !unicode.IsDigit(c) && c != '-' && c != '_' && c != '.' {
			return fmt.Errorf("invalid config: %s: invalid character '%c' in '%s'", field, c, name)
		}
	}
	return nil
}

func validateRate(field, rate string) error {
	if rate == "" {
		return nil // empty = disabled
	}
	for _, suffix := range []string{"Mbps", "Gbps", "Kbps", "bps"} {
		if strings.HasSuffix(rate, suffix) {
			numStr := strings.TrimSuffix(rate, suffix)
			if numStr == "" {
				return fmt.Errorf("invalid config: %s: missing value before '%s'", field, rate)
			}
			v, err := strconv.ParseFloat(numStr, 64)
			if err != nil || v <= 0 {
				return fmt.Errorf("invalid config: %s: '%s' must be a positive number like '100Mbps'", field, rate)
			}
			return nil
		}
	}
	return fmt.Errorf("invalid config: %s: must end with 'Mbps', 'Gbps', 'Kbps', or 'bps', got '%s'", field, rate)
}

func validateDNSName(field, name string) error {
	if name == "" {
		return nil
	}
	if len(name) > 253 {
		return fmt.Errorf("invalid config: %s: too long (max 253 chars)", field)
	}
	parts := strings.Split(name, ".")
	for _, part := range parts {
		if part == "" {
			return fmt.Errorf("invalid config: %s: empty label in '%s'", field, name)
		}
		if len(part) > 63 {
			return fmt.Errorf("invalid config: %s: label too long (max 63 chars) in '%s'", field, name)
		}
		// Must start and end with alphanumeric
		for _, i := range []int{0, len(part) - 1} {
			if !unicode.IsLetter(rune(part[i])) && !unicode.IsDigit(rune(part[i])) {
				return fmt.Errorf("invalid config: %s: label must start and end with alphanumeric in '%s'", field, name)
			}
		}
	}
	return nil
}

func validateLogLevel(field, level string) error {
	switch level {
	case "", "debug", "info", "warn", "error":
		return nil
	default:
		return fmt.Errorf("invalid config: %s: '%s' must be 'debug', 'info', 'warn', or 'error'", field, level)
	}
}

// validatePortSpec validates an ACL port field: "0" (all), "80", or "8000-9000".
func validatePortSpec(field, spec string) error {
	if spec == "" || spec == "0" {
		return nil
	}
	if strings.Contains(spec, "-") {
		parts := strings.SplitN(spec, "-", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return fmt.Errorf("invalid config: %s: invalid range format '%s' (use 'LOW-HIGH')", field, spec)
		}
		low, err1 := strconv.Atoi(parts[0])
		high, err2 := strconv.Atoi(parts[1])
		if err1 != nil || err2 != nil || low < 0 || low > 65535 || high < 0 || high > 65535 {
			return fmt.Errorf("invalid config: %s: invalid range '%s' (ports must be 0-65535)", field, spec)
		}
		if low > high {
			return fmt.Errorf("invalid config: %s: low bound %d > high bound %d in '%s'", field, low, high, spec)
		}
		return nil
	}
	p, err := strconv.Atoi(spec)
	if err != nil || p < 0 || p > 65535 {
		return fmt.Errorf("invalid config: %s: '%s' must be a port number 0-65535", field, spec)
	}
	return nil
}

// wrapPeerErr converts normalizePeerAddresses errors to the standard format.
func wrapPeerErr(field string, err error) error {
	return fmt.Errorf("invalid config: %s: %v", field, err)
}

// configFilePerm picks the on-disk permission for a config file: configs that
// carry a secret are written owner-only, everything else stays group/other
// readable so an operator can inspect a node's settings without sudo.
//
// This matters more than it looks. The PSK is simultaneously the libp2p
// private-network membership key and the HKDF salt that every per-peer session
// key derives from, so any local user able to read config.json can join the
// mesh and derive traffic keys. A pinned web_ui.auth_token is the same class of
// secret — it is a bearer credential for the entire HTTP control plane.
func configFilePerm(cfg *Config) os.FileMode {
	if cfg != nil && (cfg.PSK != "" || cfg.WebUI.AuthToken != "") {
		return 0600
	}
	return 0644
}

// tightenExistingPerm repairs configs written before writes were
// secret-aware. Best-effort by design: a read-only filesystem, or a file owned
// by another user, must never stop the node from starting — we only try to
// remove group/other access when we already own it.
func tightenExistingPerm(path string, cfg *Config) {
	want := configFilePerm(cfg)
	if want != 0600 {
		return
	}
	fi, err := os.Stat(path)
	if err != nil || fi.Mode().Perm()&0o077 == 0 {
		return
	}
	if err := os.Chmod(path, want); err != nil {
		return
	}
	fmt.Fprintf(os.Stderr,
		"[config] %s holds secrets (psk/auth_token) — tightened permissions %o -> %o\n",
		path, fi.Mode().Perm(), want)
}

// ParseFlagsAndLoadConfig parses -c CLI flag and loads config file
func ParseFlagsAndLoadConfig(args []string) (*Config, string, error) {
	fs := flag.NewFlagSet("p2ptap", flag.ContinueOnError)
	configPath := fs.String("c", "config.json", "Path to config file")

	if err := fs.Parse(args); err != nil {
		return nil, "", err
	}

	cfg, err := LoadConfigFromFile(*configPath)
	if err != nil {
		// If default config.json does not exist, write default config to it
		if errors.Is(err, os.ErrNotExist) && *configPath == "config.json" {
			defCfg := DefaultConfig()
			data, mErr := json.MarshalIndent(defCfg, "", "  ")
			if mErr != nil {
				return nil, *configPath, fmt.Errorf("failed to marshal default config: %w", mErr)
			}
			if wErr := os.WriteFile("config.json", data, configFilePerm(defCfg)); wErr != nil {
				return nil, *configPath, fmt.Errorf("failed to write default config.json: %w", wErr)
			}
			return defCfg, *configPath, nil
		}
		return nil, *configPath, err
	}

	return cfg, *configPath, nil
}

// UpdateConfigFileDelta incrementally updates specific modified fields in the JSON config file on disk
func UpdateConfigFileDelta(configPath string, incoming *Config) error {
	if configPath == "" {
		return nil
	}

	var rawMap map[string]interface{}
	data, err := os.ReadFile(configPath)
	if err == nil && len(data) > 0 {
		if err := json.Unmarshal(data, &rawMap); err != nil {
			// Corrupt config: do NOT silently drop the whole file. If we
			// replaced rawMap with an empty map, the unlisted fields below
			// (stun_servers, turn_servers, hole_punch_timeout, etc.) would
			// be lost — they are only preserved from the parsed rawMap.
			return fmt.Errorf("config %s: JSON parse failed: %w", configPath, err)
		}
	}
	if rawMap == nil {
		rawMap = make(map[string]interface{})
	}

	// Update only modified mutable fields
	rawMap["node_name"] = incoming.NodeName
	rawMap["transport_strategy"] = incoming.TransportStrategy
	rawMap["psk"] = incoming.PSK
	rawMap["log_level"] = incoming.LogLevel
	rawMap["bootstrap_peers"] = incoming.BootstrapPeers
	rawMap["static_peers"] = incoming.StaticPeers
	rawMap["enable_mdns"] = incoming.EnableMDNS

	// Immutable-at-runtime fields (require restart) — persist to disk for next startup
	rawMap["tap_name"] = incoming.TapName
	rawMap["tap_ip"] = incoming.TapIP
	rawMap["tap_ipv6"] = incoming.TapIPv6
	rawMap["tap_mac"] = incoming.TapMAC
	rawMap["mtu"] = incoming.MTU
	rawMap["node_key_file"] = incoming.NodeKeyFile
	rawMap["listen_addrs"] = incoming.ListenAddrs
	rawMap["transports"] = incoming.Transports
	rawMap["web_ui"] = incoming.WebUI
	rawMap["driver_type"] = incoming.DriverType

	// Obfuscation delta — persist all obfuscation fields
	obfsMap, ok := rawMap["obfuscation"].(map[string]interface{})
	if !ok {
		obfsMap = make(map[string]interface{})
	}
	obfsMap["enable"] = incoming.Obfuscation.Enable
	obfsMap["mode"] = incoming.Obfuscation.Mode
	obfsMap["fixed_size"] = incoming.Obfuscation.FixedSize
	obfsMap["block_size"] = incoming.Obfuscation.BlockSize
	obfsMap["jitter_range"] = incoming.Obfuscation.JitterRange
	obfsMap["min_size"] = incoming.Obfuscation.MinSize
	obfsMap["max_size"] = incoming.Obfuscation.MaxSize
	obfsMap["auto_detect_interval"] = incoming.Obfuscation.AutoDetectInterval
	obfsMap["auto_threshold_bytes"] = incoming.Obfuscation.AutoThresholdBytes
	obfsMap["allow_mode_switch"] = incoming.Obfuscation.AllowModeSwitch
	obfsMap["max_frag_size"] = incoming.Obfuscation.MaxFragSize
	obfsMap["algorithm"] = incoming.Obfuscation.Algorithm
	obfsMap["strict_key_negotiation"] = incoming.Obfuscation.StrictKeyNegotiation
	rawMap["obfuscation"] = obfsMap

	// ExitNode delta
	exitMap, ok := rawMap["exit_node"].(map[string]interface{})
	if !ok {
		exitMap = make(map[string]interface{})
	}
	exitMap["enable"] = incoming.ExitNode.Enable
	exitMap["nat_masquerade"] = incoming.ExitNode.NATMasquerade
	exitMap["wan_interface"] = incoming.ExitNode.WANInterface
	rawMap["exit_node"] = exitMap

	// Subnet Router & ACL delta
	rawMap["advertised_subnets"] = incoming.AdvertisedSubnets
	rawMap["accept_advertised_subnets"] = incoming.AcceptAdvertisedSubnets
	rawMap["allowed_subnet_peers"] = incoming.AllowedSubnetPeers

	aclMap, ok := rawMap["acl"].(map[string]interface{})
	if !ok {
		aclMap = make(map[string]interface{})
	}
	aclMap["enable"] = incoming.ACL.Enable
	aclMap["default_action"] = incoming.ACL.DefaultAction
	aclMap["rules"] = incoming.ACL.Rules
	rawMap["acl"] = aclMap

	updatedBytes, err := json.MarshalIndent(rawMap, "", "  ")
	if err != nil {
		return err
	}

	// Atomic write: marshal to a temp file in the same directory then rename
	// over the target. A crash or full disk mid-write would otherwise leave
	// config.json truncated/corrupt, bricking the node's next startup.
	return atomicWriteFile(configPath, updatedBytes, configFilePerm(incoming))
}

// atomicWriteFile writes data to path atomically: it writes to a uniquely-named
// temp file in the same directory (so the rename stays on one filesystem and is
// atomic), fsyncs it, then renames it over the target. On any failure the temp
// file is removed and the original target is left untouched. Config file
// persistence is exactly the kind of state that must not be torn by a crash.
func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		if tmpName != "" {
			_ = os.Remove(tmpName) // no-op after a successful rename
		}
	}()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, perm); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	tmpName = "" // rename succeeded — don't remove the temp path (it no longer exists)
	return nil
}

// WebUITokenFile is the sidecar file (next to config.json) where the running
// daemon persists the WebUI auth token. A local control client (e.g. the system
// tray) reads it so it can authenticate to /api/* without the operator pasting
// the token by hand. It lives next to the config so it follows the config around
// and is only readable by the same user that owns the config.
const WebUITokenFile = ".p2ptap_webui_token"

// PersistWebUIToken writes the resolved WebUI auth token to a sidecar file in
// the same directory as configPath. The token is a loopback-only bearer
// credential, so a 0600 file readable by the local user is an acceptable store.
func PersistWebUIToken(configPath, token string) error {
	if configPath == "" || token == "" {
		return nil
	}
	sidecar := filepath.Join(filepath.Dir(configPath), WebUITokenFile)
	return atomicWriteFile(sidecar, []byte(token), 0600)
}

// LoadWebUIToken reads the WebUI auth token a local control client should use.
// It prefers the sidecar file written by the running daemon; falls back to the
// token embedded in the config file (if any). Returns "" when unavailable.
func LoadWebUIToken(configPath string) string {
	if configPath == "" {
		return ""
	}
	sidecar := filepath.Join(filepath.Dir(configPath), WebUITokenFile)
	if data, err := os.ReadFile(sidecar); err == nil {
		return strings.TrimSpace(string(data))
	}
	return ""
}
