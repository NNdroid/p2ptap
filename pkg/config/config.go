package config

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
)

// WebUIConfig defines Web Dashboard options
type WebUIConfig struct {
	Enable     bool   `json:"enable"`
	ListenIP   string `json:"listen_ip"`
	ListenIPv6 string `json:"listen_ipv6"`
	Port       int    `json:"port"`
}

// TransportsConfig defines transport layer protocol options
type TransportsConfig struct {
	EnableQUICReuse    bool   `json:"enable_quic_reuse"`
	EnableWebRTC       bool   `json:"enable_webrtc"`
	EnableWebTransport bool   `json:"enable_webtransport"`
	EnableTCPReuse     bool   `json:"enable_tcp_reuse"`
	EnableTCPBrutal    bool   `json:"enable_tcp_brutal"`
	TCPBrutalRate      string `json:"tcp_brutal_rate"`
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
	Mode        string `json:"mode"`        // "fixed","block","random","dynamic","auto"
	FixedSize   int    `json:"fixed_size"`  // target total frame size (fixed/dynamic max)
	BlockSize   int    `json:"block_size"`  // block alignment granularity
	JitterRange int    `json:"jitter_range"` // ±N byte random jitter on fixed/block modes (0=off)
	MinSize     int    `json:"min_size"`     // minimum frame size for dynamic mode
	MaxSize     int    `json:"max_size"`     // maximum frame size for dynamic mode

	// Auto-detection
	AutoDetectInterval int  `json:"auto_detect_interval"` // seconds between re-evaluations (default 30)
	AutoThresholdBytes int  `json:"auto_threshold_bytes"` // bytes before evaluating switch
	AllowModeSwitch    bool `json:"allow_mode_switch"`    // allow engine to auto-switch mode

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
	LogLevel          string            `json:"log_level"` // "debug", "info", "warn", "error"
	ListenAddrs       []string          `json:"listen_addrs"`
	BootstrapPeers    []string          `json:"bootstrap_peers"`
	StaticPeers       []string          `json:"static_peers"`
	EnableMDNS        bool              `json:"enable_mdns"`
	WebUI             WebUIConfig       `json:"web_ui"`
	Transports        TransportsConfig  `json:"transports"`
	TransportStrategy string            `json:"transport_strategy"` // "best_path", "redundant", "fallback"
	NodeName          string            `json:"node_name"`          // e.g. "my-node" or empty for os.Hostname()
	TapName           string            `json:"tap_name"`
	TapIP             string            `json:"tap_ip"`        // e.g. "10.0.0.1/24"
	TapIPv6           string            `json:"tap_ipv6"`      // e.g. "fd00::1/64"
	TapMAC            string            `json:"tap_mac"`       // e.g. "02:00:00:00:00:01"
	MTU               int               `json:"mtu"`           // e.g. 1500 (default 1500)
	DriverType        string            `json:"driver_type"`   // "auto", "tap", or "wintun" (Windows only, default "auto")
	NodeKeyFile       string            `json:"node_key_file"` // e.g. "node.key"
	PSK                     string            `json:"psk"`
	Obfuscation             ObfuscationConfig `json:"obfuscation"`
	ExitNode                ExitNodeConfig    `json:"exit_node"`
	AdvertisedSubnets       []string          `json:"advertised_subnets"`        // e.g. ["192.168.1.0/24"]
	AcceptAdvertisedSubnets bool              `json:"accept_advertised_subnets"` // Default: false
	AllowedSubnetPeers      []string          `json:"allowed_subnet_peers"`      // Allowed Peer IDs or ["*"]
	ACL                     ACLConfig         `json:"acl"`
	ConfigPath              string            `json:"-"`
}

// DefaultConfig returns a sane default configuration
func DefaultConfig() *Config {
	hostName, err := os.Hostname()
	if err != nil || hostName == "" {
		hostName = "p2ptap-node"
	}

	return &Config{
		LogLevel: "info",
		ListenAddrs: []string{
			"/ip4/0.0.0.0/udp/0/quic-v1",
			"/ip6/::/udp/0/quic-v1",
			"/ip4/0.0.0.0/udp/0/webrtc-direct",
			"/ip6/::/udp/0/webrtc-direct",
			"/ip4/0.0.0.0/udp/0/webtransport",
			"/ip6/::/udp/0/webtransport",
			"/ip4/0.0.0.0/tcp/0",
			"/ip6/::/tcp/0",
		},
		BootstrapPeers: []string{
			"/dnsaddr/bootstrap.libp2p.io/p2p/QmNnooDu7bfjPFoTmoXMY5PeBKyy1EicV2g7HQ1b18423b",
		},
		StaticPeers: []string{},
		EnableMDNS:  true,
		WebUI: WebUIConfig{
			Enable:     true,
			ListenIP:   "0.0.0.0",
			ListenIPv6: "::",
			Port:       80,
		},
		Transports: TransportsConfig{
			EnableQUICReuse:    true,
			EnableWebRTC:       true,
			EnableWebTransport: true,
			EnableTCPReuse:     true,
			EnableTCPBrutal:    false,
			TCPBrutalRate:      "100Mbps",
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
		Obfuscation: ObfuscationConfig{
			Enable:             true,
			Mode:               "random",
			FixedSize:          1500,
			BlockSize:          256,
			JitterRange:        64,
			MinSize:            512,
			MaxSize:            1500,
			AutoDetectInterval: 30,
			AutoThresholdBytes: 65536,
		AllowModeSwitch:    false,
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
	return cfg, nil
}

func GenerateRandomMAC() string {
	buf := make([]byte, 6)
	_, _ = rand.Read(buf)
	buf[0] = (buf[0] | 0x02) & 0xfe // Locally administered unicast MAC
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", buf[0], buf[1], buf[2], buf[3], buf[4], buf[5])
}

func GenerateMACFromIP(ipStr string) string {
	if ipStr == "" {
		return GenerateRandomMAC()
	}
	ipStrClean := strings.Split(ipStr, "/")[0]
	ip := net.ParseIP(ipStrClean)
	if ip != nil && len(ip.To4()) == 4 {
		ip4 := ip.To4()
		return fmt.Sprintf("02:00:%02x:%02x:%02x:%02x", ip4[0], ip4[1], ip4[2], ip4[3])
	}
	return GenerateRandomMAC()
}

// Validate checks the configuration for correctness
func (c *Config) Validate() error {
	if c.TapMAC == "" || c.TapMAC == "auto" {
		c.TapMAC = GenerateRandomMAC()
	}

	if c.TapIP != "" {
		_, _, err := net.ParseCIDR(c.TapIP)
		if err != nil {
			return fmt.Errorf("invalid tap_ip CIDR format '%s': %w", c.TapIP, err)
		}
	}
	if c.TapIPv6 != "" {
		_, _, err := net.ParseCIDR(c.TapIPv6)
		if err != nil {
			return fmt.Errorf("invalid tap_ipv6 CIDR format '%s': %w", c.TapIPv6, err)
		}
	}
	if c.TapMAC != "" {
		mac, err := net.ParseMAC(c.TapMAC)
		if err != nil || len(mac) != 6 {
			return fmt.Errorf("invalid tap_mac '%s' (must be a 6-octet MAC address)", c.TapMAC)
		}
	}
	if c.TransportStrategy != "best_path" && c.TransportStrategy != "redundant" && c.TransportStrategy != "fallback" {
		return fmt.Errorf("unsupported transport_strategy '%s' (must be 'best_path', 'redundant', or 'fallback')", c.TransportStrategy)
	}
	validModes := map[string]bool{"fixed": true, "block": true, "random": true, "dynamic": true, "auto": true}
	if c.Obfuscation.Mode != "" && !validModes[c.Obfuscation.Mode] {
		return fmt.Errorf("unsupported obfuscation mode '%s' (must be fixed/block/random/dynamic/auto)", c.Obfuscation.Mode)
	}
	if c.Obfuscation.Mode == "fixed" && c.Obfuscation.FixedSize <= 0 {
		return errors.New("fixed_size must be > 0 when obfuscation mode is 'fixed'")
	}
	if c.Obfuscation.Mode == "block" && c.Obfuscation.BlockSize <= 0 {
		return errors.New("block_size must be > 0 when obfuscation mode is 'block'")
	}
	if c.Obfuscation.JitterRange < 0 {
		return errors.New("jitter_range must be >= 0")
	}
	if c.Obfuscation.MinSize > 0 && c.Obfuscation.MaxSize > 0 && c.Obfuscation.MinSize > c.Obfuscation.MaxSize {
		return errors.New("min_size must be <= max_size")
	}
	if c.MTU <= 0 {
		c.MTU = 1500
	}
	if c.DriverType == "" {
		c.DriverType = "auto"
	}
	if c.DriverType != "auto" && c.DriverType != "tap" && c.DriverType != "wintun" {
		return fmt.Errorf("invalid driver_type '%s' (must be 'auto', 'tap', or 'wintun')", c.DriverType)
	}
	for _, sub := range c.AdvertisedSubnets {
		if sub != "" {
			if _, _, err := net.ParseCIDR(sub); err != nil {
				return fmt.Errorf("invalid advertised_subnet CIDR format '%s': %w", sub, err)
			}
		}
	}
	if c.ACL.Enable {
		if c.ACL.DefaultAction != "accept" && c.ACL.DefaultAction != "allow" && c.ACL.DefaultAction != "drop" && c.ACL.DefaultAction != "deny" {
			return fmt.Errorf("invalid acl default_action '%s' (must be 'accept'/'allow' or 'drop'/'deny')", c.ACL.DefaultAction)
		}
		for i, r := range c.ACL.Rules {
			act := strings.ToLower(r.Action)
			if act != "accept" && act != "allow" && act != "drop" && act != "deny" {
				return fmt.Errorf("invalid acl rule[%d] action '%s' (must be 'accept'/'allow' or 'drop'/'deny')", i, r.Action)
			}
			proto := strings.ToLower(r.Protocol)
			if proto != "" && proto != "any" && proto != "tcp" && proto != "udp" && proto != "icmp" {
				return fmt.Errorf("invalid acl rule[%d] protocol '%s' (must be 'tcp', 'udp', 'icmp', or 'any')", i, r.Protocol)
			}
			dir := strings.ToLower(r.Direction)
			if dir != "" && dir != "both" && dir != "inbound" && dir != "outbound" {
				return fmt.Errorf("invalid acl rule[%d] direction '%s' (must be 'both', 'inbound', or 'outbound')", i, r.Direction)
			}
			if r.IPCIDR != "" && r.IPCIDR != "*" {
				if _, _, err := net.ParseCIDR(r.IPCIDR); err != nil {
					return fmt.Errorf("invalid acl rule[%d] ip_cidr '%s': %w", i, r.IPCIDR, err)
				}
			}
		}
	}
	return nil
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
			data, _ := json.MarshalIndent(defCfg, "", "  ")
			_ = os.WriteFile("config.json", data, 0644)
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
		_ = json.Unmarshal(data, &rawMap)
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

	return os.WriteFile(configPath, updatedBytes, 0644)
}
