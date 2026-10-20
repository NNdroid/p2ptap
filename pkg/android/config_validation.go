package P2PTap

import (
	"encoding/json"
	"fmt"
	"reflect"

	"p2ptap/pkg/config"
)

func parseConfig(cfgJSON string) (*config.Config, error) {
	cfg := config.DefaultConfig()
	if cfgJSON != "" {
		if err := json.Unmarshal([]byte(cfgJSON), cfg); err != nil {
			return nil, fmt.Errorf("android: invalid config JSON: %w", err)
		}
	}
	if err := cfg.Validate(); err != nil {
		// Config.Validate already prefixes its message with "invalid config:", so
		// adding the same words here produced "invalid config: invalid config:".
		return nil, fmt.Errorf("android: %w", err)
	}
	if cfg.ExitNode.Enable {
		return nil, fmt.Errorf("android: exit node server is not supported on this build")
	}
	return cfg, nil
}

// ValidateConfig checks the same candidate as Start, without consuming a TUN
// descriptor, stopping the running node, or modifying its configuration.
func ValidateConfig(cfgJSON string) error {
	_, err := parseConfig(cfgJSON)
	return err
}

// NormalizePeerAddress validates an address for a static/bootstrap list.
func NormalizePeerAddress(address string) (string, error) {
	return config.NormalizePeerAddress(address)
}

// Plan verdicts returned by PlanReload.
const (
	PlanVerdictNoop    = "noop"    // nothing changed
	PlanVerdictReload  = "reload"  // apply without tearing the node down
	PlanVerdictRestart = "restart" // rebuild required
)

// PlanReload reports whether replacing oldJSON with newJSON needs the node
// rebuilt from scratch, or can be applied onto the running process.
//
// The field list lives in config.RestartRequiredFields and nowhere else: Android
// used to keep its own copy of that list in Kotlin, and the two drifted (it
// demanded a restart for ACL and advertised-subnet changes that the engine
// demonstrably hot-reloads, via the OnSubnetsChanged callback). Exporting the
// verdict instead of the list means a new engine-side restart-required field
// reaches every client automatically.
//
// It deliberately returns only a verdict, not the field names: a stale or
// malformed caller should not have to understand the engine's field taxonomy to
// decide what to do with a VPN.
func PlanReload(oldJSON, newJSON string) string {
	if newJSON == "" {
		return PlanVerdictNoop
	}
	if oldJSON == "" {
		// Nothing known to be running. The caller cannot hot-reload onto a config
		// it has not told us about, so it must start the node from newJSON.
		return PlanVerdictRestart
	}
	new, err := parseConfig(newJSON)
	if new == nil || err != nil {
		// Cannot tell. Reporting "reload" for a candidate we could not parse would
		// be the dangerous half of this bug class — a change that looks applied and
		// is not. "restart" surfaces the same validation error at Start, which
		// validates the same JSON through parseConfig.
		return PlanVerdictRestart
	}
	old, err := parseConfig(oldJSON)
	if old == nil || err != nil {
		// The running config is unknown or unreadable; treat it as a cold start.
		return PlanVerdictRestart
	}
	if len(config.RestartRequiredFields(old, new)) > 0 {
		return PlanVerdictRestart
	}
	if reflect.DeepEqual(old, new) {
		return PlanVerdictNoop
	}
	return PlanVerdictReload
}

// mergeHotReload preserves every running-config field the caller did not
// actually send, so a partial config cannot silently downgrade the running one.
// Three rules, one per kind of zero value:
//
//   - strings/durations where zero is never a valid setting: preserved when the
//     key is absent OR when it was sent empty (an empty node_name falls back to
//     the hostname, MTU 0 is invalid — neither is a real request to clear).
//   - slices where an empty list IS a valid setting: preserved only when absent,
//     so "advertised_subnets": [] still clears.
//   - bools, which have no zero value at all: preserved only when absent. This
//     replaces the old bool exemption — a reload that omits enable_mdns used to
//     take DefaultConfig's value instead of the running one.
//
// sent is the set of keys actually present in the incoming JSON.
func mergeHotReload(dst *config.Config, src *config.Config, sent map[string]bool) {
	if !sent["node_name"] || dst.NodeName == "" {
		dst.NodeName = src.NodeName
	}
	if !sent["tap_ip"] || dst.TapIP == "" {
		dst.TapIP = src.TapIP
	}
	if !sent["tap_ipv6"] || dst.TapIPv6 == "" {
		dst.TapIPv6 = src.TapIPv6
	}
	if !sent["tap_mac"] || dst.TapMAC == "" {
		dst.TapMAC = src.TapMAC
	}
	if !sent["mtu"] || dst.MTU == 0 {
		dst.MTU = src.MTU
	}
	if !sent["driver_type"] || dst.DriverType == "" {
		dst.DriverType = src.DriverType
	}
	if !sent["psk"] || dst.PSK == "" {
		dst.PSK = src.PSK
	}
	if !sent["node_key_file"] || dst.NodeKeyFile == "" {
		dst.NodeKeyFile = src.NodeKeyFile
	}
	if !sent["listen_addrs"] {
		dst.ListenAddrs = src.ListenAddrs
	}
	if !sent["bootstrap_peers"] {
		dst.BootstrapPeers = src.BootstrapPeers
	}
	if !sent["static_peers"] {
		dst.StaticPeers = src.StaticPeers
	}
	if !sent["stun_servers"] {
		dst.StunServers = src.StunServers
	}
	if !sent["turn_servers"] {
		dst.TurnServers = src.TurnServers
	}
	if !sent["hole_punch_timeout"] || dst.HolePunchTimeout == 0 {
		dst.HolePunchTimeout = src.HolePunchTimeout
	}
	if !sent["relay_upgrade_interval"] || dst.RelayUpgradeInterval == 0 {
		dst.RelayUpgradeInterval = src.RelayUpgradeInterval
	}
	if !sent["relay_upgrade_max_backoff"] || dst.RelayUpgradeMaxBackoff == 0 {
		dst.RelayUpgradeMaxBackoff = src.RelayUpgradeMaxBackoff
	}
	if !sent["transport_strategy"] || dst.TransportStrategy == "" {
		dst.TransportStrategy = src.TransportStrategy
	}
	if !sent["log_level"] || dst.LogLevel == "" {
		dst.LogLevel = src.LogLevel
	}

	// Struct and list fields with no meaningful zero.
	if !sent["web_ui"] {
		dst.WebUI = src.WebUI
	}
	if !sent["transports"] {
		dst.Transports = src.Transports
	}
	if !sent["obfuscation"] {
		dst.Obfuscation = src.Obfuscation
	}
	if !sent["exit_node"] {
		dst.ExitNode = src.ExitNode
	}
	if !sent["acl"] {
		dst.ACL = src.ACL
	}
	if !sent["advertised_subnets"] {
		dst.AdvertisedSubnets = src.AdvertisedSubnets
	}
	if !sent["allowed_subnet_peers"] {
		dst.AllowedSubnetPeers = src.AllowedSubnetPeers
	}

	// Bool fields: absence is the only reliable "not sent" signal.
	if !sent["enable_mdns"] {
		dst.EnableMDNS = src.EnableMDNS
	}
	if !sent["discover_boot_mesh"] {
		dst.DiscoverBootMesh = src.DiscoverBootMesh
	}
	if !sent["force_private_reachability"] {
		dst.ForcePrivateReachability = src.ForcePrivateReachability
	}
	if !sent["accept_advertised_subnets"] {
		dst.AcceptAdvertisedSubnets = src.AcceptAdvertisedSubnets
	}

	// json:"-" — never in the JSON, so always carried over from the running
	// config. Dropping it would make the running config lose the path it was
	// loaded from.
	dst.ConfigPath = src.ConfigPath
}
