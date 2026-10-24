package config

import (
	"slices"
	"testing"
	"time"
)

// hasField reports whether name appears in the returned list.
func hasField(fields []string, name string) bool {
	return slices.Contains(fields, name)
}

func assertHasField(t *testing.T, fields []string, name string) {
	t.Helper()
	if !hasField(fields, name) {
		t.Errorf("expected %q in restart-required list, got %v", name, fields)
	}
}

func assertNoField(t *testing.T, fields []string, name string) {
	t.Helper()
	if hasField(fields, name) {
		t.Errorf("did not expect %q to be restart-required (it is hot-reloadable), got %v", name, fields)
	}
}

func TestRestartRequiredFieldsIdenticalIsEmpty(t *testing.T) {
	base := DefaultConfig()
	if fields := RestartRequiredFields(base, base); fields != nil {
		t.Fatalf("identical configs must not require a restart, got %v", fields)
	}
}

func TestRestartRequiredFieldsNilSafe(t *testing.T) {
	base := DefaultConfig()
	if got := RestartRequiredFields(nil, base); got != nil {
		t.Errorf("nil old must yield nil, got %v", got)
	}
	if got := RestartRequiredFields(base, nil); got != nil {
		t.Errorf("nil new must yield nil, got %v", got)
	}
}

func TestRestartRequiredFieldsConstructionTime(t *testing.T) {
	base := DefaultConfig()
	cases := map[string]struct {
		mutate func(*Config)
		want   string
	}{
		"tap_name":                   {func(c *Config) { c.TapName = "other" }, "tap_name"},
		"tap_ip":                     {func(c *Config) { c.TapIP = "10.88.88.2/24" }, "tap_ip"},
		"tap_ipv6":                   {func(c *Config) { c.TapIPv6 = "fd00::2/64" }, "tap_ipv6"},
		"tap_mac":                    {func(c *Config) { c.TapMAC = "02:00:00:00:00:02" }, "tap_mac"},
		"mtu":                        {func(c *Config) { c.MTU = 1280 }, "mtu"},
		"driver_type":                {func(c *Config) { c.DriverType = "tap" }, "driver_type"},
		"node_key_file":              {func(c *Config) { c.NodeKeyFile = "other.key" }, "node_key_file"},
		"listen_addrs":               {func(c *Config) { c.ListenAddrs = append(c.ListenAddrs, "/ip4/0.0.0.0/udp/41149") }, "listen_addrs"},
		"bootstrap_peers":            {func(c *Config) { c.BootstrapPeers = append(c.BootstrapPeers, "peer-a") }, "bootstrap_peers"},
		"static_peers":               {func(c *Config) { c.StaticPeers = append(c.StaticPeers, "peer-b") }, "static_peers"},
		"node_name":                  {func(c *Config) { c.NodeName = "renamed" }, "node_name"},
		"psk":                        {func(c *Config) { c.PSK = "another-key" }, "psk"},
		"transport_strategy":         {func(c *Config) { c.TransportStrategy = "redundant" }, "transport_strategy"},
		"enable_mdns":                {func(c *Config) { c.EnableMDNS = !c.EnableMDNS }, "enable_mdns"},
		"force_private_reachability": {func(c *Config) { c.ForcePrivateReachability = true }, "force_private_reachability"},
		"hole_punch_timeout":         {func(c *Config) { c.HolePunchTimeout = c.HolePunchTimeout + time.Second }, "hole_punch_timeout"},
		"relay_upgrade_interval":     {func(c *Config) { c.RelayUpgradeInterval = c.RelayUpgradeInterval + time.Second }, "relay_upgrade_interval"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			newCfg := *base
			tc.mutate(&newCfg)
			assertHasField(t, RestartRequiredFields(base, &newCfg), tc.want)
		})
	}
}

// relay_upgrade_interval is restart-required because the ticker is created once
// at loop start, but relay_upgrade_max_backoff is read on every tick, so it is
// hot-reloadable. Pinning the split here keeps a later edit from "tidying" the
// cap into the restart list on the strength of its sibling.
func TestRestartRequiredFieldsRelayUpgradeMaxBackoffIsHot(t *testing.T) {
	base := DefaultConfig()

	newCfg := *base
	newCfg.RelayUpgradeMaxBackoff = 5 * time.Minute
	assertNoField(t, RestartRequiredFields(base, &newCfg), "relay_upgrade_max_backoff")

	newCfg = *base
	newCfg.RelayUpgradeInterval += time.Second
	assertHasField(t, RestartRequiredFields(base, &newCfg), "relay_upgrade_interval")
}

// The flap window is read on every tick, so it hot-reloads like the backoff
// cap. It is the third of the three relay-upgrade knobs, and only
// relay_upgrade_interval needs a restart.
func TestRestartRequiredFieldsRelayUpgradeFlapWindowIsHot(t *testing.T) {
	base := DefaultConfig()

	newCfg := *base
	newCfg.RelayUpgradeFlapWindow = time.Minute
	assertNoField(t, RestartRequiredFields(base, &newCfg), "relay_upgrade_flap_window")
}

// TestRestartRequiredFieldsTransports is the regression net for the Android
// build: eight transport-derived fields were classified hot-reloadable there,
// though every one is consumed once at libp2p host construction. The web-side
// list groups the whole block under "transports", so assert each switch
// individually to keep the grouping honest.
func TestRestartRequiredFieldsTransports(t *testing.T) {
	base := DefaultConfig()
	cases := []struct {
		name   string
		mutate func(*TransportsConfig)
	}{
		{"disable_relay", func(tr *TransportsConfig) { tr.DisableRelay = true }},
		{"tls_server_name", func(tr *TransportsConfig) { tr.TLSServerName = "cdn.example.com" }},
		{"tls_sni_suffix", func(tr *TransportsConfig) { tr.TLSSNISuffix = "cdn.example.com" }},
		{"enable_quic_reuse", func(tr *TransportsConfig) { tr.EnableQUICReuse = !tr.EnableQUICReuse }},
		{"enable_webrtc", func(tr *TransportsConfig) { tr.EnableWebRTC = !tr.EnableWebRTC }},
		{"enable_webtransport", func(tr *TransportsConfig) { tr.EnableWebTransport = !tr.EnableWebTransport }},
		{"enable_tcp_reuse", func(tr *TransportsConfig) { tr.EnableTCPReuse = !tr.EnableTCPReuse }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			newCfg := *base
			tc.mutate(&newCfg.Transports)
			fields := RestartRequiredFields(base, &newCfg)
			if !hasField(fields, "transports") {
				t.Errorf("%s changed but %q is not restart-required; got %v", tc.name, "transports", fields)
			}
		})
	}
}

func TestRestartRequiredFieldsWebUI(t *testing.T) {
	base := DefaultConfig()
	cases := []struct {
		name   string
		mutate func(*WebUIConfig)
	}{
		{"enable", func(w *WebUIConfig) { w.Enable = !w.Enable }},
		{"listen_ip", func(w *WebUIConfig) { w.ListenIP = "127.0.0.1" }},
		{"listen_ipv6", func(w *WebUIConfig) { w.ListenIPv6 = "::1" }},
		{"port", func(w *WebUIConfig) { w.Port = w.Port + 1 }},
		{"auth_token", func(w *WebUIConfig) { w.AuthToken = "rotated-token" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			newCfg := *base
			tc.mutate(&newCfg.WebUI)
			assertHasField(t, RestartRequiredFields(base, &newCfg), "web_ui")
		})
	}
}

// TestRestartRequiredFieldsExcludesHotReloadable guards the other direction:
// fields that applyHotReload genuinely re-applies, or whose consumers read the
// live snapshot, must NOT be reported as restart-required — otherwise every
// save would warn and the warning loses all meaning.
func TestRestartRequiredFieldsExcludesHotReloadable(t *testing.T) {
	base := DefaultConfig()
	newCfg := *base
	newCfg.LogLevel = "debug"
	newCfg.StunServers = append(newCfg.StunServers, "stun:stun.l.google.com:19302")
	newCfg.TurnServers = append(newCfg.TurnServers, "turn:turn.example.com:3478")
	newCfg.DiscoverBootMesh = !newCfg.DiscoverBootMesh
	newCfg.AllowedSubnetPeers = append(newCfg.AllowedSubnetPeers, "peer-a")
	newCfg.Obfuscation.Algorithm = "aes-gcm"
	newCfg.Obfuscation.Mode = "udp+tcp"
	newCfg.Obfuscation.StrictKeyNegotiation = !newCfg.Obfuscation.StrictKeyNegotiation
	newCfg.ExitNode.Enable = !newCfg.ExitNode.Enable
	newCfg.ExitNode.WANInterface = "eth0"

	fields := RestartRequiredFields(base, &newCfg)
	if fields != nil {
		t.Fatalf("no hot-reloadable field should require a restart, got %v", fields)
	}
}

func TestRestartRequiredFieldsAccumulates(t *testing.T) {
	base := DefaultConfig()
	newCfg := *base
	newCfg.MTU = 1280
	newCfg.Transports.DisableRelay = true
	newCfg.WebUI.Port = 9090

	fields := RestartRequiredFields(base, &newCfg)
	for _, want := range []string{"mtu", "transports", "web_ui"} {
		assertHasField(t, fields, want)
	}
}
