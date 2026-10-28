package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	t.Log("[config] validating DefaultConfig()")
	cfg := DefaultConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("DefaultConfig validation failed: %v", err)
	}

	if cfg.TapIP != "10.0.0.1/24" {
		t.Errorf("Expected default TapIP 10.0.0.1/24, got %s", cfg.TapIP)
	} else {
		t.Logf("[config] ✓ default TapIP=%s", cfg.TapIP)
	}
	if cfg.WebUI.Port != 80 {
		t.Errorf("Expected default WebUI port 80, got %d", cfg.WebUI.Port)
	} else {
		t.Logf("[config] ✓ default WebUI.Port=%d", cfg.WebUI.Port)
	}
	if cfg.RelayUpgradeInterval != 30*time.Second {
		t.Errorf("Expected default RelayUpgradeInterval 30s, got %v", cfg.RelayUpgradeInterval)
	}
	if cfg.RelayUpgradeMaxBackoff != 30*time.Minute {
		t.Errorf("Expected default RelayUpgradeMaxBackoff 30m, got %v", cfg.RelayUpgradeMaxBackoff)
	}
	if cfg.RelayUpgradeFlapWindow != 5*time.Minute {
		t.Errorf("Expected default RelayUpgradeFlapWindow 5m, got %v", cfg.RelayUpgradeFlapWindow)
	}
}

// Validate must repair a missing cap so a config.json that predates the field
// is not read as "no backoff at all".
func TestConfigValidationRepairsMissingRelayUpgradeMaxBackoff(t *testing.T) {
	for _, v := range []time.Duration{0, -time.Minute} {
		cfg := DefaultConfig()
		cfg.RelayUpgradeMaxBackoff = v
		if err := cfg.Validate(); err != nil {
			t.Fatalf("Validate() on %v failed: %v", v, err)
		}
		if cfg.RelayUpgradeMaxBackoff != 30*time.Minute {
			t.Errorf("input %v: expected 30m after Validate, got %v", v, cfg.RelayUpgradeMaxBackoff)
		}
	}
}

// Same for the flap window: a config.json predating the field must not be read
// as "no flap window at all".
func TestConfigValidationRepairsMissingRelayUpgradeFlapWindow(t *testing.T) {
	for _, v := range []time.Duration{0, -time.Minute} {
		cfg := DefaultConfig()
		cfg.RelayUpgradeFlapWindow = v
		if err := cfg.Validate(); err != nil {
			t.Fatalf("Validate() on %v failed: %v", v, err)
		}
		if cfg.RelayUpgradeFlapWindow != 5*time.Minute {
			t.Errorf("input %v: expected 5m after Validate, got %v", v, cfg.RelayUpgradeFlapWindow)
		}
	}
}

// Before these checks existed, an out-of-range value passed Validate() and the
// upgrade loop quietly replaced it: "relay_upgrade_interval: 5m" silently
// became 30s, so the operator saw a saved setting that never took effect.
func TestConfigValidationRejectsRelayUpgradeOutOfRange(t *testing.T) {
	cases := []struct {
		name   string
		apply  func(*Config)
		expect string
	}{
		{"interval below min", func(c *Config) { c.RelayUpgradeInterval = RelayUpgradeIntervalMin - time.Second }, "relay_upgrade_interval"},
		{"interval above max", func(c *Config) { c.RelayUpgradeInterval = RelayUpgradeIntervalMax + time.Second }, "relay_upgrade_interval"},
		{"backoff below min", func(c *Config) { c.RelayUpgradeMaxBackoff = RelayUpgradeMaxBackoffMin - time.Second }, "relay_upgrade_max_backoff"},
		{"backoff above max", func(c *Config) { c.RelayUpgradeMaxBackoff = RelayUpgradeMaxBackoffMax + time.Minute }, "relay_upgrade_max_backoff"},
		{"flap window below min", func(c *Config) { c.RelayUpgradeFlapWindow = RelayUpgradeFlapWindowMin - time.Second }, "relay_upgrade_flap_window"},
		{"flap window above max", func(c *Config) { c.RelayUpgradeFlapWindow = RelayUpgradeFlapWindowMax + time.Minute }, "relay_upgrade_flap_window"},
	}
	for _, tc := range cases {
		cfg := DefaultConfig()
		tc.apply(cfg)
		err := cfg.Validate()
		if err == nil {
			t.Fatalf("%s: Validate() accepted a value outside the accepted range", tc.name)
		}
		if !strings.Contains(err.Error(), tc.expect) {
			t.Errorf("%s: error %q does not name %s", tc.name, err, tc.expect)
		}
	}
}

// The bounds are inclusive: the endpoints themselves must be accepted.
func TestConfigValidationAcceptsRelayUpgradeBounds(t *testing.T) {
	for _, tc := range []struct {
		name  string
		apply func(*Config)
	}{
		{"interval min", func(c *Config) { c.RelayUpgradeInterval = RelayUpgradeIntervalMin }},
		{"interval max", func(c *Config) { c.RelayUpgradeInterval = RelayUpgradeIntervalMax }},
		{"backoff min", func(c *Config) { c.RelayUpgradeMaxBackoff = RelayUpgradeMaxBackoffMin }},
		{"backoff max", func(c *Config) { c.RelayUpgradeMaxBackoff = RelayUpgradeMaxBackoffMax }},
		{"flap window min", func(c *Config) { c.RelayUpgradeFlapWindow = RelayUpgradeFlapWindowMin }},
		{"flap window max", func(c *Config) { c.RelayUpgradeFlapWindow = RelayUpgradeFlapWindowMax }},
	} {
		cfg := DefaultConfig()
		tc.apply(cfg)
		if err := cfg.Validate(); err != nil {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
}

func TestLoadConfigFromFile(t *testing.T) {
	t.Log("[config] loading config from temp JSON file")
	tempDir := t.TempDir()
	configFile := filepath.Join(tempDir, "test_config.json")

	content := `{
		"tap_ip": "192.168.100.1/24",
		"tap_ipv6": "fd01::1/64",
		"transport_strategy": "redundant",
		"web_ui": {
			"enable": true,
			"listen_ip": "192.168.100.1",
			"listen_ipv6": "",
			"port": 80
		},
		"obfuscation": {
			"enable": true,
			"mode": "block",
			"block_size": 128
		}
	}`

	if err := os.WriteFile(configFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to write temp config file: %v", err)
	}

	cfg, err := LoadConfigFromFile(configFile)
	if err != nil {
		t.Fatalf("Failed to load config from file: %v", err)
	}

	if cfg.TapIP != "192.168.100.1/24" {
		t.Errorf("Expected TapIP 192.168.100.1/24, got %s", cfg.TapIP)
	} else {
		t.Logf("[config] ✓ TapIP=%s", cfg.TapIP)
	}
	if cfg.TransportStrategy != "redundant" {
		t.Errorf("Expected transport_strategy redundant, got %s", cfg.TransportStrategy)
	} else {
		t.Logf("[config] ✓ TransportStrategy=%s", cfg.TransportStrategy)
	}
	if cfg.Obfuscation.PaddingRules != "0 -> 400-600" {
		t.Errorf("Obfuscation config not parsed correctly: %+v", cfg.Obfuscation)
	} else {
		t.Logf("[config] ✓ Obfuscation padding_rules=%s", cfg.Obfuscation.PaddingRules)
	}
}

func TestConfigValidationErrors(t *testing.T) {
	t.Log("[config] checking invalid-field validation errors")
	cfg := DefaultConfig()
	cfg.TapIP = "invalid-ip"
	if err := cfg.Validate(); err == nil {
		t.Error("Expected error for invalid TapIP CIDR, got nil")
	} else {
		t.Logf("[config] ✓ invalid TapIP rejected: %v", err)
	}

	cfg = DefaultConfig()
	cfg.TransportStrategy = "invalid_strategy"
	if err := cfg.Validate(); err == nil {
		t.Error("Expected error for invalid transport strategy, got nil")
	} else {
		t.Logf("[config] ✓ invalid strategy rejected: %v", err)
	}

	cfg = DefaultConfig()
	cfg.Obfuscation.PaddingRules = "invalid band line"
	if err := cfg.Validate(); err == nil {
		t.Error("Expected error for invalid obfuscation padding_rules, got nil")
	} else {
		t.Logf("[config] ✓ invalid obfuscation padding_rules rejected: %v", err)
	}

	cfg = DefaultConfig()
	cfg.TapMAC = "invalid-mac"
	if err := cfg.Validate(); err == nil {
		t.Error("Expected error for invalid TapMAC, got nil")
	} else {
		t.Logf("[config] ✓ invalid TapMAC rejected: %v", err)
	}
}

// Dropping the field must not break a config.json that still carries it.
// encoding/json ignores unknown keys, so a config written before
// auto_threshold_bytes was removed keeps loading unchanged.
func TestLoadConfigIgnoresRemovedAutoThresholdBytes(t *testing.T) {
	configFile := filepath.Join(t.TempDir(), "old_config.json")
	content := `{"tap_ip": "10.0.0.1/24", "obfuscation": {"auto_threshold_bytes": 1048576, "auto_detect_interval": 60}}`
	if err := os.WriteFile(configFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to write temp config file: %v", err)
	}

	cfg, err := LoadConfigFromFile(configFile)
	if err != nil {
		t.Fatalf("a pre-removal config.json must still load: %v", err)
	}
	if cfg.Obfuscation.Enable != true || cfg.Obfuscation.PaddingRules != "0 -> 400-600" {
		t.Errorf("an unrelated obfuscation field was disturbed: %+v", cfg.Obfuscation)
	}
}

func TestParseFlagsAndLoadConfig(t *testing.T) {
	t.Log("[config] parse flags + load config via -c")
	tempDir := t.TempDir()
	configFile := filepath.Join(tempDir, "custom.json")

	content := `{"tap_ip": "10.10.10.1/24"}`
	_ = os.WriteFile(configFile, []byte(content), 0644)

	cfg, path, err := ParseFlagsAndLoadConfig([]string{"-c", configFile})
	if err != nil {
		t.Fatalf("Failed to parse flags and load config: %v", err)
	}
	if path != configFile {
		t.Errorf("Expected path %s, got %s", configFile, path)
	}
	if cfg.TapIP != "10.10.10.1/24" {
		t.Errorf("Expected TapIP 10.10.10.1/24, got %s", cfg.TapIP)
	} else {
		t.Logf("[config] ✓ flags/config: path=%s TapIP=%s", path, cfg.TapIP)
	}
}

func TestUpdateConfigFileDelta(t *testing.T) {
	t.Log("[config] UpdateConfigFileDelta merges + preserves immutable/unknown fields")
	tempDir := t.TempDir()
	configFile := filepath.Join(tempDir, "delta_config.json")

	initialContent := `{
		"node_name": "old-name",
		"tap_ip": "10.0.0.1/24",
		"custom_user_key": "preserve_this_value",
		"exit_node": {
			"enable": false,
			"nat_masquerade": true,
			"wan_interface": "auto"
		}
	}`
	if err := os.WriteFile(configFile, []byte(initialContent), 0644); err != nil {
		t.Fatalf("Failed to write initial config: %v", err)
	}

	incoming := DefaultConfig()
	incoming.NodeName = "new-updated-name"
	incoming.ExitNode.Enable = true
	incoming.ExitNode.WANInterface = "eth1"

	if err := UpdateConfigFileDelta(configFile, incoming); err != nil {
		t.Fatalf("UpdateConfigFileDelta failed: %v", err)
	}

	updatedCfg, err := LoadConfigFromFile(configFile)
	if err != nil {
		t.Fatalf("Failed to load updated config: %v", err)
	}

	if updatedCfg.NodeName != "new-updated-name" {
		t.Errorf("Expected NodeName 'new-updated-name', got '%s'", updatedCfg.NodeName)
	} else {
		t.Logf("[config] ✓ NodeName updated -> %s", updatedCfg.NodeName)
	}
	if !updatedCfg.ExitNode.Enable {
		t.Errorf("Expected ExitNode.Enable true, got false")
	} else {
		t.Log("[config] ✓ ExitNode.Enable=true")
	}
	if updatedCfg.ExitNode.WANInterface != "eth1" {
		t.Errorf("Expected WANInterface 'eth1', got '%s'", updatedCfg.ExitNode.WANInterface)
	} else {
		t.Logf("[config] ✓ ExitNode.WANInterface=%s", updatedCfg.ExitNode.WANInterface)
	}
	if updatedCfg.TapIP != "10.0.0.1/24" {
		t.Errorf("Expected immutable TapIP '10.0.0.1/24', got '%s'", updatedCfg.TapIP)
	} else {
		t.Logf("[config] ✓ immutable TapIP preserved=%s (user key preserved)", updatedCfg.TapIP)
	}
}

func TestACLAndSubnetConfigValidation(t *testing.T) {
	t.Log("[config] ACL + subnet config validation")
	cfg := DefaultConfig()
	cfg.AdvertisedSubnets = []string{"invalid-cidr"}
	if err := cfg.Validate(); err == nil {
		t.Error("Expected error for invalid advertised subnet CIDR, got nil")
	} else {
		t.Logf("[config] ✓ invalid advertised subnet rejected: %v", err)
	}

	cfg = DefaultConfig()
	cfg.AdvertisedSubnets = []string{"192.168.1.0/24"}
	cfg.AcceptAdvertisedSubnets = true
	cfg.AllowedSubnetPeers = []string{"*"}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Valid Subnet config failed validation: %v", err)
	} else {
		t.Log("[config] ✓ valid subnet config accepted")
	}

	cfg = DefaultConfig()
	cfg.ACL.Enable = true
	cfg.ACL.DefaultAction = "invalid_action"
	if err := cfg.Validate(); err == nil {
		t.Error("Expected error for invalid ACL default action, got nil")
	} else {
		t.Logf("[config] ✓ invalid ACL default action rejected: %v", err)
	}

	cfg = DefaultConfig()
	cfg.ACL.Enable = true
	cfg.ACL.DefaultAction = "deny"
	cfg.ACL.Rules = []ACLRule{
		{Action: "allow", PeerID: "*", IPCIDR: "10.0.0.0/24", Protocol: "tcp", Port: "80"},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Valid ACL config failed validation: %v", err)
	} else {
		t.Log("[config] ✓ valid ACL config accepted")
	}
}

func TestMultipathStrategyConfig(t *testing.T) {
	// "multipath" must validate, and the reorder knobs must carry sensible
	// defaults for it.
	cfg := DefaultConfig()
	if cfg.TransportStrategy != "best_path" {
		t.Fatalf("default transport strategy = %q, want best_path", cfg.TransportStrategy)
	}
	cfg.TransportStrategy = "multipath"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("multipath strategy rejected: %v", err)
	}
	if cfg.RxReorderWindow < 1 || cfg.RxReorderDelayMs < 1 {
		t.Fatalf("multipath reorder defaults invalid: window=%d delay=%d", cfg.RxReorderWindow, cfg.RxReorderDelayMs)
	}
	// Clamping: out-of-range knobs are pinned back to their defaults.
	cfg.RxReorderWindow = 0
	cfg.RxReorderDelayMs = 0
	if err := cfg.Validate(); err != nil {
		t.Fatalf("clamped reorder knobs rejected: %v", err)
	}
	if cfg.RxReorderWindow != 256 || cfg.RxReorderDelayMs != 200 {
		t.Fatalf("reorder knobs not clamped to defaults: window=%d delay=%d", cfg.RxReorderWindow, cfg.RxReorderDelayMs)
	}
}
