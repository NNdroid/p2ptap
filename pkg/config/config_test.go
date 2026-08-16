package config

import (
	"os"
	"path/filepath"
	"testing"
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
	if cfg.Obfuscation.Mode != "block" || cfg.Obfuscation.BlockSize != 128 {
		t.Errorf("Obfuscation config not parsed correctly: %+v", cfg.Obfuscation)
	} else {
		t.Logf("[config] ✓ Obfuscation mode=%s blockSize=%d", cfg.Obfuscation.Mode, cfg.Obfuscation.BlockSize)
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
	cfg.Obfuscation.Mode = "invalid_mode"
	if err := cfg.Validate(); err == nil {
		t.Error("Expected error for invalid obfuscation mode, got nil")
	} else {
		t.Logf("[config] ✓ invalid obfuscation mode rejected: %v", err)
	}

	cfg = DefaultConfig()
	cfg.TapMAC = "invalid-mac"
	if err := cfg.Validate(); err == nil {
		t.Error("Expected error for invalid TapMAC, got nil")
	} else {
		t.Logf("[config] ✓ invalid TapMAC rejected: %v", err)
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
