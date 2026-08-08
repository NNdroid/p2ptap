package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("DefaultConfig validation failed: %v", err)
	}

	if cfg.TapIP != "10.0.0.1/24" {
		t.Errorf("Expected default TapIP 10.0.0.1/24, got %s", cfg.TapIP)
	}
	if cfg.WebUI.Port != 80 {
		t.Errorf("Expected default WebUI port 80, got %d", cfg.WebUI.Port)
	}
}

func TestLoadConfigFromFile(t *testing.T) {
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
	}
	if cfg.TransportStrategy != "redundant" {
		t.Errorf("Expected transport_strategy redundant, got %s", cfg.TransportStrategy)
	}
	if cfg.Obfuscation.Mode != "block" || cfg.Obfuscation.BlockSize != 128 {
		t.Errorf("Obfuscation config not parsed correctly: %+v", cfg.Obfuscation)
	}
}

func TestConfigValidationErrors(t *testing.T) {
	cfg := DefaultConfig()
	cfg.TapIP = "invalid-ip"
	if err := cfg.Validate(); err == nil {
		t.Error("Expected error for invalid TapIP CIDR, got nil")
	}

	cfg = DefaultConfig()
	cfg.TransportStrategy = "invalid_strategy"
	if err := cfg.Validate(); err == nil {
		t.Error("Expected error for invalid transport strategy, got nil")
	}

	cfg = DefaultConfig()
	cfg.Obfuscation.Mode = "invalid_mode"
	if err := cfg.Validate(); err == nil {
		t.Error("Expected error for invalid obfuscation mode, got nil")
	}

	cfg = DefaultConfig()
	cfg.TapMAC = "invalid-mac"
	if err := cfg.Validate(); err == nil {
		t.Error("Expected error for invalid TapMAC, got nil")
	}
}

func TestParseFlagsAndLoadConfig(t *testing.T) {
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
	}
}

func TestUpdateConfigFileDelta(t *testing.T) {
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
	}
	if !updatedCfg.ExitNode.Enable {
		t.Errorf("Expected ExitNode.Enable true, got false")
	}
	if updatedCfg.ExitNode.WANInterface != "eth1" {
		t.Errorf("Expected WANInterface 'eth1', got '%s'", updatedCfg.ExitNode.WANInterface)
	}
	if updatedCfg.TapIP != "10.0.0.1/24" {
		t.Errorf("Expected immutable TapIP '10.0.0.1/24', got '%s'", updatedCfg.TapIP)
	}
}

func TestACLAndSubnetConfigValidation(t *testing.T) {
	cfg := DefaultConfig()
	cfg.AdvertisedSubnets = []string{"invalid-cidr"}
	if err := cfg.Validate(); err == nil {
		t.Error("Expected error for invalid advertised subnet CIDR, got nil")
	}

	cfg = DefaultConfig()
	cfg.AdvertisedSubnets = []string{"192.168.1.0/24"}
	cfg.AcceptAdvertisedSubnets = true
	cfg.AllowedSubnetPeers = []string{"*"}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Valid Subnet config failed validation: %v", err)
	}

	cfg = DefaultConfig()
	cfg.ACL.Enable = true
	cfg.ACL.DefaultAction = "invalid_action"
	if err := cfg.Validate(); err == nil {
		t.Error("Expected error for invalid ACL default action, got nil")
	}

	cfg = DefaultConfig()
	cfg.ACL.Enable = true
	cfg.ACL.DefaultAction = "deny"
	cfg.ACL.Rules = []ACLRule{
		{Action: "allow", PeerID: "*", IPCIDR: "10.0.0.0/24", Protocol: "tcp", Port: "80"},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Valid ACL config failed validation: %v", err)
	}
}
