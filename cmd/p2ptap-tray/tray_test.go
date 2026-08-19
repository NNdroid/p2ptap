//go:build windows

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"p2ptap/pkg/config"
)

func TestResolveWebuiURL_ConfiguredListenIP(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.json")
	cfg := config.DefaultConfig()
	cfg.WebUI.Enable = true
	cfg.WebUI.ListenIP = "10.0.0.3"
	cfg.WebUI.Port = 5857
	cfg.WebUI.AuthToken = "admin"

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	if err := os.WriteFile(cfgPath, data, 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	sidecarPath := filepath.Join(tmpDir, ".p2ptap_webui_url")
	_ = os.WriteFile(sidecarPath, []byte("http://127.0.0.1:5857\nhttp://10.0.0.3:5857\n"), 0644)

	globalConfig = cfg
	globalConfigPath = cfgPath

	u := resolveWebuiURL()
	expected := "http://10.0.0.3:5857/?token=admin"
	if u != expected {
		t.Errorf("resolveWebuiURL() = %q, want %q", u, expected)
	}
}

func TestResolveWebuiURL_WildcardLoopback(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.json")
	cfg := config.DefaultConfig()
	cfg.WebUI.Enable = true
	cfg.WebUI.ListenIP = "0.0.0.0"
	cfg.WebUI.Port = 5857
	cfg.WebUI.AuthToken = "secret"

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	if err := os.WriteFile(cfgPath, data, 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	sidecarPath := filepath.Join(tmpDir, ".p2ptap_webui_url")
	_ = os.WriteFile(sidecarPath, []byte("http://127.0.0.1:5857\n"), 0644)

	globalConfig = cfg
	globalConfigPath = cfgPath

	u := resolveWebuiURL()
	expected := "http://127.0.0.1:5857/?token=secret"
	if u != expected {
		t.Errorf("resolveWebuiURL() = %q, want %q", u, expected)
	}
}

func TestResolveWebuiURL_IPv6Only(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.json")
	cfg := config.DefaultConfig()
	cfg.WebUI.Enable = true
	cfg.WebUI.ListenIP = ""
	cfg.WebUI.ListenIPv6 = "fd00::3"
	cfg.WebUI.Port = 5857
	cfg.WebUI.AuthToken = "admin"

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	if err := os.WriteFile(cfgPath, data, 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	sidecarPath := filepath.Join(tmpDir, ".p2ptap_webui_url")
	_ = os.WriteFile(sidecarPath, []byte("http://[fd00::3]:5857\n"), 0644)

	globalConfig = cfg
	globalConfigPath = cfgPath

	u := resolveWebuiURL()
	expected := "http://[fd00::3]:5857/?token=admin"
	if u != expected {
		t.Errorf("resolveWebuiURL() = %q, want %q", u, expected)
	}
}

func TestResolveWebuiURL_IPv6Wildcard(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.json")
	cfg := config.DefaultConfig()
	cfg.WebUI.Enable = true
	cfg.WebUI.ListenIP = ""
	cfg.WebUI.ListenIPv6 = "::"
	cfg.WebUI.Port = 5857
	cfg.WebUI.AuthToken = "token123"

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	if err := os.WriteFile(cfgPath, data, 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	sidecarPath := filepath.Join(tmpDir, ".p2ptap_webui_url")
	_ = os.WriteFile(sidecarPath, []byte("http://[::1]:5857\n"), 0644)

	globalConfig = cfg
	globalConfigPath = cfgPath

	u := resolveWebuiURL()
	expected := "http://[::1]:5857/?token=token123"
	if u != expected {
		t.Errorf("resolveWebuiURL() = %q, want %q", u, expected)
	}
}

func TestResolveWebuiURL_DualStackSpecific(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.json")
	cfg := config.DefaultConfig()
	cfg.WebUI.Enable = true
	cfg.WebUI.ListenIP = "10.0.0.3"
	cfg.WebUI.ListenIPv6 = "fd00::3"
	cfg.WebUI.Port = 5857
	cfg.WebUI.AuthToken = "admin"

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	if err := os.WriteFile(cfgPath, data, 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	sidecarPath := filepath.Join(tmpDir, ".p2ptap_webui_url")
	_ = os.WriteFile(sidecarPath, []byte("http://10.0.0.3:5857\nhttp://[fd00::3]:5857\n"), 0644)

	globalConfig = cfg
	globalConfigPath = cfgPath

	u := resolveWebuiURL()
	// When both specific v4 and specific v6 are configured, v4 is chosen for best browser compatibility
	expected := "http://10.0.0.3:5857/?token=admin"
	if u != expected {
		t.Errorf("resolveWebuiURL() = %q, want %q", u, expected)
	}
}

func TestResolveWebuiURL_DualStackWildcard(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.json")
	cfg := config.DefaultConfig()
	cfg.WebUI.Enable = true
	cfg.WebUI.ListenIP = "0.0.0.0"
	cfg.WebUI.ListenIPv6 = "::"
	cfg.WebUI.Port = 5857
	cfg.WebUI.AuthToken = "admin"

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	if err := os.WriteFile(cfgPath, data, 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	sidecarPath := filepath.Join(tmpDir, ".p2ptap_webui_url")
	_ = os.WriteFile(sidecarPath, []byte("http://127.0.0.1:5857\nhttp://[::1]:5857\n"), 0644)

	globalConfig = cfg
	globalConfigPath = cfgPath

	u := resolveWebuiURL()
	expected := "http://127.0.0.1:5857/?token=admin"
	if u != expected {
		t.Errorf("resolveWebuiURL() = %q, want %q", u, expected)
	}
}
