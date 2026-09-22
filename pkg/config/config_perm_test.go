package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// A config carrying the PSK is effectively a keyring: the PSK doubles as the
// libp2p private-network membership key and as the HKDF salt every per-peer
// session key derives from. These tests pin both the permission decision and
// the resulting on-disk mode, so a future refactor cannot quietly restore a
// world-readable mode.
//
// The filesystem half is POSIX-only — on Windows chmod has no group/other bits
// to remove, so those assertions would compare 0666 against anything.

func TestConfigFilePermDecision(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*Config)
		want os.FileMode
	}{
		{"psk present -> owner only", func(c *Config) { c.PSK = "s3cret" }, 0o600},
		{"pinned auth token -> owner only", func(c *Config) { c.WebUI.AuthToken = "tok" }, 0o600},
		{"both secrets -> owner only", func(c *Config) {
			c.PSK = "s3cret"
			c.WebUI.AuthToken = "tok"
		}, 0o600},
		{"no secrets -> stays inspectable", func(c *Config) {
			c.PSK = ""
			c.WebUI.AuthToken = ""
		}, 0o644},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := DefaultConfig()
			tc.mut(c)
			if got := configFilePerm(c); got != tc.want {
				t.Errorf("configFilePerm = %o, want %o", got, tc.want)
			}
		})
	}
}

func requirePOSIXPerms(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits unavailable on Windows")
	}
}

func TestUpdateConfigFileDeltaPSKIsOwnerOnly(t *testing.T) {
	requirePOSIXPerms(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	cfg := DefaultConfig()
	cfg.PSK = "unit-test-psk"
	if err := UpdateConfigFileDelta(path, cfg); err != nil {
		t.Fatalf("UpdateConfigFileDelta: %v", err)
	}
	assertPerm(t, path, 0o600)
}

func TestUpdateConfigFileDeltaKeepsOpenPermWithoutSecrets(t *testing.T) {
	requirePOSIXPerms(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	cfg := DefaultConfig()
	cfg.PSK = ""
	cfg.WebUI.AuthToken = ""
	if err := UpdateConfigFileDelta(path, cfg); err != nil {
		t.Fatalf("UpdateConfigFileDelta: %v", err)
	}
	assertPerm(t, path, 0o644)
}

func TestPinnedAuthTokenIsTreatedAsSecret(t *testing.T) {
	requirePOSIXPerms(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	cfg := DefaultConfig()
	cfg.PSK = ""
	cfg.WebUI.AuthToken = "operator-pinned-token"
	if err := UpdateConfigFileDelta(path, cfg); err != nil {
		t.Fatalf("UpdateConfigFileDelta: %v", err)
	}
	assertPerm(t, path, 0o600)
}

// A node upgraded from a build that always wrote 0644 keeps a world-readable
// config on disk. Loading it must repair the mode rather than wait for the
// next write.
func TestLoadConfigFromFileTightensLegacyPerm(t *testing.T) {
	requirePOSIXPerms(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	legacy := DefaultConfig()
	legacy.PSK = "unit-test-psk"
	data, err := json.MarshalIndent(legacy, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("seed legacy config: %v", err)
	}
	// Pin the mode regardless of the test runner's umask.
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	if _, err := LoadConfigFromFile(path); err != nil {
		t.Fatalf("LoadConfigFromFile: %v", err)
	}
	assertPerm(t, path, 0o600)
}

func TestLoadConfigFromFileLeavesSecretlessConfigAlone(t *testing.T) {
	requirePOSIXPerms(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	cfg := DefaultConfig()
	cfg.PSK = ""
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("seed config: %v", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	if _, err := LoadConfigFromFile(path); err != nil {
		t.Fatalf("LoadConfigFromFile: %v", err)
	}
	assertPerm(t, path, 0o644)
}

func assertPerm(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if got := fi.Mode().Perm(); got != want {
		t.Errorf("%s: permissions = %o, want %o", path, got, want)
	}
}
