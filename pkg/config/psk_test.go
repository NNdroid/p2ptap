package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// productionPSK is the 32-byte / 64-hex-char key deployed on the production
// bootstrap server. It is used as-is so the regression cannot be fixed by
// editing the fixture.
const productionPSK = "2d5c54ee79fcd3855c23d521c413985e23ad5f31cf039737fd28d84f98683b39"

func TestValidatePSKAcceptsStandardHexKey(t *testing.T) {
	if err := validatePSK(productionPSK); err != nil {
		t.Fatalf("the 64-hex-char key every installer ships must validate, got: %v", err)
	}
}

// A random hex key can be all letters ("deadbeef...") or nearly all digits.
// The character class heuristic is meaningless for a fixed alphabet, so such a
// key must not be rejected — the previous implementation did reject it.
func TestValidatePSKHexNotSubjectToCharacterClassRule(t *testing.T) {
	lettersOnly := "deadbeefdeadbeefdeadbeefdeadbeef" // 32 hex chars = 16 bytes
	if err := validatePSK(lettersOnly); err != nil {
		t.Errorf("single-class hex key rejected: %v", err)
	}
	digitsHeavy := "0123456789abcdef0123456789abcdef" // 32 hex chars = 16 bytes
	if err := validatePSK(digitsHeavy); err != nil {
		t.Errorf("mixed-digit/letter hex key rejected: %v", err)
	}
	upper := strings.ToUpper(productionPSK)
	if err := validatePSK(upper); err != nil {
		t.Errorf("uppercase hex key rejected: %v", err)
	}
}

func TestValidatePSKHexLengthBoundaries(t *testing.T) {
	// Use a varying pattern (not a single repeated character) so the length
	// test does not trip the isAllSameChar entropy guard — a key of all "0"s
	// is trivially brute-forceable and must be rejected.
	repeat := func(hexChars int) string {
		pattern := "0123456789abcdef"
		return strings.Repeat(pattern, hexChars/len(pattern)+1)[:hexChars]
	}

	cases := []struct {
		name    string
		psk     string
		wantErr string
	}{
		{"below minimum: 14 hex chars is 7 bytes", repeat(14), "below the 8-byte minimum"},
		{"at minimum: 16 hex chars is 8 bytes", repeat(16), ""},
		{"standard: 64 hex chars is 32 bytes", repeat(64), ""},
		{"at maximum: 128 hex chars is 64 bytes", repeat(128), ""},
		{"above maximum: 130 hex chars is 65 bytes", repeat(130), "above the 64-byte maximum"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validatePSK(tc.psk)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("want accept, got: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("want error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.wantErr)
			}
		})
	}
}

func TestValidatePSKOddHexCount(t *testing.T) {
	err := validatePSK("2d5c54ee79fcd3855c23d521c413985e23ad5f31cf039737fd28d84f98683b3")
	if err == nil {
		t.Fatal("odd hex count accepted")
	}
	if !strings.Contains(err.Error(), "odd count") {
		t.Fatalf("error %q should explain the odd hex count", err.Error())
	}
}

func TestValidatePSKPlaintextPath(t *testing.T) {
	cases := []struct {
		name    string
		psk     string
		wantErr string
	}{
		{"too short", "s3cret", "below the 16-character minimum"},
		{"at minimum with two classes", "s3cret-passphrase1", ""},
		// 'g' is deliberately not a hex digit, so these stay on the plaintext
		// path instead of being read as an encoded key.
		{"single character class", "gggggggggggggggg", "only one character class"},
		{"128 chars accepted", strings.Repeat("g", 122) + "111111", ""},
		{"129 chars exceeds maximum", strings.Repeat("g", 123) + "111111", "exceeds the 128-character maximum"},
		{"non-hex too short", "zzzz", "below the 16-character minimum"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validatePSK(tc.psk)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("want accept, got: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("want error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.wantErr)
			}
		})
	}
}

// TestValidateConfigAcceptsProductionPSK is the end-to-end regression for the
// Android launch failure: a client configured with the server's own key was
// rejected by Config.Validate with "64 characters exceeds the 32-character
// maximum".
func TestValidateConfigAcceptsProductionPSK(t *testing.T) {
	cfg := DefaultConfig()
	cfg.PSK = productionPSK
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Config.Validate rejected the production PSK: %v", err)
	}

	// LoadConfigFromFile is the path p2ptap-boot and the WebUI save use; the
	// singular "psk" key is the mesh-node field (p2ptap-boot's own config uses
	// the plural "psks" array and has a separate validator).
	tempDir := t.TempDir()
	path := filepath.Join(tempDir, "test_config.json")
	content := `{"tap_ip": "10.0.0.1/24", "psk": "` + productionPSK + `"}`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write temp config: %v", err)
	}
	loaded, err := LoadConfigFromFile(path)
	if err != nil {
		t.Fatalf("LoadConfigFromFile rejected the production PSK: %v", err)
	}
	if loaded.PSK != productionPSK {
		t.Fatalf("round-trip lost the PSK: got %q", loaded.PSK)
	}
}
