package P2PTap

import (
	"strings"
	"testing"
)

// TestValidateConfigErrorDoesNotRepeatPrefix: Config.Validate already starts its
// message with "invalid config:", so wrapping it with the same words produced
// "android: invalid config: invalid config: psk: ..." in device logs.
func TestValidateConfigErrorDoesNotRepeatPrefix(t *testing.T) {
	cfg := `{"psk":"s3cret"}` // too short, so Validate fails deterministically
	err := ValidateConfig(cfg)
	if err == nil {
		t.Fatal("expected validation to fail for a 6-character PSK")
	}
	msg := err.Error()
	if !strings.Contains(msg, "android: ") {
		t.Errorf("platform marker lost: %q", msg)
	}
	if strings.Contains(msg, "invalid config: invalid config:") {
		t.Errorf("prefix duplicated: %q", msg)
	}
	if !strings.HasPrefix(msg, "android: invalid config: ") {
		t.Errorf("unexpected error shape: %q", msg)
	}
}

func TestValidateConfigWithoutStartingEngine(t *testing.T) {
	for _, strategy := range []string{"best_path", "redundant", "fallback"} {
		if err := ValidateConfig(`{"transport_strategy":"` + strategy + `","bootstrap_peers":[],"static_peers":[]}`); err != nil {
			t.Fatal(err)
		}
	}
	for _, cfg := range []string{
		`{"transport_strategy":""}`, `{"transport_strategy":"BEST_PATH"}`,
		`{"static_peers":["192.0.2.1"]}`, `{"exit_node":{"enable":true}}`, `{broken`,
	} {
		if err := ValidateConfig(cfg); err == nil {
			t.Fatalf("accepted invalid candidate %s", cfg)
		}
	}
}

// TestValidateConfigAcceptsServerPSK is the regression for the Android launch
// failure: the VPN refused to start with "psk: 64 characters exceeds the
// 32-character maximum" for the 32-byte key the bootstrap server ships.
func TestValidateConfigAcceptsServerPSK(t *testing.T) {
	const serverPSK = "2d5c54ee79fcd3855c23d521c413985e23ad5f31cf039737fd28d84f98683b39"
	cfg := `{"tap_ip":"10.0.0.1/24","psk":"` + serverPSK + `","bootstrap_peers":[],"static_peers":[]}`
	if err := ValidateConfig(cfg); err != nil {
		t.Fatalf("ValidateConfig rejected the server's own 64-hex-char PSK: %v", err)
	}
}
