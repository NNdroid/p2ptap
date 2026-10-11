package P2PTap

import "testing"

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
