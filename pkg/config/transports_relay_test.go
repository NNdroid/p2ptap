package config

import "testing"

// The relay flags used to be one boolean that bundled libp2p circuit relay +
// AutoRelay with DCUtR hole-punching. They are split now, and disable_relay is
// kept as a legacy umbrella so existing configs keep their meaning. These tests
// pin the full truth table so the umbrella cannot silently stop dominating the
// specific flags.
func TestTransportsRelayGating(t *testing.T) {
	tests := []struct {
		name     string
		cfg      TransportsConfig
		relay    bool
		punching bool
	}{
		{"nothing disabled", TransportsConfig{}, true, true},
		{"only circuit relay off", TransportsConfig{DisableCircuitRelay: true}, false, true},
		{"only hole punching off", TransportsConfig{DisableHolePunching: true}, true, false},
		{"both specific flags off", TransportsConfig{DisableCircuitRelay: true, DisableHolePunching: true}, false, false},
		{"legacy umbrella off", TransportsConfig{DisableRelay: true}, false, false},
		{"umbrella plus circuit relay", TransportsConfig{DisableRelay: true, DisableCircuitRelay: true}, false, false},
		{"umbrella plus hole punching", TransportsConfig{DisableRelay: true, DisableHolePunching: true}, false, false},
		{"all three set", TransportsConfig{DisableRelay: true, DisableCircuitRelay: true, DisableHolePunching: true}, false, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.cfg.CircuitRelayEnabled(); got != tc.relay {
				t.Errorf("CircuitRelayEnabled() = %v, want %v", got, tc.relay)
			}
			if got := tc.cfg.HolePunchingEnabled(); got != tc.punching {
				t.Errorf("HolePunchingEnabled() = %v, want %v", got, tc.punching)
			}
		})
	}
}

// The regression this exists to catch: an operator who had disable_relay=true
// must not suddenly get circuit relay and hole punching back just because a new
// engine version added two more fine-grained flags. The umbrella has to win.
func TestDisableRelayIsLegacyUmbrella(t *testing.T) {
	cfg := TransportsConfig{DisableRelay: true, DisableCircuitRelay: false, DisableHolePunching: false}
	if cfg.CircuitRelayEnabled() || cfg.HolePunchingEnabled() {
		t.Fatalf("disable_relay=true must disable both features regardless of the specific flags, got relay=%v punching=%v",
			cfg.CircuitRelayEnabled(), cfg.HolePunchingEnabled())
	}
}

func TestDisabledRelayFeatures(t *testing.T) {
	tests := []struct {
		name string
		cfg  TransportsConfig
		want []string
	}{
		{"all enabled", TransportsConfig{}, nil},
		{"circuit only", TransportsConfig{DisableCircuitRelay: true}, []string{"circuit relay + AutoRelay"}},
		{"punching only", TransportsConfig{DisableHolePunching: true}, []string{"hole punching"}},
		{"both specific", TransportsConfig{DisableCircuitRelay: true, DisableHolePunching: true},
			[]string{"circuit relay + AutoRelay", "hole punching"}},
		{"umbrella reports both", TransportsConfig{DisableRelay: true, DisableHolePunching: false},
			[]string{"circuit relay + AutoRelay", "hole punching"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.cfg.DisabledRelayFeatures()
			if len(got) == 0 && len(tc.want) == 0 {
				return
			}
			if len(got) != len(tc.want) {
				t.Fatalf("DisabledRelayFeatures() = %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("DisabledRelayFeatures()[%d] = %q, want %q", i, got[i], tc.want[i])
				}
			}
		})
	}
}

// These two fields must participate in restart-required detection, because they
// become libp2p.New options at host construction time and cannot be unwound.
// The comparison is on the whole TransportsConfig struct, so this pins that a
// flip of either new field alone is reported.
func TestRestartRequiredFieldsRelaySplit(t *testing.T) {
	base := DefaultConfig()
	if base == nil {
		t.Fatal("DefaultConfig() returned nil")
	}
	for name, mutate := range map[string]func(*Config){
		"circuit relay":   func(c *Config) { c.Transports.DisableCircuitRelay = true },
		"hole punching":   func(c *Config) { c.Transports.DisableHolePunching = true },
		"legacy umbrella": func(c *Config) { c.Transports.DisableRelay = true },
		"tls server name": func(c *Config) { c.Transports.TLSServerName = "www.example.com" },
	} {
		newCfg := *base
		mutate(&newCfg)
		fields := RestartRequiredFields(base, &newCfg)
		if len(fields) != 1 || fields[0] != "transports" {
			t.Errorf("%s: RestartRequiredFields = %v, want [transports]", name, fields)
		}
	}
}
