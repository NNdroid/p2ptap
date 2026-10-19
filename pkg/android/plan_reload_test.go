package P2PTap

import (
	"encoding/json"
	"testing"

	"p2ptap/pkg/config"
)

// baseEngineJSON is a fully-populated config so that every field, including
// tap_mac, is present in the JSON. Fields that DefaultConfig generates randomly
// and that are absent from the JSON would differ between two parses and make
// PlanReload report "reload" for an unchanged config.
func baseEngineJSON(t *testing.T) string {
	t.Helper()
	return marshalConfig(t, config.DefaultConfig())
}

// mutateEngineJSON derives a variant from the SAME baseline JSON, so the only
// difference between base and the variant is whatever fn changes. Unmarshalling
// base over a fresh DefaultConfig matters: DefaultConfig invents a new random
// tap_mac every call, and tapping that would make every variant look changed for
// the wrong reason.
func mutateEngineJSON(t *testing.T, base string, fn func(*config.Config)) string {
	t.Helper()
	cfg := config.DefaultConfig()
	if cfg == nil {
		t.Fatal("DefaultConfig() returned nil")
	}
	if err := json.Unmarshal([]byte(base), cfg); err != nil {
		t.Fatalf("unmarshal base: %v", err)
	}
	fn(cfg)
	return marshalConfig(t, cfg)
}

func marshalConfig(t *testing.T, cfg *config.Config) string {
	t.Helper()
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	return string(data)
}

func TestPlanReloadIdenticalIsNoop(t *testing.T) {
	base := baseEngineJSON(t)
	if got := PlanReload(base, base); got != PlanVerdictNoop {
		t.Errorf("PlanReload(same, same) = %q, want %q", got, PlanVerdictNoop)
	}
}

func TestPlanReloadEmptyInputs(t *testing.T) {
	if got := PlanReload("", ""); got != PlanVerdictNoop {
		t.Errorf("PlanReload(\"\", \"\") = %q, want %q", got, PlanVerdictNoop)
	}
	// Nothing known to be running -> the caller must build the node from scratch.
	if got := PlanReload("", baseEngineJSON(t)); got != PlanVerdictRestart {
		t.Errorf("PlanReload(\"\", new) = %q, want %q", got, PlanVerdictRestart)
	}
}

func TestPlanReloadUnparseableInputsAreRestart(t *testing.T) {
	base := baseEngineJSON(t)
	for name, pair := range map[string][2]string{
		"malformed new": {"{\"node_name\":\"a\"}", `{"transports": {`},
		"malformed old": {`{"transports": {`, base},
	} {
		if got := PlanReload(pair[0], pair[1]); got != PlanVerdictRestart {
			t.Errorf("%s: PlanReload = %q, want %q", name, got, PlanVerdictRestart)
		}
	}
}

// These are the fields the engine explicitly documents as hot-reloadable: the
// running consumer reads the live snapshot, or a dedicated On*Changed callback
// re-applies them.
func TestPlanReloadHotFields(t *testing.T) {
	base := baseEngineJSON(t)
	for name, fn := range map[string]func(*config.Config){
		"log level":            func(c *config.Config) { c.LogLevel = "debug" },
		"obfuscation enable":   func(c *config.Config) { c.Obfuscation.Enable = false },
		"stun servers":         func(c *config.Config) { c.StunServers = []string{"stun.example.com:3478"} },
		"acl rules":            func(c *config.Config) { c.ACL.Enable = true; c.ACL.DefaultAction = "accept" },
		"accept subnets":       func(c *config.Config) { c.AcceptAdvertisedSubnets = true },
		"advertised subnets":   func(c *config.Config) { c.AdvertisedSubnets = []string{"192.168.50.0/24"} },
		"allowed subnet peers": func(c *config.Config) { c.AllowedSubnetPeers = []string{"*"} },
		"turn servers":         func(c *config.Config) { c.TurnServers = []string{"turn:turn.example.com:3478"} },
	} {
		if got := PlanReload(base, mutateEngineJSON(t, base, fn)); got != PlanVerdictReload {
			t.Errorf("%s: PlanReload = %q, want %q", name, got, PlanVerdictReload)
		}
	}
}

func TestPlanReloadRestartFields(t *testing.T) {
	base := baseEngineJSON(t)
	for name, fn := range map[string]func(*config.Config){
		"tap ip":              func(c *config.Config) { c.TapIP = "10.1.0.1/24" },
		"tap mac":             func(c *config.Config) { c.TapMAC = "aa:bb:cc:dd:ee:ff" },
		"mtu":                 func(c *config.Config) { c.MTU = 1280 },
		"psk":                 func(c *config.Config) { c.PSK = "secret" },
		"node name":           func(c *config.Config) { c.NodeName = "changed" },
		"transport strategy":  func(c *config.Config) { c.TransportStrategy = "redundant" },
		"listen addrs":        func(c *config.Config) { c.ListenAddrs = []string{"0.0.0.0:443"} },
		"enable mdns":         func(c *config.Config) { c.EnableMDNS = false },
		"force private reach": func(c *config.Config) { c.ForcePrivateReachability = true },
		"hole punch timeout":  func(c *config.Config) { c.HolePunchTimeout = 40_000_000_000 },
		"relay upgrade":       func(c *config.Config) { c.RelayUpgradeInterval = 600_000_000_000 },
		"webui port":          func(c *config.Config) { c.WebUI.Port = 18080 },
		"webui token":         func(c *config.Config) { c.WebUI.AuthToken = "rotated" },
		"static peers":        func(c *config.Config) { c.StaticPeers = []string{"endpoint"} },
	} {
		if got := PlanReload(base, mutateEngineJSON(t, base, fn)); got != PlanVerdictRestart {
			t.Errorf("%s: PlanReload = %q, want %q", name, got, PlanVerdictRestart)
		}
	}
}

// The relay split is the point of this test: the two new fine-grained flags must
// be restart-required on their own, and the legacy umbrella must still mean
// "everything relaying off". If any of these came back "reload", a user flipping
// the toggle in the UI would see "saved and applied" while the running node kept
// its old relay behaviour.
func TestPlanReloadRelaySplit(t *testing.T) {
	base := baseEngineJSON(t)
	for name, fn := range map[string]func(*config.Config){
		"disable circuit relay": func(c *config.Config) { c.Transports.DisableCircuitRelay = true },
		"disable hole punching": func(c *config.Config) { c.Transports.DisableHolePunching = true },
		"legacy disable relay":  func(c *config.Config) { c.Transports.DisableRelay = true },
	} {
		if got := PlanReload(base, mutateEngineJSON(t, base, fn)); got != PlanVerdictRestart {
			t.Errorf("%s: PlanReload = %q, want %q", name, got, PlanVerdictRestart)
		}
	}
}

// A restart-required change plus a hot change must still report restart, and the
// hot part must not mask it.
func TestPlanReloadRestartWinsOverHot(t *testing.T) {
	base := baseEngineJSON(t)
	fn := func(c *config.Config) {
		c.MTU = 1280
		c.LogLevel = "debug"
	}
	if got := PlanReload(base, mutateEngineJSON(t, base, fn)); got != PlanVerdictRestart {
		t.Errorf("PlanReload = %q, want %q", got, PlanVerdictRestart)
	}
}

// Android's own exit-node and DNS settings are applied outside the engine, so
// they never appear in these JSONs and are Android's business to restart on.
// This pins that PlanReload does not claim knowledge of them: an unknown
// top-level key passes through untouched instead of being mistaken for a
// change.
func TestPlanReloadIgnoresUnmodelledFields(t *testing.T) {
	base := baseEngineJSON(t)
	// Insert before the closing brace: base already ends with "}".
	mutated := base[:len(base)-1] + `, "dns_servers": ["1.1.1.1"]}`
	if got := PlanReload(base, mutated); got != PlanVerdictNoop {
		t.Errorf("PlanReload with an unknown key = %q, want %q", got, PlanVerdictNoop)
	}
}
