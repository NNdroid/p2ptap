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
