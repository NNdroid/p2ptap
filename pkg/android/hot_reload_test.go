package P2PTap

import (
	"encoding/json"
	"testing"

	"p2ptap/pkg/config"
)

// sentKeys parses a JSON object and returns the set of keys present in it —
// the same shape ApplyHotReload hands to mergeHotReload.
func sentKeys(t *testing.T, raw string) map[string]bool {
	t.Helper()
	var fields map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &fields); err != nil {
		t.Fatalf("parsing %q: %v", raw, err)
	}
	sent := make(map[string]bool, len(fields))
	for k := range fields {
		sent[k] = true
	}
	return sent
}

// applyPartialUpdate reproduces the exact order ApplyHotReload uses to turn a
// partial config JSON into the next running snapshot: start from the running
// config, unmarshal the incoming JSON over that copy, then let mergeHotReload
// carry over every field the JSON did not mention. Tests call this instead of
// mergeHotReload directly so they exercise the real sequence — the unmarshal is
// what puts an explicit "" or [] into the candidate in the first place, and
// without it the merge has nothing to reconcile.
func applyPartialUpdate(t *testing.T, running *config.Config, raw string) config.Config {
	t.Helper()
	candidate := *running
	sent := sentKeys(t, raw)
	if err := json.Unmarshal([]byte(raw), &candidate); err != nil {
		t.Fatalf("unmarshalling %q: %v", raw, err)
	}
	mergeHotReload(&candidate, running, sent)
	return candidate
}

// TestMergeHotReloadPreservesSecurityFields guards the regression where
// ApplyHotReload seeded DefaultConfig() instead of the running config: any key
// a partial reload left out came back as its default, so omitting web_ui wiped
// the dashboard auth token and omitting acl switched the mesh firewall off.
func TestMergeHotReloadPreservesSecurityFields(t *testing.T) {
	running := &config.Config{
		NodeName:                "node-a",
		PSK:                     "running-mesh-secret",
		WebUI:                   config.WebUIConfig{AuthToken: "running-dashboard-token", Port: 15858},
		ACL:                     config.ACLConfig{Enable: true, DefaultAction: "deny"},
		AdvertisedSubnets:       []string{"192.168.1.0/24"},
		AcceptAdvertisedSubnets: true,
		EnableMDNS:              true,
		Transports:              config.TransportsConfig{TLSServerName: "chat.example.com"},
		ConfigPath:              "/etc/p2ptap/config.json",
	}

	dst := applyPartialUpdate(t, running, `{"node_name":"node-b","node_key_file":"node.key"}`)

	if dst.WebUI.AuthToken != "running-dashboard-token" {
		t.Errorf("web_ui.auth_token wiped by a reload that never mentioned web_ui: %q", dst.WebUI.AuthToken)
	}
	if dst.WebUI.Port != 15858 {
		t.Errorf("web_ui.port wiped by a reload that never mentioned web_ui: %d", dst.WebUI.Port)
	}
	if dst.ACL.Enable != true || dst.ACL.DefaultAction != "deny" {
		t.Errorf("ACL reset by a reload that never mentioned acl: %+v", dst.ACL)
	}
	if len(dst.AdvertisedSubnets) != 1 || dst.AdvertisedSubnets[0] != "192.168.1.0/24" {
		t.Errorf("advertised_subnets wiped by a reload that never mentioned them: %v", dst.AdvertisedSubnets)
	}
	if !dst.AcceptAdvertisedSubnets {
		t.Error("accept_advertised_subnets reset by a reload that never mentioned it")
	}
	if !dst.EnableMDNS {
		t.Error("enable_mdns reset by a reload that never mentioned it")
	}
	if dst.Transports.TLSServerName != "chat.example.com" {
		t.Errorf("transports reset by a reload that never mentioned them: %+v", dst.Transports)
	}
	if dst.ConfigPath != "/etc/p2ptap/config.json" {
		t.Errorf("json:\"-\" field ConfigPath dropped: %q", dst.ConfigPath)
	}
	if dst.PSK != "running-mesh-secret" {
		t.Errorf("PSK lost by a reload that never mentioned psk: %q", dst.PSK)
	}
	if dst.NodeName != "node-b" {
		t.Errorf("explicit change ignored: node_name=%q", dst.NodeName)
	}
	if dst.NodeKeyFile != "node.key" {
		t.Errorf("explicit change ignored: node_key_file=%q", dst.NodeKeyFile)
	}
}

// TestMergeHotReloadSentinelScalarsCannotBeCleared: an empty node name and an
// empty PSK are not valid requests to clear, so the running value wins — but the
// same request shape for a bool must stick, because bools have no zero value
// and presence alone is the only signal.
func TestMergeHotReloadSentinelScalarsCannotBeCleared(t *testing.T) {
	running := &config.Config{NodeName: "node-a", PSK: "running-mesh-secret", MTU: 1400, EnableMDNS: true}

	dst := applyPartialUpdate(t, running, `{"node_name":"","psk":"","mtu":0,"enable_mdns":false}`)
	if dst.NodeName != "node-a" || dst.PSK != "running-mesh-secret" || dst.MTU != 1400 {
		t.Errorf("zero values cleared sentinel scalars: node_name=%q psk=%q mtu=%d",
			dst.NodeName, dst.PSK, dst.MTU)
	}
	if dst.EnableMDNS {
		t.Error("explicit enable_mdns:false was ignored — bools must honor presence")
	}
}

// TestMergeHotReloadEmptyListStillClears: an empty slice IS a valid setting,
// so presence alone must let an explicit [] win over the running value.
func TestMergeHotReloadEmptyListStillClears(t *testing.T) {
	running := &config.Config{
		AdvertisedSubnets:  []string{"192.168.1.0/24"},
		AllowedSubnetPeers: []string{"*"},
		StaticPeers:        []string{"/ip4/192.0.2.1/tcp/4001/p2p/12D3KooWB"},
	}

	dst := applyPartialUpdate(t, running, `{"advertised_subnets":[],"allowed_subnet_peers":[],"static_peers":[]}`)
	if len(dst.AdvertisedSubnets) != 0 {
		t.Errorf("explicit empty advertised_subnets ignored: %v", dst.AdvertisedSubnets)
	}
	if len(dst.AllowedSubnetPeers) != 0 {
		t.Errorf("explicit empty allowed_subnet_peers ignored: %v", dst.AllowedSubnetPeers)
	}
	if len(dst.StaticPeers) != 0 {
		t.Errorf("explicit empty static_peers ignored: %v", dst.StaticPeers)
	}
}
