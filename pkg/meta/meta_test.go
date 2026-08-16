package meta

import (
	"encoding/json"
	"testing"
)

func TestNodeMetaPayloadJSONRoundTrip(t *testing.T) {
	t.Log("[meta] NodeMetaPayload JSON marshal -> unmarshal round-trip")
	p := NodeMetaPayload{
		NodeName:          "r5s-ndjc0",
		TapIP:             "10.0.0.5",
		TapIPv6:           "fd00::5",
		TapMAC:            "7a:9a:bc:de:f0:12",
		OS:                "linux",
		Arch:              "arm64",
		Version:           "v1.2.3",
		IsExitNode:        true,
		AdvertisedSubnets: []string{"192.168.1.0/24", "10.10.0.0/16"},
	}

	data, err := json.Marshal(&p)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var got NodeMetaPayload
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if got.NodeName != p.NodeName || got.TapIP != p.TapIP || got.TapIPv6 != p.TapIPv6 ||
		got.TapMAC != p.TapMAC || got.OS != p.OS || got.Arch != p.Arch ||
		got.Version != p.Version || got.IsExitNode != p.IsExitNode {
		t.Errorf("scalar fields mismatch:\n got %+v\nwant %+v", got, p)
	}
	if len(got.AdvertisedSubnets) != len(p.AdvertisedSubnets) {
		t.Fatalf("AdvertisedSubnets len = %d, want %d", len(got.AdvertisedSubnets), len(p.AdvertisedSubnets))
	}
	for i, s := range p.AdvertisedSubnets {
		if got.AdvertisedSubnets[i] != s {
			t.Errorf("AdvertisedSubnets[%d] = %q, want %q", i, got.AdvertisedSubnets[i], s)
		}
	}
	t.Logf("[meta] ✓ round-trip preserved name=%s tapIP=%s subnets=%v", got.NodeName, got.TapIP, got.AdvertisedSubnets)
}

func TestNodeMetaPayloadJSONFieldNames(t *testing.T) {
	t.Log("[meta] serialized JSON contains expected field names")
	p := NodeMetaPayload{NodeName: "x", AdvertisedSubnets: []string{"10.0.0.0/8"}}
	data, err := json.Marshal(&p)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	s := string(data)
	for _, want := range []string{"node_name", "tap_ip", "advertised_subnets"} {
		if !contains(s, want) {
			t.Errorf("serialized payload missing field %q: %s", want, s)
		}
	}
}

func contains(haystack, needle string) bool {
	if needle == "" {
		return true
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
