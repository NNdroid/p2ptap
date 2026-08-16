package node

import (
	"net"
	"testing"

	"p2ptap/pkg/config"
)

func TestBuildLocalARPEntriesIncludesLocalTAPAddresses(t *testing.T) {
	node := &Node{
		Config:    &config.Config{NodeName: "win-node"},
		localV4IP: net.ParseIP("10.0.0.3"),
		localV6IP: net.ParseIP("fd00::3"),
		localMAC:  net.HardwareAddr{0x02, 0x00, 0x5e, 0x10, 0x00, 0x03},
	}

	entries := node.buildLocalARPEntries("win-node")
	t.Logf("[arp] built %d local entries: v4=%s/%s v6=%s/%s",
		len(entries), entries[0].IP, entries[0].MAC, entries[1].IP, entries[1].Type)
	if len(entries) != 2 {
		t.Fatalf("expected 2 local ARP/NDP entries, got %d", len(entries))
	}

	if entries[0].IP != "10.0.0.3" || entries[0].MAC != "02:00:5e:10:00:03" {
		t.Fatalf("unexpected first local ARP entry: %+v", entries[0])
	}
	if entries[1].IP != "fd00::3" || entries[1].Type != "Dynamic (NDP)" {
		t.Fatalf("unexpected second local NDP entry: %+v", entries[1])
	}
	t.Log("[arp] ✓ local ARP (IPv4) + NDP (IPv6) entries correct")
}
