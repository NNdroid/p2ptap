package vswitch

import (
	"net"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
)

func TestMACTableLearnAndLookup(t *testing.T) {
	table := NewMACTable()
	peerA := peer.ID("12D3KooWPeerA")
	peerB := peer.ID("12D3KooWPeerB")

	macA := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	macB := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x02}

	table.Learn(macA, peerA)
	table.Learn(macB, peerB)
	t.Logf("[mac-table] learned macA=%s->%s macB=%s->%s", macA, peerA, macB, peerB)

	foundPeer, ok := table.Lookup(macA)
	if !ok || foundPeer != peerA {
		t.Errorf("Lookup macA expected %s, got %s (found: %v)", peerA, foundPeer, ok)
	} else {
		t.Logf("[mac-table] ✓ lookup macA -> %s", foundPeer)
	}

	foundPeer, ok = table.Lookup(macB)
	if !ok || foundPeer != peerB {
		t.Errorf("Lookup macB expected %s, got %s (found: %v)", peerB, foundPeer, ok)
	} else {
		t.Logf("[mac-table] ✓ lookup macB -> %s", foundPeer)
	}

	unknownMAC := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x99}
	_, ok = table.Lookup(unknownMAC)
	if ok {
		t.Error("Expected unknown MAC lookup to return false")
	} else {
		t.Logf("[mac-table] ✓ unknown MAC %s not found", unknownMAC)
	}
}

func TestBroadcastAndMulticastDetection(t *testing.T) {
	bcast := net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	if !IsBroadcastOrMulticast(bcast) {
		t.Error("Expected broadcast MAC to return true")
	} else {
		t.Log("[mac-table] ✓ ff:ff:ff:ff:ff:ff detected as broadcast")
	}

	ipv4Multicast := net.HardwareAddr{0x01, 0x00, 0x5e, 0x00, 0x00, 0x01}
	if !IsBroadcastOrMulticast(ipv4Multicast) {
		t.Error("Expected IPv4 multicast MAC to return true")
	} else {
		t.Log("[mac-table] ✓ 01:00:5e:.. detected as IPv4 multicast")
	}

	ipv6Multicast := net.HardwareAddr{0x33, 0x33, 0x00, 0x00, 0x00, 0x01}
	if !IsBroadcastOrMulticast(ipv6Multicast) {
		t.Error("Expected IPv6 multicast MAC to return true")
	} else {
		t.Log("[mac-table] ✓ 33:33:.. detected as IPv6 multicast")
	}

	unicast := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	if IsBroadcastOrMulticast(unicast) {
		t.Error("Expected unicast MAC to return false")
	} else {
		t.Log("[mac-table] ✓ unicast 02:00:00:00:00:01 correctly not flagged")
	}
}

func TestMACCleanStale(t *testing.T) {
	table := NewMACTable()
	peerA := peer.ID("12D3KooWPeerA")
	macA := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}

	table.Learn(macA, peerA)
	t.Logf("[mac-table] learned macA=%s; will sleep 10ms then CleanStale(1ms)", macA)

	// Clean entries older than 1ms after sleeping 10ms
	time.Sleep(10 * time.Millisecond)
	table.CleanStale(1 * time.Millisecond)

	_, ok := table.Lookup(macA)
	if ok {
		t.Error("Expected stale MAC entry to be cleaned, but it was found")
	} else {
		t.Log("[mac-table] ✓ stale entry cleaned")
	}
}

func TestExtractEthernetMACs(t *testing.T) {
	dummyFrame := []byte{
		0x02, 0x00, 0x00, 0x00, 0x00, 0x02, // Dst MAC
		0x02, 0x00, 0x00, 0x00, 0x00, 0x01, // Src MAC
		0x08, 0x00,                         // EtherType IPv4
		0x45, 0x00, 0x00, 0x20,
	}
	t.Logf("[mac-table] extract MACs from %d-byte frame", len(dummyFrame))

	dst, src, err := ExtractEthernetMACs(dummyFrame)
	if err {
		t.Fatal("Failed to extract Ethernet MACs")
	}
	if dst.String() != "02:00:00:00:00:02" {
		t.Errorf("Dst MAC extracted incorrectly: %s", dst.String())
	}
	if src.String() != "02:00:00:00:00:01" {
		t.Errorf("Src MAC extracted incorrectly: %s", src.String())
	}
	t.Logf("[mac-table] ✓ dst=%s src=%s", dst, src)
}
