//go:build windows

package tap

import (
	"net"
	"testing"
)

func TestWintunDynamicMACLearning(t *testing.T) {
	dev := &WintunTAPDevice{
		localMAC:   net.HardwareAddr{0x02, 0x00, 0x5e, 0x10, 0x00, 0x01},
		localIP:    net.ParseIP("10.0.0.1"),
		ipToMacMap: make(map[string]net.HardwareAddr),
	}
	t.Log("[wintun] dynamic MAC learning: localMAC=02:00:5e:10:00:01 localIP=10.0.0.1")

	peerMAC := net.HardwareAddr{0x52, 0x54, 0x00, 0x12, 0x34, 0x56}
	peerIP := "10.0.0.2"

	// Record MAC
	dev.recordMAC(peerIP, peerMAC)
	t.Logf("[wintun] recorded peerIP=%s -> peerMAC=%s", peerIP, peerMAC)

	// Lookup MAC
	learned := dev.lookupMAC(peerIP)
	if learned == nil {
		t.Fatalf("Expected learned MAC for %s, got nil", peerIP)
	}

	if learned.String() != peerMAC.String() {
		t.Errorf("Expected learned MAC %s, got %s", peerMAC.String(), learned.String())
	} else {
		t.Logf("[wintun] ✓ lookup peerIP=%s -> %s", peerIP, learned)
	}
}
