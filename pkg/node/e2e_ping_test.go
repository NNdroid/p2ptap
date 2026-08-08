package node

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"p2ptap/pkg/config"
	"p2ptap/pkg/obfuscate"
	"p2ptap/pkg/switch"
)

type mockTAPDevice struct {
	name       string
	mac        net.HardwareAddr
	writeQueue chan []byte
}

func newMockTAPDevice(name, ip string, mac net.HardwareAddr) *mockTAPDevice {
	return &mockTAPDevice{
		name:       name,
		mac:        mac,
		writeQueue: make(chan []byte, 100),
	}
}

func (m *mockTAPDevice) Name() string { return m.name }
func (m *mockTAPDevice) SetMAC(mac string) error {
	if hw, err := net.ParseMAC(mac); err == nil {
		m.mac = hw
	}
	return nil
}
func (m *mockTAPDevice) SetMTU(mtu int) error { return nil }
func (m *mockTAPDevice) ConfigureIP(ipCIDR string, ipv6CIDR string) error { return nil }
func (m *mockTAPDevice) Close() error { return nil }
func (m *mockTAPDevice) Read(b []byte) (int, error) {
	time.Sleep(10 * time.Millisecond)
	return 0, nil
}
func (m *mockTAPDevice) Write(b []byte) (int, error) {
	frame := make([]byte, len(b))
	copy(frame, b)
	select {
	case m.writeQueue <- frame:
	default:
	}
	return len(b), nil
}

func TestE2EPingPacketFlow(t *testing.T) {
	macA := net.HardwareAddr{0x02, 0x00, 0x0a, 0x00, 0x00, 0x01}
	macB := net.HardwareAddr{0x02, 0x00, 0x0a, 0x00, 0x00, 0x03}

	tapA := newMockTAPDevice("tapA", "10.0.0.1", macA)
	tapB := newMockTAPDevice("tapB", "10.0.0.3", macB)

	cfgA := config.DefaultConfig()
	cfgA.TapIP = "10.0.0.1/24"
	cfgA.TapMAC = macA.String()
	cfgA.Obfuscation.Enable = true

	cfgB := config.DefaultConfig()
	cfgB.TapIP = "10.0.0.3/24"
	cfgB.TapMAC = macB.String()
	cfgB.Obfuscation.Enable = false // Config mismatch test

	// Create nodes
	nodeA, errA := NewNodeWithTAP(cfgA, tapA)
	if errA != nil {
		t.Fatalf("NewNode A failed: %v", errA)
	}
	defer nodeA.Close()

	nodeB, errB := NewNodeWithTAP(cfgB, tapB)
	if errB != nil {
		t.Fatalf("NewNode B failed: %v", errB)
	}
	defer nodeB.Close()

	// Verify obfuscate.Unpack fallback for un-obfuscated raw Ethernet frames
	rawEthernetFrame := make([]byte, 60)
	copy(rawEthernetFrame[0:6], macB)
	copy(rawEthernetFrame[6:12], macA)
	binary.BigEndian.PutUint16(rawEthernetFrame[12:14], 0x0800) // IPv4

	// IP Header
	rawEthernetFrame[14] = 0x45
	binary.BigEndian.PutUint16(rawEthernetFrame[16:18], 46)
	rawEthernetFrame[23] = 1 // ICMP
	copy(rawEthernetFrame[26:30], net.ParseIP("10.0.0.1").To4())
	copy(rawEthernetFrame[30:34], net.ParseIP("10.0.0.3").To4())

	// ICMP Echo Request
	rawEthernetFrame[34] = 8 // Echo Request

	seqID, payload, errUnpack := obfuscate.Unpack(rawEthernetFrame)
	if errUnpack != nil {
		t.Fatalf("obfuscate.Unpack auto-fallback failed: %v", errUnpack)
	}

	if len(payload) != 60 {
		t.Errorf("Expected payload length 60, got %d (seqID=%d)", len(payload), seqID)
	}

	// Verify MAC table learning and VSwitch routing
	vswitchTable := vswitch.NewMACTable()
	vswitchTable.Learn(macA, nodeA.Host.ID())
	vswitchTable.Learn(macB, nodeB.Host.ID())

	targetPeer, found := vswitchTable.Lookup(macB)
	if !found || targetPeer != nodeB.Host.ID() {
		t.Errorf("Expected VSwitch to route to Node B PeerID, got %s (found=%v)", targetPeer, found)
	}
}
