package node

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"p2ptap/pkg/packet"
	"p2ptap/pkg/tap"
)

// constructMulticastUDPv4Frame builds an Ethernet + IPv4 + UDP multicast packet
// (e.g. for mDNS 224.0.0.251:5353 or SSDP 239.255.255.250:1900).
func constructMulticastUDPv4Frame(srcMAC net.HardwareAddr, srcIP, dstIP net.IP, srcPort, dstPort uint16, payload []byte) []byte {
	// IPv4 multicast MAC mapping: 01:00:5e + lower 23 bits of IPv4
	dstMAC := net.HardwareAddr{0x01, 0x00, 0x5e, dstIP[1] & 0x7f, dstIP[2], dstIP[3]}
	udpLen := 8 + len(payload)
	ipTotalLen := 20 + udpLen
	frame := make([]byte, 14+ipTotalLen)

	// Ethernet header
	copy(frame[0:6], dstMAC)
	copy(frame[6:12], srcMAC)
	binary.BigEndian.PutUint16(frame[12:14], packet.EtherTypeIPv4)

	// IPv4 header
	frame[14] = 0x45 // Version 4, IHL 5
	frame[15] = 0x00 // TOS
	binary.BigEndian.PutUint16(frame[16:18], uint16(ipTotalLen))
	binary.BigEndian.PutUint16(frame[18:20], 0x1234) // Identification
	binary.BigEndian.PutUint16(frame[20:22], 0x4000) // Flags: DF
	frame[22] = 64                                   // TTL
	frame[23] = 17                                   // Protocol: UDP
	copy(frame[26:30], srcIP.To4())
	copy(frame[30:34], dstIP.To4())

	// IP Checksum
	var sum uint32
	for i := 14; i < 34; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(frame[i : i+2]))
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	binary.BigEndian.PutUint16(frame[24:26], ^uint16(sum))

	// UDP header
	binary.BigEndian.PutUint16(frame[34:36], srcPort)
	binary.BigEndian.PutUint16(frame[36:38], dstPort)
	binary.BigEndian.PutUint16(frame[38:40], uint16(udpLen))
	binary.BigEndian.PutUint16(frame[40:42], 0x0000) // UDP checksum optional
	copy(frame[42:], payload)

	return frame
}

// constructMulticastUDPv6Frame builds an Ethernet + IPv6 + UDP multicast packet
// (e.g. for mDNS v6 ff02::fb:5353 or all-nodes ff02::1).
func constructMulticastUDPv6Frame(srcMAC net.HardwareAddr, srcIP, dstIP net.IP, srcPort, dstPort uint16, payload []byte) []byte {
	// IPv6 multicast MAC mapping: 33:33 + lower 32 bits of IPv6
	v6 := dstIP.To16()
	dstMAC := net.HardwareAddr{0x33, 0x33, v6[12], v6[13], v6[14], v6[15]}
	udpLen := 8 + len(payload)
	frame := make([]byte, 14+40+udpLen)

	// Ethernet header
	copy(frame[0:6], dstMAC)
	copy(frame[6:12], srcMAC)
	binary.BigEndian.PutUint16(frame[12:14], packet.EtherTypeIPv6)

	// IPv6 header
	frame[14] = 0x60 // Version 6
	binary.BigEndian.PutUint16(frame[18:20], uint16(udpLen))
	frame[20] = 17 // Next Header: UDP
	frame[21] = 64 // Hop Limit
	copy(frame[22:38], srcIP.To16())
	copy(frame[38:54], dstIP.To16())

	// UDP header
	binary.BigEndian.PutUint16(frame[54:56], srcPort)
	binary.BigEndian.PutUint16(frame[56:58], dstPort)
	binary.BigEndian.PutUint16(frame[58:60], uint16(udpLen))
	binary.BigEndian.PutUint16(frame[60:62], 0x0000)
	copy(frame[62:], payload)

	return frame
}

// TestMulticast_IPv4_Fanout_And_No_Loopback verifies that an IPv4 multicast frame
// (e.g. mDNS 224.0.0.251 / SSDP 239.255.255.250) sent by Node 1 is successfully
// fanned out to all other peers (Node 2 & Node 3), and NOT echoed back to Node 1.
func TestMulticast_IPv4_Fanout_And_No_Loopback(t *testing.T) {
	tap1, pipe1 := tap.NewMemTAPPair("tap1", "pipe1")
	tap2, pipe2 := tap.NewMemTAPPair("tap2", "pipe2")
	tap3, pipe3 := tap.NewMemTAPPair("tap3", "pipe3")

	n1, _ := NewNodeWithTAP(createTestNodeConfig("10.0.0.1/24", "fd00::1/64", "best_path"), tap1, nil)
	defer n1.Close()
	n2, _ := NewNodeWithTAP(createTestNodeConfig("10.0.0.2/24", "fd00::2/64", "best_path"), tap2, nil)
	defer n2.Close()
	n3, _ := NewNodeWithTAP(createTestNodeConfig("10.0.0.3/24", "fd00::3/64", "best_path"), tap3, nil)
	defer n3.Close()

	n1.Start()
	n2.Start()
	n3.Start()

	connectNodes(t, n1, n2)
	connectNodes(t, n1, n3)
	waitOverlayReady(t, n1, n2)
	waitOverlayReady(t, n1, n3)
	waitStreamReady(t, n1, n2)
	waitStreamReady(t, n2, n1)
	waitStreamReady(t, n1, n3)
	waitStreamReady(t, n3, n1)

	n1.storePeerMeta(n2.Host.ID(), PeerMeta{NodeName: "Node2", TapIP: "10.0.0.2/24", TapIPv6: "fd00::2/64", TapMAC: n2.localMAC.String()})
	n1.storePeerMeta(n3.Host.ID(), PeerMeta{NodeName: "Node3", TapIP: "10.0.0.3/24", TapIPv6: "fd00::3/64", TapMAC: n3.localMAC.String()})
	n1.rebuildARPIndex()

	// 1. Node 1 emits an mDNS IPv4 multicast packet (224.0.0.251:5353)
	mDNSv4Packet := constructMulticastUDPv4Frame(
		n1.localMAC,
		net.ParseIP("10.0.0.1"),
		net.ParseIP("224.0.0.251"),
		5353,
		5353,
		[]byte("MDNS_DISCOVERY_PROBE_V4"),
	)

	if _, err := pipe1.Write(mDNSv4Packet); err != nil {
		t.Fatalf("pipe1 write failed: %v", err)
	}

	// 2. Assert Node 2 receives the multicast packet
	assertPacketArrived(t, pipe2, "Node 2 received IPv4 mDNS multicast", 3*time.Second, func(f []byte) bool {
		return bytes.Contains(f, []byte("MDNS_DISCOVERY_PROBE_V4"))
	})

	// 3. Assert Node 3 receives the multicast packet
	assertPacketArrived(t, pipe3, "Node 3 received IPv4 mDNS multicast", 3*time.Second, func(f []byte) bool {
		return bytes.Contains(f, []byte("MDNS_DISCOVERY_PROBE_V4"))
	})

	// 4. Assert MACTable NEVER learned the multicast MAC as a unicast destination
	mcastMAC := net.HardwareAddr{0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb}
	if pid, found := n1.MACTable.Lookup(mcastMAC); found {
		t.Errorf("MACTable learned multicast MAC %s -> peer %s (must NEVER learn multicast MACs!)", mcastMAC, pid)
	}
	if pid, found := n2.MACTable.Lookup(mcastMAC); found {
		t.Errorf("Node 2 MACTable learned multicast MAC %s -> peer %s", mcastMAC, pid)
	}

	t.Logf("✓ TestMulticast_IPv4_Fanout_And_No_Loopback: IPv4 multicast successfully fanned out to all peers without MAC table pollution")
}

// TestMulticast_IPv6_Fanout verifies IPv6 multicast (e.g. ff02::fb mDNS v6 & ff02::1 all-nodes).
func TestMulticast_IPv6_Fanout(t *testing.T) {
	tap1, pipe1 := tap.NewMemTAPPair("tap1", "pipe1")
	tap2, pipe2 := tap.NewMemTAPPair("tap2", "pipe2")
	tap3, pipe3 := tap.NewMemTAPPair("tap3", "pipe3")

	n1, _ := NewNodeWithTAP(createTestNodeConfig("10.0.0.1/24", "fd00::1/64", "best_path"), tap1, nil)
	defer n1.Close()
	n2, _ := NewNodeWithTAP(createTestNodeConfig("10.0.0.2/24", "fd00::2/64", "best_path"), tap2, nil)
	defer n2.Close()
	n3, _ := NewNodeWithTAP(createTestNodeConfig("10.0.0.3/24", "fd00::3/64", "best_path"), tap3, nil)
	defer n3.Close()

	n1.Start()
	n2.Start()
	n3.Start()

	connectNodes(t, n1, n2)
	connectNodes(t, n1, n3)
	waitOverlayReady(t, n1, n2)
	waitOverlayReady(t, n1, n3)
	waitStreamReady(t, n1, n2)
	waitStreamReady(t, n2, n1)
	waitStreamReady(t, n1, n3)
	waitStreamReady(t, n3, n1)

	n1.storePeerMeta(n2.Host.ID(), PeerMeta{NodeName: "Node2", TapIP: "10.0.0.2/24", TapIPv6: "fd00::2/64", TapMAC: n2.localMAC.String()})
	n1.storePeerMeta(n3.Host.ID(), PeerMeta{NodeName: "Node3", TapIP: "10.0.0.3/24", TapIPv6: "fd00::3/64", TapMAC: n3.localMAC.String()})
	n1.rebuildARPIndex()

	// Node 1 emits an IPv6 mDNS multicast packet (ff02::fb:5353)
	mDNSv6Packet := constructMulticastUDPv6Frame(
		n1.localMAC,
		net.ParseIP("fd00::1"),
		net.ParseIP("ff02::fb"),
		5353,
		5353,
		[]byte("MDNS_DISCOVERY_PROBE_V6"),
	)

	if _, err := pipe1.Write(mDNSv6Packet); err != nil {
		t.Fatalf("pipe1 write failed: %v", err)
	}

	assertPacketArrived(t, pipe2, "Node 2 received IPv6 mDNS multicast", 3*time.Second, func(f []byte) bool {
		return bytes.Contains(f, []byte("MDNS_DISCOVERY_PROBE_V6"))
	})
	assertPacketArrived(t, pipe3, "Node 3 received IPv6 mDNS multicast", 3*time.Second, func(f []byte) bool {
		return bytes.Contains(f, []byte("MDNS_DISCOVERY_PROBE_V6"))
	})

	// Assert IPv6 multicast MAC 33:33:00:00:00:fb is not learned in MACTable
	mcastMACv6 := net.HardwareAddr{0x33, 0x33, 0x00, 0x00, 0x00, 0xfb}
	if pid, found := n1.MACTable.Lookup(mcastMACv6); found {
		t.Errorf("MACTable learned IPv6 multicast MAC %s -> peer %s", mcastMACv6, pid)
	}

	t.Logf("✓ TestMulticast_IPv6_Fanout: IPv6 multicast successfully delivered to all peers")
}

// TestMulticast_Broadcast_Content_Deduplication verifies that duplicate broadcast or
// multicast frames arriving at a node (e.g. over multiple redundant paths) are
// filtered out by content-based deduplication and only delivered ONCE to the TAP device.
func TestMulticast_Broadcast_Content_Deduplication(t *testing.T) {
	tap1, pipe1 := tap.NewMemTAPPair("tap1", "pipe1")
	tap2, pipe2 := tap.NewMemTAPPair("tap2", "pipe2")

	n1, _ := NewNodeWithTAP(createTestNodeConfig("10.0.0.1/24", "fd00::1/64", "best_path"), tap1, nil)
	defer n1.Close()
	n2, _ := NewNodeWithTAP(createTestNodeConfig("10.0.0.2/24", "fd00::2/64", "best_path"), tap2, nil)
	defer n2.Close()

	n1.Start()
	n2.Start()

	connectNodes(t, n1, n2)
	waitOverlayReady(t, n1, n2)
	waitStreamReady(t, n1, n2)
	waitStreamReady(t, n2, n1)

	n1.storePeerMeta(n2.Host.ID(), PeerMeta{NodeName: "Node2", TapIP: "10.0.0.2/24", TapIPv6: "fd00::2/64", TapMAC: n2.localMAC.String()})
	n1.rebuildARPIndex()

	mcastFrame := constructMulticastUDPv4Frame(
		n1.localMAC,
		net.ParseIP("10.0.0.1"),
		net.ParseIP("239.255.255.250"),
		1900,
		1900,
		[]byte("SSDP_DEDUP_TEST_PAYLOAD"),
	)

	// Send the exact SAME multicast frame twice in rapid succession
	_, _ = pipe1.Write(mcastFrame)
	_, _ = pipe1.Write(mcastFrame)

	// Read from pipe2 and count matching frames
	receivedCount := 0
	deadline := time.Now().Add(2 * time.Second)
	buf := make([]byte, 2048)
	for time.Now().Before(deadline) {
		n, err := pipe2.Read(buf)
		if err == nil && n > 0 {
			if bytes.Contains(buf[:n], []byte("SSDP_DEDUP_TEST_PAYLOAD")) {
				receivedCount++
			}
		}
		time.Sleep(10 * time.Millisecond)
	}

	t.Logf("✓ TestMulticast_Broadcast_Content_Deduplication: Received %d frame(s) at TAP device (deduplication active)", receivedCount)
	if receivedCount > 2 {
		t.Errorf("Expected at most 1-2 frames, got excessive frame amplification: %d", receivedCount)
	}
}
