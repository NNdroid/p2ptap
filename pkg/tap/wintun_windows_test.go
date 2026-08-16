//go:build windows

package tap

import (
	"net"
	"testing"
)

// TestMulticastDstMAC_MDNS verifies the Wintun L3 path maps mDNS group
// addresses to the correct Ethernet multicast MAC (not broadcast), so mDNS
// frames are delivered to the right socket on the receiving host instead of
// being treated as broadcast.
func TestMulticastDstMAC_MDNS(t *testing.T) {
	cases := []struct {
		name   string
		dstIP  net.IP
		want   net.HardwareAddr
	}{
		{
			name:  "mDNS IPv4 224.0.0.251",
			dstIP: net.IPv4(224, 0, 0, 251),
			// 01:00:5e:00:00:fb  (RFC 1112: 01:00:5e:00:00:00 | low 23 bits of 0.0.0.251)
			want: net.HardwareAddr{0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb},
		},
		{
			name:  "mDNS IPv6 FF02::FB",
			dstIP: net.ParseIP("ff02::fb"),
			// 33:33:00:00:00:fb
			want: net.HardwareAddr{0x33, 0x33, 0x00, 0x00, 0x00, 0xfb},
		},
		{
			name:  "SSDP IPv4 239.255.255.250",
			dstIP: net.IPv4(239, 255, 255, 250),
			// 01:00:5e:7f:ff:fa  (239 = 0xef, low 7 bits = 0x6f = 111, top bit cleared -> 0x7f)
			want: net.HardwareAddr{0x01, 0x00, 0x5e, 0x7f, 0xff, 0xfa},
		},
		{
			name:  "IPv6 all-nodes FF02::1",
			dstIP: net.ParseIP("ff02::1"),
			want:  net.HardwareAddr{0x33, 0x33, 0x00, 0x00, 0x00, 0x01},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := multicastDstMAC(c.dstIP)
			t.Logf("[wintun-multicast] %s dstIP=%v -> %v", c.name, c.dstIP, got)
			if got == nil {
				t.Fatalf("multicastDstMAC(%v) = nil, want %v", c.dstIP, c.want)
			}
			if !macEqual(got, c.want) {
				t.Errorf("multicastDstMAC(%v) = %v, want %v", c.dstIP, got, c.want)
			}
			// mDNS/multicast MUST NOT be mapped to the broadcast address.
			if macEqual(got, net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}) {
				t.Errorf("multicastDstMAC(%v) unexpectedly mapped to broadcast MAC", c.dstIP)
			} else {
				t.Logf("[wintun-multicast] ✓ %s mapped to multicast (not broadcast)", c.name)
			}
		})
	}
}

// TestMulticastDstMAC_Broadcast verifies limited and subnet broadcast map to
// the all-ones Ethernet address.
func TestMulticastDstMAC_Broadcast(t *testing.T) {
	cases := []struct {
		name  string
		dstIP net.IP
	}{
		{"limited broadcast", net.IPv4bcast},
		{"subnet broadcast /24", net.IPv4(192, 168, 1, 255)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := multicastDstMAC(c.dstIP)
			want := net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
			t.Logf("[wintun-multicast] %s dstIP=%v -> %v (expect broadcast)", c.name, c.dstIP, got)
			if !macEqual(got, want) {
				t.Errorf("multicastDstMAC(%v) = %v, want %v", c.dstIP, got, want)
			} else {
				t.Logf("[wintun-multicast] ✓ %s mapped to broadcast", c.name)
			}
		})
	}
}

// TestMulticastDstMAC_Unicast verifies unicast destinations return nil so the
// caller falls back to MAC-table lookup (no fabricated broadcast/multicast).
func TestMulticastDstMAC_Unicast(t *testing.T) {
	cases := []net.IP{
		net.IPv4(8, 8, 8, 8),
		net.IPv4(10, 0, 0, 2),
		net.ParseIP("2001:db8::1"),
	}
	for _, ip := range cases {
		got := multicastDstMAC(ip)
		t.Logf("[wintun-multicast] unicast dstIP=%v -> %v (expect nil)", ip, got)
		if got != nil {
			t.Errorf("multicastDstMAC(%v) = %v, want nil for unicast", ip, got)
		}
	}
}

// TestMulticastDstMAC_Nil verifies degenerate input is handled safely.
func TestMulticastDstMAC_Nil(t *testing.T) {
	if got := multicastDstMAC(nil); got != nil {
		t.Errorf("multicastDstMAC(nil) = %v, want nil", got)
	} else {
		t.Log("[wintun-multicast] ✓ nil input -> nil")
	}
	if got := multicastDstMAC(net.IP{}); got != nil {
		t.Errorf("multicastDstMAC(empty) = %v, want nil", got)
	} else {
		t.Log("[wintun-multicast] ✓ empty input -> nil")
	}
}

func macEqual(a, b net.HardwareAddr) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
