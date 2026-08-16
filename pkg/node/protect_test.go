package node

import "testing"

// TestShouldProtectSkipsOverlayAndLoopback pins the socket-protection gate used
// by every Control hook (P2P dial/listen and the WebUI listener):
//   - physical / LAN / global / DNS addresses MUST be protected (pinned to the
//     physical NIC via IP_UNICAST_IF / SO_BINDTODEVICE) so they never loop into
//     the TAP tunnel under Exit Node;
//   - loopback, link-local and TAP/mesh OVERLAY addresses (10.0.0.0/8,
//     172.16.0.0/12, fd00::/8) MUST NOT be protected — a listener bound to a
//     TAP IP ("strict listener split") must keep egressing via the TAP itself.
func TestShouldProtectSkipsOverlayAndLoopback(t *testing.T) {
	protected := []string{
		"1.2.3.4:443",
		"192.168.1.100:80",
		"8.8.8.8:53",
		"[2606:4700:4700::1111]:443",
		"example.com:443",
	}
	for _, a := range protected {
		if !shouldProtect(a) {
			t.Errorf("shouldProtect(%q) = false, want true (must be pinned to physical NIC)", a)
		}
	}

	skipped := []string{
		"127.0.0.1:8080", // loopback
		"[::1]:8080",     // loopback (IPv6 is bracketed by the net package)
		"169.254.1.1:80", // IPv4 link-local
		"10.0.0.254:80",  // TAP/mesh 10.0.0.0/8
		"172.16.0.1:80",  // TAP/mesh 172.16.0.0/12
		"[fd00::254]:80", // TAP/mesh fd00::/8 ULA
	}
	for _, a := range skipped {
		if shouldProtect(a) {
			t.Errorf("shouldProtect(%q) = true, want false (must NOT be pinned to physical NIC)", a)
		}
	}
}
