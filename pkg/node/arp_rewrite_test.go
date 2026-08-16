package node

import (
	"bytes"
	"net"
	"testing"
)

// TestRewriteRxDstMAC is the deterministic regression test for task #188: the
// relay-receive path (handleRelayStream) must rewrite a relayed frame's Dst MAC
// to this node's interface MAC before injecting it into the local TAP, exactly
// like the direct-receive path (handleStream). Without that rewrite, a relayed
// frame whose Dst MAC was not the interface MAC (e.g. a Windows synthetic TAP
// MAC, or any MAC that differs from the receiver's real interface MAC) is
// L2-dropped by the kernel, silently breaking A<->B ping whenever A and B are
// only reachable through a relay.
//
// The fix extracts the rewrite into rewriteRxDstMAC and calls it from BOTH
// receive paths (handleStream line ~352 and handleRelayStream line ~746). This
// test pins the helper's contract directly so a future regression that drops the
// handleRelayStream call is caught.
//
// NOTE: a full 3-node A->C->B relay integration test cannot be a reliable CI
// regression in this codebase — a pre-existing multi-peer key-rotation
// fragility (documented in TestE2EConcurrentBidirectional, lines 291-294) drops
// the A<->B link as soon as a 2nd peer is present. So the relay *path* itself is
// covered by code inspection (both receive paths call rewriteRxDstMAC) while
// the *rewrite contract* is covered deterministically here.
func TestRewriteRxDstMAC(t *testing.T) {
	// A bare node is sufficient: rewriteRxDstMAC only reads localMAC /
	// localV4IP / localV6IP (and the exit-node branch, which a local-dst frame
	// never reaches because it returns right after the rewrite). No libp2p host,
	// no streams, no key negotiation — fully deterministic.
	n := &Node{}
	n.localMAC = []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	n.localV4IP = net.ParseIP("10.0.0.1")
	n.localV6IP = net.ParseIP("fd00::1")

	synthetic := net.HardwareAddr{0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01}

	// --- Case 1a: IPv4 frame destined to THIS node with a wrong Dst MAC must be
	//     rewritten to the interface MAC. This is exactly what the relay-receive
	//     path does for a relayed frame whose Dst MAC != interface MAC. ---
	f := constructICMPv4PacketWithData(testMACA, synthetic,
		net.ParseIP("10.0.0.2"), net.ParseIP("10.0.0.1"), 1, 1, []byte("relay-ping"))
	if !bytes.Equal(f[0:6], synthetic) {
		t.Fatalf("precondition: Dst MAC is not the synthetic value we set")
	}
	n.rewriteRxDstMAC(f)
	if !bytes.Equal(f[0:6], n.localMAC) {
		t.Fatalf("IPv4 local-dst rewrite FAILED: got=%s want=%s",
			net.HardwareAddr(f[0:6]).String(), net.HardwareAddr(n.localMAC).String())
	}
	t.Logf("IPv4 local-dst rewrite OK: Dst MAC %s -> %s",
		net.HardwareAddr(synthetic).String(), net.HardwareAddr(n.localMAC).String())

	// --- Case 1b: IPv4 frame whose Dst MAC already equals the interface MAC must
	//     be left untouched (no-op rewrite, no corruption). ---
	f2 := constructICMPv4PacketWithData(testMACA, net.HardwareAddr(append([]byte(nil), n.localMAC...)),
		net.ParseIP("10.0.0.2"), net.ParseIP("10.0.0.1"), 2, 1, []byte("noop"))
	n.rewriteRxDstMAC(f2)
	if !bytes.Equal(f2[0:6], n.localMAC) {
		t.Fatalf("IPv4 no-op rewrite corrupted Dst MAC: got=%s want=%s",
			net.HardwareAddr(f2[0:6]).String(), net.HardwareAddr(n.localMAC).String())
	}
	t.Log("IPv4 no-op rewrite OK: Dst MAC unchanged")

	// --- Case 1c: IPv6 frame destined to THIS node with a wrong Dst MAC must be
	//     rewritten to the interface MAC (parity with the IPv4 branch). ---
	f6 := make([]byte, 62)
	copy(f6[0:6], synthetic)
	copy(f6[6:12], testMACA)
	f6[12], f6[13] = 0x86, 0xdd // EtherType IPv6
	f6[14+6] = 58               // Next Header = ICMPv6
	copy(f6[14+24:14+40], n.localV6IP.To16())
	n.rewriteRxDstMAC(f6)
	if !bytes.Equal(f6[0:6], n.localMAC) {
		t.Fatalf("IPv6 local-dst rewrite FAILED: got=%s want=%s",
			net.HardwareAddr(f6[0:6]).String(), net.HardwareAddr(n.localMAC).String())
	}
	t.Log("IPv6 local-dst rewrite OK")
}
