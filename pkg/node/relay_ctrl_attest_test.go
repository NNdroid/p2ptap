package node

import (
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"

	"p2ptap/pkg/config"
	"p2ptap/pkg/routing"
)

// TestRelayCtrlOriginAttestation locks the relay-ctrl anti-spoof gate: in a PSK
// network an Origin claim that is not the transport peer itself must carry a
// valid PSK-keyed endorsement, minted by a PSK holder that verified the claim
// directly. Tampered tuples, other PSKs, and missing stamps all fail. In a
// PSK-less mesh stamps are neither minted nor required (behaviour identical to
// pre-attestation, as documented in relay_ctrl_attest.go).
func TestRelayCtrlOriginAttestation(t *testing.T) {
	origin := peer.ID("attest-origin")
	target := peer.ID("attest-target")
	proto := protocol.ID("/p2ptap/seqsync/1.0.0")

	newNode := func(psk string) *Node {
		n := &Node{}
		n.SetConfig(&config.Config{PSK: psk})
		return n
	}

	// PSK-less mesh: no stamp minted, any stamp verifies.
	plain := newNode("")
	if s := plain.stampRelayCtrlOrigin(origin, target, proto); s != "" {
		t.Fatalf("PSK-less mesh must not mint a stamp, got %q", s)
	}
	if !plain.verifyRelayCtrlStamp(origin, target, proto, "") {
		t.Fatal("PSK-less verification must accept no stamp")
	}

	// PSK mesh: mint then verify.
	n := newNode("shared-secret")
	stamp := n.stampRelayCtrlOrigin(origin, target, proto)
	if stamp == "" {
		t.Fatal("expected a stamp in a PSK mesh")
	}
	if !n.verifyRelayCtrlStamp(origin, target, proto, stamp) {
		t.Fatal("valid stamp must verify")
	}
	if n.verifyRelayCtrlStamp(origin, target, proto, "") {
		t.Fatal("empty stamp must fail in a PSK mesh")
	}

	// The stamp is bound to the full claimed tuple — a captured stamp must not
	// be replayable for a different origin, target, or protocol.
	if n.verifyRelayCtrlStamp(peer.ID("other-origin"), target, proto, stamp) {
		t.Fatal("stamp must be bound to the origin")
	}
	if n.verifyRelayCtrlStamp(origin, peer.ID("other-target"), proto, stamp) {
		t.Fatal("stamp must be bound to the target")
	}
	if n.verifyRelayCtrlStamp(origin, target, protocol.ID("/p2ptap/meta/1.0.0"), stamp) {
		t.Fatal("stamp must be bound to the protocol")
	}

	// Different PSK = different network: the stamp must not verify.
	other := newNode("different-secret")
	if other.verifyRelayCtrlStamp(origin, target, proto, stamp) {
		t.Fatal("stamp from a foreign PSK network must not verify")
	}
}

// TestRelayCtrlOriginAttestationExportedParity locks the byte-parity contract
// the custom boot node depends on. The boot is a first relay for clients that
// never share a Node's config plumbing: it mints with StampRelayCtrlOrigin and
// routing.PSKKeyBytes(its configured PSK) rather than pskSaltBytes(). If the
// two drifted, the target node would reject every tunnel the boot established —
// the exact failure this call site exists to fix.
//
// The mixed-case hex PSK is deliberate: routing.PSKKeyBytes lowercases hex PSKs,
// so a node configured "0123456789ABCDEF" and a boot configured with the same
// string must still derive the same HMAC key. A test on plain-text PSKs alone
// would not catch a lowercase-handling regression.
func TestRelayCtrlOriginAttestationExportedParity(t *testing.T) {
	origin := peer.ID("boot-origin")
	target := peer.ID("boot-target")
	proto := protocol.ID("/p2ptap/seqsync/1.0.0")

	for _, psk := range []string{"shared-secret", "0123456789abcdef", "0123456789ABCDEF"} {
		n := &Node{}
		n.SetConfig(&config.Config{PSK: psk})
		key := routing.PSKKeyBytes(psk)

		nodeStamp := n.stampRelayCtrlOrigin(origin, target, proto)
		bootStamp := StampRelayCtrlOrigin(key, origin, target, proto)
		if nodeStamp == "" {
			t.Fatalf("psk=%q: expected a stamp in a PSK mesh", psk)
		}
		if nodeStamp != bootStamp {
			t.Fatalf("psk=%q: boot stamp %q != node stamp %q", psk, bootStamp, nodeStamp)
		}
		if !n.verifyRelayCtrlStamp(origin, target, proto, bootStamp) {
			t.Fatalf("psk=%q: a node must accept a boot-minted stamp", psk)
		}
		if !VerifyRelayCtrlStamp(key, origin, target, proto, nodeStamp) {
			t.Fatalf("psk=%q: a boot must accept a node-minted stamp", psk)
		}
		if VerifyRelayCtrlStamp(key, origin, target, proto, "") {
			t.Fatalf("psk=%q: an empty stamp must not verify in a PSK mesh", psk)
		}
		if VerifyRelayCtrlStamp(routing.PSKKeyBytes("different-secret"), origin, target, proto, bootStamp) {
			t.Fatalf("psk=%q: a foreign network's PSK must not verify", psk)
		}
	}

	// Open mode: no key, no stamp, and verification is not applicable.
	if s := StampRelayCtrlOrigin(nil, origin, target, proto); s != "" {
		t.Fatalf("open mode must not mint a stamp, got %q", s)
	}
	if !VerifyRelayCtrlStamp(nil, origin, target, proto, "") {
		t.Fatal("open mode must not require a stamp")
	}
}
