package P2PTap

import (
	"testing"

	"github.com/ipfs/go-cid"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multibase"
)

// testPeerID returns a syntactically valid peer ID with a real key behind it.
func testPeerID(t *testing.T) peer.ID {
	t.Helper()
	_, pub, err := crypto.GenerateEd25519Key(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pid, err := peer.IDFromPublicKey(pub)
	if err != nil {
		t.Fatalf("derive peer id: %v", err)
	}
	return pid
}

// base36Form renders the same key the way libp2p's CIDv1 form does. One peer
// has several textual encodings and the app may store any of them; the exit
// node check must not care which.
func base36Form(t *testing.T, pid peer.ID) string {
	t.Helper()
	s, err := cid.Cid(peer.ToCid(pid)).StringOfBase(multibase.Base36)
	if err != nil {
		t.Fatalf("encode peer id as base36: %v", err)
	}
	return s
}

// TestExitPeerMatchesIgnoresEncoding pins the reason the exit-node check decodes
// instead of comparing strings: the same peer written in base58 and in base36
// used to compare unequal, so the app showed "unavailable" and re-activated a
// gateway that was already routing.
func TestExitPeerMatchesIgnoresEncoding(t *testing.T) {
	pid := testPeerID(t)
	other := testPeerID(t)

	b58 := pid.String()
	b36 := base36Form(t, pid)
	if b58 == b36 {
		t.Fatalf("fixture is degenerate: base58 and base36 forms are identical (%q)", b58)
	}

	for _, tc := range []struct {
		name string
		want string
		ok   bool
	}{
		{"base58", b58, true},
		{"base36", b36, true},
		{"base58 with surrounding whitespace", "  " + b58 + "\t", true},
		{"different peer", other.String(), false},
		{"empty selection", "", false},
		{"not a peer id", "not-a-peer-id", false},
		{"truncated peer id", b58[:len(b58)-2], false},
	} {
		if got := exitPeerMatches(pid, tc.want); got != tc.ok {
			t.Errorf("%s: exitPeerMatches(active=%s, want=%q) = %v, want %v", tc.name, b58, tc.want, got, tc.ok)
		}
	}
}

// TestExitPeerMatchesNothingActive: with no active exit node recorded, no
// selection is "active" — otherwise a stale selection would suppress the retry
// that is supposed to bring the tunnel up.
func TestExitPeerMatchesNothingActive(t *testing.T) {
	if exitPeerMatches("", testPeerID(t).String()) {
		t.Fatal("an empty active PID must never match a selection")
	}
}

// TestExitNodeActiveWithoutNode covers the nil guards the retry loop can hit
// while Stop() is tearing the process down.
func TestExitNodeActiveWithoutNode(t *testing.T) {
	if exitNodeActive(nil, "12D3KooW") {
		t.Fatal("nil node must not report an active exit node")
	}
}
