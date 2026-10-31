package node

import (
	"testing"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"
	"p2ptap/pkg/maddrutil"
)

// testPeer is the logical peer the mock streams are registered under. The mock
// conn's RemotePeer() returns its "remote" field, so keeping it equal to testPeer
// makes a direct stream's connection peer match the logical peer (not a relay).
const testPeer = peer.ID("peer")

// relayStreamOn builds a mock stream riding a libp2p /p2p-circuit connection.
func relayStreamOn(t *testing.T) network.Stream {
	t.Helper()
	a, err := ma.NewMultiaddr("/ip4/1.2.3.4/tcp/4001/p2p-circuit")
	if err != nil {
		t.Fatalf("bad relay fixture: %v", err)
	}
	return newMockStream(&mockConn{remote: "peer", addr: a})
}

// directStreamOn builds a mock stream riding a direct (non-relay) connection
// whose connection peer matches the logical peer.
func directStreamOn(t *testing.T) network.Stream {
	t.Helper()
	a, err := ma.NewMultiaddr("/ip4/1.2.3.4/udp/5001/quic-v1")
	if err != nil {
		t.Fatalf("bad direct fixture: %v", err)
	}
	return newMockStream(&mockConn{remote: "peer", addr: a})
}

// bootRelayStreamOn builds a mock stream riding a boot-relay (overlay-relay)
// connection: the underlying transport connection terminates at the boot hop, so
// its RemoteMultiaddr is a DIRECT address of the boot and IsCircuitRelay is
// false, but its RemotePeer() is the boot, not the logical peer. This is exactly
// the case the old IsCircuitRelay-only check missed.
func bootRelayStreamOn(t *testing.T) network.Stream {
	t.Helper()
	a, err := ma.NewMultiaddr("/ip4/9.9.9.9/tcp/4001")
	if err != nil {
		t.Fatalf("bad boot-relay fixture: %v", err)
	}
	return newMockStream(&mockConn{remote: "boot", addr: a})
}

func TestNonRelayStreams(t *testing.T) {
	relay := func() network.Stream { return relayStreamOn(t) }
	direct := func() network.Stream { return directStreamOn(t) }

	t.Run("nil input unchanged", func(t *testing.T) {
		if got := nonRelayStreams(nil, testPeer); got != nil {
			t.Fatalf("nonRelayStreams(nil) = %v, want nil", got)
		}
	})
	t.Run("empty input unchanged", func(t *testing.T) {
		if got := nonRelayStreams([]network.Stream{}, testPeer); len(got) != 0 {
			t.Fatalf("nonRelayStreams([]) = %v, want empty", got)
		}
	})
	t.Run("single direct kept", func(t *testing.T) {
		in := []network.Stream{direct()}
		got := nonRelayStreams(in, testPeer)
		if len(got) != 1 || got[0] != in[0] {
			t.Fatalf("single direct: got %d stream(s), want the input preserved", len(got))
		}
	})
	t.Run("single relay kept (relay-only peer)", func(t *testing.T) {
		in := []network.Stream{relay()}
		got := nonRelayStreams(in, testPeer)
		if len(got) != 1 || got[0] != in[0] {
			t.Fatalf("relay-only: got %d stream(s), want the relay preserved", len(got))
		}
	})
	t.Run("relay-only with several relays all kept", func(t *testing.T) {
		in := []network.Stream{relay(), relay(), relay()}
		got := nonRelayStreams(in, testPeer)
		if len(got) != 3 {
			t.Fatalf("relay-only set: got %d, want all 3 relay streams kept", len(got))
		}
	})
	t.Run("relay dropped when a direct exists", func(t *testing.T) {
		d := direct()
		in := []network.Stream{relay(), d}
		got := nonRelayStreams(in, testPeer)
		if len(got) != 1 || got[0] != d {
			t.Fatalf("relay+direct: got %d stream(s), want only the direct", len(got))
		}
	})
	t.Run("relay interleaved among directs removed, order preserved", func(t *testing.T) {
		d1, d2 := direct(), direct()
		in := []network.Stream{d1, relay(), d2}
		got := nonRelayStreams(in, testPeer)
		if len(got) != 2 || got[0] != d1 || got[1] != d2 {
			t.Fatalf("mixed set: got %d stream(s), want [d1 d2] in order", len(got))
		}
	})
	t.Run("filtered result is a fresh slice, input untouched", func(t *testing.T) {
		d1, d2 := direct(), direct()
		in := []network.Stream{relay(), d1, d2}
		got := nonRelayStreams(in, testPeer)
		if len(got) == 0 || &got[0] == &in[0] {
			t.Fatalf("result aliases the input backing array")
		}
		if len(in) != 3 || in[0] == nil || in[1] != d1 || in[2] != d2 {
			t.Fatalf("input slice was mutated: %v", in)
		}
	})
	t.Run("nil stream treated as non-relay", func(t *testing.T) {
		d := direct()
		got := nonRelayStreams([]network.Stream{nil, d}, testPeer)
		if len(got) != 2 {
			t.Fatalf("nil+direct: got %d, want 2 (nil kept, direct kept)", len(got))
		}
	})
	t.Run("boot-relay counted as relay and dropped alongside direct", func(t *testing.T) {
		// Regression for F3: a boot-relay stream's RemoteMultiaddr is NOT a
		// circuit, so the old IsCircuitRelay-only check missed it. It must still
		// be treated as relay and dropped when a direct path exists.
		d := direct()
		in := []network.Stream{bootRelayStreamOn(t), d}
		got := nonRelayStreams(in, testPeer)
		if len(got) != 1 || got[0] != d {
			t.Fatalf("boot-relay+direct: got %d stream(s), want only the direct", len(got))
		}
	})
}

// TestStreamIsRelayForPeer locks down the F3 unified relay detection: a
// boot-relay (overlay-relay) stream — whose connection terminates at the boot
// hop — must be recognized as relayed even though IsCircuitRelay is false.
func TestStreamIsRelayForPeer(t *testing.T) {
	t.Run("libp2p circuit is relay", func(t *testing.T) {
		if !streamIsRelayForPeer(relayStreamOn(t), testPeer) {
			t.Fatalf("circuit stream should be relay")
		}
	})
	t.Run("direct is not relay", func(t *testing.T) {
		if streamIsRelayForPeer(directStreamOn(t), testPeer) {
			t.Fatalf("direct stream should not be relay")
		}
	})
	t.Run("boot-relay is relay despite non-circuit addr", func(t *testing.T) {
		s := bootRelayStreamOn(t)
		if maddrutil.IsCircuitRelay(s.Conn().RemoteMultiaddr()) {
			t.Fatalf("fixture must be a non-circuit addr to prove the F3 fix")
		}
		if !streamIsRelayForPeer(s, testPeer) {
			t.Fatalf("boot-relay stream must be detected as relay via RemotePeer() != peerID")
		}
	})
	t.Run("direct stream whose conn peer mismatches is flagged relay", func(t *testing.T) {
		// Defensive: a stream whose connection peer is not the logical peer is, by
		// definition, relayed — even with a direct-looking address.
		a, _ := ma.NewMultiaddr("/ip4/1.2.3.4/udp/5001/quic-v1")
		s := newMockStream(&mockConn{remote: "other", addr: a})
		if !streamIsRelayForPeer(s, testPeer) {
			t.Fatalf("conn peer != logical peer must be relay")
		}
	})
}
