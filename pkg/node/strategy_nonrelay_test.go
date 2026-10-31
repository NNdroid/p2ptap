package node

import (
	"testing"

	"github.com/libp2p/go-libp2p/core/network"
	ma "github.com/multiformats/go-multiaddr"
)

// relayStreamOn builds a mock stream riding a circuit-relay connection, and
// directStreamOn a direct one. isRelayStream keys off the connection's
// RemoteMultiaddr only, so a mockConn with the right addr suffices.
func relayStreamOn(t *testing.T) network.Stream {
	t.Helper()
	a, err := ma.NewMultiaddr("/ip4/1.2.3.4/tcp/4001/p2p-circuit")
	if err != nil {
		t.Fatalf("bad relay fixture: %v", err)
	}
	return newMockStream(&mockConn{remote: "peer", addr: a})
}

func directStreamOn(t *testing.T) network.Stream {
	t.Helper()
	a, err := ma.NewMultiaddr("/ip4/1.2.3.4/udp/5001/quic-v1")
	if err != nil {
		t.Fatalf("bad direct fixture: %v", err)
	}
	return newMockStream(&mockConn{remote: "peer", addr: a})
}

func TestNonRelayStreams(t *testing.T) {
	relay := func() network.Stream { return relayStreamOn(t) }
	direct := func() network.Stream { return directStreamOn(t) }

	t.Run("nil input unchanged", func(t *testing.T) {
		if got := nonRelayStreams(nil); got != nil {
			t.Fatalf("nonRelayStreams(nil) = %v, want nil", got)
		}
	})
	t.Run("empty input unchanged", func(t *testing.T) {
		if got := nonRelayStreams([]network.Stream{}); len(got) != 0 {
			t.Fatalf("nonRelayStreams([]) = %v, want empty", got)
		}
	})
	t.Run("single direct kept", func(t *testing.T) {
		in := []network.Stream{direct()}
		got := nonRelayStreams(in)
		if len(got) != 1 || got[0] != in[0] {
			t.Fatalf("single direct: got %d stream(s), want the input preserved", len(got))
		}
	})
	t.Run("single relay kept (relay-only peer)", func(t *testing.T) {
		in := []network.Stream{relay()}
		got := nonRelayStreams(in)
		if len(got) != 1 || got[0] != in[0] {
			t.Fatalf("relay-only: got %d stream(s), want the relay preserved", len(got))
		}
	})
	t.Run("relay-only with several relays all kept", func(t *testing.T) {
		in := []network.Stream{relay(), relay(), relay()}
		got := nonRelayStreams(in)
		if len(got) != 3 {
			t.Fatalf("relay-only set: got %d, want all 3 relay streams kept", len(got))
		}
	})
	t.Run("relay dropped when a direct exists", func(t *testing.T) {
		d := direct()
		in := []network.Stream{relay(), d}
		got := nonRelayStreams(in)
		if len(got) != 1 || got[0] != d {
			t.Fatalf("relay+direct: got %d stream(s), want only the direct", len(got))
		}
	})
	t.Run("relay interleaved among directs removed, order preserved", func(t *testing.T) {
		d1, d2 := direct(), direct()
		in := []network.Stream{d1, relay(), d2}
		got := nonRelayStreams(in)
		if len(got) != 2 || got[0] != d1 || got[1] != d2 {
			t.Fatalf("mixed set: got %d stream(s), want [d1 d2] in order", len(got))
		}
	})
	t.Run("filtered result is a fresh slice, input untouched", func(t *testing.T) {
		d1, d2 := direct(), direct()
		in := []network.Stream{relay(), d1, d2}
		got := nonRelayStreams(in)
		// The result must not alias the shared snapshot backing array (the
		// doc comment on nonRelayStreams calls this out explicitly).
		if len(got) == 0 || &got[0] == &in[0] {
			t.Fatalf("result aliases the input backing array")
		}
		if len(in) != 3 || in[0] == nil || in[1] != d1 || in[2] != d2 {
			t.Fatalf("input slice was mutated: %v", in)
		}
	})
	t.Run("nil stream treated as non-relay", func(t *testing.T) {
		// isRelayStream(nil) is false, so a nil entry counts as a usable path.
		d := direct()
		got := nonRelayStreams([]network.Stream{nil, d})
		if len(got) != 2 {
			t.Fatalf("nil+direct: got %d, want 2 (nil kept, direct kept)", len(got))
		}
	})
}
