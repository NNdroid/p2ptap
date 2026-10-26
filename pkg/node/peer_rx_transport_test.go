package node

import (
	"context"
	"testing"
	"time"

	ic "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	multiaddr "github.com/multiformats/go-multiaddr"
)

// fakePeerConn satisfies network.Conn with just enough behaviour for
// transportLabelForConn, which only reads RemoteMultiaddr.
type fakePeerConn struct{ addr multiaddr.Multiaddr }

func (c *fakePeerConn) Close() error                                      { return nil }
func (c *fakePeerConn) LocalPeer() peer.ID                                { return "" }
func (c *fakePeerConn) RemotePeer() peer.ID                               { return "" }
func (c *fakePeerConn) RemotePublicKey() ic.PubKey                        { return nil }
func (c *fakePeerConn) ConnState() network.ConnectionState                { return network.ConnectionState{} }
func (c *fakePeerConn) LocalMultiaddr() multiaddr.Multiaddr               { return c.addr }
func (c *fakePeerConn) RemoteMultiaddr() multiaddr.Multiaddr              { return c.addr }
func (c *fakePeerConn) Stat() network.ConnStats                           { return network.ConnStats{} }
func (c *fakePeerConn) Scope() network.ConnScope                          { return nil }
func (c *fakePeerConn) CloseWithError(network.ConnErrorCode) error        { return nil }
func (c *fakePeerConn) ID() string                                        { return "" }
func (c *fakePeerConn) NewStream(context.Context) (network.Stream, error) { return nil, nil }
func (c *fakePeerConn) GetStreams() []network.Stream                      { return nil }
func (c *fakePeerConn) IsClosed() bool                                    { return false }
func (c *fakePeerConn) As(target any) bool                                { return false }

func TestTransportLabelForConn(t *testing.T) {
	for _, tt := range []struct {
		addr   string
		expect string
	}{
		{"/ip4/1.2.3.4/udp/5001/quic-v1", "direct"},
		{"/ip4/192.168.1.9/tcp/4001", "direct"},
		{"/ip4/1.2.3.4/udp/11234/webrtc-direct", "direct"},
		{"/ip4/1.2.3.4/tcp/443/webtransport", "direct"},
		{"/ip4/1.2.3.4/tcp/4001/p2p-circuit", "circuit-relay"},
	} {
		addr, err := multiaddr.NewMultiaddr(tt.addr)
		if err != nil {
			t.Fatalf("bad test fixture %q: %v", tt.addr, err)
		}
		if got := transportLabelForConn(&fakePeerConn{addr: addr}); got != tt.expect {
			t.Errorf("transportLabelForConn(%q) = %q, want %q", tt.addr, got, tt.expect)
		}
	}
	if got := transportLabelForConn(nil); got != "" {
		t.Errorf("transportLabelForConn(nil) = %q, want empty", got)
	}
}

func TestPeerRxTransportPath(t *testing.T) {
	n := &Node{}
	src := peer.ID("src-origin")
	hop := peer.ID("relay-hop")

	if label, rh := n.peerRxTransportPath(src, time.Minute); label != "" || rh != "" {
		t.Fatalf("empty tracker = %q via %q, want both empty", label, rh)
	}

	// First sighting over an overlay relay hop.
	n.notePeerRxTransport(src, "overlay-relay", hop)
	if label, rh := n.peerRxTransportPath(src, time.Minute); label != "overlay-relay" || rh != hop {
		t.Fatalf("after relay frame = %q via %q, want overlay-relay via %s", label, rh, hop)
	}

	// A direct frame from the same peer must win, and clear the hop.
	n.notePeerRxTransport(src, "direct", "")
	if label, rh := n.peerRxTransportPath(src, time.Minute); label != "direct" || rh != "" {
		t.Fatalf("after direct frame = %q via %q, want direct with no hop", label, rh)
	}

	// The annotation must not leak to a different peer.
	if label, _ := n.peerRxTransportPath(peer.ID("someone-else"), time.Minute); label != "" {
		t.Fatalf("unrelated peer = %q, want empty", label)
	}

	// Empty label is a no-op so control-plane bookkeeping cannot manufacture a
	// return medium out of thin air.
	n.notePeerRxTransport(peer.ID("blank"), "", "")
	if label, _ := n.peerRxTransportPath(peer.ID("blank"), time.Minute); label != "" {
		t.Fatalf("empty label recorded as %q, want empty", label)
	}
}

// TestPeerRxTransportPathStaleness pins the freshness gate: an annotation from
// a frame older than the caller's window must read as UNKNOWN, not as a stale
// but present medium. That is what keeps return_transport from reporting a path
// nobody has used in any recent frame.
// backdatePeerRxTransport sets a peer's annotation to now-ago, so a test can
// assert the freshness gate without racing its own runtime.
func backdatePeerRxTransport(t *testing.T, n *Node, p peer.ID, ago time.Duration) {
	t.Helper()
	n.peerRxTransportMu.Lock()
	defer n.peerRxTransportMu.Unlock()
	m := n.peerRxTransport.Load()
	if m == nil {
		t.Fatalf("no peerRxTransport map for %s", p)
	}
	info, ok := (*m)[p]
	if !ok || info == nil {
		t.Fatalf("no rx annotation for %s", p)
	}
	info.lastTs.Store(time.Now().Add(-ago).UnixNano())
}

func TestPeerRxTransportPathStaleness(t *testing.T) {
	n := &Node{}
	src := peer.ID("stale-src")
	hop := peer.ID("stale-hop")
	n.notePeerRxTransport(src, "overlay-relay", hop)

	// Fresh enough for a generous window.
	if label, rh := n.peerRxTransportPath(src, time.Hour); label != "overlay-relay" || rh != hop {
		t.Fatalf("1h window = %q via %q, want overlay-relay via %s", label, rh, hop)
	}

	// Backdate past every window below, so each assertion is about the gate
	// itself and not about how long this test happened to take.
	backdatePeerRxTransport(t, n, src, 2*time.Hour)
	if label, _ := n.peerRxTransportPath(src, time.Hour); label != "" {
		t.Fatalf("1h window after 2h = %q, want empty", label)
	}
	if label, _ := n.peerRxTransportPath(src, time.Second); label != "" {
		t.Fatalf("1s window after 2h = %q, want empty", label)
	}
	if label, _ := n.peerRxTransportPath(src, time.Millisecond); label != "" {
		t.Fatalf("1ms window after 2h = %q, want empty", label)
	}

	// A non-positive window is always unknown, never "always fresh".
	if label, _ := n.peerRxTransportPath(src, 0); label != "" {
		t.Fatalf("0 window = %q, want empty", label)
	}
	if label, _ := n.peerRxTransportPath(src, -time.Second); label != "" {
		t.Fatalf("negative window = %q, want empty", label)
	}
}

// TestPeerRxTransportIsPerFrameNotPerConn pins why the return side is tracked
// separately from describeTransportPath: a peer can keep carrying our return
// frames over an overlay relay even after it establishes a direct connection
// with us, because it picked its own egress. The annotation must follow the
// frames, not our connections.
func TestPeerRxTransportIsPerFrameNotPerConn(t *testing.T) {
	n := &Node{}
	src := peer.ID("asymmetric-src")
	hop := peer.ID("asym-hop")

	n.notePeerRxTransport(src, "overlay-relay", hop)
	// Peer establishes a direct connection with us; our EGRESS now prefers it,
	// but its frames are still arriving over the relay hop.
	if label, rh := n.peerRxTransportPath(src, time.Minute); label != "overlay-relay" || rh != hop {
		t.Fatalf("asymmetric return = %q via %q, want overlay-relay via %s", label, rh, hop)
	}
	// Only the next actual direct frame flips the reported medium.
	n.notePeerRxTransport(src, "direct", "")
	if label, rh := n.peerRxTransportPath(src, time.Minute); label != "direct" || rh != "" {
		t.Fatalf("after direct frame = %q via %q, want direct with no hop", label, rh)
	}
}
