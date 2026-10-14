package node

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/peer"
	quic "github.com/libp2p/go-libp2p/p2p/transport/quic"
	quicreuse "github.com/libp2p/go-libp2p/p2p/transport/quicreuse"
	webtransport "github.com/libp2p/go-libp2p/p2p/transport/webtransport"
	"github.com/multiformats/go-multiaddr"
)

// freeUDPPort returns a UDP port the kernel reports as free. It is released
// before the return, so there is a small window; on a CI machine with few
// listeners that is stable enough.
func freeUDPPort(t *testing.T) int {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("reserve UDP port: %v", err)
	}
	port := c.LocalAddr().(*net.UDPAddr).Port
	if err := c.Close(); err != nil {
		t.Fatalf("release UDP port: %v", err)
	}
	return port
}

func stringAddrs(addrs []multiaddr.Multiaddr) []string {
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		if a != nil {
			out = append(out, a.String())
		}
	}
	return out
}

// TestSharedQUICReuseSharesAPortBetweenQUICAndWebTransport guards the two
// invariants that let QUIC and WebTransport coexist on a single UDP port; a
// broken one of them looks exactly like "one of my protocols cannot connect at
// all".
//
//  1. Both transports must receive the SAME quicreuse.ConnManager, which keys
//     its listeners by address string and therefore folds the two associations
//     into ONE socket. With two independent managers — the old design, where
//     each transport constructor built its own — reuseport makes the kernel
//     split datagrams between two listeners bound to the same port, and a raw
//     QUIC ClientHello landing on the WebTransport listener is still ACCEPTED
//     (its ALPN offer contains "h3", which that listener registered) and then
//     mis-framed as HTTP/3. Without reuseport the second bind fails outright
//     instead.
//
//  2. The two transports' registered ALPN sets must stay DISJOINT, because
//     quicreuse demultiplexes an incoming hello by ALPN. WebTransport's is
//     "h3" and cannot change; a QUIC listener that also offers "h3" makes
//     quicreuse.Listener.Add return "already listening for protocol h3" and the
//     transport that registers second silently loses its listener while its
//     address is still advertised. This test fails if that is reintroduced; see
//     the retraction note in pkg/go-libp2p/LOCAL_PATCHES.md.
func TestSharedQUICReuseSharesAPortBetweenQUICAndWebTransport(t *testing.T) {
	for _, reuseport := range []bool{false, true} {
		reuseport := reuseport
		t.Run(fmt.Sprintf("reuseport=%t", reuseport), func(t *testing.T) {
			port := freeUDPPort(t)
			portSlot := fmt.Sprintf("/udp/%d/", port)
			quicAddr := fmt.Sprintf("/ip4/127.0.0.1/udp/%d/quic-v1", port)
			wtAddr := fmt.Sprintf("/ip4/127.0.0.1/udp/%d/quic-v1/webtransport", port)

			extra := []quicreuse.Option(nil)
			if !reuseport {
				extra = append(extra, quicreuse.DisableReuseport())
			}

			h, err := libp2p.New(
				QUICReuseOption(func(network string, laddr *net.UDPAddr) (net.PacketConn, error) {
					return net.ListenUDP(network, laddr)
				}, extra...),
				libp2p.Transport(quic.NewTransport),
				libp2p.Transport(webtransport.New),
				libp2p.ListenAddrs(mustMA(quicAddr), mustMA(wtAddr)),
			)
			if err != nil {
				t.Fatalf("create host: %v", err)
			}
			t.Cleanup(func() { _ = h.Close() })

			// Advertised addresses are suffixed with /certhash/ per registered
			// ALPN, so match on the protocol path rather than the string end.
			got := stringAddrs(h.Addrs())
			var haveQUIC, haveWT bool
			for _, s := range got {
				if !strings.Contains(s, portSlot) {
					continue
				}
				if strings.Contains(s, "/quic-v1/webtransport") {
					haveWT = true
				} else if strings.Contains(s, "/quic-v1") {
					haveQUIC = true
				}

			}
			if !haveQUIC {
				t.Fatalf("QUIC listener on the shared port is missing; advertised: %v\n"+
					"usually QUIC's ALPN set overlaps WebTransport's \"h3\" and "+
					"quicreuse refused to register it", got)
			}
			if !haveWT {
				t.Fatalf("WebTransport listener on the shared port is missing; advertised: %v\n"+
					"usually QUIC's ALPN set overlaps WebTransport's \"h3\" and "+
					"quicreuse refused to register it", got)
			}

			// Both transports must actually be reachable through that one port.
			dialer, err := libp2p.New(libp2p.NoListenAddrs)
			if err != nil {
				t.Fatalf("create dialer: %v", err)
			}
			t.Cleanup(func() { _ = dialer.Close() })

			for _, aStr := range []string{quicAddr, wtAddr} {
				if err := dialer.Connect(context.Background(), peer.AddrInfo{
					ID:    h.ID(),
					Addrs: []multiaddr.Multiaddr{mustMA(aStr)},
				}); err != nil {
					t.Fatalf("cannot connect via %s: %v", aStr, err)
				}
			}
		})
	}
}
