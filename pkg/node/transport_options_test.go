package node

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	tpt "github.com/libp2p/go-libp2p/core/transport"
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
//
// newSharedPortHost builds a host that listens for QUIC and WebTransport on the
// SAME UDP port, and returns it with the two listen addresses and the port
// slot for matching them against advertised addresses.
//
// freeUDPPort releases its port before returning, so a busy CI machine can hand
// the same number to someone else in the meantime. Retry on "address already in
// use" — but not on any other error, which is a real registration defect and
// must fail fast rather than be retried away.
func newSharedPortHost(t *testing.T, reuseport bool) (host.Host, string, string, string) {
	t.Helper()
	extra := []quicreuse.Option(nil)
	if !reuseport {
		extra = append(extra, quicreuse.DisableReuseport())
	}

	var lastErr error
	for attempt := 0; attempt < 8; attempt++ {
		port := freeUDPPort(t)
		quicAddr := fmt.Sprintf("/ip4/127.0.0.1/udp/%d/quic-v1", port)
		wtAddr := fmt.Sprintf("/ip4/127.0.0.1/udp/%d/quic-v1/webtransport", port)

		h, err := libp2p.New(
			QUICReuseOption(func(network string, laddr *net.UDPAddr) (net.PacketConn, error) {
				return net.ListenUDP(network, laddr)
			}, extra...),
			libp2p.Transport(quic.NewTransport),
			libp2p.Transport(webtransport.New),
			libp2p.ListenAddrs(mustMA(quicAddr), mustMA(wtAddr)),
		)
		if err == nil {
			return h, quicAddr, wtAddr, fmt.Sprintf("/udp/%d/", port)
		}
		if !strings.Contains(err.Error(), "in use") {
			t.Fatalf("create host: %v", err)
		}
		lastErr = err
	}
	t.Fatalf("create host: port was still held after 8 free ports, last error: %v", lastErr)
	return nil, "", "", ""
}

func TestSharedQUICReuseSharesAPortBetweenQUICAndWebTransport(t *testing.T) {
	for _, reuseport := range []bool{false, true} {
		reuseport := reuseport
		t.Run(fmt.Sprintf("reuseport=%t", reuseport), func(t *testing.T) {
			h, quicAddr, _, portSlot := newSharedPortHost(t, reuseport)
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

			// WebTransport refuses to dial an address without a /certhash/
			// component — the dialer must state the certificate it expects to
			// see — and the listener's advertised address is exactly the form a
			// real peer would receive. Dial that one, not the bare listen addr.
			wtDialAddr := ""
			for _, s := range got {
				if strings.Contains(s, "/quic-v1/webtransport") {
					wtDialAddr = s
					break
				}
			}
			if wtDialAddr == "" {
				t.Fatalf("no advertised WebTransport address to dial; advertised: %v", got)
			}

			// Both transports must actually be reachable through that one port.
			// A FRESH dialer per case, rather than one host reused with
			// ClearAddrs/ClosePeer between dials. This fork's host.Connect does
			// not dial the addresses it is given: it absorbs them into the
			// peerstore and then dials by peer ID (see
			// pkg/go-libp2p/p2p/host/basic/basic_host.go), so the peerstore is
			// the dialer's real source of truth. ClosePeer triggers address-book
			// cleanup for the peer, and under -race on macOS that cleanup can
			// land after the next Connect's AddAddrs, leaving the peerstore
			// empty and surfacing "no addresses" for an address that is
			// perfectly dialable — a false failure of a protocol that works.
			// A fresh dialer has no prior state to clean up, and ConnsToPeer
			// returns exactly the one connection this address produced, so the
			// transport attribution below stays unambiguous.
			for _, tc := range []struct {
				addr   string
				expect string
			}{
				{quicAddr, "quic"},
				{wtDialAddr, "webtransport"},
			} {
				dialer, err := libp2p.New(libp2p.NoListenAddrs)
				if err != nil {
					t.Fatalf("create dialer: %v", err)
				}
				t.Cleanup(func() { _ = dialer.Close() })

				if err := dialer.Connect(context.Background(), peer.AddrInfo{
					ID:    h.ID(),
					Addrs: []multiaddr.Multiaddr{mustMA(tc.addr)},
				}); err != nil {
					t.Fatalf("cannot connect via %s: %v", tc.addr, err)
				}
				// Not enough that the connection came up: p2ptap must be able to
				// TELL the two transports apart afterwards, because every peer
				// list and per-transport counter in the WebUI is derived from it.
				// TransportOfConn answers from ConnState().Transport, which the
				// transport that carried the bytes wrote; the log line below also
				// records what the address-based TransportOf would have said, so a
				// fork change that stops recording /webtransport on the connection
				// shows up here as a divergence rather than as a silent
				// misclassification in the WebUI.
				conns := dialer.Network().ConnsToPeer(h.ID())
				if len(conns) == 0 {
					t.Fatalf("no connection to %s after Connect", tc.addr)
				}
				for _, c := range conns {
					if got := TransportOfConn(c); got != tc.expect {
						t.Fatalf("dialing %s came up as transport %q (ConnState=%q), want %q",
							tc.addr, got, c.ConnState().Transport, tc.expect)
					}
					t.Logf("addr=%s ConnState=%q TransportOf=%q TransportOfConn=%q",
						c.RemoteMultiaddr(), c.ConnState().Transport,
						TransportOf(c.RemoteMultiaddr()), TransportOfConn(c))
				}
				// No ClosePeer here: the dialer's own Close in the cleanup is
				// enough, and closing the peer between cases is what makes the
				// peerstore race above reachable.
			}
		})
	}
}

// dialerNetwork exposes the swarm's dial-side transport chooser.
type dialerNetwork interface {
	TransportForDialing(multiaddr.Multiaddr) tpt.Transport
}

// TestDialTransportSelectionIsDeterministic pins dial-side transport selection
// to a single answer per address. The swarm chooses by walking a Go map (see
// pkg/go-libp2p/p2p/net/swarm/swarm_transport.go) and taking the FIRST transport
// whose CanDial matches, so the choice is order-dependent: if QUIC's dialMatcher
// ever started accepting a /quic-v1/webtransport address, roughly half of all
// WebTransport dials would randomly go out as raw QUIC and arrive at an HTTP/3
// listener. The dial would still "succeed" at the libp2p layer, so it presents
// exactly as a protocol that only connects some of the time.
//
// QUIC's matcher is mafmt.And(mafmt.IP, mafmt.Base(UDP), mafmt.Base(QUIC_V1)):
// mafmt.Base only matches a multiaddr whose ENTIRE protocol path is that single
// protocol, and And requires the whole path to be consumed with no remainder, so
// /udp/443/quic-v1/webtransport does not match. This test is the guard for that,
// and it uses a host's REAL advertised addresses — which carry the /certhash/
// suffix the peer actually dials — rather than hand-built ones.
func TestDialTransportSelectionIsDeterministic(t *testing.T) {
	h, _, _, portSlot := newSharedPortHost(t, true)
	t.Cleanup(func() { _ = h.Close() })

	nw, ok := h.Network().(dialerNetwork)
	if !ok {
		t.Fatalf("network does not expose TransportForDialing")
	}

	var checked int
	for _, a := range h.Addrs() {
		if !strings.Contains(a.String(), portSlot) {
			continue
		}
		wantPC := multiaddr.P_WEBTRANSPORT
		if !strings.Contains(a.String(), "/quic-v1/webtransport") {
			wantPC = multiaddr.P_QUIC_V1
		}

		const iterations = 500
		picked := map[tpt.Transport]int{}
		for i := 0; i < iterations; i++ {
			tr := nw.TransportForDialing(a)
			if tr == nil {
				t.Fatalf("%s: no transport selected after %d lookups", a, i)
			}
			picked[tr]++
		}
		if len(picked) != 1 {
			t.Fatalf("%s: transport selection is NON-DETERMINISTIC — %d distinct "+
				"transports chosen over %d lookups", a, len(picked), iterations)
		}
		var got tpt.Transport
		for got = range picked {
		}
		if gotPC := got.Protocols()[0]; gotPC != wantPC {
			t.Fatalf("%s: selected transport protocol %d (%s), want %d",
				a, gotPC, multiaddr.ProtocolWithCode(gotPC).Name, wantPC)
		}
		checked++
	}
	if checked == 0 {
		t.Fatalf("host advertised no addresses on %s; advertised: %v", portSlot, stringAddrs(h.Addrs()))
	}
}
