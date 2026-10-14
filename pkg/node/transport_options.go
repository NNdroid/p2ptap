package node

import (
	"net"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/p2p/transport/quicreuse"
	quic "github.com/quic-go/quic-go"
)

// quicReuseOption installs a single quicreuse ConnManager shared by the QUIC
// and WebTransport transports, routing every UDP socket it opens through
// listenUDP.
//
// "Shared" is the important part: it is what lets /udp/N/quic-v1 and
// /udp/N/quic-v1/webtransport bind the SAME socket and demultiplex incoming
// connections by ALPN. Each ConnManager keys its listeners by address string,
// so two managers listening on one address build two independent quicListener
// instances. With reuseport the kernel then splits packets between them at
// random, and a raw-QUIC ClientHello that lands on the WebTransport listener is
// still accepted — its ALPN offer contains "h3", which is in that listener's
// protocol set — and mis-framed as an HTTP/3 connection. Two managers without
// reuseport is worse: the second bind fails outright and one of the two
// transports silently never listens at all.
//
// Registering the manager through libp2p.QUICReuse rather than building it
// inside a transport constructor also keeps ConnContext and
// VerifySourceAddress wired. With VerifySourceAddress unset, quicreuse's own
// anti-spoofing rate limiter REJECTS every inbound connection past its
// 1000-connection burst instead of verifying it, so an inbound burst was
// hard-refused with no log line. Keys are derived from the node identity, so
// stateless resets stay valid across restarts.
// QUICReuseOption is the single place that builds the QUIC/WebTransport
// ConnManager. Exported so p2ptap-boot uses the same wiring as the node; the two
// binaries differ only in the listenUDP hook they pass.
func QUICReuseOption(listenUDP func(network string, laddr *net.UDPAddr) (net.PacketConn, error), extra ...quicreuse.Option) libp2p.Option {
	opts := append([]quicreuse.Option{quicreuse.OverrideListenUDP(listenUDP)}, extra...)
	return libp2p.QUICReuse(
		func(key quic.StatelessResetKey, tokenKey quic.TokenGeneratorKey) (*quicreuse.ConnManager, error) {
			return quicreuse.NewConnManager(key, tokenKey, opts...)
		})
}

// protectedListenUDPForQUIC is the OverrideListenUDP hook: a TURN relay
// connection wins for its own address, everything else binds to the physical
// NIC so the socket never loops back into the TAP tunnel.
func protectedListenUDPForQUIC(network string, laddr *net.UDPAddr) (net.PacketConn, error) {
	if conn, ok := getTURNRelayConn(laddr.String()); ok {
		log.Debug("QUIC ConnManager: using TURN relay connection for %s", laddr.String())
		return conn, nil
	}
	return ProtectedListenUDP(network, laddr)
}
