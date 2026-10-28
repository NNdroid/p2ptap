package quicreuse

import (
	"time"

	"github.com/quic-go/quic-go"
)

// quicConfig is the base config for every QUIC and WebTransport connection this
// process accepts or dials (see ConnManager.clientConfig and newQuicListener).
//
// NOTE (p2ptap): the receive windows below are tuned for a VPN, not for the
// request/response traffic upstream libp2p expects. A flow-control window is a
// hard ceiling on throughput: bytes in flight cannot exceed it, so the best a
// single stream can do is window/RTT. At the upstream defaults (512 KB initial,
// 6 MB max stream, 15 MB connection) a transfer over a 100 ms path tops out
// around 490 Mbps no matter how fast the link is, and the initial 512 KB makes
// the first few hundred milliseconds of every bulk transfer crawl.
//
// Raising them costs no memory up front — quic-go sizes these as credit, and
// only payload actually in flight occupies a buffer — so the ceilings are set
// roughly an order of magnitude above the largest paths this overlay is
// expected to run over (32 MB covers 1.28 Gbps at 200 ms RTT). The initial
// windows are raised as well so a transfer reaches the ceiling in one RTT
// instead of ramping through quic-go's window autotuning.
var quicConfig = &quic.Config{
	MaxIncomingStreams:             256,
	MaxIncomingUniStreams:          5,              // allow some unidirectional streams, in case we speak WebTransport
	InitialStreamReceiveWindow:     1 * (1 << 20),  // 1 MB (quic-go default: 512 KB)
	MaxStreamReceiveWindow:         32 * (1 << 20), // 32 MB (upstream libp2p: 10 MB)
	InitialConnectionReceiveWindow: 4 * (1 << 20),  // 4 MB
	MaxConnectionReceiveWindow:     64 * (1 << 20), // 64 MB (upstream libp2p: 15 MB)
	KeepAlivePeriod:                15 * time.Second,
	Versions:                       []quic.Version{quic.Version1},
	// We don't use datagrams (yet), but this is necessary for WebTransport
	EnableDatagrams: true,
	// Required for WebTransport
	EnableStreamResetPartialDelivery: true,
}
