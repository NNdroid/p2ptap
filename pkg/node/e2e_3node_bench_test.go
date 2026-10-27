package node

// e2e_3node_bench_test.go — 3-node topology benchmarks. *_Mesh runs a full A-B-C
// mesh; *_Relay runs A -- B(relay) -- C with NO A<->C link so every frame must be
// routed. All four measure the real A TAP -> destination TAP path, pipelined
// (Throughput) or one frame at a time (Latency). This is not the ONLY end-to-end
// benchmark in the package: BenchmarkE2ERelayThroughput in
// e2e_relay_bench_test.go reaches the same shape through a different topology,
// and BenchmarkE2EFullPathTCP in e2e_rxpath_bench_test.go is the untrimmed
// two-node control.
//
// WHAT IS REAL HERE
//   Topology : three live libp2p hosts, each on its own MemTAP pair, each with a
//              REAL libp2p TCP listener on /ip4/0.0.0.0/tcp/0 (the wildcard
//              form is mandatory, not a portability compromise: AddrsFactory
//              runs filterAdvertisedAddrs, which drops every loopback address,
//              so a 127.0.0.1 listener advertises nothing and no peer can dial
//              it — see createTestNodeConfig).
//   Identity : real Ed25519 host keys, real libp2p connection handshake.
//              Peers recognise each other the same way production does — by
//              pushing the remote PeerInfo/Addresses and calling Host.Connect
//              (StaticPeers and BootstrapPeers are both empty, MDNS off).
//   Cipher   : the real SeqSync obfuscation session, established before any
//              measurement starts (e2e3bpWaitOverlayReady gates on
//              obfStateForPeer returning negotiated AND encrypted on both ends).
//              Every measured frame is then opened and re-sealed by the real
//              per-peer AEAD in processTapFrame / handleDirectFrame.
//   Forwarding: the real egress pipeline — MACTable/ARP-index resolution,
//              overlayRoute, canEgressWithRoute, ACL, Packer.Pack with a fresh
//              per-frame seqID, dispatchNonblocking, StrategyDispatcher.SendToPeer.
//   Multi-hop: the *_Relay variants run A -> B -> C with NO A<->C transport
//              link, so every frame must be wrapped in a routing.PackRelayFrame
//              envelope, hop-by-hop sealed by sealRelayEnvelopeForHop, carried
//              over the OverlayRelayProtocolID relay pool, and unwrapped by
//              handleRelayStream/handleRelayFrame at each hop. Nothing is
//              stubbed or mocked.
//   Receive  : the real handleStream read loop (4-byte length prefix + ReadFull
//              + per-stream decrypt scratch), per-peer seqID dedup, inbound ACL,
//              MAC learning, rewriteRxDstMAC, then enqueueTapWrite into the
//              destination node's MemTAP, which the drain goroutine reads.
//
// WHAT IS NOT MEASURED
//   The native kernel TAP driver (MemTAP is an in-process pipe with a 1024-deep
//   channel per direction) and any WAN/serialisation cost. This is an in-process
//   loopback overlay: the numbers are the overlay's own floor, not what a
//   laptop-over-the-internet run achieves.
//
// WHY EVERY FRAME CARRIES ITS OWN MARKER
//   processTapFrame calls n.Packer.NextSeqID(n.txEpochForPeer(target)) itself
//   (node_tap.go:888), so the seqID — and therefore the AEAD nonce derived from
//   it — is unique per frame and the per-peer seqID dedup window in
//   handleDirectFrame (node_streams.go:437) never eats one of our frames. On top
//   of that each UDP payload carries a 16-byte marker: an 8-byte monotonically
//   increasing sequence number plus 8 bytes of constant filler. The seq number
//   makes every frame individually addressable, so the latency runner can match
//   a delivered sample to the exact frame it sent and no delivered frame can be
//   mistaken for a stale one.
//
// NO SEND TIMESTAMP IS EMBEDDED IN THE PAYLOAD
//   The obvious way to get one-way latency is a time.Now().UnixNano() in the
//   payload. It does not work on this host and was tried: the monotonic clock
//   behind time.Now() quantises at ~505us here (199997 of 199999 consecutive
//   readings returned an identical value, and the only two distinct deltas were
//   0 and ~506us), so 94 % of sub-millisecond one-way latencies collapsed to
//   exactly 0 ns. Those numbers are worse than no numbers, so they were deleted
//   rather than reported. Latency is instead taken from testing.B's own ns/op,
//   which accumulates one high-precision (QueryPerformanceCounter-based) timer
//   reading over the whole benchmark and divides by b.N — the ~505us quantum
//   is spread across every iteration instead of hitting each frame.
//
// THROUGHPUT IS PACTED, NOT BURSTED
//   An unbounded burst into this pipeline is not a measurement: a 2000-frame
//   burst written in 5ms overruns the 1024-deep per-peer dedup window, and the
//   receiver then drops tail frames as "dedup desync" and re-anchors SeqSync
//   mid-flight ("16 sustained dedup desyncs ... triggering SeqSync
//   re-handshake"). The timed region therefore writes frames one at a time and
//   lets the real pipeline backpressure it: pipe.Write blocks as soon as the
//   sender's TAP channel is full, so the loop paces itself to whatever the
//   whole path — TAP, egress queue, p2p stream flow control, receiver dispatch
//   channel, destination TAP — can actually sustain.
//
// WARMUP IS OUT OF THE TIMED REGION
//   Handshake, key negotiation, MAC learning, ARP-index rebuild, dispatcher
//   stream open, relay-pool stream open, fragmentation/reassembly init and the
//   first-frame cold starts all cost a one-off. e2e3bpWarmup pushes
//   e2e3bpWarmupFrames and blocks until every one of them has crossed the
//   overlay and reached the destination TAP before b.ResetTimer() is called.
//   The timed region only ever sees steady-state frames.
//
// METRIC DEFINITIONS (read these before reading the numbers)
//   ns/op, B/op and allocs/op are testing.B's own, never overridden. They cover
//   exactly one "op" = one frame written into the source TAP, i.e. the whole
//   sender-side cost: frame build, MemTAP copy, the node's TAP read, egress
//   pipeline, p2p stream write, plus whatever wait time the pipeline's
//   backpressure imposes on that Write. B/op and allocs/op come from
//   b.ReportAllocs(), which samples the global allocator, so they include the
//   overlay's own goroutines, not only the sender.
//   Throughput variants additionally report frames/s and MB/s, computed from
//   the same wall time as ns/op so all three agree, plus %delivered / in_flight
//   / dispatch_drops which say how many of the written frames were actually read
//   back out of the destination TAP. dispatch_drops is summed over BOTH
//   endpoints: the counter that dispatchNonblocking (node_dispatch.go:138)
//   increments lives on the node that dispatches into its own TAP, i.e. the
//   destination.
//
//   in_flight is a LOWER BOUND on lost frames, and on *_Relay it is mostly
//   loss rather than queueing. Two uncounted paths were observed, neither of
//   which increments dispatchDropCount:
//     - "RelayPool: write queue full for <peer>, dropping frame" — the relay
//       pool's own admission drop. A minority of the shortfall: a handful of
//       occurrences per run, most of them inside the timed pump.
//     - a relay link tearing down mid-settle ("Peer disconnected ... transport
//       lost, cleaning link", followed by "Ping-pong keepalive failed 2 times
//       ... triggering reconnect") — frames in flight across the dead relay hop
//       are gone with no counter at all. This is the majority cause on
//       *_Relay: roughly 12000 of the 12824 unaccounted frames in the run that
//       produced the figures below, against 3 queue-full drops.
//   So %delivered on *_Relay is a lower bound on a churn-prone path, not a
//   steady-state loss rate. ns/op is unaffected because it only measures the
//   sender's paced cost.
//
//   Dedup-desync drops ("N sustained dedup desyncs ... triggering SeqSync
//   re-handshake") are a third uncounted path: they happen in handleDirectFrame
//   before dispatch, so they never reach dispatchDropCount either. They showed
//   up during warmup here, which is exactly why warmup is allowed to retry.
//
//   The mesh variants are usually clean but not always. Across three runs of
//   this benchmark the mesh residual after the 30s settle was 1248 then 595
//   then 0 frames on AtoB and 804 then 5 then 5 on AtoC, against 332461 and
//   245077 frames written — at most ~0.4 % and once fully drained. On the
//   relay path the residual is systematic instead: 12824, 7495 and 7380
//   frames against 40833, 40420 and 41995 written (17-31 %).
//   Where the mesh residual appears there is no corresponding counter and no
//   disconnect, dedup-desync or queue-full log line, so from outside the
//   process it cannot be told apart between "still queued somewhere inside
//   p2ptap" and "silently lost". Treating in_flight as loss is the
//   conservative reading. It also means the 30s settle cap is partly a
//   measurement artifact: a residual that will not drain in 30s is stuck, not
//   merely slow, so a longer cap would not recover those frames — but note
//   the cap is generous enough that a healthy path does fully drain (see the
//   0-frame AtoB run above).
//   Practical consequence: trust ns/op for the sender-side cost and the
//   latency variants for end-to-end time, and read %delivered / in_flight as
//   loss indicators with an explicit lower-bound meaning, never as queue depth.
//   Latency variants leave b.N as the iteration count, so ns/op is the mean
//   one-way end-to-end latency of one frame: write it, block until that frame is
//   read out of the destination TAP. The iteration also includes the driver's
//   own channel hand-off, which is sub-microsecond.
//
// LOG LEVEL
//   arp_ping_3node_test.go pins this package to LevelDebug from init(). Every
//   benchmark below pins LevelWarn for the measurement and restores LevelWarn,
//   deliberately NOT LevelDebug: the node teardown and drain goroutines run
//   AFTER the deferred restore, and restoring Debug there re-logs one line per
//   in-flight frame (a real topology leaves thousands in flight), flooding the
//   benchmark's stdout by megabytes. LevelWarn suppresses every per-frame DEBUG
//   line while leaving WARN+ visible. The hot-path per-frame logs are all
//   behind log.IsDebug() (node_streams.go:515, node_tap.go:907), so Warn vs
//   Debug costs nothing on the measured path.

import (
	"context"
	"encoding/binary"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"p2ptap/pkg/logger"
	"p2ptap/pkg/routing"
	"p2ptap/pkg/tap"
)

const (
	// e2e3bpTCPListen pins every node to a REAL libp2p TCP listener.
	e2e3bpTCPListen = "/ip4/0.0.0.0/tcp/0"

	// The marker-bearing ports make the delivered-frame shape unmistakable, so
	// control traffic (gratuitous ARP, NDP replies) can never be counted as a
	// delivered benchmark frame.
	e2e3bpSrcPort = 40000
	e2e3bpDstPort = 53

	// 8-byte sequence number + 8 bytes of constant filler, at the head of the
	// UDP payload (frame offset 42).
	e2e3bpMarkerLen = 16

	// 14 (Ethernet) + 20 (IPv4) + 8 (UDP) + 1188 = 1230 bytes, well under the
	// min(MTU+14, obfuscate.MaxFrameSize) cap validateTapWrite enforces.
	e2e3bpPayloadLen = 1188
	e2e3bpFrameBytes = 14 + 20 + 8 + e2e3bpPayloadLen

	e2e3bpWarmupFrames = 48
	e2e3bpWarmupCap    = 20 * time.Second

	// e2e3bpWarmupAttempts / e2e3bpWarmupRetryDelay bound how many times the
	// warmup is re-tried if a burst loses frames to a transient re-handshake.
	// Warmup is never timed, so absorbing churn here costs wall time and no
	// measurement integrity.
	e2e3bpWarmupAttempts   = 4
	e2e3bpWarmupRetryDelay = 500 * time.Millisecond
	e2e3bpWarmupSettle     = 150 * time.Millisecond

	// e2e3bpSettleCap bounds the POST-timer drain of the frames still in flight
	// when b.N iterations finished. They are not part of the measurement — they
	// exist only so the topology can be torn down without a live stream.
	e2e3bpSettleCap = 30 * time.Second

	// e2e3bpLatencyCap bounds one latency iteration: if the frame the benchmark
	// just sent has not reached the destination TAP by then the path is stalled.
	e2e3bpLatencyCap = 3 * time.Second

	// e2e3bpLatencyBatch is the group size used for the batch-granular latency
	// cross-check. 1024 frames at a 50us frame latency is about 51ms of wall
	// time, so this host's ~505us time.Now() quantum only costs ~1 % of
	// resolution per frame instead of destroying it.
	e2e3bpLatencyBatch = 1024

	e2e3bpSetupTimeout = 20 * time.Second
	e2e3bpEdgeRTTMs    = 10 // cost seeded for every real transport edge
	e2e3bpRelayRTTMs   = 12 // cost seeded for the B<->C edge
)

var (
	e2e3bpCIDRs = [3]string{"10.0.0.1/24", "10.0.0.2/24", "10.0.0.3/24"}
	e2e3bpIP6s  = [3]string{"fd00::1/64", "fd00::2/64", "fd00::3/64"}
	e2e3bpIP4s  = [3]net.IP{net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"), net.ParseIP("10.0.0.3")}
	e2e3bpNames = [3]string{"A", "B", "C"}
)

// e2e3bpNode is one node of the benchmark topology. tapDev is the device the
// Node owns; pipe is the OTHER end of the same MemTAP pair, so Write(pipe)
// injects a frame into this node's TAP and Read(pipe) yields this node's TAP
// output. NewMemTAPPair gives the two halves ONE shared closedChan, which is
// what makes the teardown below able to unblock a reader parked in Read().
type e2e3bpNode struct {
	tapDev *tap.MemTAP
	pipe   *tap.MemTAP
	node   *Node
	mac    net.HardwareAddr
	ip4    net.IP
	drains []*e2e3bpDrain
}

// e2e3bpMakeNode creates and starts one node with a real TCP listener.
func e2e3bpMakeNode(b *testing.B, idx int) *e2e3bpNode {
	b.Helper()
	tapDev, pipe := tap.NewMemTAPPair("e2e3bp-tap-"+strconv.Itoa(idx), "e2e3bp-pipe-"+strconv.Itoa(idx))
	cfg := createTestNodeConfig(e2e3bpCIDRs[idx], e2e3bpIP6s[idx], "best_path")
	cfg.ListenAddrs = []string{e2e3bpTCPListen}
	// This benchmark claims to measure the libp2p TCP path, so the hosts are
	// hardened to TCP only. Left at the defaults, WebRTC, WebTransport, DCUtR
	// hole-punching and libp2p circuit relay are all live as well: with no NAT or
	// STUN servers reachable they churn in the background — repeated STUN wipeouts,
	// periodic "Send failure ... triggering automatic hole-punching" reconnects and
	// the SeqSync re-handshakes those reconnects force. None of that traffic is part
	// of what is being measured, and the churn drops frames mid-warmup.
	// DisableRelay is deliberately NOT touched: p2ptap's own overlay relay (the
	// *_Relay variants) is not gated by it, per TransportsConfig.DisableRelay.
	cfg.Transports.EnableWebRTC = false
	cfg.Transports.EnableWebTransport = false
	cfg.Transports.DisableHolePunching = true
	cfg.Transports.DisableCircuitRelay = true
	// A real WebUI collector, not a noop: RecordFrame / RecordPacketDir /
	// RecordTxSeq / CaptureFrameWithPeers are no-ops on a noopCollector, which
	// would make the B/op and allocs/op numbers here uncomparable with the other
	// e2e slices. Every node on the path carries one, because they all sit on
	// the measured flow.
	col := e2eBenchCollector()
	n, err := NewNodeWithTAP(cfg, tapDev, col)
	if err != nil {
		col.Stop() // NewNodeWithTAP returns nil on error, so the collector is unowned
		b.Fatalf("e2e3bp: create node %s: %v", e2e3bpNames[idx], err)
	}
	n.Start()
	if len(n.localMAC) != 6 {
		n.Close()
		b.Fatalf("e2e3bp: node %s has no usable localMAC (len=%d)", e2e3bpNames[idx], len(n.localMAC))
	}
	return &e2e3bpNode{tapDev: tapDev, pipe: pipe, node: n, mac: n.localMAC, ip4: e2e3bpIP4s[idx]}
}

// e2e3bpConnect opens a real libp2p connection a -> c, bounded by a deadline
// because Host.Connect without one can block forever.
func e2e3bpConnect(b *testing.B, a, c *e2e3bpNode) {
	b.Helper()
	ctx, cancel := context.WithTimeout(a.node.ctx, 15*time.Second)
	defer cancel()
	ti := c.node.Host.Peerstore().PeerInfo(c.node.Host.ID())
	ti.Addrs = c.node.Host.Addrs()
	if err := a.node.Host.Connect(ctx, ti); err != nil {
		b.Fatalf("e2e3bp: connect %s -> %s: %v", e2e3bpNames[e2e3bpIndexOf(a)], e2e3bpNames[e2e3bpIndexOf(c)], err)
	}
}

// e2e3bpIndexOf recovers the topology slot of a node for error messages.
func e2e3bpIndexOf(n *e2e3bpNode) int {
	for i, ip := range e2e3bpIP4s {
		if ip.Equal(n.ip4) {
			return i
		}
	}
	return -1
}

// e2e3bpSeedMeta teaches every node about every other node's TAP identity, so
// MACTable lookup / IP fallback resolution is deterministic instead of racing
// LSA timing. This mirrors the production LSA/meta path's effect on the ARP
// index; the DATA path is still exercised in full.
func e2e3bpSeedMeta(nodes []*e2e3bpNode) {
	for _, src := range nodes {
		for _, dst := range nodes {
			if src == dst {
				continue
			}
			src.node.storePeerMeta(dst.node.Host.ID(), PeerMeta{
				NodeName: e2e3bpNames[e2e3bpIndexOf(dst)],
				TapIP:    dst.node.Config.TapIP,
				TapIPv6:  dst.node.Config.TapIPv6,
				TapMAC:   dst.mac.String(),
			})
		}
	}
}

// e2e3bpWaitOverlayReady blocks until the SeqSync obfuscation session is
// negotiated AND encrypted on BOTH ends of every connected pair. Until then a
// transmitted frame races the handshake and the per-peer cipher is missing.
func e2e3bpWaitOverlayReady(b *testing.B, nodes []*e2e3bpNode, pairs [][2]int) {
	b.Helper()
	deadline := time.Now().Add(e2e3bpSetupTimeout)
	for {
		var pending [][2]int
		for _, pr := range pairs {
			a, c := nodes[pr[0]], nodes[pr[1]]
			okA, _, encA := a.node.obfStateForPeer(c.node.Host.ID())
			okC, _, encC := c.node.obfStateForPeer(a.node.Host.ID())
			if !(okA && encA && okC && encC) {
				pending = append(pending, pr)
			}
		}
		if len(pending) == 0 {
			return
		}
		if time.Now().After(deadline) {
			b.Fatalf("e2e3bp: overlay encryption not ready for %d/%d pairs after %v",
				len(pending), len(pairs), e2e3bpSetupTimeout)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// e2e3bpSeedRelayRoute teaches `from` that `dst` is reachable only through
// `via`, the way B's flooded LSA would in production, and then asserts the
// router actually computes the non-direct route. Without this the relay data
// path is only reached if LSA propagation wins a race.
func e2e3bpSeedRelayRoute(b *testing.B, from, via, dst *e2e3bpNode) {
	b.Helper()
	from.node.Router.UpdateDirectLink(via.node.Host.ID(), e2e3bpEdgeRTTMs, routing.LinkDirect)
	via.node.Router.UpdateDirectLink(from.node.Host.ID(), e2e3bpEdgeRTTMs, routing.LinkDirect)
	via.node.Router.UpdateDirectLink(dst.node.Host.ID(), e2e3bpRelayRTTMs, routing.LinkDirect)

	lsa := buildSeedLSA(via.node, from.node)
	if !from.node.Router.ProcessLSA(lsa) {
		b.Fatalf("e2e3bp: %s rejected the seeded LSA from %s (seq=%d)",
			e2e3bpNames[e2e3bpIndexOf(from)], e2e3bpNames[e2e3bpIndexOf(via)], lsa.Seq)
	}
	from.node.invalidateRouteCache()

	r, ok := from.node.Router.ComputeRoutes()[dst.node.Host.ID()]
	if !ok || r.IsDirect || r.NextHop != via.node.Host.ID() {
		b.Fatalf("e2e3bp: %s has no relay route to %s via %s (ok=%v isDirect=%v nextHop=%v)",
			e2e3bpNames[e2e3bpIndexOf(from)], e2e3bpNames[e2e3bpIndexOf(dst)], e2e3bpNames[e2e3bpIndexOf(via)],
			ok, r.IsDirect, r.NextHop)
	}
	if rb, okB := via.node.Router.ComputeRoutes()[dst.node.Host.ID()]; !okB || rb.NextHop != dst.node.Host.ID() {
		b.Fatalf("e2e3bp: relay %s has no usable next hop to %s (ok=%v nextHop=%v) — it cannot forward",
			e2e3bpNames[e2e3bpIndexOf(via)], e2e3bpNames[e2e3bpIndexOf(dst)], okB, rb.NextHop)
	}
}

// e2e3bpBuildMesh builds the 3-node topology and registers an ordered teardown.
// linkAC=false leaves A and C without a transport link, forcing A->C traffic
// through B (a true multi-hop relay).
func e2e3bpBuildMesh(b *testing.B, linkAC bool) []*e2e3bpNode {
	b.Helper()
	nodes := make([]*e2e3bpNode, 3)
	for i := 0; i < 3; i++ {
		nodes[i] = e2e3bpMakeNode(b, i)
	}

	pairs := [][2]int{{0, 1}, {1, 2}}
	if linkAC {
		pairs = append(pairs, [2]int{0, 2})
	}
	for _, pr := range pairs {
		e2e3bpConnect(b, nodes[pr[0]], nodes[pr[1]])
	}

	e2e3bpSeedMeta(nodes)
	e2e3bpWaitOverlayReady(b, nodes, pairs)

	// Record the transport edges we really opened, in both directions, so the
	// router's graph matches the topology instead of disagreeing with it.
	for _, pr := range pairs {
		nodes[pr[0]].node.Router.UpdateDirectLink(nodes[pr[1]].node.Host.ID(), e2e3bpEdgeRTTMs, routing.LinkDirect)
		nodes[pr[1]].node.Router.UpdateDirectLink(nodes[pr[0]].node.Host.ID(), e2e3bpEdgeRTTMs, routing.LinkDirect)
	}
	if !linkAC {
		e2e3bpSeedRelayRoute(b, nodes[0], nodes[1], nodes[2])
	}
	nodes[0].node.invalidateRouteCache()
	nodes[1].node.invalidateRouteCache()
	nodes[2].node.invalidateRouteCache()

	_ = nodes[0].pipe.ConfigureIP(nodes[0].node.Config.TapIP, nodes[0].node.Config.TapIPv6)
	_ = nodes[1].pipe.ConfigureIP(nodes[1].node.Config.TapIP, nodes[1].node.Config.TapIPv6)
	_ = nodes[2].pipe.ConfigureIP(nodes[2].node.Config.TapIP, nodes[2].node.Config.TapIPv6)

	// Ordered teardown: close the nodes first (Node.Close closes the TAP, which
	// closes the shared closedChan and gives the drain goroutines EOF), then the
	// pipes, then wait for the drains, then yield so the next benchmark round
	// cannot race this one for local socket ports.
	b.Cleanup(func() {
		for i := 0; i < len(nodes); i++ {
			_ = nodes[i].node.Close()
		}
		for i := range nodes {
			_ = nodes[i].tapDev.Close()
			_ = nodes[i].pipe.Close()
		}
		for i := range nodes {
			for _, d := range nodes[i].drains {
				select {
				case <-d.done:
				case <-time.After(5 * time.Second):
					b.Logf("e2e3bp: a drain goroutine on node %s did not exit within 5s", e2e3bpNames[i])
				}
			}
		}
		time.Sleep(300 * time.Millisecond)
	})
	return nodes
}

// e2e3bpVerifyPath proves the measured flow actually takes the path the
// benchmark claims. A benchmark that reports "1 hop" for a frame that silently
// took 2 hops is worse than no number at all.
func e2e3bpVerifyPath(b *testing.B, from, via, dst *e2e3bpNode, wantDirect bool) {
	b.Helper()
	route, ok := from.node.overlayRoute(dst.node.Host.ID(), routing.MaxRelayTTL, "")
	if wantDirect {
		if ok && !route.IsDirect && route.NextHop != "" {
			b.Fatalf("e2e3bp: expected a direct A->%s path but the router chose nextHop=%v — refusing to measure",
				e2e3bpNames[e2e3bpIndexOf(dst)], route.NextHop)
		}
		return
	}
	if !ok || route.IsDirect || route.NextHop != via.node.Host.ID() {
		b.Fatalf("e2e3bp: expected %s -> %s -> %s but got ok=%v isDirect=%v nextHop=%v",
			e2e3bpNames[e2e3bpIndexOf(from)], e2e3bpNames[e2e3bpIndexOf(via)], e2e3bpNames[e2e3bpIndexOf(dst)],
			ok, e2e3bpIsDirect(route), route.NextHop)
	}
}

// e2e3bpIsDirect isolates the field read so the Fatalf above stays readable.
func e2e3bpIsDirect(r routing.RouteInfo) bool { return r.IsDirect }

// e2e3bpFrame builds one 1230-byte Ethernet/IPv4/UDP frame carrying the
// 16-byte marker. seq makes the frame individually addressable.
func e2e3bpFrame(seq uint64, srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP) []byte {
	payload := make([]byte, e2e3bpPayloadLen)
	binary.BigEndian.PutUint64(payload[0:8], seq)
	for i := e2e3bpMarkerLen; i < len(payload); i++ {
		payload[i] = byte(i & 0x7f)
	}
	return buildUDPIPv4Frame(srcMAC, dstMAC, srcIP, dstIP, e2e3bpSrcPort, e2e3bpDstPort, payload)
}

// e2e3bpIsMarkerFrame reports whether f is one of OUR frames, and nothing else.
// It is the only filter the drain uses, so gratuitous ARP, NDP and any other
// control traffic the nodes emit cannot pollute the count.
func e2e3bpIsMarkerFrame(f []byte) bool {
	if len(f) < 42+e2e3bpMarkerLen {
		return false
	}
	if binary.BigEndian.Uint16(f[12:14]) != 0x0800 { // IPv4
		return false
	}
	if f[23] != 17 { // UDP
		return false
	}
	if binary.BigEndian.Uint16(f[34:36]) != e2e3bpSrcPort || binary.BigEndian.Uint16(f[36:38]) != e2e3bpDstPort {
		return false
	}
	return true
}

// e2e3bpSample is one delivered frame as seen at the destination TAP. Only the
// sequence number is carried: it is what the latency runner uses to match a
// sample to the frame it sent. No timestamp — see the header note on why.
type e2e3bpSample struct {
	seq uint64
}

// e2e3bpDrain is the single long-lived consumer of one destination MemTAP. It
// counts delivered marker frames and, when asked, publishes them on a channel
// for the latency runner. One reader per pipe is mandatory: two readers would
// silently split the frame stream (MemTAP.ErrConcurrentRead makes that loud,
// but there is no reason to take the risk).
type e2e3bpDrain struct {
	frames  atomic.Uint64
	bytes   atomic.Uint64
	samples chan e2e3bpSample
	done    chan struct{}
}

func e2e3bpStartDrain(pipe *tap.MemTAP, withSamples bool) *e2e3bpDrain {
	d := &e2e3bpDrain{done: make(chan struct{})}
	if withSamples {
		d.samples = make(chan e2e3bpSample, 512)
	}
	go func() {
		defer close(d.done)
		buf := make([]byte, 8192)
		for {
			n, err := pipe.Read(buf)
			if err != nil {
				return
			}
			if !e2e3bpIsMarkerFrame(buf[:n]) {
				continue
			}
			payload := buf[42:n]
			d.frames.Add(1)
			d.bytes.Add(uint64(n))
			if d.samples != nil {
				d.samples <- e2e3bpSample{seq: binary.BigEndian.Uint64(payload[0:8])}
			}
		}
	}()
	return d
}

// e2e3bpWarmup pushes e2e3bpWarmupFrames over the REAL path and blocks until
// every one has crossed the overlay into the destination TAP. It is what pays
// for the handshake leftovers, MAC learning, dispatcher stream open and the
// relay-pool stream open, so all of it stays OUT of the timed region.
//
// It RETRIES on a stalled attempt rather than failing the benchmark. A single
// frame lost to a transient re-handshake would otherwise sink the whole run for
// a reason that is not the thing being measured; warmup is the place to absorb
// it, because it is the one part of this file that is never timed. Each retry
// uses a fresh sequence range so a re-anchored seqID epoch cannot collide with
// an attempt that is still draining.
//
// Returns the first sequence number free for measurement.
func e2e3bpWarmup(b *testing.B, tx, dst *e2e3bpNode, d *e2e3bpDrain, startSeq uint64) uint64 {
	b.Helper()
	next := startSeq
	for attempt := 1; attempt <= e2e3bpWarmupAttempts; attempt++ {
		base := d.frames.Load()
		for i := 0; i < e2e3bpWarmupFrames; i++ {
			frame := e2e3bpFrame(next+uint64(i), tx.mac, dst.mac, tx.ip4, dst.ip4)
			if _, err := tx.pipe.Write(frame); err != nil {
				b.Fatalf("e2e3bp: warmup write %d failed: %v", i, err)
			}
		}
		next += e2e3bpWarmupFrames

		deadline := time.Now().Add(e2e3bpWarmupCap)
		for d.frames.Load()-base < e2e3bpWarmupFrames && time.Now().Before(deadline) {
			time.Sleep(5 * time.Millisecond)
		}
		delivered := d.frames.Load() - base
		if delivered >= e2e3bpWarmupFrames {
			// Let the last warmup frame settle through the writer queue and dedup
			// window before the measurement starts.
			time.Sleep(e2e3bpWarmupSettle)
			return next
		}
		b.Logf("e2e3bp: warmup attempt %d/%d stalled at %d/%d frames — retrying after %v",
			attempt, e2e3bpWarmupAttempts, delivered, e2e3bpWarmupFrames, e2e3bpWarmupRetryDelay)
		time.Sleep(e2e3bpWarmupRetryDelay)
	}
	b.Fatalf("e2e3bp: warmup stalled on %d attempts — refusing to measure on a path that will not warm up",
		e2e3bpWarmupAttempts)
	return 0
}

// e2e3bpDrops sums the dispatch-queue drops across the given nodes. The counter
// is bumped by dispatchNonblocking (node_dispatch.go:138) on the node that
// dispatches a frame into its OWN TAP, so for a source->destination flow the
// number that matters is the destination's — reading only the sender's would
// silently report zero.
func e2e3bpDrops(nodes ...*e2e3bpNode) uint64 {
	var sum uint64
	for _, n := range nodes {
		sum += atomic.LoadUint64(&n.node.dispatchDropCount)
	}
	return sum
}

// e2e3bpRunThroughput writes one 1230-byte frame per benchmark iteration into
// the sender's TAP. That Write blocks as soon as the path is full, so the loop
// paces itself to whatever the whole pipeline — TAP channel, egress queue, p2p
// stream flow control, receiver dispatch channel, destination TAP — can
// actually sustain. testing.B's own ns/op, B/op and allocs/op are left in
// place and never overridden.
func e2e3bpRunThroughput(b *testing.B, tx, dst *e2e3bpNode, d *e2e3bpDrain, startSeq uint64) {
	b.Helper()
	if b.N < 1 {
		b.N = 1
	}
	// The frame body is a steady-state shape, so build it once and only roll the
	// sequence marker per iteration. What matters here is the frame as it hits
	// the TAP, not how the bytes were assembled.
	frame := e2e3bpFrame(startSeq, tx.mac, dst.mac, tx.ip4, dst.ip4)

	baseFrames := d.frames.Load()
	baseBytes := d.bytes.Load()
	baseDrops := e2e3bpDrops(tx, dst)

	b.ReportAllocs()
	b.ResetTimer()
	start := time.Now()

	for i := 0; i < b.N; i++ {
		binary.BigEndian.PutUint64(frame[42:50], startSeq+uint64(i))
		if _, err := tx.pipe.Write(frame); err != nil {
			b.Fatalf("e2e3bp: write frame %d: %v", i, err)
		}
	}
	b.StopTimer()
	started := time.Since(start)

	// The measured work is done, so whatever is still inside the pipeline is
	// bookkeeping, not throughput. Drain it so the teardown below does not race
	// a live stream.
	for time.Since(start) < e2e3bpSettleCap {
		if d.frames.Load()-baseFrames+e2e3bpDrops(tx, dst)-baseDrops >= uint64(b.N) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	deliveredN := d.frames.Load() - baseFrames
	deliveredBytes := d.bytes.Load() - baseBytes
	droppedN := e2e3bpDrops(tx, dst) - baseDrops
	inFlight := uint64(b.N) - deliveredN - droppedN
	if inFlight > uint64(b.N) {
		inFlight = 0
	}
	if inFlight > 0 {
		b.Logf("e2e3bp: %d frames still inside the pipeline %v after the pump (neither delivered nor counted as dispatch drops)",
			inFlight, time.Since(start).Truncate(time.Millisecond))
	}
	if deliveredN == 0 {
		b.Fatalf("e2e3bp: ZERO frames delivered over %v — the data path is stalled", started.Truncate(time.Millisecond))
	}

	// frames/s, MB/s and bytes/frame cover ONE frame written into the source
	// TAP, not just what happened to be read back when the run ended. They come
	// from time.Now() rather than testing.B's high-precision timer, so on this
	// host they disagree with 1e9/ns_op by up to a few percent: the coarse
	// clock's tick is about 400-505us, so a 300ms window carries roughly
	// 1-2 ticks of rounding. ns/op is the accurate one; these are for reading.
	// At a -benchtime so small that one op fits inside a tick, time.Since reads
	// 0 and these two are reported as 0 rather than +Inf — ns/op is still exact.
	perFrameNs := float64(started.Nanoseconds()) / float64(b.N)
	framesPerSec, mbPerSec := 0.0, 0.0
	if perFrameNs > 0 {
		framesPerSec = 1e9 / perFrameNs
		mbPerSec = float64(e2e3bpFrameBytes) * 1e9 / perFrameNs / 1e6
	}
	b.ReportMetric(framesPerSec, "frames/s")
	b.ReportMetric(mbPerSec, "MB/s")
	// There is deliberately no frames/s-style "delivery rate" here. The timed
	// loop only waits on the sender's TAP channel, never on delivery, so a rate
	// over the write wall would overstate the rate at which frames reach the
	// destination TAP on a path that drops frames; and a rate over the write
	// plus drain window collapses to ~delivered/e2e3bpSettleCap whenever the
	// drain runs to the settle cap instead of breaking early. Which variants hit
	// the cap depends on runtime load, so a delivery rate is either wrong or
	// meaningless. The delivery verdict is the counts below — %delivered and
	// in_flight — which stay honest regardless of how the drain ended.
	b.ReportMetric(float64(e2e3bpFrameBytes), "bytes/frame")
	b.ReportMetric(100*float64(deliveredN)/float64(b.N), "%delivered")
	b.ReportMetric(float64(b.N), "written")
	b.ReportMetric(float64(deliveredN), "delivered")
	b.ReportMetric(float64(droppedN), "dispatch_drops")
	// in_flight is a LOWER BOUND on frames that never surfaced. The relay pool
	// drops frames when its write queue is full ("RelayPool: write queue full ...
	// dropping frame") and that drop does NOT touch dispatchDropCount, so on the
	// *_Relay variant some of this number is silently dropped rather than
	// genuinely in flight. Verify against the log before trusting it.
	b.ReportMetric(float64(inFlight), "in_flight")
	b.Logf("e2e3bp: %d frames written, %d delivered (%.1f%%), %d dispatch drops, %d still in flight, %d bytes delivered, %.3f s",
		b.N, deliveredN, 100*float64(deliveredN)/float64(b.N), droppedN, inFlight, deliveredBytes, started.Seconds())
}

// e2e3bpRunLatency sends exactly one frame per benchmark iteration and blocks
// until THAT frame is read out of the destination TAP. One frame in flight at
// a time, so testing.B's ns/op is the one-way end-to-end latency, not a queueing
// artefact — and testing.B's timer accumulates ONE high-precision reading over
// the whole run and divides by b.N, so the mean is not poisoned by this host's
// ~505us time.Now() quantum the way a per-frame timestamp would be.
//
// The lat_batch_* metrics are a batch-granular cross-check of that mean. The
// quantum only costs 505us of resolution per BATCH instead of per frame, so a
// 1024-frame batch resolves to about a microsecond per frame. Read the check
// against ns/op: at -benchtime 1x there is one frame in one batch, so the whole
// batch fits inside a single clock tick and lat_batch_ns legitimately reads 0 —
// ns/op is still right because it comes from testing.B's own timer.
func e2e3bpRunLatency(b *testing.B, tx, dst *e2e3bpNode, d *e2e3bpDrain, startSeq uint64) {
	b.Helper()
	if d.samples == nil {
		b.Fatalf("e2e3bp: latency runner needs a sample-producing drain")
	}
	if b.N < 1 {
		b.N = 1
	}
	frame := e2e3bpFrame(startSeq, tx.mac, dst.mac, tx.ip4, dst.ip4)

	b.ReportAllocs()
	b.ResetTimer()

	timer := time.NewTimer(e2e3bpLatencyCap)
	defer timer.Stop()

	batchWall := make([]int64, 0, 16)
	batchStart := time.Now()
	for i := 0; i < b.N; i++ {
		seq := startSeq + uint64(i)
		binary.BigEndian.PutUint64(frame[42:50], seq)
		if _, err := tx.pipe.Write(frame); err != nil {
			b.Fatalf("e2e3bp: latency write seq=%d: %v", seq, err)
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(e2e3bpLatencyCap)

		got := e2e3bpSample{}
		for got.seq != seq {
			select {
			case sp, ok := <-d.samples:
				if !ok {
					b.Fatalf("e2e3bp: destination drain exited before seq %d was delivered", seq)
				}
				got = sp
			case <-timer.C:
				b.Fatalf("e2e3bp: no frame arrived within %v for seq %d — the data path is stalled",
					e2e3bpLatencyCap, seq)
			}
		}

		if (i+1)%e2e3bpLatencyBatch == 0 || i == b.N-1 {
			end := time.Now()
			batchWall = append(batchWall, end.Sub(batchStart).Nanoseconds())
			batchStart = end
		}
	}
	b.StopTimer()

	// Per-frame latency implied by each batch, so a stable path yields a tight
	// set and a jumpy one does not.
	batchPer := make([]int64, len(batchWall))
	for i, w := range batchWall {
		n := int64(e2e3bpLatencyBatch)
		if i == len(batchWall)-1 {
			if tail := int64(b.N) % n; tail > 0 {
				n = tail
			}
		}
		batchPer[i] = w / n
	}
	var batchSum int64
	min, max := batchPer[0], batchPer[0]
	for _, v := range batchPer {
		batchSum += v
		if v < min {
			min = v
		}
		if v > max {
			max = v
		}
	}
	b.ReportMetric(float64(batchSum)/float64(len(batchPer)), "lat_batch_ns")
	b.ReportMetric(float64(max-min), "lat_batch_spread_ns")
	b.ReportMetric(float64(b.N)/float64(len(batchWall)), "lat_batch_frames")
	b.ReportMetric(float64(e2e3bpFrameBytes), "bytes/frame")
	b.Logf("e2e3bp: %d frames matched one-for-one at the destination TAP in %d batches (mean %.1f frames/batch); batch mean=%d ns, spread=%d ns, %d bytes/frame",
		b.N, len(batchWall), float64(b.N)/float64(len(batchWall)),
		batchSum/int64(len(batchPer)), max-min, e2e3bpFrameBytes)
}

// e2e3bpFlow is one warmed-up source->destination pair, ready to measure.
type e2e3bpFlow struct {
	name string
	tx   *e2e3bpNode
	dst  *e2e3bpNode
	d    *e2e3bpDrain
	seq  uint64
	via  *e2e3bpNode
}

// e2e3bpSetupFlow verifies the router really chose the path the benchmark claims
// to measure, opens a drain on the destination TAP and warms the path up. The
// drain is recorded on tx.drains so the shared teardown closes it with the pipe.
func e2e3bpSetupFlow(b *testing.B, tx, via, dst *e2e3bpNode, name string, withSamples, wantDirect bool) e2e3bpFlow {
	b.Helper()
	d := e2e3bpStartDrain(dst.pipe, withSamples)
	tx.drains = append(tx.drains, d)
	e2e3bpVerifyPath(b, tx, via, dst, wantDirect)
	seq := e2e3bpWarmup(b, tx, dst, d, 1)
	return e2e3bpFlow{name: name, tx: tx, dst: dst, d: d, seq: seq, via: via}
}

// BenchmarkE2E3NodeThroughput_Mesh — sustained per-frame cost on a REAL 3-node
// full mesh (A-B, B-C, A-C all live libp2p TCP links). One op is one 1230-byte
// frame written into A's TAP, paced by the pipeline's own backpressure. The
// subtests cover both direct destinations reachable from A: one hop to B and
// one hop to C.
//
// The topology and both warmups live in this function body, not in the b.Run
// closures. testing.B calibrates by replaying whatever function it is given:
// a b.Run closure is replayed at every calibration N (on Go 1.27 a 50x run
// replays it at N=1 and then at N=50), and a benchmark that declares NO
// subtests replays its ENTIRE body instead. So with build-and-warm above and
// only the measurement inside the closure, this benchmark builds one mesh and
// pays the 48-frame warmup — which itself retries to absorb transient
// re-handshakes — exactly once, instead of once per calibration replay. Each
// extra mesh build would also be another chance to land on a flapping link.
// Verified by probe: the parent body of a b.Run-bearing benchmark runs once,
// while each b.Run closure runs once per calibration N.
func BenchmarkE2E3NodeThroughput_Mesh(b *testing.B) {
	logger.SetGlobalLevel(logger.LevelWarn)
	defer logger.SetGlobalLevel(logger.LevelWarn)

	nodes := e2e3bpBuildMesh(b, true)
	flows := []e2e3bpFlow{
		e2e3bpSetupFlow(b, nodes[0], nil, nodes[1], "AtoB_1hop", false, true),
		e2e3bpSetupFlow(b, nodes[0], nil, nodes[2], "AtoC_1hop", false, true),
	}
	for _, f := range flows {
		f := f
		b.Run(f.name, func(b *testing.B) { e2e3bpRunThroughput(b, f.tx, f.dst, f.d, f.seq) })
	}
}

// BenchmarkE2E3NodeLatency_Mesh — one-way end-to-end latency per frame on the
// same full mesh. Each iteration sends one 1230-byte frame and waits for that
// frame to be read out of the destination TAP.
func BenchmarkE2E3NodeLatency_Mesh(b *testing.B) {
	logger.SetGlobalLevel(logger.LevelWarn)
	defer logger.SetGlobalLevel(logger.LevelWarn)

	nodes := e2e3bpBuildMesh(b, true)
	flows := []e2e3bpFlow{
		e2e3bpSetupFlow(b, nodes[0], nil, nodes[1], "AtoB_1hop", true, true),
		e2e3bpSetupFlow(b, nodes[0], nil, nodes[2], "AtoC_1hop", true, true),
	}
	for _, f := range flows {
		f := f
		b.Run(f.name, func(b *testing.B) { e2e3bpRunLatency(b, f.tx, f.dst, f.d, f.seq) })
	}
}

// BenchmarkE2E3NodeThroughput_Relay — sustained delivered throughput for the
// only topology that forces multi-hop forwarding: A -- B(relay) -- C with NO
// A<->C link. Every frame is end-to-end wrapped in a relay envelope, hop-by-hop
// sealed, and rewritten once at B. This is the kind:2 dispatch path.
//
// Read %delivered and in_flight together — dispatch_drops stays 0 here and
// that is NOT because nothing was lost. The relay path's links flap during a
// run (repeated "Peer disconnected ... transport lost, cleaning link" events
// followed by keepalive failures and a reconnect/re-handshake cycle), and a
// frame in flight across a torn-down relay hop is dropped with no counter
// anywhere in the code. "RelayPool: write queue full ... dropping frame" is
// another uncounted drop, but it is only a minority of the shortfall. Observed
// across two runs: 7495 and 12824 frames unaccounted at the 30s settle
// deadline, against 2-3 queue-full drops.
//
// So in_flight is a lower bound on LOST frames, not a queue depth, and
// %delivered is a lower bound on a churn-prone path rather than a
// steady-state loss rate. ns/op is unaffected: it only measures the sender's
// paced cost.
func BenchmarkE2E3NodeThroughput_Relay(b *testing.B) {
	logger.SetGlobalLevel(logger.LevelWarn)
	defer logger.SetGlobalLevel(logger.LevelWarn)

	nodes := e2e3bpBuildMesh(b, false)
	f := e2e3bpSetupFlow(b, nodes[0], nodes[1], nodes[2], "AtoC_2hop_via_B", false, false)
	b.Run("AtoC_2hop_via_B", func(b *testing.B) { e2e3bpRunThroughput(b, f.tx, f.dst, f.d, f.seq) })
}

// BenchmarkE2E3NodeLatency_Relay — one-way end-to-end latency of the same
// A -> B(relay) -> C two-hop path, one frame in flight at a time. Comparing it
// with BenchmarkE2E3NodeLatency_Mesh gives the cost of one relay hop
// (envelope wrap/unwrap, a second AEAD seal, one extra stream and one extra
// hop-by-hop decrypt) in the same units.
func BenchmarkE2E3NodeLatency_Relay(b *testing.B) {
	logger.SetGlobalLevel(logger.LevelWarn)
	defer logger.SetGlobalLevel(logger.LevelWarn)

	nodes := e2e3bpBuildMesh(b, false)
	f := e2e3bpSetupFlow(b, nodes[0], nodes[1], nodes[2], "AtoC_2hop_via_B", true, false)
	b.Run("AtoC_2hop_via_B", func(b *testing.B) { e2e3bpRunLatency(b, f.tx, f.dst, f.d, f.seq) })
}
