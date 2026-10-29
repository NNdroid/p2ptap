package node

// Overlay-relay data-path benchmark.
//
// WHAT IS END-TO-END
//   BenchmarkE2ERelayThroughput is the real flow: a frame written to nodeA's
//   TAP, resolved, packed, sealed end-to-end for C, wrapped in a relay envelope,
//   hop-sealed for B, carried over the real libp2p stream, forwarded by nodeB
//   (re-pack + re-seal + relay stream Submit), counted at nodeC's TAP. Every
//   stage is live, including both stream writes.
//
// WHAT IS HOP-ONLY
//   BenchmarkE2ERelayForwardHop and BenchmarkE2ERelayFinalHop are hop-level
//   micro-benchmarks of handleRelayFrame (node_streams.go:1183), the function
//   every inbound relay stream funnels through. They are NOT end-to-end: the
//   envelope is built by the benchmark itself (rlbpEnvelopeBuilder /
//   rlbpFinalHopBuilder, mirroring node_tap.go:888-958) and fed straight to
//   handleRelayFrame, so the origin TAP entry and the A->B transport are out of
//   scope. Read them as hop-cost breakdowns, never as end-to-end numbers.
//
// Topology: A(origin) -- B(relay) -- C(final destination). All three pairs are
// connected and fully negotiated, so every cipher used anywhere on the path is
// a real SeqSync cipher — including A<->C, which the inner end-to-end layer
// requires. A's A-C edge is then withdrawn from A's ROUTER graph only, so A's
// routing says "C is reachable only via B" while the transport stays up. That
// is exactly the production shape: a route that must go through a relay, with
// a usable end-to-end key to the destination.
//
// Two scratch buffers, never one. handleRelayFrame takes two and rebases both
// on every call (node_streams.go:1136-1137, 1146): the outer envelope opens
// into relayDecScratch and innerPayload is a SUB-SLICE of it
// (node_streams.go:1248), so the end-to-end inner decrypt
// (node_streams.go:1375) must open into a second, independent buffer — the
// in-place AEAD-open-over-overlapping-memory trap called out in frag.go and
// re-flagged at node_streams.go:1372-1374. One shared scratch would open a
// frame against its own output.

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"p2ptap/pkg/logger"
	"p2ptap/pkg/obfuscate"
	"p2ptap/pkg/routing"
	"p2ptap/pkg/tap"
)

const (
	// 58 * 20B repeat units = 1160B payload, so the whole Ethernet frame is
	// 14+20+8+1160 = 1202B: under the 1514 TAP cap, and small enough that the
	// hop-sealed relay envelope still fits one 2 KiB pooled buffer
	// (acquireFrameBuf, bufpool.go:38).
	rlbpPayloadLen = 1160

	// MaxRelayTTL-1: the envelope must reach B ALREADY decremented once, so the
	// origin gate admits it. A frame claiming srcPeer != carrier with
	// ttl == MaxRelayTTL advertises a zero-hop path that cannot exist and is
	// dropped at node_streams.go:1337 (the ROUND 8 TTL-downgrade gate).
	rlbpRelayedTTL = routing.MaxRelayTTL - 1
)

// rlbpPayload is 58 copies of the 20-byte wire marker "RLBPRELAY0RLBPRELAY0".
// The repeat makes the payload long enough that no control frame can ever
// collide with the marker the drain matcher looks for.
var rlbpPayload = bytes.Repeat([]byte("RLBPRELAY0RLBPRELAY0"), rlbpPayloadLen/len("RLBPRELAY0RLBPRELAY0"))

// rlbpThruPayload is the throughput benchmark's own marker, deliberately NOT a
// substring of rlbpPayload: rlbpWarmThroughRelay pushes a warm-up frame that
// ends with rlbpPayload into the same topology before the drain starts, and
// rlbpUDPMatch matches by SUFFIX, so a shared marker would count the straggler
// warm frame as a delivered timed frame (observed: delivered = written + 1).
var rlbpThruPayload = bytes.Repeat([]byte("RLBPTH00"), rlbpPayloadLen/len("RLBPTH00"))

func init() {
	if len(rlbpPayload) != rlbpPayloadLen {
		panic("rlbpPayloadLen must be a multiple of the repeat unit")
	}
	if len(rlbpThruPayload) != rlbpPayloadLen {
		panic("rlbpPayloadLen must be a multiple of the throughput repeat unit")
	}
	if bytes.Contains(rlbpThruPayload, rlbpPayload) || bytes.Contains(rlbpPayload, rlbpThruPayload) {
		panic("rlbpThruPayload must be distinguishable from rlbpPayload")
	}
}

// rlbpCounter is a lock-free monotonic frame counter: the drain goroutine adds
// once per delivered frame, the benchmark reads it after stopping the timer.
// The mutex-based atomicCounter used by the throughput benchmarks serialises on
// every frame and would sit in the measured path.
type rlbpCounter uint64

func (c *rlbpCounter) add(n uint64)   { atomic.AddUint64((*uint64)(c), n) }
func (c *rlbpCounter) load() uint64   { return atomic.LoadUint64((*uint64)(c)) }
func (c *rlbpCounter) store(n uint64) { atomic.StoreUint64((*uint64)(c), n) }

// rlbpIP keeps the frame builders short.
func rlbpIP(s string) net.IP { return net.ParseIP(s) }

// rlbpMesh is the A -- B -- C topology shared by every benchmark in this file.
type rlbpMesh struct {
	nodeA, nodeB, nodeC *Node
	pipeA, pipeB, pipeC *tap.MemTAP

	drainedA  chan struct{} // closed when pipeA's drain goroutine exits
	drainedC  chan struct{} // closed when pipeC's drain goroutine exits
	closeOnce sync.Once
}

// rlbpWaitOverlayReady is the benchmark-shaped twin of waitOverlayReady: it
// blocks until the encrypted overlay between two nodes is negotiated BOTH
// ways, because a frame sent earlier races the ECDH handshake and is dropped.
func rlbpWaitOverlayReady(b *testing.B, a, c *Node) {
	b.Helper()
	for i := 0; i < 150; i++ {
		okA, _, encA := a.obfStateForPeer(c.Host.ID())
		okC, _, encC := c.obfStateForPeer(a.Host.ID())
		if okA && encA && okC && encC {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	b.Fatalf("rlbp: overlay never became ready between %s and %s",
		a.Host.ID().ShortString(), c.Host.ID().ShortString())
}

// rlbpWarmStream is the benchmark-shaped twin of waitStreamReady: it pre-pays
// the one-off NewStream + application-protocol negotiation so the timed region
// is steady state. The probe is packed with a FRESH seqID per attempt, because
// the AEAD nonce is derived from the frame header and a reused seqID would
// reuse one nonce under the same key.
func rlbpWarmStream(b *testing.B, a, c *Node) {
	b.Helper()
	ctx, cancel := context.WithTimeout(a.ctx, 12*time.Second)
	defer cancel()
	probe := []byte("RLBP_STREAM_WARMUP_PROBE")
	for i := 0; i < 150; i++ {
		outBuf := make([]byte, len(probe)+obfuscate.HeaderLen+4096)
		n, perr := a.Packer.Pack(a.nextTxSeqID(c.Host.ID()), probe, outBuf)
		if perr != nil {
			b.Fatalf("rlbp: pack stream warm-up probe: %v", perr)
		}
		if err := a.Dispatcher.SendToPeer(ctx, c.Host.ID(), outBuf[:n]); err == nil {
			time.Sleep(100 * time.Millisecond)
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	b.Fatalf("rlbp: %s could not open a working stream to %s in time",
		a.Host.ID().ShortString(), c.Host.ID().ShortString())
}

// rlbpSeedLSA builds an LSA advertising from's graph that to's router accepts.
// ProcessLSA rejects a replay on two axes — the sequence must exceed to's
// recorded sequence for the origin and must not jump by more than
// maxLSASeqJump — so the anchor is to's recorded sequence, not the wall clock
// that startup LSA broadcasts run from.
func rlbpSeedLSA(from, to *Node) *routing.LinkStatePayload {
	return from.Router.BuildLSA(to.Router.SeedableLSASeq(from.Host.ID()), routing.NodeIdentity{
		NodeName:          from.nodeName,
		TapIP:             from.Config.TapIP,
		TapIPv6:           from.Config.TapIPv6,
		TapMAC:            from.Config.TapMAC,
		OS:                runtime.GOOS,
		Arch:              runtime.GOARCH,
		IsExitNode:        from.Config.ExitNode.Enable,
		AdvertisedSubnets: from.Config.AdvertisedSubnets,
	})
}

// rlbpSetup builds the three-node mesh and returns it in steady state: ciphers
// negotiated both ways on every edge, deterministic router tables, and a
// non-direct A->C route whose next hop is the relay.
//
// A and C are connected even though A never uses that edge to reach C. The
// inner payload is sealed END-TO-END for C by A (node_tap.go:932-943), so
// without an A<->C cipher C's inner decrypt (node_streams.go:1371) finds a nil
// cipher, silently SKIPS the stage, and the benchmark would report a number for
// an inner payload that was never decrypted. Every A<->B forward is also gated
// on B advertising OverlayRelayProtocolID (route_selection.go:47), which is
// registered for every node at node.go:2339.
func rlbpSetup(b *testing.B) *rlbpMesh {
	b.Helper()
	const listen = "/ip4/0.0.0.0/tcp/0" // wildcard is mandatory: loopback addrs are not advertised

	tapA, pipeA := tap.NewMemTAPPair("rlbp-tapA", "rlbp-pipeA")
	tapB, pipeB := tap.NewMemTAPPair("rlbp-tapB", "rlbp-pipeB")
	tapC, pipeC := tap.NewMemTAPPair("rlbp-tapC", "rlbp-pipeC")

	cfgA := createTestNodeConfig("10.0.0.1/24", "fd00::1/64", "best_path")
	cfgB := createTestNodeConfig("10.0.0.2/24", "fd00::2/64", "best_path")
	cfgC := createTestNodeConfig("10.0.0.3/24", "fd00::3/64", "best_path")
	cfgA.ListenAddrs = []string{listen}
	cfgB.ListenAddrs = []string{listen}
	cfgC.ListenAddrs = []string{listen}

	// Every node carries a real WebUI collector, not a noop: the relay path
	// exercises RecordFrame / RecordPacketDir / CaptureFrameWithPeers on A
	// (egress), B (forward) and C (delivery), and a noopCollector would
	// understate B/op and allocs/op against the other e2e slices.
	colA := e2eBenchCollector()
	nodeA, err := NewNodeWithTAP(cfgA, tapA, colA)
	if err != nil {
		colA.Stop()
		b.Fatalf("rlbp: create nodeA: %v", err)
	}
	colB := e2eBenchCollector()
	nodeB, err := NewNodeWithTAP(cfgB, tapB, colB)
	if err != nil {
		_ = nodeA.Close() // stops colA via the stoppable type-assert
		colB.Stop()
		b.Fatalf("rlbp: create nodeB: %v", err)
	}
	colC := e2eBenchCollector()
	nodeC, err := NewNodeWithTAP(cfgC, tapC, colC)
	if err != nil {
		_ = nodeA.Close()
		_ = nodeB.Close()
		colC.Stop()
		b.Fatalf("rlbp: create nodeC: %v", err)
	}

	p := &rlbpMesh{nodeA: nodeA, nodeB: nodeB, nodeC: nodeC, pipeA: pipeA, pipeB: pipeB, pipeC: pipeC}
	b.Cleanup(p.tearDown)

	nodeA.Start()
	nodeB.Start()
	nodeC.Start()

	connect := func(from, to *Node) {
		ti := to.Host.Peerstore().PeerInfo(to.Host.ID())
		ti.Addrs = to.Host.Addrs()
		if cerr := from.Host.Connect(from.ctx, ti); cerr != nil {
			b.Fatalf("rlbp: connect %s->%s: %v", from.Host.ID().ShortString(), to.Host.ID().ShortString(), cerr)
		}
	}
	// A<->B carries the first relay hop, B<->C the second. A<->C carries the
	// END-TO-END inner key only; A's router entry for it is withdrawn below.
	connect(nodeA, nodeB)
	connect(nodeB, nodeC)
	connect(nodeA, nodeC)
	connect(nodeB, nodeA)
	connect(nodeC, nodeB)
	connect(nodeC, nodeA)

	for _, pair := range [][2]*Node{{nodeA, nodeB}, {nodeB, nodeC}, {nodeA, nodeC}} {
		rlbpWaitOverlayReady(b, pair[0], pair[1])
	}
	for _, pair := range [][2]*Node{{nodeA, nodeB}, {nodeB, nodeA}, {nodeB, nodeC}, {nodeC, nodeB}} {
		rlbpWarmStream(b, pair[0], pair[1])
	}

	// TAP IPs must resolve to peer IDs on every node: A for the egress lookup,
	// B for the second-hop route, C for the return path.
	peerNodes := []*Node{nodeA, nodeB, nodeC}
	peerMeta := []PeerMeta{
		{NodeName: "rlbpA", TapIP: "10.0.0.1/24", TapIPv6: "fd00::1/64", TapMAC: nodeA.localMAC.String()},
		{NodeName: "rlbpB", TapIP: "10.0.0.2/24", TapIPv6: "fd00::2/64", TapMAC: nodeB.localMAC.String()},
		{NodeName: "rlbpC", TapIP: "10.0.0.3/24", TapIPv6: "fd00::3/64", TapMAC: nodeC.localMAC.String()},
	}
	for i, src := range peerNodes {
		for j, dstNode := range peerNodes {
			if i == j {
				continue
			}
			src.storePeerMeta(dstNode.Host.ID(), peerMeta[j])
		}
		src.rebuildARPIndex()
	}

	// --- Force A's traffic to C through the relay -------------------------
	// Physical links: A-B, B-C, A-C. Only A's A-C ROUTER EDGE is made
	// deliberately expensive, which is what "the path through B" means. The
	// transport and the A<->C cipher stay live, so nodeA.processTapFrame takes
	// the relay branch at node_tap.go:911 while still being able to seal inner
	// for C at :933.
	//
	// The edge is priced, not removed: RemoveDirectLink is not sticky. C keeps
	// broadcasting its own LSA, which re-adds the A-C adjacency to A's graph,
	// and A's router then computes a DIRECT route to C — skipping the relay
	// branch entirely and delivering those frames to C over the direct stream.
	// They reach C's TAP (so the drain still counts them) but never touch
	// relayDiag, so the measured "delivered" fraction was inflated. Pricing the
	// edge 22x above A-B keeps A->B->C (10+12) strictly cheaper than A-C no
	// matter how often the adjacency is re-learned.
	nodeA.Router.UpdateDirectLink(nodeB.Host.ID(), 10, routing.LinkDirect)
	nodeB.Router.UpdateDirectLink(nodeA.Host.ID(), 10, routing.LinkDirect)
	nodeB.Router.UpdateDirectLink(nodeC.Host.ID(), 12, routing.LinkDirect)
	nodeC.Router.UpdateDirectLink(nodeB.Host.ID(), 12, routing.LinkDirect)
	nodeA.Router.UpdateDirectLink(nodeC.Host.ID(), 64, routing.LinkDirect)
	lsa := rlbpSeedLSA(nodeB, nodeA) // B advertises its neighbour C
	if !nodeA.Router.ProcessLSA(lsa) {
		b.Fatalf("rlbp: nodeA.ProcessLSA (from B) refused: lsa seq=%d neighbors=%v", lsa.Seq, lsa.Neighbors)
	}
	nodeA.invalidateRouteCache()

	rc, ok := nodeA.Router.ComputeRoutes()[nodeC.Host.ID()]
	if !ok {
		b.Fatalf("rlbp: nodeA has no route to C after seeding — topology is wrong, not the data path")
	}
	if rc.IsDirect {
		b.Fatalf("rlbp: nodeA route to C is DIRECT (nextHop=%s); A->C traffic would bypass the relay entirely",
			rc.NextHop)
	}
	if rc.NextHop != nodeB.Host.ID() {
		b.Fatalf("rlbp: nodeA route to C nextHop=%s, expected relay nodeB=%s", rc.NextHop, nodeB.Host.ID())
	}
	if rb, okB := nodeB.Router.ComputeRoutes()[nodeC.Host.ID()]; !okB || rb.NextHop != nodeC.Host.ID() {
		b.Fatalf("rlbp: relay nodeB has no usable route to C (ok=%v nextHop=%s) — cannot forward the second hop",
			okB, rb.NextHop)
	}
	if nodeA.obfCipherForPeer(nodeC.Host.ID()) == nil || nodeC.obfCipherForPeer(nodeA.Host.ID()) == nil {
		b.Fatalf("rlbp: no end-to-end cipher A<->C — the inner decrypt stage would not be exercised")
	}
	if nodeA.obfCipherForPeer(nodeB.Host.ID()) == nil || nodeB.obfCipherForPeer(nodeC.Host.ID()) == nil {
		b.Fatalf("rlbp: no hop cipher A->B or B->C — the relay envelopes would travel unsealed")
	}

	// A warm frame proves the full relay path is live BEFORE any number is taken.
	rlbpWarmThroughRelay(b, p)
	return p
}

// rlbpWarmThroughRelay pushes one frame into A's TAP and requires it to appear
// on C's TAP — only possible over A -> B(relay) -> C. relayDiag.Deliv is
// bumped only after the frame really reached the TAP (node_tap.go:308-311).
func rlbpWarmThroughRelay(b *testing.B, p *rlbpMesh) {
	b.Helper()
	base := p.nodeC.relayDiag.Deliv.Load()
	frame := buildUDPIPv4Frame(p.nodeA.localMAC, p.nodeC.localMAC,
		rlbpIP("10.0.0.1"), rlbpIP("10.0.0.3"), 53000, 11111, rlbpPayload)
	for i := 0; i < 5; i++ {
		if _, werr := p.pipeA.Write(frame); werr != nil {
			b.Fatalf("rlbp: warm write to pipeA: %v", werr)
		}
		deadline := time.Now().Add(4 * time.Second)
		for time.Now().Before(deadline) {
			if p.nodeC.relayDiag.Deliv.Load() > base {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	b.Fatalf("rlbp: no relayed frame reached nodeC's TAP (diag=%v) — the A->B->C path is not live",
		p.nodeC.relayDiag.snapshot())
}

// rlbpStartDrain reads a TAP device continuously and counts frames accepted by
// matches. Left unread a MemTAP fills its 1024-deep channel, which stalls the
// node's tapWriteLoop and then its relay RX stream — the benchmark would
// measure queue backpressure instead of crypto.
func rlbpStartDrain(b *testing.B, p *rlbpMesh, dev *tap.MemTAP, out *chan struct{}, into *rlbpCounter, matches func([]byte) bool) {
	b.Helper()
	ch := make(chan struct{})
	*out = ch
	go func() {
		defer close(ch)
		buf := make([]byte, 2048)
		for {
			n, err := dev.Read(buf)
			if err != nil {
				return
			}
			if n > 0 && matches(buf[:n]) {
				into.add(1)
			}
		}
	}()
}

// rlbpStopDrains is folded into rlbpMesh.tearDown: stop the drains first, then
// the pipes, then the nodes. MemTAP's shared closedChan is guarded by
// sync.Once, so a repeated Close is a no-op, and Node.Close is bounded by
// teardownTAPTimeout/teardownHostTimeout (node.go:4233-4235) — nothing here can
// hang the package.
func (p *rlbpMesh) tearDown() {
	p.closeOnce.Do(func() {
		// Wait for the drain goroutines with a bounded deadline. If one is
		// parked in a blocking Read we must not wait forever: the pipes are
		// closed immediately after, which is what unblocks the Read with EOF.
		for _, done := range []chan struct{}{p.drainedA, p.drainedC} {
			if done != nil {
				select {
				case <-done:
				case <-time.After(2 * time.Second):
				}
			}
		}
		if p.pipeA != nil {
			_ = p.pipeA.Close()
		}
		if p.pipeB != nil {
			_ = p.pipeB.Close()
		}
		if p.pipeC != nil {
			_ = p.pipeC.Close()
		}
		if p.nodeC != nil {
			_ = p.nodeC.Close()
		}
		if p.nodeB != nil {
			_ = p.nodeB.Close()
		}
		if p.nodeA != nil {
			_ = p.nodeA.Close()
		}
	})
}

// rlbpUDPMatch accepts only the benchmark's own UDP payload frame — EtherType
// 0x0800 and the marker at the end, payload offset 42 — so the GARP that
// nodeC injects when it learns A's address (boot_relay.go:752) cannot inflate
// the count.
func rlbpUDPMatch(payload []byte) func([]byte) bool {
	return func(f []byte) bool {
		return len(f) >= 42+len(payload) &&
			bytes.Equal(f[12:14], []byte{0x08, 0x00}) &&
			bytes.HasSuffix(f, payload)
	}
}

// rlbpEnvelopeBuilder owns the private packing buffer of one origin and the
// flow constants. Build mirrors node_tap.go:888-958 exactly:
//
//	seqID    = Packer.NextSeqID(txEpochForPeer(dst))    fresh nonce per frame
//	inner    = sealPeerFrame(dst, pack(ethFrame))       END-TO-END for dst
//	envelope = packRelayFrame(dst, src, ttl, inner)
//	return   = sealRelayEnvelopeForHop(nextHop, envelope)   hop-sealed
//
// seqID must be fresh on every frame: the AEAD nonce is derived from the frame
// header's 32-bit counter (node_crypto.go:67-73), so a fixed seqID both reuses
// a (key, nonce) pair and is rejected by the destination's per-peer dedup
// window (boot_relay.go:709). One pooled buffer per builder keeps the
// steady-state path at a single allocation; sealPeerFrame and packRelayFrame
// each copy out of it.
type rlbpEnvelopeBuilder struct {
	origin  *Node
	dst     *Node
	nextHop *Node
	ttl     uint8
	buf     []byte
}

func rlbpNewEnvelopeBuilder(b *testing.B, origin, dst, nextHop *Node, ttl uint8, frameLen int) *rlbpEnvelopeBuilder {
	b.Helper()
	return &rlbpEnvelopeBuilder{
		origin:  origin,
		dst:     dst,
		nextHop: nextHop,
		ttl:     ttl,
		buf:     make([]byte, origin.Packer.MaxPackedLen(frameLen)),
	}
}

func (eb *rlbpEnvelopeBuilder) build(ethFrame []byte) ([]byte, error) {
	n := eb.origin
	dstID := eb.dst.Host.ID()
	cipher := n.obfCipherForPeer(dstID)
	if cipher == nil {
		return nil, fmt.Errorf("rlbp: no end-to-end cipher %s->%s", n.Host.ID().ShortString(), dstID.ShortString())
	}
	seqID := n.nextTxSeqID(dstID)
	total, perr := n.Packer.Pack(seqID, ethFrame, eb.buf)
	if perr != nil {
		return nil, perr
	}
	inner := make([]byte, total)
	copy(inner, eb.buf[:total])
	sealed, serr := n.sealPeerFrame(dstID, cipher, inner)
	if serr != nil {
		return nil, serr
	}
	envelope, rerr := n.packRelayFrame(dstID, n.Host.ID(), eb.ttl, sealed)
	if rerr != nil {
		return nil, rerr
	}
	return n.sealRelayEnvelopeForHop(eb.nextHop.Host.ID(), envelope)
}

// rlbpFinalHopBuilder builds the envelope as it arrives at the FINAL node:
// nodeA does the origin work (Pack, end-to-end seal for C, packRelayFrame) and
// nodeB does the one thing every intermediate hop does at node_streams.go:1517
// — sealRelayEnvelopeForHop for the NEXT carrier, which here is C itself.
//
// The inner payload stays sealed by A for C (end-to-end); B only ever touches
// the outer envelope. C therefore has to run the full hop decrypt PLUS the
// end-to-end inner decrypt, into the second scratch.
type rlbpFinalHopBuilder struct {
	origin *Node
	dst    *Node
	relay  *Node // the hop that carries the frame to dst, and seals it for dst
	ttl    uint8
	buf    []byte
}

func rlbpNewFinalHopBuilder(b *testing.B, origin, relay, dst *Node, ttl uint8, frameLen int) *rlbpFinalHopBuilder {
	b.Helper()
	if relay.obfCipherForPeer(dst.Host.ID()) == nil {
		b.Fatalf("rlbp: relay %s has no hop cipher to %s — cannot hop-seal for the final node",
			relay.Host.ID().ShortString(), dst.Host.ID().ShortString())
	}
	return &rlbpFinalHopBuilder{
		origin: origin,
		dst:    dst,
		relay:  relay,
		ttl:    ttl,
		buf:    make([]byte, origin.Packer.MaxPackedLen(frameLen)),
	}
}

func (eb *rlbpFinalHopBuilder) build(ethFrame []byte) ([]byte, error) {
	n := eb.origin
	dstID := eb.dst.Host.ID()
	cipher := n.obfCipherForPeer(dstID)
	if cipher == nil {
		return nil, fmt.Errorf("rlbp: no end-to-end cipher %s->%s", n.Host.ID().ShortString(), dstID.ShortString())
	}
	seqID := n.nextTxSeqID(dstID)
	total, perr := n.Packer.Pack(seqID, ethFrame, eb.buf)
	if perr != nil {
		return nil, perr
	}
	inner := make([]byte, total)
	copy(inner, eb.buf[:total])
	sealed, serr := n.sealPeerFrame(dstID, cipher, inner)
	if serr != nil {
		return nil, serr
	}
	envelope, rerr := n.packRelayFrame(dstID, n.Host.ID(), eb.ttl, sealed)
	if rerr != nil {
		return nil, rerr
	}
	return eb.relay.sealRelayEnvelopeForHop(dstID, envelope)
}

// ---------------------------------------------------------------------------
// Benchmark 1: the middle hop.
// ---------------------------------------------------------------------------

// BenchmarkE2ERelayForwardHop measures ONE intermediate relay hop, outside in:
// the hop-by-hop envelope decrypt (for the carrier), the carried obfuscate
// frame Unpack, UnpackRelayFrame, origin verification, transit ACL, route
// lookup, envelope re-pack at TTL-1, hop re-seal, and the persistent relay
// stream Submit (node_streams.go:1434-1535).
//
// handleRelayFrame is called directly with the same two independent scratch
// buffers handleRelayStream hands it (node_streams.go:1136-1137), so the
// steady-state path is allocation-free by construction. nodeC's TAP is
// drained by a separate goroutine, which keeps nodeC's relay stream reader
// from stalling on its own write queue — the only way B's Submit pool can fill
// up is its own enqueue rate, never a reader we accidentally forgot.
//
// %poolFull is reported as a first-class metric. It is the honest number: if
// it is high, the reported ns/op is measuring an enqueue-rejected path rather
// than a real forward, and the benchmark is measuring pool saturation.
func BenchmarkE2ERelayForwardHop(b *testing.B) {
	logger.SetGlobalLevel(logger.LevelWarn)
	defer logger.SetGlobalLevel(logger.LevelWarn)

	p := rlbpSetup(b)

	// nodeC is the destination of every envelope B forwards, so B's Submit
	// lands on C's relay stream and C runs the full final-hop path, ending in
	// a TAP write to pipeC. Left unread, the 1024-deep MemTAP channel fills,
	// tapWriteLoop blocks, and C's relay stream reader backs up behind it —
	// which fills B's 128-deep relay pool with backpressure from a TAP sink we
	// forgot to open, not from B's own enqueue rate. Drain it: rlbpStartDrain
	// is the only reader of pipeC (nodeC's tapReadLoop reads the other side of
	// the pair, so no ErrConcurrentRead).
	var discardedC rlbpCounter
	rlbpStartDrain(b, p, p.pipeC, &p.drainedC, &discardedC, rlbpUDPMatch(rlbpPayload))

	ethFrame := buildUDPIPv4Frame(p.nodeA.localMAC, p.nodeC.localMAC,
		rlbpIP("10.0.0.1"), rlbpIP("10.0.0.3"), 40000, 53, rlbpPayload)

	bld := rlbpNewEnvelopeBuilder(b, p.nodeA, p.nodeC, p.nodeB, rlbpRelayedTTL, len(ethFrame))

	// Warm-up: the first envelope pre-pays nodeB's lazy relay stream to nodeC
	// (relayStreamPool.Submit -> getOrCreate) so the timed region is steady
	// state, and it pre-warms nodeB's seenOrigins entry for the origin.
	envelope, err := bld.build(ethFrame)
	if err != nil {
		b.Fatalf("rlbp: build warm envelope: %v", err)
	}
	if len(envelope) == 0 {
		b.Fatalf("rlbp: empty warm envelope")
	}
	p.nodeB.handleRelayFrame(p.nodeA.Host.ID(), envelope, &[]byte{}, &[]byte{})
	// Settle the warm frame before baselining: relayDiag.Deliv is bumped by
	// tapWriteLoop, after handleRelayFrame has returned.
	baseWarmC := p.nodeC.relayDiag.Deliv.Load()
	warmCountedC := discardedC.load()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) &&
		(p.nodeC.relayDiag.Deliv.Load() <= baseWarmC || discardedC.load() <= warmCountedC) {
		time.Sleep(10 * time.Millisecond)
	}

	// Two independent scratch buffers, rebased by handleRelayFrame on every
	// call. Never the same slice.
	relayDecScratch := make([]byte, 0, 9600)
	relayInnerScratch := make([]byte, 0, 9600)
	baseDelivC := p.nodeC.relayDiag.Deliv.Load()
	discardedC.store(0)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sealed, cerr := bld.build(ethFrame)
		if cerr != nil {
			b.Fatalf("rlbp: build envelope %d: %v", i, cerr)
		}
		p.nodeB.handleRelayFrame(p.nodeA.Host.ID(), sealed, &relayDecScratch, &relayInnerScratch)
	}
	b.StopTimer()

	diag := p.nodeB.relayDiag.snapshot()
	if diag.HopGarbage != 0 || diag.EnvBad != 0 || diag.SealFail != 0 || diag.TtlExpired != 0 || diag.LoopGuardDrop != 0 {
		b.Fatalf("rlbp: non-forwarding relay drops in the timed region (diag=%v) — the number measures a drop path, not forwarding",
			diag)
	}
	if diag.ForwardedIn < uint64(b.N) {
		b.Fatalf("rlbp: relayDiag.ForwardedIn=%d < b.N=%d — envelopes were dropped before being counted",
			diag.ForwardedIn, b.N)
	}
	// Settle: relayDiag.Deliv is bumped only after the frame reached C's TAP,
	// and the drain counts what came out of it. Both are after StopTimer, so
	// this costs nothing in the measurement. A fresh deadline — `deadline` was
	// already spent waiting for the warm frame above.
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && discardedC.load() < p.nodeC.relayDiag.Deliv.Load()-baseDelivC {
		time.Sleep(20 * time.Millisecond)
	}
	relayedOut := p.nodeC.relayDiag.Deliv.Load() - baseDelivC
	dropRate := 100 * float64(diag.ForwardDrop) / float64(diag.ForwardedIn)
	b.ReportMetric(dropRate, "%poolFull")
	b.ReportMetric(float64(diag.ForwardDrop), "poolFull")
	b.ReportMetric(100*float64(relayedOut)/float64(b.N), "%arrivedAtDst")
	b.Logf("nodeB: forwardedIn=%d forwardDrop=%d (%.2f%%) loopGuard=%d sealFail=%d; "+
		"nodeC: arrivedAtTap=%d (%.2f%% of b.N=%d)",
		diag.ForwardedIn, diag.ForwardDrop, dropRate, diag.LoopGuardDrop, diag.SealFail,
		relayedOut, 100*float64(relayedOut)/float64(b.N), b.N)
}

// ---------------------------------------------------------------------------
// Benchmark 2: the final destination hop.
// ---------------------------------------------------------------------------

// BenchmarkE2ERelayFinalHop measures the FINAL destination hop together with
// the origin-side envelope construction, both real:
//
//	build (nodeA) Pack -> end-to-end seal for C -> packRelayFrame
//	             -> nodeB's sealRelayEnvelopeForHop(C, envelope)
//	handle(nodeC) hop decrypt for B -> UnpackRelayFrame -> END-TO-END inner
//	               decrypt into the SECOND scratch -> Unpack -> TAP delivery
//
// nodeB is the carrier that delivered the frame to C, so C reads it off a
// stream whose remotePeer is B and looks up its hop cipher to B — exactly the
// real final-hop shape (node_streams.go:1190-1426).
// The build stays inside the timed region because a fresh seqID is mandatory
// per frame (see rlbpEnvelopeBuilder): the nonce derives from the frame
// counter and the destination's dedup window rejects a reused seqID, so a
// pre-built envelope would measure the dedup-drop path after the first frame.
// The delta from BenchmarkE2ERelayForwardHop shows how much of the total is
// origin work versus relay work.
func BenchmarkE2ERelayFinalHop(b *testing.B) {
	logger.SetGlobalLevel(logger.LevelWarn)
	defer logger.SetGlobalLevel(logger.LevelWarn)

	p := rlbpSetup(b)
	ethFrame := buildUDPIPv4Frame(p.nodeA.localMAC, p.nodeC.localMAC,
		rlbpIP("10.0.0.1"), rlbpIP("10.0.0.3"), 40000, 53, rlbpPayload)

	// nodeC writes every successfully decrypted frame to pipeC. MemTAP.Write
	// blocks on its 1024-deep channel (tap/tap.go:179-196), so the drain keeps
	// the TAP sink open and the timed region measures crypto, not backpressure.
	// The drain is the only reader of pipeC: nodeC's tapReadLoop reads the OTHER
	// side of the pair, so this does not trip MemTAP's ErrConcurrentRead.
	var counted rlbpCounter
	rlbpStartDrain(b, p, p.pipeC, &p.drainedC, &counted, rlbpUDPMatch(rlbpPayload))

	bld := rlbpNewFinalHopBuilder(b, p.nodeA, p.nodeB, p.nodeC, rlbpRelayedTTL, len(ethFrame))

	// Warm-up: pre-warm nodeC's seenOrigins entry for A and its per-peer dedup
	// map so the timed region is steady state.
	envelope, err := bld.build(ethFrame)
	if err != nil {
		b.Fatalf("rlbp: build warm envelope: %v", err)
	}
	p.nodeC.handleRelayFrame(p.nodeB.Host.ID(), envelope, &[]byte{}, &[]byte{})
	// handleRelayFrame returns before the frame is out of the TAP: it goes
	// through tapWriteCh and relayDiag.Deliv is bumped by tapWriteLoop. Settle
	// it first, otherwise the warm frame lands inside the timed region and both
	// baselines below are off by one.
	baseWarm := p.nodeC.relayDiag.Deliv.Load()
	warmCounted := counted.load()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) &&
		(p.nodeC.relayDiag.Deliv.Load() <= baseWarm || counted.load() <= warmCounted) {
		time.Sleep(10 * time.Millisecond)
	}

	relayDecScratch := make([]byte, 0, 9600)
	relayInnerScratch := make([]byte, 0, 9600)
	baseDeliv := p.nodeC.relayDiag.Deliv.Load()
	// The drain has been reading since before the warm-up, so start counting
	// from zero here: the two checks below are both relative to this point.
	counted.store(0)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sealed, cerr := bld.build(ethFrame)
		if cerr != nil {
			b.Fatalf("rlbp: build envelope %d: %v", i, cerr)
		}
		p.nodeC.handleRelayFrame(p.nodeB.Host.ID(), sealed, &relayDecScratch, &relayInnerScratch)
	}
	b.StopTimer()

	// relayDiag.Deliv is bumped only after the frame really reached the TAP
	// (node_tap.go:308-311), and the drain counts what came out of it, so the
	// two must agree at exactly b.N. handleRelayFrame returns synchronously
	// but tapWriteLoop can still be finishing the last writes off tapWriteCh,
	// so poll for both to settle — well after StopTimer.
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if p.nodeC.relayDiag.Deliv.Load()-baseDeliv == uint64(b.N) && counted.load() == uint64(b.N) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := p.nodeC.relayDiag.Deliv.Load() - baseDeliv; got != uint64(b.N) {
		b.Fatalf("rlbp: nodeC delivered %d of %d timed frames (diag=%v) — inner decrypt or TAP delivery failed",
			got, b.N, p.nodeC.relayDiag.snapshot())
	}
	if got := counted.load(); got != uint64(b.N) {
		b.Fatalf("rlbp: only %d of %d timed frames came out of nodeC's TAP", got, b.N)
	}

	diag := p.nodeC.relayDiag.snapshot()
	if diag.HopGarbage != 0 || diag.EnvBad != 0 || diag.FinalDecryptFail != 0 || diag.FinalUnpackFail != 0 {
		b.Fatalf("rlbp: final-hop drops in the timed region (diag=%v) — the number measures a drop path",
			diag)
	}
	b.Logf("nodeC: forwardedIn=%d deliveredToTap=%d finalDecFail=%d finalUnpackFail=%d",
		diag.ForwardedIn, diag.DeliveredToTap, diag.FinalDecryptFail, diag.FinalUnpackFail)
}

// ---------------------------------------------------------------------------
// Benchmark 3: the full multi-hop flow.
// ---------------------------------------------------------------------------

// BenchmarkE2ERelayThroughput measures the relayed flow end to end over real
// transports: a frame is written to nodeA's TAP, resolved, packed, sealed
// end-to-end for C, wrapped in a relay envelope, hop-sealed for B, sent over
// the libp2p stream, forwarded by nodeB (re-pack + re-seal + relay stream
// Submit), and counted when it reaches nodeC's TAP. Every stage is live,
// including both libp2p stream writes. The legacy direct-link benchmark
// (BenchmarkThroughput_TCP) is not a like-for-like comparator: it runs on a
// noop collector and reports no B/op, so only the frame-rate magnitude is
// comparable across the two, never the allocation numbers. Not every delivered
// frame rides the relay — see the direct-fallback note below — so read
// %delivered together with %relayDelivered / %directFallback.
//
// Because A and C are still connected (A needs the end-to-end cipher for the
// inner seal), the relay Submit can fail open: dispatchWorker's onFail handler
// re-sends the frame over A's direct stream to C when B's relay pool queue is
// full. The relay pool maxes out at 128 jobs (relayPoolMaxQueue) and B's relay
// stream reader is one goroutine per hop, so under sustained load a share of
// the frames rides the direct link. The benchmark reports %relayDelivered and
// %directFallback separately instead of collapsing the two.
func BenchmarkE2ERelayThroughput(b *testing.B) {
	logger.SetGlobalLevel(logger.LevelWarn)
	defer logger.SetGlobalLevel(logger.LevelWarn)

	p := rlbpSetup(b)

	var counted rlbpCounter
	// nodeC writes relayed frames to pipeC. nodeC's own GARP lands on pipeB,
	// which nodeB's tapReadLoop already drains. pipeA is drained only so that
	// C's ARP replies cannot fill it.
	rlbpStartDrain(b, p, p.pipeC, &p.drainedC, &counted, rlbpUDPMatch(rlbpThruPayload))
	discarded := rlbpCounter(0)
	rlbpStartDrain(b, p, p.pipeA, &p.drainedA, &discarded, func([]byte) bool { return false })

	frame := buildUDPIPv4Frame(p.nodeA.localMAC, p.nodeC.localMAC,
		rlbpIP("10.0.0.1"), rlbpIP("10.0.0.3"), 40000, 53, rlbpThruPayload)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := p.pipeA.Write(frame); err != nil {
			b.Fatalf("rlbp: write frame %d to pipeA: %v", i, err)
		}
	}
	b.StopTimer()

	// Three genuinely different "delivered" numbers, all real, and the gap
	// between them is itself the interesting result:
	//
	//	relayDiag.DeliveredToTap  frames C opened and wrote to its TAP via the
	//	                          RELAY path (bumped only after the TAP write,
	//	                          node_tap.go:308-311).
	//	drain count on pipeC      frames that came out of C's TAP, relay or not.
	//	nodeB ForwardDrop         frames B refused because its relay stream pool
	//	                          queue (128) was full.
	//
	// The gap is the DIRECT FALLBACK: dispatchWorker's relay onFail handler
	// re-sends the same frame over A's direct stream to C (node_tap.go:917-924
	// and 969-977) whenever the relay Submit fails, so those frames reach C's
	// TAP without ever touching B. They are counted by the drain and not by
	// relayDiag. Without reporting all three, "%delivered" reads as "the relay
	// delivered everything" when in fact a share of it rode the direct link.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && counted.load() < p.nodeC.relayDiag.Deliv.Load() {
		time.Sleep(20 * time.Millisecond)
	}
	diagA, diagB, diagC := p.nodeA.relayDiag.snapshot(), p.nodeB.relayDiag.snapshot(), p.nodeC.relayDiag.snapshot()
	delivered := counted.load()
	relayDelivered := diagC.DeliveredToTap
	if relayDelivered == 0 {
		b.Fatalf("rlbp: ZERO relayed frames reached nodeC — the A->B->C data path stalled")
	}
	gap := int64(delivered) - int64(relayDelivered)
	if gap < 0 {
		gap = 0
	}
	b.ReportMetric(float64(delivered)/float64(b.N), "deliveredPerWritten")
	b.ReportMetric(100*float64(delivered)/float64(b.N), "%delivered")
	b.ReportMetric(100*float64(relayDelivered)/float64(b.N), "%relayDelivered")
	b.ReportMetric(100*float64(gap)/float64(delivered), "%directFallback")
	b.ReportMetric(100*float64(diagB.ForwardDrop)/float64(diagB.ForwardedIn), "%poolFull")
	b.Logf("written=%d tapOut=%d relayDelivered=%d directFallback=%d "+
		"nodeB(fwdIn=%d poolFull=%d) nodeA=%v",
		b.N, delivered, relayDelivered, gap, diagB.ForwardedIn, diagB.ForwardDrop, diagA)
}
