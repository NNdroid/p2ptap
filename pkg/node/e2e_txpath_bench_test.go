package node

// End-to-end TRANSMIT-path benchmarks: one real Ethernet frame is written into
// nodeA's in-memory TAP device and the whole way out is timed, on a real
// negotiated per-peer cipher over a real TCP loopback transport:
//
//	pipeA.Write(frame)                   tap.MemTAP.Write              tap.go:179
//	  -> tapReadLoop / tapReadLoopPoll   node_tap.go:25 / :71
//	  -> processTapFrame                 node_tap.go:650
//	     (ARP/NDP proxy, Interceptor, MAC learn + Collector.RecordFrame,
//	      MACTable lookup / ResolvePeerIDByIP fallback, observeTapICMPEchoRequest,
//	      overlayRoute, canEgressWithRoute, checkACL, Packer.Pack)
//	  -> dispatchNonblocking (kind 0)    node_tap.go:984
//	  -> dispatchWorker                  node_dispatch.go:290
//	  -> StrategyDispatcher.SendToPeer   strategy.go:350
//	  -> encryptAndFragment              strategy.go:457  (per-peer AEAD seal,
//	                                                          fragmentFrame, and a
//	                                                          second per-fragment
//	                                                          seal when it splits)
//	  -> writeFragsToStreams / WriteFrame strategy.go:924 / framing.go
//	  -> Collector.RecordSent            node_dispatch.go:291   == chain END
//
// The boundary is that last call: RecordSent fires only after SendToPeer has
// returned nil, i.e. after the framed, sealed, fragmented bytes were handed to
// the transport. The frame MUST enter through processTapFrame (never through
// StrategyDispatcher directly), because node_tap.go:888 is where the real seqID
// is minted — Packer.NextSeqID(txEpochForPeer(target)) — so every iteration gets
// a distinct (seqID, nonce) pair and the RX dedup window
// (pkg/obfuscate/dedup.go, window 1024) cannot drop the second frame of the
// loop. dstMAC is nodeB's UNICAST MAC, so the broadcast content-hash dedup at
// node_streams.go:518 never applies either.
//
// Each iteration blocks until the previous one has completed its framing write,
// so ns/op is the latency of ONE frame through the full chain rather than a
// pipelined write rate, and B/op / allocs/op are attributable to that chain
// instead of to a buffered channel send alone.
//
// Three branch shapes:
//   - 64 B   (14 eth + 20 ipv4 + 8 udp + 22 payload) — the smallest realistic
//     frame; never fragments.
//   - 1400 B — MTU-sized. With the shipped config (obfuscation.max_frag_size=0)
//     a node holding a live stream on a reliable transport gets
//     maxFragPayloadStream = 65400 (frag.go:413), so this one still does NOT
//     fragment.
//   - 1400 B with obfuscation.max_frag_size=512 — the same frame now splits and
//     each chunk is re-sealed by encryptAndFragment (strategy.go:498), which is
//     the fragmentation branch the other two skip.
//
// The cipher is real, not injected: setup waits for obfStateForPeer to report
// negotiated+encrypted in BOTH directions and hard-fails if obfCipherForPeer is
// nil, because a nil cipher makes encryptAndFragment skip the seal entirely
// (strategy.go:467) and measure the plaintext branch.

import (
	"context"
	"encoding/binary"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"p2ptap/pkg/logger"
	"p2ptap/pkg/obfuscate"
	"p2ptap/pkg/observer"
	"p2ptap/pkg/tap"
	"p2ptap/pkg/web"
)

const (
	// txbpFragAuto is obfuscation.max_frag_size == 0 ("auto"): a node with a
	// live stream on a reliable transport uses maxFragPayloadStream and never
	// fragments.
	txbpFragAuto = 0
	// txbpFragForce is small enough that a packed 1400 B frame splits into
	// several fragments and large enough for a 64 B frame to stay whole.
	// 256..1400 is the only range cfg.Validate accepts (config.go:777-784).
	txbpFragForce = 512

	// txbpFrameTimeout bounds a single iteration. A missed completion is a
	// genuine data-path failure and must fail the benchmark, not be averaged
	// away as a slow sample.
	txbpFrameTimeout = 5 * time.Second
	// txbpSetupBudget bounds the whole non-measured setup (connect + overlay
	// negotiation + stream warmup).
	txbpSetupBudget = 20 * time.Second
	// txbpDeliverBudget bounds the post-timer delivery check.
	txbpDeliverBudget = 15 * time.Second

	// txbpGateWake re-wakes the gates' condition variables so a lost frame
	// cannot hang the benchmark inside cv.Wait() forever.
	txbpGateWake = 2 * time.Millisecond

	txbpWarmupFrames = 32

	txbpSrcPort = 40000
	txbpDstPort = 80
)

var (
	txbpSrcIP = net.ParseIP("10.0.0.1")
	txbpDstIP = net.ParseIP("10.0.0.2")
)

// ── Completion barrier ──────────────────────────────────────────────────────

// txbpGate is an allocation-free monotonic counter the benchmark blocks on.
// A condition variable rather than a per-iteration channel or time.AfterFunc
// keeps the timed loop from allocating for the sake of the harness. The keeper
// goroutine re-wakes it periodically so a lost frame cannot hang cv.Wait().
type txbpGate struct {
	mu   sync.Mutex
	cv   *sync.Cond
	seen uint64
}

func txbpNewGate() *txbpGate {
	g := &txbpGate{}
	g.cv = sync.NewCond(&g.mu)
	return g
}

func (g *txbpGate) mark() {
	g.mu.Lock()
	g.seen++
	g.cv.Broadcast()
	g.mu.Unlock()
}

func (g *txbpGate) count() uint64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.seen
}

// waitAtLeast blocks until seen >= want or the deadline passes.
func (g *txbpGate) waitAtLeast(want uint64, deadline time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	for g.seen < want && time.Now().Before(deadline) {
		g.cv.Wait()
	}
	return g.seen >= want
}

func (g *txbpGate) wake() {
	g.mu.Lock()
	g.cv.Broadcast()
	g.mu.Unlock()
}

// txbpKeeper re-wakes g until stop is closed. One goroutine, one ticker.
func txbpKeeper(g *txbpGate, stop chan struct{}) {
	t := time.NewTicker(txbpGateWake)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			g.wake()
		}
	}
}

// ── TX completion collector ─────────────────────────────────────────────────

// txbpSentCollector wraps the production WebUI collector so the node runs the
// real RecordFrame / RecordPacketDir / RecordTxSeq / CaptureFrameWithPeers
// chain (see e2eBenchCollector) rather than a noop, while additionally arming
// one completion barrier per matching frame.
type txbpSentCollector struct {
	*web.StatsCollector
	gate     *txbpGate
	frameLen int
}

var _ observer.Collector = (*txbpSentCollector)(nil)

// RecordSent fires after Dispatcher.SendToPeer returned nil for one dispatch
// task — i.e. after the framed, sealed, fragmented bytes were written. The
// production collector's own RecordSent still runs (it feeds the TX counter);
// only frames of the length under test additionally arm the barrier, because
// control traffic (GARP, broadcast waves, relay fallbacks) reaches the same
// callback and must not desynchronise the per-iteration barrier.
func (c *txbpSentCollector) RecordSent(bytes int) {
	c.StatsCollector.RecordSent(bytes)
	if c.gate != nil && bytes == c.frameLen {
		c.gate.mark()
	}
}

// ── Topology ────────────────────────────────────────────────────────────────

type txbpTopo struct {
	nodeA, nodeB *Node
	pipeA, pipeB *tap.MemTAP
	macA, macB   net.HardwareAddr
	gate         *txbpGate     // TX completion barrier, fed by RecordSent
	keeperStop   chan struct{} // stops the gate keeper
	drainDone    chan struct{} // closed when the pipeB drain goroutine exits
	closeOnce    sync.Once
}

// tearDown is idempotent and ordered: stop the drain of nodeB's TAP, close both
// nodes (Node.Close closes the TAP first, node.go:4290, which is what hands
// tapReadLoop its EOF; MemTAP's shared closedChan is guarded by sync.Once so a
// second Close is a no-op), then stop the keeper. Node.Close is bounded by
// teardownTAPTimeout / teardownWebTimeout / teardownHostTimeout, so this cannot
// hang the package.
func (p *txbpTopo) tearDown() {
	p.closeOnce.Do(func() {
		if p.pipeB != nil {
			_ = p.pipeB.Close()
		}
		if p.pipeA != nil {
			_ = p.pipeA.Close()
		}
		if p.drainDone != nil {
			<-p.drainDone
		}
		if p.nodeB != nil {
			_ = p.nodeB.Close()
		}
		if p.nodeA != nil {
			_ = p.nodeA.Close()
		}
		if p.keeperStop != nil {
			close(p.keeperStop)
		}
	})
}

func txbpSetup(b *testing.B, fragCap, frameLen int) *txbpTopo {
	b.Helper()
	const listen = "/ip4/0.0.0.0/tcp/0" // wildcard is mandatory: loopback addrs are not advertised

	tapA, pipeA := tap.NewMemTAPPair("txbp-tapA", "txbp-pipeA")
	tapB, pipeB := tap.NewMemTAPPair("txbp-tapB", "txbp-pipeB")

	p := &txbpTopo{
		pipeA:      pipeA,
		pipeB:      pipeB,
		keeperStop: make(chan struct{}),
	}

	cfgA := createTestNodeConfig("10.0.0.1/24", "fd00::1/64", "best_path")
	cfgB := createTestNodeConfig("10.0.0.2/24", "fd00::2/64", "best_path")
	cfgA.ListenAddrs = []string{listen}
	cfgB.ListenAddrs = []string{listen}
	if fragCap > 0 {
		cfgA.Obfuscation.MaxFragSize = fragCap
		cfgB.Obfuscation.MaxFragSize = fragCap
	}

	p.gate = txbpNewGate()
	colA := &txbpSentCollector{StatsCollector: e2eBenchCollector(), gate: p.gate, frameLen: frameLen}

	nodeA, err := NewNodeWithTAP(cfgA, tapA, colA)
	if err != nil {
		b.Fatalf("txbp: create nodeA: %v", err)
	}
	// nodeB is the receiver end of the same overlay. It gets a real collector
	// as well: nodeA's SendToPeer is throttled by the stream's flow-control
	// window, which nodeB's RX goroutine — including its per-frame capture
	// cost — is what drains. A noop collector here would understate the
	// backpressure the timed loop sees.
	colB := e2eBenchCollector()
	nodeB, err := NewNodeWithTAP(cfgB, tapB, colB)
	if err != nil {
		_ = nodeA.Close() // closes nodeA's TAP and stops colA via the stoppable type-assert
		colB.Stop()
		b.Fatalf("txbp: create nodeB: %v", err)
	}
	p.nodeA, p.nodeB = nodeA, nodeB
	b.Cleanup(p.tearDown)

	nodeA.Start()
	nodeB.Start()
	go txbpKeeper(p.gate, p.keeperStop)

	// Command-style peer resolution: no StaticPeers, no BootstrapPeers, no mDNS.
	connectCtx, cancel := context.WithTimeout(nodeA.ctx, txbpSetupBudget)
	defer cancel()
	ti := nodeB.Host.Peerstore().PeerInfo(nodeB.Host.ID())
	ti.Addrs = nodeB.Host.Addrs()
	if err := nodeA.Host.Connect(connectCtx, ti); err != nil {
		b.Fatalf("txbp: connect A->B: %v", err)
	}

	// Wait for the negotiated per-peer cipher in BOTH directions. Without this
	// the first frames race the ECDH handshake and are dropped.
	deadline := time.Now().Add(txbpSetupBudget)
	for {
		okA, _, encA := nodeA.obfStateForPeer(nodeB.Host.ID())
		okB, _, encB := nodeB.obfStateForPeer(nodeA.Host.ID())
		if okA && encA && okB && encB {
			break
		}
		if time.Now().After(deadline) {
			b.Fatalf("txbp: per-peer cipher did not negotiate in time (A: negotiated=%v encrypted=%v, B: negotiated=%v encrypted=%v)",
				okA, encA, okB, encB)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if nodeA.obfCipherForPeer(nodeB.Host.ID()) == nil {
		b.Fatalf("txbp: per-peer TX cipher is nil — encryptAndFragment would skip the seal and measure the plaintext branch")
	}

	// Pre-pay the one-off NewStream + /p2ptap protocol negotiation so the timed
	// region is steady state. This is the real TX path, not a mock.
	txbpWarmStream(b, nodeA, nodeB)

	nodeA.storePeerMeta(nodeB.Host.ID(), PeerMeta{NodeName: "txbpB", TapIP: "10.0.0.2/24", TapMAC: nodeB.localMAC.String()})
	nodeB.storePeerMeta(nodeA.Host.ID(), PeerMeta{NodeName: "txbpA", TapIP: "10.0.0.1/24", TapMAC: nodeA.localMAC.String()})
	nodeA.rebuildARPIndex()
	nodeB.rebuildARPIndex()

	p.macA = nodeA.localMAC
	p.macB = nodeB.localMAC
	return p
}

// txbpWarmStream pushes one properly Packed probe through Dispatcher.SendToPeer
// so the application stream (and its per-peer seal) is open and warm before the
// timed region starts. A fresh seqID is required: the AEAD nonce is derived from
// the frame header.
func txbpWarmStream(b *testing.B, a, target *Node) {
	b.Helper()
	ctx, cancel := context.WithTimeout(a.ctx, 8*time.Second)
	defer cancel()
	probe := []byte("TXBP_STREAM_WARMUP")
	out := make([]byte, len(probe)+obfuscate.HeaderLen+4096)
	n, err := a.Packer.Pack(a.Packer.NextSeqID(a.txEpochForPeer(target.Host.ID())), probe, out)
	if err != nil {
		b.Fatalf("txbp: warm pack: %v", err)
	}
	if err := a.Dispatcher.SendToPeer(ctx, target.Host.ID(), out[:n]); err != nil {
		b.Fatalf("txbp: warm SendToPeer: %v", err)
	}
	time.Sleep(200 * time.Millisecond)
}

// txbpStartDrain counts the frames that actually reach nodeB's TAP. nodeB reads
// tapB and writes to tapB; tapB's writes land on pipeB, whose only reader is
// this goroutine, so MemTAP's single-reader invariant (ErrConcurrentRead) holds.
func txbpStartDrain(p *txbpTopo, frameLen int) *txbpGate {
	g := txbpNewGate()
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 4096)
		for {
			n, err := p.pipeB.Read(buf)
			if err != nil {
				return
			}
			if n == frameLen {
				g.mark()
			}
		}
	}()
	p.drainDone = done
	return g
}

// ── Frame builder ───────────────────────────────────────────────────────────

// txbpFrame builds an Ethernet + IPv4 + UDP frame of EXACTLY totalLen bytes.
// The UDP checksum is left zero — this is an L2/L3 pipe and nobody verifies it
// here. The IPv4 checksum IS computed, so the frame is a well-formed packet.
func txbpFrame(totalLen int, srcMAC, dstMAC net.HardwareAddr) []byte {
	const (
		ethHdr = 14
		ipHdr  = 20
		udpHdr = 8
	)
	if totalLen < ethHdr+ipHdr+udpHdr {
		panic("txbp: frame length too small")
	}
	frame := make([]byte, totalLen)
	copy(frame[0:6], dstMAC)
	copy(frame[6:12], srcMAC)
	binary.BigEndian.PutUint16(frame[12:14], 0x0800) // IPv4

	frame[14] = 0x45 // IPv4, IHL 5
	binary.BigEndian.PutUint16(frame[16:18], uint16(totalLen-ethHdr))
	frame[22] = 64 // TTL
	frame[23] = 17 // UDP
	copy(frame[26:30], txbpSrcIP.To4())
	copy(frame[30:34], txbpDstIP.To4())

	var sum uint32
	for i := 14; i < 34; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(frame[i : i+2]))
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	binary.BigEndian.PutUint16(frame[24:26], ^uint16(sum))

	binary.BigEndian.PutUint16(frame[34:36], txbpSrcPort)
	binary.BigEndian.PutUint16(frame[36:38], txbpDstPort)
	binary.BigEndian.PutUint16(frame[38:40], uint16(totalLen-ethHdr-ipHdr))
	for i := ethHdr + ipHdr + udpHdr; i < totalLen; i++ {
		frame[i] = byte(i)
	}
	return frame
}

// ── The benchmark body ──────────────────────────────────────────────────────

func txbpRun(b *testing.B, fragCap, frameLen int) {
	b.Helper()
	p := txbpSetup(b, fragCap, frameLen)

	// One pre-built buffer is safe to reuse: tap.MemTAP.Write copies the frame
	// before publishing it (tap.go:187), so processTapFrame's in-place dstMAC
	// rewrite at node_tap.go:823 never corrupts it.
	frame := txbpFrame(frameLen, p.macA, p.macB)

	// Drain pipeB before any frame is written so nothing is missed, and so the
	// delivery count below is a real end-to-end check.
	delivered := txbpStartDrain(p, frameLen)

	// Warm the TAP path itself: the very first frame takes the MACTable MISS →
	// ResolvePeerIDByIP fallback at node_tap.go:794, which self-learns dstMAC.
	// Doing that before ResetTimer means the timed region runs the direct
	// MACTable hit.
	for i := 0; i < txbpWarmupFrames; i++ {
		if _, err := p.pipeA.Write(frame); err != nil {
			b.Fatalf("txbp: warmup write %d: %v", i, err)
		}
	}
	if !p.gate.waitAtLeast(uint64(txbpWarmupFrames), time.Now().Add(txbpSetupBudget)) {
		b.Fatalf("txbp: warmup stalled — %d/%d frames never completed the framing write (dispatch_drops=%d)",
			p.gate.count(), txbpWarmupFrames, atomic.LoadUint64(&p.nodeA.dispatchDropCount))
	}
	if !delivered.waitAtLeast(uint64(txbpWarmupFrames), time.Now().Add(txbpDeliverBudget)) {
		b.Fatalf("txbp: warmup frames did not reach nodeB's TAP (%d/%d) — the data path is broken",
			delivered.count(), txbpWarmupFrames)
	}
	// Only after the warmups have both completed AND been delivered: every count
	// read from here on belongs to the timed region.
	baseDelivered := delivered.count()

	b.ReportAllocs()
	b.ResetTimer()

	base := p.gate.count()
	want := base + 1
	dropped0 := atomic.LoadUint64(&p.nodeA.dispatchDropCount)
	for i := 0; i < b.N; i++ {
		if _, err := p.pipeA.Write(frame); err != nil {
			b.Fatalf("txbp: tx write %d: %v", i, err)
		}
		// Block until THIS frame's framing write has completed. Serial by
		// construction, so the dispatch worker always sees a single-task batch
		// and takes the SendToPeer branch at node_dispatch.go:290.
		if !p.gate.waitAtLeast(want, time.Now().Add(txbpFrameTimeout)) {
			b.Fatalf("txbp: tx frame %d did not complete the framing write within %v (seen=%d want=%d dispatch_drops=%d)",
				i, txbpFrameTimeout, p.gate.count(), want,
				atomic.LoadUint64(&p.nodeA.dispatchDropCount)-dropped0)
		}
		want++
	}
	b.StopTimer()

	// Delivery health: every framed frame must also have been decrypted,
	// reassembled and written into nodeB's TAP. This is a sanity assertion on
	// the measured chain, not part of the timing.
	wantDelivered := baseDelivered + uint64(b.N)
	if !delivered.waitAtLeast(wantDelivered, time.Now().Add(txbpDeliverBudget)) {
		b.Fatalf("txbp: only %d/%d frames reached nodeB's TAP — the TX chain reports success but the peer drops the frames",
			delivered.count()-baseDelivered, b.N)
	}

	b.ReportMetric(100*float64(delivered.count()-baseDelivered)/float64(b.N), "%delivered")
	b.ReportMetric(float64(atomic.LoadUint64(&p.nodeA.dispatchDropCount)-dropped0), "dispatch_drops")
	b.ReportMetric(float64(frameLen), "frame_bytes")

	p.tearDown()
}

// BenchmarkE2ETXTapFrame64B times one smallest realistic frame (14 eth + 20
// ipv4 + 8 udp + 22 payload = 64 B) through the full transmit chain. With the
// shipped auto fragment policy this frame never fragments.
func BenchmarkE2ETXTapFrame64B(b *testing.B) {
	logger.SetGlobalLevel(logger.LevelWarn)
	defer logger.SetGlobalLevel(logger.LevelWarn)
	txbpRun(b, txbpFragAuto, 64)
}

// BenchmarkE2ETXTapFrame1400B times one MTU-sized 1400 B frame through the full
// transmit chain under the shipped auto fragment policy. A live stream on a
// reliable transport yields maxFragPayloadStream (65400), so this frame is also
// NOT fragmented — it is the single-fragment steady state at MTU size.
func BenchmarkE2ETXTapFrame1400B(b *testing.B) {
	logger.SetGlobalLevel(logger.LevelWarn)
	defer logger.SetGlobalLevel(logger.LevelWarn)
	txbpRun(b, txbpFragAuto, 1400)
}

// BenchmarkE2ETXTapFrame1400BFragmented times the SAME 1400 B frame with
// obfuscation.max_frag_size=512, which forces encryptAndFragment to split it
// into several chunks and re-seal every one of them (strategy.go:498) — the
// fragmentation branch the other two benchmarks do not take.
func BenchmarkE2ETXTapFrame1400BFragmented(b *testing.B) {
	logger.SetGlobalLevel(logger.LevelWarn)
	defer logger.SetGlobalLevel(logger.LevelWarn)
	txbpRun(b, txbpFragForce, 1400)
}
