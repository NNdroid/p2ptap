package node

// End-to-end receive-path benchmark.
//
// WHAT IS MEASURED. One on-the-wire SEALED frame — the 4-byte big-endian
// length prefix plus an obfuscate frame whose payload region is ChaCha20
// ciphertext — read by ReadFrame and pushed through the production RX chain on
// a live node:
//
//	decryptPeerFrame           AEAD open, real negotiated per-peer cipher
//	  -> obfuscate.Unpack       seqID + payload
//	  -> dedup                  IsDuplicateReason, real per-peer window + epoch
//	  -> checkACL               compiled rules, config-driven
//	  -> MAC learning           MACTable.Learn, observed-MAC, ARP/NDP index
//	  -> collector              RecordRecv / RecordPacketDir /
//	                           CaptureFrameWithPeers / RecordFrame
//	  -> IPTracker.ExtractAndRecord
//	  -> rewriteRxDstMAC
//	  -> enqueueTapWrite        -> tapWriteLoop -> real MemTAP write, drained by
//	                             a separate goroutine the way a NIC reader
//	                             would consume it
//
// Two Ethernet frame sizes (64B, 1400B) crossed with ACL on/off, because ACL
// matching sits on the per-frame path.
//
// WHY A REAL TWO-NODE OVERLAY. The per-peer cipher, the anti-replay epoch, the
// peer metadata, the ARP index and the TAP writer are all populated by the real
// SeqSync handshake, so no stage of the RX chain is hand-faked. Frames are
// sealed with nodeA's REAL negotiated TX cipher for nodeB and nodeA's REAL
// per-peer epoch, and every frame gets a fresh seqID from nodeA's FramePacker
// (Packer.NextSeqID). Reusing one seqID would trip nodeB's per-peer dedup
// window and would reuse the AEAD (key, nonce) pair, so the frames would be
// dropped and the number would be fake.
//
// WHAT IS NOT IN THE TIMED REGION. The TX half — Ethernet frame build, Pack,
// AEAD seal, Dispatcher.SendToPeer, TCP — is run once, before b.ResetTimer, to
// produce a framed wire image; the timed loop is the read-and-process half only.
// BenchmarkE2EFullPathTCP measures the untrimmed round trip (TAP -> overlay ->
// TAP) for comparison.
//
// ONE DELIBERATE DEVIATION FROM THE PRODUCTION STREAM READER. The framed bytes
// are served from a *bytes.Reader instead of a live libp2p stream, so the
// per-frame cost of a TCP recv is out of scope (that is the transport, not the
// RX chain). ReadFrame itself is the production function and sees exactly the
// framing WriteFrame produces.

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"

	"p2ptap/pkg/config"
	"p2ptap/pkg/logger"
	"p2ptap/pkg/obfuscate"
	"p2ptap/pkg/tap"
	"p2ptap/pkg/web"
)

const (
	// rxbpListen pins both nodes to the TCP overlay. 0.0.0.0 is mandatory, not
	// a portability escape hatch: filterAdvertisedAddrs drops every loopback
	// address, so a 127.0.0.1 listener advertises nothing and cannot be dialed.
	rxbpListen = "/ip4/0.0.0.0/tcp/0"

	// rxbpBatchCapBytes bounds the pre-sealed wire image. Every frame needs its
	// own seqID -- the per-peer dedup window drops repeats -- so the image cannot
	// be cycled and b.N is capped to what fits here.
	//
	// The cap must leave room for the calibration to finish: testing.launch stops
	// only when the timed run reaches -benchtime (benchmark.go:351), and
	// predictN grows its counter by exactly 1 once it asks for more than the cap
	// allows (benchmark.go:321). If the cap sat at the -benchtime boundary the
	// harness would clamp b.N, never reach -benchtime, and rebuild the overlay
	// once per counter tick forever -- 549 teardowns and counting is the
	// signature. That is why the budget is wide: capped by the worst-case wire
	// size (MaxPackedLen + overhead + length prefix = 1123 B for a 64B frame),
	// 512MiB gives 477,980 frames, and 477,980 x ~2us = 960ms, three times the
	// 300ms target. The real allocation tracks b.N and stays near 170MiB.
	rxbpBatchCapBytes = 512 << 20

	// rxbpMaxCalibSteps bounds the harness's ramp-up. A healthy calibration takes
	// four steps (1, 100, 10000, ~186000); if this is exceeded the cap is binding
	// and the ramp will never terminate, so fail instead of spinning for hours.
	// This is the only tripwire -- a stalled calibration errors out nothing, it
	// just runs, so a -timeout is the other half of the defence.
	rxbpMaxCalibSteps = 12

	// rxbpPreflight runs the synchronous RX chain a handful of times before the
	// timed loop, so a broken setup fails loudly instead of timing a black hole.
	rxbpPreflight = 16

	// rxbpReadyPolls bounds the overlay-ready wait: 750 * 20ms = 15s.
	rxbpReadyPolls = 750

	// rxbpPortSettle keeps this test from racing the next subtest's
	// NewNodeWithTAP for the same local socket range, exactly like the other e2e
	// suites in this package.
	rxbpPortSettle = 300 * time.Millisecond
)

// rxbpSize is one frame-size leg of the matrix.
type rxbpSize struct {
	name  string
	frame int
}

func rxbpSizes() []rxbpSize {
	return []rxbpSize{
		{name: "64B", frame: 64},
		{name: "1400B", frame: 1400},
	}
}

var (
	rxbpSrcIP = net.ParseIP("10.0.0.1")
	rxbpDstIP = net.ParseIP("10.0.0.2")
)

// rxbpACL is the policy the acl-on legs run under. Two rules so the matcher
// really walks the list instead of hitting rule zero: rule one (tcp/80) must be
// evaluated and rejected as a protocol mismatch, rule two (udp/53 to 10.0.0.2)
// is the first-match accept that lets the benchmark frame through. The compiled
// form is cached per config snapshot by compiledACLFor, exactly as in production.
func rxbpACL() config.ACLConfig {
	return config.ACLConfig{
		Enable:        true,
		DefaultAction: "accept",
		Rules: []config.ACLRule{
			{RuleID: "rx-tcp-80", Action: "accept", Direction: "both", IPCIDR: "10.0.0.2/32", Protocol: "tcp", Port: "80"},
			{RuleID: "rx-udp-53", Action: "accept", Direction: "both", IPCIDR: "10.0.0.2/32", Protocol: "udp", Port: "53"},
		},
	}
}

// e2eBenchCollector builds a production WebUI collector with the pcap ring
// armed, so the measured path pays the same per-frame capture cost production
// pays while the operator has the packet panel open. A noopCollector would make
// RecordFrame / RecordPacketDir / RecordTxSeq / CaptureFrameWithPeers no-ops
// and report B/op that is uncomparable across the four e2e slices. Node.Close
// type-asserts the injected collector to interface{ Stop() } (node.go:4366) and
// stops it, so teardown needs nothing extra.
func e2eBenchCollector() *web.StatsCollector {
	c := web.NewStatsCollector()
	c.Pcap.SetIdleSkip(false)
	c.Pcap.Start()
	return c
}

// rxbpFrame is an Ethernet + IPv4 + UDP frame of exactly size bytes:
// 14 (Ethernet) + 20 (IPv4) + 8 (UDP) + (size-42) bytes of payload. Dst MAC is
// the RX node's own MAC so rewriteRxDstMAC and MAC learning see a
// locally-destined frame, and the UDP destination port is 53 so the acl-on leg
// exercises a real first-match accept.
func rxbpFrame(srcMAC, dstMAC net.HardwareAddr, size int) []byte {
	if size < 42 {
		return nil
	}
	payload := make([]byte, size-42)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	return buildUDPIPv4Frame(srcMAC, dstMAC, rxbpSrcIP, rxbpDstIP, 40000, 53, payload)
}

// rxbpHarness holds one live A<->B overlay plus the negotiated crypto state the
// frame builder needs.
type rxbpHarness struct {
	nodeA, nodeB *Node
	pipeA, pipeB *tap.MemTAP
	macA, macB   net.HardwareAddr
	peerA        peer.ID // nodeA's ID: the remotePeer nodeB's RX chain sees
	peerB        peer.ID
	epoch        uint64              // nodeA's per-peer anti-replay epoch for nodeB
	cipher       obfuscate.ObfCipher // nodeA's negotiated TX cipher for nodeB
	delivered    atomic.Uint64       // frames drained out of nodeB's TAP
	rxCalls      atomic.Int64        // calibration invocations of rxbpRunRX for this leg
	drainDone    chan struct{}
	closeOnce    sync.Once
}

// close tears the topology down in the order the other e2e suites use: stop the
// TAP consumer, close both pipes so every blocked reader/writer gets EOF, then
// close both nodes (each Close is bounded by internal timeouts), then let the
// bound sockets settle before the next subtest rebinds.
func (h *rxbpHarness) close() {
	h.closeOnce.Do(func() {
		if h.pipeB != nil {
			_ = h.pipeB.Close()
		}
		if h.pipeA != nil {
			_ = h.pipeA.Close()
		}
		if h.drainDone != nil {
			<-h.drainDone
		}
		if h.nodeB != nil {
			_ = h.nodeB.Close()
		}
		if h.nodeA != nil {
			_ = h.nodeA.Close()
		}
		// nodeB.Close stops the stats collector itself (Node.Close type-asserts
		// its collector to a stoppable interface), so calling Stop here would
		// close an already-closed channel.
		time.Sleep(rxbpPortSettle)
	})
}

// waitFor reports whether the drain count reached target within timeout.
func (h *rxbpHarness) waitFor(target uint64, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for h.delivered.Load() < target {
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(5 * time.Millisecond)
	}
	return true
}

// rxbpSetup builds the topology, completes the real handshake, warms the first
// application stream, and proves the untrimmed round trip works. aclOn installs
// a real ACL policy on the RX node.
func rxbpSetup(b *testing.B, aclOn bool) *rxbpHarness {
	b.Helper()

	tapA, pipeA := tap.NewMemTAPPair("rxbp-tapA", "rxbp-pipeA")
	tapB, pipeB := tap.NewMemTAPPair("rxbp-tapB", "rxbp-pipeB")

	cfgA := createTestNodeConfig("10.0.0.1/24", "fd00::1/64", "best_path")
	cfgB := createTestNodeConfig("10.0.0.2/24", "fd00::2/64", "best_path")
	cfgA.ListenAddrs = []string{rxbpListen}
	cfgB.ListenAddrs = []string{rxbpListen}
	if aclOn {
		cfgB.ACL = rxbpACL()
	}

	// The real WebUI collector, with the pcap ring armed. See e2eBenchCollector:
	// NewStatsCollector leaves capture idle-skipped (no live subscriber), which
	// would make the capture stage a no-op; SetIdleSkip(false) + Start() puts the
	// production "operator has the packet panel open" cost on the measured path.
	collector := e2eBenchCollector()

	nodeA, err := NewNodeWithTAP(cfgA, tapA, nil)
	if err != nil {
		pipeA.Close()
		pipeB.Close()
		collector.Stop()
		b.Fatalf("rxbp: create nodeA: %v", err)
	}
	nodeB, err := NewNodeWithTAP(cfgB, tapB, collector)
	if err != nil {
		_ = nodeA.Close()
		pipeA.Close()
		pipeB.Close()
		collector.Stop()
		b.Fatalf("rxbp: create nodeB: %v", err)
	}
	nodeA.Start()
	nodeB.Start()

	h := &rxbpHarness{
		nodeA:     nodeA,
		nodeB:     nodeB,
		pipeA:     pipeA,
		pipeB:     pipeB,
		macA:      nodeA.localMAC,
		macB:      nodeB.localMAC,
		peerA:     nodeA.Host.ID(),
		peerB:     nodeB.Host.ID(),
		drainDone: make(chan struct{}),
	}

	// Command-driven mutual recognition: no StaticPeers, BootstrapPeers or mDNS.
	connectCtx, cancel := context.WithTimeout(nodeA.ctx, 15*time.Second)
	defer cancel()
	ti := nodeB.Host.Peerstore().PeerInfo(nodeB.Host.ID())
	ti.Addrs = nodeB.Host.Addrs()
	if err := nodeA.Host.Connect(connectCtx, ti); err != nil {
		h.close()
		b.Fatalf("rxbp: connect A->B: %v", err)
	}

	ready := false
	for i := 0; i < rxbpReadyPolls; i++ {
		okA, _, encA := nodeA.obfStateForPeer(nodeB.Host.ID())
		okB, _, encB := nodeB.obfStateForPeer(nodeA.Host.ID())
		if okA && encA && okB && encB {
			ready = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !ready {
		h.close()
		b.Fatalf("rxbp: overlay encryption never became ready")
	}

	// Forwarding bookkeeping, both directions.
	nodeA.storePeerMeta(nodeB.Host.ID(), PeerMeta{NodeName: "rxbp-B", TapIP: "10.0.0.2/24", TapMAC: nodeB.localMAC.String()})
	nodeB.storePeerMeta(nodeA.Host.ID(), PeerMeta{NodeName: "rxbp-A", TapIP: "10.0.0.1/24", TapMAC: nodeA.localMAC.String()})
	nodeA.rebuildARPIndex()
	nodeB.rebuildARPIndex()

	// Pre-pay the one-off NewStream + /p2ptap negotiation so the first data
	// frame is not dropped on cold start.
	probe := []byte("RXPB_WARMUP")
	out := make([]byte, len(probe)+obfuscate.HeaderLen+4096)
	pn, perr := nodeA.Packer.Pack(nodeA.Packer.NextSeqID(nodeA.txEpochForPeer(nodeB.Host.ID())), probe, out)
	if perr != nil {
		h.close()
		b.Fatalf("rxbp: warm pack: %v", perr)
	}
	if err := nodeA.Dispatcher.SendToPeer(nodeA.ctx, nodeB.Host.ID(), out[:pn]); err != nil {
		h.close()
		b.Fatalf("rxbp: warm send: %v", err)
	}
	time.Sleep(100 * time.Millisecond)

	cipher := nodeA.obfCipherForPeer(nodeB.Host.ID())
	if cipher == nil {
		h.close()
		b.Fatalf("rxbp: nodeA has no negotiated TX cipher for nodeB")
	}
	rxCipher := nodeB.obfDecryptCipherForPeer(nodeA.Host.ID())
	if rxCipher == nil {
		h.close()
		b.Fatalf("rxbp: nodeB has no RX cipher for nodeA -- the measured path would skip decryptPeerFrame's AEAD open")
	}
	h.cipher = cipher
	h.epoch = nodeA.txEpochForPeer(nodeB.Host.ID())

	// The RX node must see the policy this leg intends to measure, and the
	// policy must ACCEPT the benchmark frame -- otherwise the timed loop would
	// be measuring a drop path.
	if aclOn && nodeB.compiledACLFor(nodeB.CurrentConfig()) == nil {
		h.close()
		b.Fatalf("rxbp: ACL enabled in config but compiledACLFor returned nil")
	}
	if !nodeB.checkACL(rxbpFrame(h.macA, h.macB, 1400), nodeA.Host.ID().String(), false) {
		h.close()
		b.Fatalf("rxbp: ACL rejected the benchmark frame; measured path would be a drop path")
	}

	// Prove the untrimmed path with CONTENT, not just with a delivery count.
	// A frame written into nodeA's TAP must travel nodeA's real TX chain
	// (processTapFrame -> Pack -> seal -> Dispatcher.SendToPeer -> TCP) and come
	// back out of nodeB's TAP through nodeB's REAL handleStream ->
	// handleDirectFrame. The payload bytes are checked, not just their length:
	// the delivered bytes come from the frame that was AEAD-OPENED, so a
	// working delivery count with undecrypted ciphertext would fail here.
	// rewriteRxDstMAC may legitimately normalise the two MACs, so the comparison
	// starts at byte 12 -- EtherType, IPv4, UDP and the whole payload.
	want := rxbpFrame(h.macA, h.macB, 64)
	if _, err := h.pipeA.Write(want); err != nil {
		h.close()
		b.Fatalf("rxbp: warmup TAP write: %v", err)
	}
	got := rxbpWaitForFrame(h.pipeB, rxbpMatches(want), 15*time.Second)
	if got == nil {
		h.close()
		b.Fatalf("rxbp: warmup frame never came back through the overlay -- RX path is dead")
	}

	// The single consumer for frames nodeB injects into its own TAP. The TAP
	// writer never drops (enqueueTapWrite falls back to a synchronous write when
	// its queue is full), so this count must equal the number of frames the RX
	// chain accepted.
	go func() {
		defer close(h.drainDone)
		buf := make([]byte, 2048)
		for {
			n, rerr := h.pipeB.Read(buf)
			if rerr != nil {
				return
			}
			if n > 0 {
				h.delivered.Add(1)
			}
		}
	}()
	return h
}

// rxbpMatches returns a predicate that recognises the overlay form of want:
// same length and identical bytes from the EtherType onward. The two MAC
// addresses are excluded because rewriteRxDstMAC legitimately rewrites the
// destination MAC of a locally-destined frame.
func rxbpMatches(want []byte) func([]byte) bool {
	return func(got []byte) bool {
		return len(got) == len(want) && bytes.Equal(want[12:], got[12:])
	}
}

// rxbpWaitForFrame reads frames off rd until matches accepts one, returning the
// frame, or nil if the timeout or a read error fires first. Non-matching frames
// are discarded -- they are nodeB's own control traffic (GARP/NA).
func rxbpWaitForFrame(rd io.Reader, matches func([]byte) bool, timeout time.Duration) []byte {
	frames := make(chan []byte, 1)
	readErr := make(chan error, 1)
	go func() {
		buf := make([]byte, 2048)
		for {
			n, err := rd.Read(buf)
			if err != nil {
				readErr <- err
				return
			}
			if n <= 0 {
				continue
			}
			frame := make([]byte, n)
			copy(frame, buf[:n])
			if matches(frame) {
				frames <- frame
				return
			}
		}
	}()
	deadline := time.Now().Add(timeout)
	for {
		select {
		case frame := <-frames:
			return frame
		case <-readErr:
			return nil
		case <-time.After(min(time.Second, time.Until(deadline))):
			if time.Now().After(deadline) {
				return nil
			}
		}
	}
}

// rxbpSealBatch seals count identical Ethernet frames with nodeA's real
// negotiated cipher and epoch, framing each with the 4-byte big-endian length
// prefix WriteFrame puts on the wire. Every frame gets a fresh seqID from
// nodeA's FramePacker: reusing one would trip nodeB's per-peer dedup window and
// would reuse the AEAD (key, nonce) pair, dropping the frame and falsifying the
// number.
func (h *rxbpHarness) rxbpSealBatch(eth []byte, count int) ([]byte, error) {
	packedCap := h.nodeA.Packer.MaxPackedLen(len(eth))
	sealedCap := packedCap + h.cipher.Overhead()

	wire := make([]byte, 0, (sealedCap+frameLenSize)*count)
	packed := make([]byte, packedCap)
	sealed := make([]byte, 0, sealedCap)
	var hdr [frameLenSize]byte
	for i := 0; i < count; i++ {
		seqID := h.nodeA.nextTxSeqID(h.peerB)
		n, err := h.nodeA.Packer.Pack(seqID, eth, packed)
		if err != nil {
			return nil, fmt.Errorf("frame %d: Pack: %w", i, err)
		}
		sealedFrame, err := h.nodeA.sealPeerFrameInto(h.peerB, h.cipher, packed[:n], sealed)
		if err != nil {
			return nil, fmt.Errorf("frame %d: seal: %w", i, err)
		}
		binary.BigEndian.PutUint32(hdr[:], uint32(len(sealedFrame)))
		wire = append(wire, hdr[:]...)
		wire = append(wire, sealedFrame...)
	}
	return wire, nil
}

// rxbpRunRX is the measured leg: one synchronous ReadFrame + handleDirectFrame
// per iteration, on a live node, with real negotiated crypto, real dedup state,
// real ACL config, real pcap capture, and real delivery into a drained MemTAP.
func rxbpRunRX(b *testing.B, h *rxbpHarness, sz rxbpSize) {
	b.Helper()

	// rxbpRunRX runs once per calibration step on the same harness, so the ramp
	// is observable here and can be aborted instead of spinning forever.
	if calls := h.rxCalls.Add(1); calls > rxbpMaxCalibSteps {
		b.Fatalf("rxbp: calibration did not converge in %d steps -- the batch cap is binding", calls)
	}

	eth := rxbpFrame(h.macA, h.macB, sz.frame)
	if eth == nil {
		b.Fatalf("rxbp: undersized frame leg %s", sz.name)
	}

	// Bound the pre-sealed image by the largest wire size the sealer can
	// produce for this frame. EncryptPayloadRegionInto keeps the obfuscation
	// trailing-padding region, and the default mode is "random" (config.go:462),
	// so a 64B frame comes out anywhere from ~680 to ~1100 B on the wire. A
	// single sample would be a lie and a batch average would smear across it,
	// so the cap is sized against the worst case: MaxPackedLen plus the AEAD
	// overhead.
	preflightWire, err := h.rxbpSealBatch(eth, rxbpPreflight)
	if err != nil {
		b.Fatalf("rxbp: preflight seal: %v", err)
	}
	wireFrame := uint64(h.nodeA.Packer.MaxPackedLen(len(eth))+h.cipher.Overhead()) + frameLenSize
	if wireFrame == 0 {
		b.Fatalf("rxbp: zero-length sealed frame for leg %s", sz.name)
	}
	if cap := int(rxbpBatchCapBytes / wireFrame); b.N > cap {
		b.N = cap
	}
	if b.N <= 0 {
		b.Fatalf("rxbp: frame too large to build a batch (%d B/frame worst case)", wireFrame)
	}
	batchWire, err := h.rxbpSealBatch(eth, b.N)
	if err != nil {
		b.Fatalf("rxbp: seal: %v", err)
	}

	// Exactly the buffers handleStream allocates per stream.
	buf := make([]byte, obfuscate.MaxSealedFrameSize)
	scratch := make([]byte, 0, 9600)

	// Preflight: the chain must accept every frame. A dedup drop, an ACL drop or
	// a decrypt failure shows up as a short delivery count and fails the
	// benchmark instead of timing a no-op.
	deliveredBefore := h.delivered.Load()
	src := bytes.NewReader(preflightWire)
	for i := 0; i < rxbpPreflight; i++ {
		readN, rerr := ReadFrame(src, buf)
		if rerr != nil || readN == 0 {
			b.Fatalf("rxbp: preflight read %d: n=%d err=%v", i, readN, rerr)
		}
		h.nodeB.handleDirectFrame(h.peerA, buf[:readN], &scratch, "")
	}
	if !h.waitFor(deliveredBefore+uint64(rxbpPreflight), 10*time.Second) {
		b.Fatalf("rxbp: preflight delivered %d/%d frames -- the RX chain is dropping them",
			h.delivered.Load()-deliveredBefore, rxbpPreflight)
	}

	// Re-anchor the delivery baseline: the write queue may still be draining.
	deliveredBefore = h.delivered.Load()
	src = bytes.NewReader(batchWire)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		readN, rerr := ReadFrame(src, buf)
		if rerr != nil {
			b.Fatalf("rxbp: read frame %d: %v", i, rerr)
		}
		if readN == 0 {
			b.Fatalf("rxbp: zero-length frame %d -- ran past the end of the wire image", i)
		}
		h.nodeB.handleDirectFrame(h.peerA, buf[:readN], &scratch, "")
	}
	b.StopTimer()

	// Delivery accounting. The TAP writer never drops, so the delta must reach
	// b.N; anything short means a frame was silently discarded somewhere in the
	// RX chain, which would make the ns/op meaningless. Extra counts are nodeB's
	// own control frames (GARP), which are legitimate.
	delivered := h.delivered.Load() - deliveredBefore
	deadline := time.Now().Add(3 * time.Second)
	for delivered < uint64(b.N) && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
		delivered = h.delivered.Load() - deliveredBefore
	}
	if delivered < uint64(b.N) {
		b.Fatalf("rxbp: only %d/%d frames reached nodeB's TAP -- RX chain is dropping", delivered, b.N)
	}

	b.ReportMetric(float64(len(eth)), "frame_B")
	b.ReportMetric(float64(wireFrame), "wire_frame_B")
	b.ReportMetric(float64(delivered), "delivered")
}

// BenchmarkE2ERXPath measures the sealed-frame receive path described above:
// 64B and 1400B Ethernet frames, ACL disabled and enabled.
//
// The topology is built in the parent, not inside b.Run. The harness re-invokes
// a sub-benchmark once per calibration step, so building the overlay in there
// would repeat the handshake, STUN churn and 300ms port settle on every step
// (a healthy ramp is four steps). Sharing one warm node across the steps is
// also the steadier measurement, since the dedup windows, ACL caches and pcap
// ring stay in the state the timed loop expects.
func BenchmarkE2ERXPath(b *testing.B) {
	logger.SetGlobalLevel(logger.LevelWarn)
	defer logger.SetGlobalLevel(logger.LevelWarn)
	for _, aclOn := range []bool{false, true} {
		for _, sz := range rxbpSizes() {
			leg := "acl-off"
			if aclOn {
				leg = "acl-on"
			}
			rxbpRunLeg(b, sz.name+"-"+leg, aclOn, sz)
		}
	}
}

// rxbpRunLeg owns one topology for one leg: build it, hand it to the sub
// benchmark, then always take it down. b.Run blocks until the leg is done, so
// the teardown cannot race the next leg's NewNodeWithTAP for the same sockets.
func rxbpRunLeg(b *testing.B, name string, aclOn bool, sz rxbpSize) {
	b.Helper()
	h := rxbpSetup(b, aclOn)
	b.Run(name, func(b *testing.B) {
		rxbpRunRX(b, h, sz)
	})
	h.close()
}

// BenchmarkE2EFullPathTCP is the untrimmed control: the same overlay with the TX
// half in the timed region too (TAP write -> processTapFrame -> Pack -> seal ->
// Dispatcher.SendToPeer -> TCP loopback -> the RX node's real handleStream ->
// TAP). It reports delivered frames, so seqIDs come from nodeA's pacer and no
// dedup window can lie to it. Compared with BenchmarkE2ERXPath it shows how
// much of a round trip the RX half costs.
//
// RUN IT SEPARATELY FROM BenchmarkE2ERXPath. It is byte-for-byte the same body as
// BenchmarkThroughput_TCP (same pair builder, frame builder and drain matcher),
// so it is a fair control. But it is throughput-limited and order-sensitive: on
// this box it measured 802 frames/s / 96.34% delivered run on its own, against
// 827.7 / 99.62% for BenchmarkThroughput_TCP, yet only 427.3 frames/s / 51.40%
// when run in the same process after the four RX legs. Whatever the RX legs
// leave behind is still untracked here, so the standalone figure is the valid
// one and the combined-run figure should not be quoted.
func BenchmarkE2EFullPathTCP(b *testing.B) {
	logger.SetGlobalLevel(logger.LevelWarn)
	defer logger.SetGlobalLevel(logger.LevelWarn)
	b.Run("TCP", func(b *testing.B) {
		pair := benchProtocolPair(b, rxbpTCPSpec())
		build := func(seq int) []byte {
			return buildUDPIPv4Frame(pair.macA, pair.macB, rxbpSrcIP, rxbpDstIP, 40000, 53, throughputBenchPayload)
		}
		benchThroughput(b, pair, build, func(f []byte) bool {
			return len(f) >= 42+len(throughputBenchPayload) && bytes.HasPrefix(f[42:], throughputBenchPayload)
		})
	})
}

// rxbpTCPSpec looks up the TCP overlay spec instead of indexing the slice, so a
// reordering of allTransportSpecs cannot silently measure a different transport.
func rxbpTCPSpec() transportSpec {
	for _, s := range allTransportSpecs() {
		if s.name == "TCP" {
			return s
		}
	}
	panic("rxbp: TCP transport spec missing from allTransportSpecs")
}
