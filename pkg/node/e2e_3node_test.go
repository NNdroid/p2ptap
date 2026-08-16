package node

import (
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"p2ptap/pkg/tap"
)

// testMACC is the synthetic TAP MAC assigned to NodeC for these e2e frames.
var testMACC = net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x03}

// TestE2EConcurrentBidirectional3Node closes the gap flagged in
// TestE2EConcurrentBidirectional's NOTE: a true multi-peer fan-in (3+ nodes)
// "could not be added" because a pre-existing fragility dropped A<->B as soon
// as a 2nd peer was present. The 3-node ARP test (TestARPPingThreeNode) now
// passes, and its own comment attributes the OLD multi-peer failure to a zombie
// frameReader in the harness — not the data path. This test replaces that
// blocked work with a SUSTAINED concurrent bidirectional e2e across a full
// A-B-C mesh, using the same race-safe single-reader-per-pipe + per-frame-mark
// pattern as the 2-node test, so a real link-drop would be unmistakable.
//
// It also stresses KEY ROTATION under multi-peer load: after the first burst it
// forces a re-key on every directed pair (triggerPeerRekey) while all three
// peers are still connected and chatting, then runs a second burst. If a
// "key-rotation fragility" survived, the re-key window would strand one of the
// links in a permanent decrypt-fail loop and the second burst would fail.
func TestE2EConcurrentBidirectional3Node(t *testing.T) {
	tapA, pipeA := tap.NewMemTAPPair("tapA", "pipeA")
	tapB, pipeB := tap.NewMemTAPPair("tapB", "pipeB")
	tapC, pipeC := tap.NewMemTAPPair("tapC", "pipeC")

	cfgA := createTestNodeConfig("10.0.0.1/24", "fd00::1/64", "best_path")
	cfgB := createTestNodeConfig("10.0.0.2/24", "fd00::2/64", "best_path")
	cfgC := createTestNodeConfig("10.0.0.3/24", "fd00::3/64", "best_path")

	nodeA, err := NewNodeWithTAP(cfgA, tapA, nil)
	if err != nil {
		t.Fatalf("create NodeA: %v", err)
	}
	defer nodeA.Close()
	nodeB, err := NewNodeWithTAP(cfgB, tapB, nil)
	if err != nil {
		t.Fatalf("create NodeB: %v", err)
	}
	defer nodeB.Close()
	nodeC, err := NewNodeWithTAP(cfgC, tapC, nil)
	if err != nil {
		t.Fatalf("create NodeC: %v", err)
	}
	defer nodeC.Close()

	nodeA.Start()
	nodeB.Start()
	nodeC.Start()

	connect := func(a, b *Node) {
		ti := b.Host.Peerstore().PeerInfo(b.Host.ID())
		ti.Addrs = b.Host.Addrs()
		if cerr := a.Host.Connect(a.ctx, ti); cerr != nil {
			t.Fatalf("connect %s->%s: %v", a.Host.ID().ShortString(), b.Host.ID().ShortString(), cerr)
		}
	}
	connect(nodeA, nodeB)
	connect(nodeB, nodeC)
	connect(nodeA, nodeC)

	for _, pr := range [][2]*Node{{nodeA, nodeB}, {nodeB, nodeC}, {nodeA, nodeC}} {
		waitOverlayReady(t, pr[0], pr[1])
		waitStreamReady(t, pr[0], pr[1])
		waitStreamReady(t, pr[1], pr[0])
	}
	time.Sleep(300 * time.Millisecond)

	_ = pipeA.ConfigureIP("10.0.0.1/24", "fd00::1/64")
	_ = pipeB.ConfigureIP("10.0.0.2/24", "fd00::2/64")
	_ = pipeC.ConfigureIP("10.0.0.3/24", "fd00::3/64")

	// Seed peer metadata both ways so routing resolution is deterministic.
	all := map[*Node]PeerMeta{
		nodeA: {NodeName: "A", TapIP: "10.0.0.1/24", TapMAC: nodeA.localMAC.String()},
		nodeB: {NodeName: "B", TapIP: "10.0.0.2/24", TapMAC: nodeB.localMAC.String()},
		nodeC: {NodeName: "C", TapIP: "10.0.0.3/24", TapMAC: nodeC.localMAC.String()},
	}
	peers := []*Node{nodeA, nodeB, nodeC}
	for _, src := range peers {
		for _, dst := range peers {
			if src == dst {
				continue
			}
			src.storePeerMeta(dst.Host.ID(), all[dst])
		}
	}

	// ONE long-lived reader per pipe, created up front (the load-bearing fix
	// for the old zombie-reader multi-peer failure).
	readerA := newFrameReader(pipeA)
	readerB := newFrameReader(pipeB)
	readerC := newFrameReader(pipeC)
	t.Cleanup(func() {
		readerA.Close()
		readerB.Close()
		readerC.Close()
	})

	// Each directed pair gets `rounds` uniquely-marked frames. A pipe's reader
	// must observe every inbound direction's markers.
	const rounds = 6
	mk := func(tag, srcIP, dstIP string, srcMAC, dstMAC net.HardwareAddr, writer tap.TAPDevice, rdrF *frameReader) dir {
		return dir{writer: writer, srcIP: srcIP, dstIP: dstIP, srcMAC: srcMAC, dstMAC: dstMAC, tag: tag, reader: rdrF}
	}
	var dirs []dir
	// A->B / B->A
	for i := 0; i < rounds; i++ {
		dirs = append(dirs, mk(fmt.Sprintf("C3_AB_%d", i), "10.0.0.1", "10.0.0.2", testMACA, testMACB, pipeA, readerB))
		dirs = append(dirs, mk(fmt.Sprintf("C3_BA_%d", i), "10.0.0.2", "10.0.0.1", testMACB, testMACA, pipeB, readerA))
	}
	// A->C / C->A
	for i := 0; i < rounds; i++ {
		dirs = append(dirs, mk(fmt.Sprintf("C3_AC_%d", i), "10.0.0.1", "10.0.0.3", testMACA, testMACC, pipeA, readerC))
		dirs = append(dirs, mk(fmt.Sprintf("C3_CA_%d", i), "10.0.0.3", "10.0.0.1", testMACC, testMACA, pipeC, readerA))
	}
	// B->C / C->B
	for i := 0; i < rounds; i++ {
		dirs = append(dirs, mk(fmt.Sprintf("C3_BC_%d", i), "10.0.0.2", "10.0.0.3", testMACB, testMACC, pipeB, readerC))
		dirs = append(dirs, mk(fmt.Sprintf("C3_CB_%d", i), "10.0.0.3", "10.0.0.2", testMACC, testMACB, pipeC, readerB))
	}

	wantA := wantFrom(dirs, readerA)
	wantB := wantFrom(dirs, readerB)
	wantC := wantFrom(dirs, readerC)
	collA := newConcurrentPayloadCollector(readerA, wantA)
	collB := newConcurrentPayloadCollector(readerB, wantB)
	collC := newConcurrentPayloadCollector(readerC, wantC)

	// Pre-build the wire frames once (so the burst is pure writes).
	for i := range dirs {
		d := &dirs[i]
		d.tagBytes = []byte(d.tag)
		d.frame = constructICMPv4PacketWithData(d.srcMAC, d.dstMAC, net.ParseIP(d.srcIP), net.ParseIP(d.dstIP), 7000+len(dirs)+i, 1, d.tagBytes)
	}

	runBurst := func(label string) {
		var wg sync.WaitGroup
		for i := range dirs {
			d := &dirs[i]
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, werr := d.writer.Write(d.frame); werr != nil {
					t.Errorf("%s write %s failed: %v", label, d.tag, werr)
				}
			}()
		}
		wg.Wait()
		// Verify each receiving pipe got every expected marker (single retry).
		collB.wait(t, dirWriterFor(dirs, readerB), framesFor(dirs, readerB), wantB, 16*time.Second, "3node B")
		collA.wait(t, dirWriterFor(dirs, readerA), framesFor(dirs, readerA), wantA, 16*time.Second, "3node A")
		collC.wait(t, dirWriterFor(dirs, readerC), framesFor(dirs, readerC), wantC, 16*time.Second, "3node C")
	}

	runBurst("phase1")

	// KEY-ROTATION STRESS: force a re-key on every directed pair while all
	// three peers remain connected and chatting. This is the exact condition
	// the old "multi-peer key-rotation fragility" was about.
	for _, pr := range [][2]*Node{{nodeA, nodeB}, {nodeB, nodeA}, {nodeB, nodeC}, {nodeC, nodeB}, {nodeA, nodeC}, {nodeC, nodeA}} {
		pr[0].triggerPeerRekey(pr[1].Host.ID())
	}
	time.Sleep(1500 * time.Millisecond) // let the handshakes converge

	runBurst("phase2-after-rekey")

	t.Log("3-node concurrent bidirectional E2E (with key rotation) success")
}

// dir is one directed e2e flow used by TestE2EConcurrentBidirectional3Node.
type dir struct {
	writer  tap.TAPDevice // TAP pipe the sender injects into
	srcIP   string
	dstIP   string
	srcMAC  net.HardwareAddr
	dstMAC  net.HardwareAddr
	tag     string
	reader  *frameReader // receiving pipe's reader
	tagBytes []byte
	frame   []byte
}

// wantFrom returns the set of marker payloads expected on the given reader.
func wantFrom(dirs []dir, rdr *frameReader) [][]byte {
	var out [][]byte
	for i := range dirs {
		if dirs[i].reader == rdr {
			out = append(out, []byte(dirs[i].tag))
		}
	}
	return out
}

// framesFor returns the wire frames (parallel to wantFrom order) expected on rdr.
func framesFor(dirs []dir, rdr *frameReader) [][]byte {
	var out [][]byte
	for i := range dirs {
		if dirs[i].reader == rdr {
			out = append(out, dirs[i].frame)
		}
	}
	return out
}

// dirWriterFor returns the writer pipe of the first dir whose reader is rdr, so
// the collector's retry re-send targets the correct sending TAP.
func dirWriterFor(dirs []dir, rdr *frameReader) tap.TAPDevice {
	for i := range dirs {
		if dirs[i].reader == rdr {
			return dirs[i].writer
		}
	}
	return nil
}
