package node

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	relayclient "github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/client"
	ma "github.com/multiformats/go-multiaddr"
	"p2ptap/pkg/tap"
)

// TestE2EMultipathRelayDualPath is the end-to-end guard for F2: a peer behind TWO
// relays (so it advertises two /p2p-circuit addresses) must yield TWO relay paths
// in multipath mode — one circuit through each relay. The earlier code only ever
// formed a single circuit+stream for such a peer, because relayHopForTarget
// returns one deterministic hop and the path-repair dropped circuit addresses.
//
// The fix keeps every circuit address as a candidate path (repairMultipathPaths
// via filterUndialableAddrs) and EnsureStreamsOnAllConns pins a stream on every
// relay connection it holds, so the multipath set spans both relays. The data
// plane routes a relay-only peer through its PeerStreams (hasDirectStream reports
// the relay streams, so the single-hop relay block is skipped), so both circuits
// actually carry traffic.
//
// Invariant: A and C are NEVER directly connected (no discovery / hole-punch
// loops run), so the only paths are the two circuits.
func TestE2EMultipathRelayDualPath(t *testing.T) {
	if testing.Short() {
		t.Skip("skips relay e2e in -short mode")
	}

	newRelay := func(t *testing.T) host.Host {
		t.Helper()
		r, err := libp2p.New(
			libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"),
			libp2p.EnableRelayService(),
			libp2p.ForceReachabilityPublic(),
		)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = r.Close() })
		return r
	}
	r1 := newRelay(t)
	r2 := newRelay(t)
	r1Info := peer.AddrInfo{ID: r1.ID(), Addrs: r1.Addrs()}
	r2Info := peer.AddrInfo{ID: r2.ID(), Addrs: r2.Addrs()}

	newEndpoint := func(ip string) (*Node, *tap.MemTAP) {
		t.Helper()
		cfg := createTestNodeConfig(ip, "", "multipath")
		dev, pipe := tap.NewMemTAPPair("relay-node", "relay-pipe")
		n, err := NewNodeWithTAP(cfg, dev, nil)
		if err != nil {
			dev.Close()
			pipe.Close()
			t.Fatal(err)
		}
		t.Cleanup(func() { pipe.Close(); n.Close() })
		// Start only the receive writer: no discovery/hole-punch loops may run,
		// or A and C could accidentally form a direct endpoint connection and
		// defeat the "relay-only" invariant this test pins.
		n.wg.Add(1)
		go n.tapWriteLoop()
		return n, pipe
	}
	a, pipeA := newEndpoint("10.0.0.1/24")
	c, pipeC := newEndpoint("10.0.0.3/24")

	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()

	// C reserves a circuit through BOTH relays so it is reachable via each.
	if _, err := relayclient.Reserve(ctx, c.Host, r1Info); err != nil {
		t.Fatalf("C reserve via R1: %v", err)
	}
	if _, err := relayclient.Reserve(ctx, c.Host, r2Info); err != nil {
		t.Fatalf("C reserve via R2: %v", err)
	}
	// A connects to each relay so the circuit hops are reachable.
	if err := a.Host.Connect(ctx, r1Info); err != nil {
		t.Fatalf("A connect R1: %v", err)
	}
	if err := a.Host.Connect(ctx, r2Info); err != nil {
		t.Fatalf("A connect R2: %v", err)
	}

	circuit1, _ := ma.NewMultiaddr("/p2p/" + r1.ID().String() + "/p2p-circuit/p2p/" + c.Host.ID().String())
	circuit2, _ := ma.NewMultiaddr("/p2p/" + r2.ID().String() + "/p2p-circuit/p2p/" + c.Host.ID().String())

	// Seed BOTH circuit addresses so the multipath repair path sees two candidate
	// relay paths. Then dial each with dialPeerToAddr, which (unlike
	// Host.Connect) bypasses the "peer already Connected" short-circuit and opens
	// the SECOND circuit even though the first already exists — this is the exact
	// code path F2 corrected (repairMultipathPaths -> dialPeerToAddr).
	a.Host.Peerstore().AddAddrs(c.Host.ID(), []ma.Multiaddr{circuit1, circuit2}, peerstore.PermanentAddrTTL)
	if err := a.dialPeerToAddr(ctx, c.Host.ID(), circuit1); err != nil {
		t.Fatalf("A dial circuit1: %v", err)
	}
	if err := a.dialPeerToAddr(ctx, c.Host.ID(), circuit2); err != nil {
		t.Fatalf("A dial circuit2: %v", err)
	}

	// Two Limited (relay-terminated) connections from A to C.
	connDeadline := time.Now().Add(20 * time.Second)
	for {
		conns := a.Host.Network().ConnsToPeer(c.Host.ID())
		if len(conns) >= 2 && a.Host.Network().Connectedness(c.Host.ID()) == network.Limited {
			break
		}
		if time.Now().After(connDeadline) {
			t.Fatalf("A did not establish 2 circuit conns to C (got %d, connectedness=%v)",
				len(conns), a.Host.Network().Connectedness(c.Host.ID()))
		}
		time.Sleep(100 * time.Millisecond)
	}
	if a.isDirectlyConnected(c.Host.ID()) {
		t.Fatal("test accidentally established a direct A<->C connection (invariant violated)")
	}
	t.Logf("relay dual-path: A holds %d circuit connections to C", len(a.Host.Network().ConnsToPeer(c.Host.ID())))

	// Overlay handshake must converge (the control-plane SeqSync runs over one of
	// the circuit streams); gate the data-plane assertions on it like the
	// single-relay test does.
	for {
		poA, poC := a.peerObf(c.Host.ID()), c.peerObf(a.Host.ID())
		_, busyA := a.rekeyPeers.Load(c.Host.ID())
		_, busyC := c.rekeyPeers.Load(a.Host.ID())
		if !busyA && !busyC && a.isPeerReady(c.Host.ID()) && c.isPeerReady(a.Host.ID()) &&
			poA != nil && poC != nil && poA.negotiated && poC.negotiated &&
			bytes.Equal(poA.txKey, poC.rxKey) && bytes.Equal(poC.txKey, poA.rxKey) {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("relay dual-path handshake did not converge", ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}

	// Drive the multipath path-repair + per-connection stream pinning that F1/F2
	// corrected. repairMultipathPaths keeps both circuit addresses;
	// EnsureStreamsOnAllConns pins a stream on every relay conn so both circuits
	// participate.
	streamDeadline := time.Now().Add(20 * time.Second)
	var psA, psC *PeerStreams
	for {
		a.repairMultipathPaths(c.Host.ID())
		c.repairMultipathPaths(a.Host.ID())
		a.Dispatcher.EnsureStreamsOnAllConns(c.Host.ID())
		c.Dispatcher.EnsureStreamsOnAllConns(a.Host.ID())
		psA = a.Dispatcher.GetPeerStreams(c.Host.ID())
		psC = c.Dispatcher.GetPeerStreams(a.Host.ID())
		if psA != nil && psC != nil && len(psA.GetAllStreams()) >= 2 && len(psC.GetAllStreams()) >= 2 {
			break
		}
		if time.Now().After(streamDeadline) {
			t.Fatalf("multipath did not open >=2 relay streams per side (A=%d C=%d)",
				streamLen(psA), streamLen(psC))
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Logf("relay dual-path: A holds %d streams, C holds %d streams to each other",
		len(psA.GetAllStreams()), len(psC.GetAllStreams()))

	// Each stream must ride a DISTINCT relay connection (one through r1, one
	// through r2). Two streams on the same conn would be a dedup bug, not a win.
	assertDistinctRelayConns(t, psA.GetAllStreams(), "A")
	assertDistinctRelayConns(t, psC.GetAllStreams(), "C")

	// --- Data plane: a burst must flow intact across the 2-path relay set, both
	// directions. The collector reads each peer's TAP pipe; SendToPeer addresses
	// the peer by ID, so routing goes through the multipath PeerStreams. ---
	readerC := newFrameReader(pipeC)
	defer readerC.Close()
	readerA := newFrameReader(pipeA)
	defer readerA.Close()

	const frames = 32
	sendBurst := func(src, dst *Node, dstPipe *tap.MemTAP, reader *frameReader, srcIP, dstIP string, srcMAC, dstMAC net.HardwareAddr) {
		t.Helper()
		var payloads [][]byte
		var wires [][]byte
		for i := 0; i < frames; i++ {
			tag := fmt.Sprintf("MP_RELAY_%s_%d", src.Host.ID().ShortString(), i)
			payloads = append(payloads, []byte(tag))
			wires = append(wires, constructICMPv4PacketWithData(srcMAC, dstMAC, net.ParseIP(srcIP), net.ParseIP(dstIP), 8300+i, 1, payloads[i]))
		}
		coll := newConcurrentPayloadCollector(reader, payloads)
		sendAll := func() {
			for i := 0; i < frames; i++ {
				out := make([]byte, src.Packer.MaxPackedLen(len(wires[i])))
				seq := src.nextTxSeqID(dst.Host.ID())
				n, perr := src.Packer.Pack(seq, wires[i], out)
				if perr != nil {
					t.Fatalf("pack %d: %v", i, perr)
				}
				if err := src.Dispatcher.SendToPeer(ctx, dst.Host.ID(), out[:n]); err != nil {
					t.Fatalf("send %d: %v", i, err)
				}
			}
		}
		sendAll()
		if !coll.waitUntil(payloads, 15*time.Second) {
			// Tolerate a single cold-start drop on the very first frame (the
			// receiver's stream handler is still warming up): resend the still
			// missing frames once.
			for _, m := range coll.missing(payloads) {
				for i := 0; i < frames; i++ {
					if bytes.Equal(payloads[i], []byte(m)) {
						out := make([]byte, src.Packer.MaxPackedLen(len(wires[i])))
						seq := src.nextTxSeqID(dst.Host.ID())
						n, _ := src.Packer.Pack(seq, wires[i], out)
						_ = src.Dispatcher.SendToPeer(ctx, dst.Host.ID(), out[:n])
						break
					}
				}
			}
			if !coll.waitUntil(payloads, 15*time.Second) {
				t.Fatalf("%s->%s relay dual-path delivered only %d/%d frames; missing %v",
					src.Host.ID().ShortString(), dst.Host.ID().ShortString(),
					countSeen(coll, payloads), frames, coll.missing(payloads))
			}
		}
		t.Logf("%s->%s: %d/%d frames delivered intact across the 2-path relay set",
			src.Host.ID().ShortString(), dst.Host.ID().ShortString(), frames, frames)
	}

	// Warm up both directions' stream paths before the burst so the very first
	// data frame is not lost to a not-yet-ready receiver handler.
	waitStreamReady(t, a, c)
	waitStreamReady(t, c, a)

	sendBurst(a, c, pipeC, readerC, "10.0.0.1", "10.0.0.3", testMACA, testMACC)
	sendBurst(c, a, pipeA, readerA, "10.0.0.3", "10.0.0.1", testMACC, testMACA)
}

func streamLen(ps *PeerStreams) int {
	if ps == nil {
		return 0
	}
	return len(ps.GetAllStreams())
}

// assertDistinctRelayConns verifies the supplied streams span more than one
// underlying relay connection. A single relay circuit legitimately carries several
// logical streams (the peer's inbound + our outbound application stream, plus the
// control streams), so the assertion counts DISTINCT connections, not streams: F2
// requires the multipath set to span >=2 circuits (two relays), not two logical
// streams multiplexed onto one pipe.
func assertDistinctRelayConns(t *testing.T, streams []network.Stream, side string) {
	t.Helper()
	seen := make(map[string]bool)
	for _, s := range streams {
		if s == nil || s.Conn() == nil {
			t.Fatalf("%s: a registered stream has no underlying connection", side)
		}
		seen[s.Conn().ID()] = true
	}
	if len(seen) < 2 {
		t.Fatalf("%s: %d streams span only %d distinct relay connection(s); F2 requires >=2 circuits", side, len(streams), len(seen))
	}
}
