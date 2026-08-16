package main

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"

	"p2ptap/pkg/routing"
)

// --- relay-over-backbone integration test ----------------------------------
//
// This is the acceptance test for "relay-over-backbone": two boot nodes meshed
// over the boot-relay backbone so that two peers in the SAME PSK network but
// attached to DIFFERENT boots can still exchange data-plane frames (the gap
// Circuit Relay v2 per-boot cannot span). It uses REAL libp2p hosts for both
// boots and both node-like clients and drives the real /p2ptap/boot-relay/1.0.0
// and /p2ptap/boot-relay-backbone/1.0.0 protocols end to end.
//
// Topology:
//
//	nodeA(psk1) ── bootA ══ backbone ══ bootB ── nodeB(psk1)
//	nodeX(psk2) ── bootA
//
// Contracts locked:
//  1. nodeA -> nodeB frame is delivered across the backbone (finalDst/srcPeer
//     preserved, inner payload intact).
//  2. A frame from nodeX (a DIFFERENT PSK network) destined for nodeB is DROPPED
//     at the destination boot (network isolation), never reaching nodeB.
//  3. A frame whose finalDst == its own source is dropped (loop guard).
//
// Replaying this test BEFORE the length-prefix fix in relayRouter.route would
// fail contract #1 (the raw write desynced the destination's ReadFrame reader).
func TestBootRelayOverBackboneIntegration(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	psk1 := "net-alpha-shared-secret"
	psk2 := "net-beta-shared-secret"
	netA := routing.NetworkIDFromPSK(psk1)
	netX := routing.NetworkIDFromPSK(psk2)

	// Two PSKs so the boot accepts BOTH networks; the auth handler binds each
	// client to the netID of the PSK it presents.
	entries := []pskEntry{
		{hash: computePSKHash(psk1), netID: netA},
		{hash: computePSKHash(psk2), netID: netX},
	}

	bootA := startRelayBoot(t, "bootA", entries)
	bootB := startRelayBoot(t, "bootB", entries)

	// Bring the relay-over-backbone backbone up in BOTH directions (full mesh).
	// Exercise the PRODUCTION uplink loop (it retries with backoff and the
	// pre-dial jitter in runBootRelayMeshUplink breaks the simultaneous-dial
	// TLS collision), rather than the bare inner function which has no retry.
	go bootRelayMeshUplinkLoop(ctx, bootA.h, bootA.rr, peer.AddrInfo{ID: bootB.h.ID(), Addrs: bootB.h.Addrs()})
	go bootRelayMeshUplinkLoop(ctx, bootB.h, bootB.rr, peer.AddrInfo{ID: bootA.h.ID(), Addrs: bootA.h.Addrs()})

	// The flood path reads r.meshStreams, populated by runBootRelayMeshUplink on
	// each side. Wait for both directions before sending.
	waitBackboneRelay := func(rr *relayRouter, want peer.ID, label string) {
		deadline := time.Now().Add(20 * time.Second)
		for {
			rr.mu.RLock()
			_, ok := rr.meshStreams[want]
			rr.mu.RUnlock()
			if ok {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s: backbone relay peer %s never registered", label, want.ShortString())
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	waitBackboneRelay(bootA.rr, bootB.h.ID(), "bootA")
	waitBackboneRelay(bootB.rr, bootA.h.ID(), "bootB")
	t.Log("✓ boot-relay backbone established in both directions")

	// Attach clients: A and B in netA (different boots), X in netX (bootA).
	nodeA := connectRelayClient(t, bootA.h, psk1)
	nodeB := connectRelayClient(t, bootB.h, psk1)
	nodeX := connectRelayClient(t, bootA.h, psk2)

	// Wait for each client's boot-relay uplink to be registered at its boot
	// (relayRouter.clientStreams), and for nodeB at bootB specifically.
	waitClientUplink := func(rr *relayRouter, p peer.ID, label string) {
		deadline := time.Now().Add(20 * time.Second)
		for {
			rr.mu.RLock()
			_, ok := rr.clientStreams[p]
			rr.mu.RUnlock()
			if ok {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s: client %s uplink never registered at boot", label, p.ShortString())
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	waitClientUplink(bootA.rr, nodeA.h.ID(), "bootA<-A")
	waitClientUplink(bootA.rr, nodeX.h.ID(), "bootA<-X")
	waitClientUplink(bootB.rr, nodeB.h.ID(), "bootB<-B")
	t.Log("✓ all client boot-relay uplinks registered")

	// --- Contract #1: cross-boot, same-network relay A -> B ---
	payload1 := []byte("hello-across-the-backbone")
	if err := nodeA.send(nodeB.h.ID(), netA, payload1); err != nil {
		t.Fatalf("nodeA send to nodeB: %v", err)
	}
	r1, ok := nodeB.recv(15 * time.Second)
	if !ok {
		t.Fatal("Contract #1 FAILED: nodeB did not receive the frame relayed over the boot backbone")
	}
	if r1.finalDst != nodeB.h.ID() || r1.srcPeer != nodeA.h.ID() {
		t.Fatalf("Contract #1 FAILED: routing wrong (finalDst=%s srcPeer=%s, want B/A)",
			r1.finalDst.ShortString(), r1.srcPeer.ShortString())
	}
	if string(r1.payload) != string(payload1) {
		t.Fatalf("Contract #1 FAILED: payload corrupted (got %q want %q)", r1.payload, payload1)
	}
	t.Log("✓ Contract #1: frame relayed A→B across the boot backbone (same PSK network)")

	// --- Contract #2: cross-network isolation — X(psk2) -> B(psk1) dropped ---
	if err := nodeX.send(nodeB.h.ID(), netX, []byte("must-not-leak")); err != nil {
		t.Fatalf("nodeX send to nodeB: %v", err)
	}
	_, ok = nodeB.recv(3 * time.Second)
	if ok {
		t.Fatal("Contract #2 FAILED: cross-network frame leaked to nodeB — PSK isolation broken")
	}
	t.Log("✓ Contract #2: cross-network frame correctly dropped (PSK isolation enforced)")

	// --- Contract #3: loop guard — A sends to itself, dropped ---
	if err := nodeA.send(nodeA.h.ID(), netA, []byte("loop")); err != nil {
		t.Fatalf("nodeA self-send: %v", err)
	}
	_, ok = nodeA.recv(3 * time.Second)
	if ok {
		t.Fatal("Contract #3 FAILED: self-destined frame echoed back to sender (loop guard broken)")
	}
	t.Log("✓ Contract #3: self-destined frame dropped (loop guard)")
}

// startRelayBoot builds a real libp2p host wired with the boot-relay handlers
// (auth + boot-relay uplink + boot-relay backbone) and a multi-PSK ACL.
func startRelayBoot(t *testing.T, name string, entries []pskEntry) *relayBoot {
	t.Helper()
	h, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatalf("create boot host %s: %v", name, err)
	}
	t.Cleanup(func() { _ = h.Close() })

	acl := newPSKACLFilter(true) // PSK mode: every client must authenticate
	rr := newRelayRouter(acl, true)
	hub := newPeekMapHub() // only used by handleAuthStream's publishBootInfo

	h.SetStreamHandler(authProtocolID, func(s network.Stream) {
		handleAuthStream(s, entries, acl, h, hub, name)
	})
	h.SetStreamHandler(BootRelayProtocolID, makeBootRelayHandler(rr))
	h.SetStreamHandler(BootRelayBackboneProtocolID, makeBootRelayBackboneHandler(rr))
	return &relayBoot{h: h, rr: rr}
}

type relayBoot struct {
	h  host.Host
	rr *relayRouter
}

// connectRelayClient spins up a libp2p host, authenticates against boot with the
// given PSK, then opens a persistent /p2ptap/boot-relay/1.0.0 uplink and starts
// a reader goroutine for downlink frames.
func connectRelayClient(t *testing.T, boot host.Host, psk string) *relayClient {
	t.Helper()
	h, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatalf("create client host: %v", err)
	}
	t.Cleanup(func() { _ = h.Close() })

	ctx := context.Background()
	if err := h.Connect(ctx, peer.AddrInfo{ID: boot.ID(), Addrs: boot.Addrs()}); err != nil {
		t.Fatalf("client connect to boot %s: %v", boot.ID().ShortString(), err)
	}

	// PSK auth handshake: send the 32-byte hash token, expect a 1-byte 0x01.
	as, err := h.NewStream(ctx, boot.ID(), authProtocolID)
	if err != nil {
		t.Fatalf("auth stream: %v", err)
	}
	tok := computePSKHash(psk)
	if _, err := as.Write(tok[:]); err != nil {
		t.Fatalf("auth write token: %v", err)
	}
	resp := make([]byte, 1)
	if _, err := io.ReadFull(as, resp); err != nil {
		t.Fatalf("auth read response: %v", err)
	}
	if resp[0] != 0x01 {
		t.Fatalf("auth rejected for PSK (resp=%#x) — boot and client PSK mismatch", resp[0])
	}
	_ = as.Close()

	// Persistent boot-relay uplink (mirrors node.openBootRelayUplink, but here
	// we drive it directly to exercise the protocol without the full Node).
	up, err := h.NewStream(ctx, boot.ID(), BootRelayProtocolID)
	if err != nil {
		t.Fatalf("boot-relay uplink stream: %v", err)
	}
	c := &relayClient{h: h, bootID: boot.ID(), uplink: up}
	c.startRx()
	return c
}

// relayClient is a minimal node-side counterpart used only to drive the
// boot-relay wire protocol in tests. It writes length-prefixed frames (as the
// production Node does) and reads length-prefixed downlink frames (as the
// production Node's handleBootRelayDownlink does).
type relayClient struct {
	h       host.Host
	bootID  peer.ID
	uplink  network.Stream
	rxCh    chan relayRx
	done    chan struct{}
}

type relayRx struct {
	finalDst peer.ID
	srcPeer  peer.ID
	payload  []byte
}

func (c *relayClient) startRx() {
	c.rxCh = make(chan relayRx, 16)
	c.done = make(chan struct{})
	go func() {
		buf := make([]byte, 64*1024)
		for {
			n, err := readFrame(c.uplink, buf)
			if err != nil || n == 0 {
				return
			}
			_, _, _, finalDst, srcPeer, _, payload, uerr := routing.UnpackBootRelayFrame(buf[:n])
			if uerr != nil {
				continue
			}
			select {
			case c.rxCh <- relayRx{finalDst: finalDst, srcPeer: srcPeer, payload: payload}:
			case <-c.done:
				return
			}
		}
	}()
}

// send wraps payload in a routing.PackBootRelayFrame under netID and writes it
// length-prefixed to the boot-relay uplink (exactly what sendToPeerViaBootRelay
// produces, minus the end-to-end TAP seal — which is out of scope here).
func (c *relayClient) send(finalDst peer.ID, netID string, payload []byte) error {
	frame, err := routing.PackBootRelayFrame(netID, routing.BootRelayKindData, "", finalDst, c.h.ID(), routing.MaxRelayTTL, payload)
	if err != nil {
		return err
	}
	return writeFrame(c.uplink, frame)
}

func (c *relayClient) recv(timeout time.Duration) (relayRx, bool) {
	select {
	case r := <-c.rxCh:
		return r, true
	case <-time.After(timeout):
		return relayRx{}, false
	}
}
