package main

import (
	"bytes"
	"context"
	"io"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"

	"p2ptap/pkg/routing"
	"p2ptap/pkg/version"
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
		{hash: computePSKHash(psk1), netID: netA, masterKey: routing.RelayTicketMasterKey(psk1)},
		{hash: computePSKHash(psk2), netID: netX, masterKey: routing.RelayTicketMasterKey(psk2)},
	}

	bootA := startRelayBoot(t, "bootA", entries)
	bootB := startRelayBoot(t, "bootB", entries)

	// Mark each boot as a mesh peer of the other so the backbone handler's
	// mesh gate lets their uplinks through. Must happen before the uplink
	// loops start (mirrors production: markMesh at startup, uplinks after).
	bootA.hub.markMesh(bootB.h.ID())
	bootB.hub.markMesh(bootA.h.ID())

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
	nodeA, _ := connectRelayClient(t, bootA.h, psk1)
	nodeB, _ := connectRelayClient(t, bootB.h, psk1)
	nodeX, _ := connectRelayClient(t, bootA.h, psk2)

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

	// --- Contract #3: loop guard — A sends to itself ---
	// The frame IS echoed back to nodeA (that is the uplink heartbeat the node's
	// downlink reader treats as its half-open detector: bootRelayWriteLoop sends
	// finalDst==srcPeer==self every 15s and the reader's 60s deadline assumes the
	// boot sends a byte back at least that often). What must NOT happen is that
	// the frame is flooded to the backbone: nodeB sits on a different boot, so it
	// can only see the frame if bootA pushed it onto the mesh.
	if err := nodeA.send(nodeA.h.ID(), netA, []byte("loop")); err != nil {
		t.Fatalf("nodeA self-send: %v", err)
	}
	r3, ok := nodeA.recv(3 * time.Second)
	if !ok {
		t.Fatal("Contract #3 FAILED: self-destined heartbeat was not echoed back to its sender")
	}
	if r3.finalDst != nodeA.h.ID() || r3.srcPeer != nodeA.h.ID() {
		t.Fatalf("Contract #3 FAILED: echo routing wrong (finalDst=%s srcPeer=%s, want A/A)",
			r3.finalDst.ShortString(), r3.srcPeer.ShortString())
	}
	_, leaked := nodeB.recv(3 * time.Second)
	if leaked {
		t.Fatal("Contract #3 FAILED: self-destined frame was flooded across the backbone (loop guard broken)")
	}
	t.Log("✓ Contract #3: self-destined frame echoed locally to its sender and never flooded")
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
	hub := newPeekMapHub()

	h.SetStreamHandler(authProtocolID, func(s network.Stream) {
		handleAuthStream(s, entries, acl, h, hub, name)
	})
	h.SetStreamHandler(BootRelayProtocolID, makeBootRelayHandler(rr))
	h.SetStreamHandler(BootRelayBackboneProtocolID, makeBootRelayBackboneHandler(rr, hub))
	return &relayBoot{h: h, rr: rr, hub: hub}
}

type relayBoot struct {
	h   host.Host
	rr  *relayRouter
	hub *peekMapHub
}

// connectRelayClient spins up a libp2p host, authenticates against boot with the
// given PSK via the FULL challenge-response path, then opens a persistent
// /p2ptap/boot-relay/1.0.0 uplink and starts a reader goroutine for downlink
// frames. It returns the client and the session ticket the boot minted (so a
// later test can exercise the fast ticket path).
func connectRelayClient(t *testing.T, boot host.Host, psk string) (*relayClient, []byte) {
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

	as, err := h.NewStream(ctx, boot.ID(), authProtocolID)
	if err != nil {
		t.Fatalf("auth stream: %v", err)
	}
	// New full-duplex protocol: send the mode byte FIRST (the boot sends its
	// challenge at t=0 too), then read the challenge and answer with
	// HMAC-SHA256(token, challenge) ‖ nodeRecord in one write.
	if _, err := as.Write([]byte{routing.RelayAuthModeFull}); err != nil {
		t.Fatalf("auth write mode: %v", err)
	}
	challenge := make([]byte, routing.RelayAuthChallengeLen)
	if _, err := io.ReadFull(as, challenge); err != nil {
		t.Fatalf("auth read challenge: %v", err)
	}
	if challenge[0] != routing.RelayChallengeByte {
		t.Fatalf("auth challenge prefix = %#x, want %#x", challenge[0], routing.RelayChallengeByte)
	}
	authResp := routing.RelayAuthResponse(computePSKHash(psk), challenge)
	var recBuf bytes.Buffer
	_ = version.CurrentRecord().WriteRecord(&recBuf)
	buf := make([]byte, 0, len(authResp)+recBuf.Len())
	buf = append(buf, authResp[:]...)
	buf = append(buf, recBuf.Bytes()...)
	if _, err := as.Write(buf); err != nil {
		t.Fatalf("auth write response: %v", err)
	}
	resp := make([]byte, 1)
	if _, err := io.ReadFull(as, resp); err != nil {
		t.Fatalf("auth read response: %v", err)
	}
	if resp[0] != 0x01 {
		t.Fatalf("auth rejected for PSK (resp=%#x) — boot and client PSK mismatch", resp[0])
	}
	// The boot mints a fresh ticket on success; read it for later reuse.
	ticket := make([]byte, routing.RelayTicketLen)
	if _, err := io.ReadFull(as, ticket); err != nil {
		t.Fatalf("auth read ticket: %v", err)
	}
	_ = as.Close()

	c := finishRelayClient(t, h, boot, ctx)
	return c, ticket
}

// connectRelayClientTicket authenticates by replaying a cached session ticket
// (the fast path), expecting the boot to accept it without a challenge-response
// round-trip. It returns the client and the freshly minted replacement ticket.
func connectRelayClientTicket(t *testing.T, boot host.Host, psk string, ticket []byte) (*relayClient, []byte) {
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

	as, err := h.NewStream(ctx, boot.ID(), authProtocolID)
	if err != nil {
		t.Fatalf("auth stream: %v", err)
	}
	// Send [0x01] ‖ ticket ‖ nodeRecord in one write (the boot reads the ticket,
	// then the record, then decides).
	var recBuf bytes.Buffer
	_ = version.CurrentRecord().WriteRecord(&recBuf)
	buf := make([]byte, 0, 1+routing.RelayTicketLen+recBuf.Len())
	buf = append(buf, routing.RelayAuthModeTicket)
	buf = append(buf, ticket...)
	buf = append(buf, recBuf.Bytes()...)
	if _, err := as.Write(buf); err != nil {
		t.Fatalf("auth write ticket: %v", err)
	}
	// The boot sent its challenge at t=0; read and discard it (kept only for the
	// fallback, which we do not exercise here).
	challenge := make([]byte, routing.RelayAuthChallengeLen)
	if _, err := io.ReadFull(as, challenge); err != nil {
		t.Fatalf("auth read challenge: %v", err)
	}
	if challenge[0] != routing.RelayChallengeByte {
		t.Fatalf("auth challenge prefix = %#x, want %#x", challenge[0], routing.RelayChallengeByte)
	}
	resp := make([]byte, 1)
	if _, err := io.ReadFull(as, resp); err != nil {
		t.Fatalf("auth read response: %v", err)
	}
	if resp[0] != 0x01 {
		t.Fatalf("ticket fast path rejected (resp=%#x) — want 0x01", resp[0])
	}
	newTicket := make([]byte, routing.RelayTicketLen)
	if _, err := io.ReadFull(as, newTicket); err != nil {
		t.Fatalf("auth read new ticket: %v", err)
	}
	_ = as.Close()

	c := finishRelayClient(t, h, boot, ctx)
	return c, newTicket
}

// finishRelayClient opens the persistent boot-relay uplink and starts the
// downlink reader, mirroring node.openBootRelayUplink but driving the protocol
// directly to exercise it without the full Node.
func finishRelayClient(t *testing.T, h host.Host, boot host.Host, ctx context.Context) *relayClient {
	t.Helper()
	up, err := h.NewStream(ctx, boot.ID(), BootRelayProtocolID)
	if err != nil {
		t.Fatalf("boot-relay uplink stream: %v", err)
	}
	c := &relayClient{h: h, bootID: boot.ID(), uplink: up}
	c.startRx()
	return c
}

// TestBootRelayTicketFastPath locks the session-ticket fast path: a full
// handshake mints a ticket, and replaying that ticket authenticates a new
// client without a challenge-response round-trip (the boot answers 0x01 on the
// first response byte, and the new client's uplink works end to end).
func TestBootRelayTicketFastPath(t *testing.T) {
	psk := "fast-path-network-secret"
	netA := routing.NetworkIDFromPSK(psk)
	entries := []pskEntry{
		{hash: computePSKHash(psk), netID: netA, masterKey: routing.RelayTicketMasterKey(psk)},
	}
	boot := startRelayBoot(t, "bootFast", entries)

	// Full handshake mints a ticket.
	clientA, ticket := connectRelayClient(t, boot.h, psk)
	if len(ticket) != routing.RelayTicketLen {
		t.Fatalf("boot minted ticket of %d bytes, want %d", len(ticket), routing.RelayTicketLen)
	}
	t.Log("✓ full handshake minted a session ticket")

	// Replay the ticket on a fresh client: boot must accept it (0x01) and mint a
	// replacement.
	clientB, newTicket := connectRelayClientTicket(t, boot.h, psk, ticket)
	if len(newTicket) != routing.RelayTicketLen {
		t.Fatalf("boot minted replacement ticket of %d bytes", len(newTicket))
	}
	t.Log("✓ ticket fast path authenticated a new client with one round-trip")

	// The replacement ticket must itself verify (it is a fresh, valid ticket).
	if !routing.VerifyRelayTicket(routing.RelayTicketMasterKey(psk), newTicket, time.Now()) {
		t.Fatal("replacement ticket must verify under the network's master key")
	}

	// End-to-end: clientB's uplink must actually carry frames.
	if err := clientA.send(clientB.h.ID(), netA, []byte("ticket-fast-path")); err != nil {
		t.Fatalf("clientA send: %v", err)
	}
	r, ok := clientB.recv(15 * time.Second)
	if !ok {
		t.Fatal("clientB did not receive a frame over its ticket-authenticated uplink")
	}
	if string(r.payload) != "ticket-fast-path" {
		t.Fatalf("payload corrupted (got %q)", r.payload)
	}
	t.Log("✓ ticket-authenticated uplink carried a frame end to end")
}

// relayClient is a minimal node-side counterpart used only to drive the
// boot-relay wire protocol in tests. It writes length-prefixed frames (as the
// production Node does) and reads length-prefixed downlink frames (as the
// production Node's handleBootRelayDownlink does).
type relayClient struct {
	h      host.Host
	bootID peer.ID
	uplink network.Stream
	rxCh   chan relayRx
	done   chan struct{}
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
