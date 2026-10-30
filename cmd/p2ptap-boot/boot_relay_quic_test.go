package main

import (
	"bytes"
	"context"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	quict "github.com/libp2p/go-libp2p/p2p/transport/quic"

	"p2ptap/pkg/routing"
	"p2ptap/pkg/version"
)

// TestBootRelayUplinkQUIC reproduces the PRODUCTION transport for the node→boot
// relay uplink. The TCP-based TestBootRelayTicketFastPath passes, but
// production nodes reach the boot over QUIC (the boot listens on /quic-v1). If
// frames a QUIC client writes never reach the boot's read loop, this test
// reproduces the live "relay data path carries zero bytes" failure and localizes
// it to the QUIC transport rather than to node-side logic.
//
// The client here mirrors node.bootRelayWriteLoop exactly: after auth it opens
// the /p2ptap/boot-relay/1.0.0 uplink and writes a self-addressed loopback
// heartbeat frame (finalDst == srcPeer == self). The production writeLoop does
// this every 15s; the boot's makeBootRelayHandler read loop must observe it and
// bump framesFromClients.
func TestBootRelayUplinkQUIC(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	psk := "quic-repro-network-secret"
	netA := routing.NetworkIDFromPSK(psk)
	entries := []pskEntry{
		{hash: computePSKHash(psk), netID: netA, masterKey: routing.RelayTicketMasterKey(psk)},
	}

	// Boot over QUIC, exactly like production (makeBootRelayHandler + auth gate).
	bootH, err := libp2p.New(
		libp2p.Transport(quict.NewTransport),
		libp2p.ListenAddrStrings("/ip4/127.0.0.1/udp/0/quic-v1"),
	)
	if err != nil {
		t.Fatalf("boot host: %v", err)
	}
	defer bootH.Close()

	acl := newPSKACLFilter(true)
	rr := newRelayRouter(acl, true)
	hub := newPeekMapHub()
	bootH.SetStreamHandler(authProtocolID, func(s network.Stream) {
		handleAuthStream(s, entries, acl, bootH, hub, "quicboot")
	})
	bootH.SetStreamHandler(BootRelayProtocolID, makeBootRelayHandler(rr))

	// Client over QUIC.
	clientH, err := libp2p.New(
		libp2p.Transport(quict.NewTransport),
		libp2p.ListenAddrStrings("/ip4/127.0.0.1/udp/0/quic-v1"),
	)
	if err != nil {
		t.Fatalf("client host: %v", err)
	}
	defer clientH.Close()

	if err := clientH.Connect(ctx, peer.AddrInfo{ID: bootH.ID(), Addrs: bootH.Addrs()}); err != nil {
		t.Fatalf("client connect to boot: %v", err)
	}

	// Full-path auth: mode byte, challenge, HMAC response ‖ version record.
	as, err := clientH.NewStream(ctx, bootH.ID(), authProtocolID)
	if err != nil {
		t.Fatalf("auth stream: %v", err)
	}
	if _, err := as.Write([]byte{routing.RelayAuthModeFull}); err != nil {
		t.Fatalf("auth mode write: %v", err)
	}
	challenge := make([]byte, routing.RelayAuthChallengeLen)
	if _, err := io.ReadFull(as, challenge); err != nil {
		t.Fatalf("auth challenge read: %v", err)
	}
	if challenge[0] != routing.RelayChallengeByte {
		t.Fatalf("challenge prefix %#x, want %#x", challenge[0], routing.RelayChallengeByte)
	}
	authResp := routing.RelayAuthResponse(computePSKHash(psk), challenge)
	var recBuf bytes.Buffer
	_ = version.CurrentRecord().WriteRecord(&recBuf)
	buf := make([]byte, 0, len(authResp)+recBuf.Len())
	buf = append(buf, authResp[:]...)
	buf = append(buf, recBuf.Bytes()...)
	if _, err := as.Write(buf); err != nil {
		t.Fatalf("auth response write: %v", err)
	}
	resp := make([]byte, 1)
	if _, err := io.ReadFull(as, resp); err != nil {
		t.Fatalf("auth response byte read: %v", err)
	}
	if resp[0] != 0x01 {
		t.Fatalf("auth rejected (resp=%#x) — boot and client PSK mismatch", resp[0])
	}
	_ = as.Close()
	t.Log("✓ full-path auth succeeded over QUIC")
	t.Logf("IsAuthenticated(client)=%v", acl.IsAuthenticated(clientH.ID()))

	// Open the boot-relay uplink, exactly like node.openBootRelayUplink.
	up, err := clientH.NewStream(ctx, bootH.ID(), BootRelayProtocolID)
	if err != nil {
		t.Fatalf("boot-relay uplink stream: %v", err)
	}
	defer up.Close()

	// If the boot rejected the uplink (auth gate), it closes the stream: a read
	// returns EOF almost immediately. Detect that to distinguish "rejected" from
	// "handler never ran".
	_ = up.SetReadDeadline(time.Now().Add(3 * time.Second))
	probe := make([]byte, 1)
	if _, rerr := up.Read(probe); rerr != nil {
		t.Logf("uplink probe read error=%v (nil => boot still holds it open; EOF/timeout => boot closed or idle)", rerr)
	} else {
		t.Log("uplink probe read 1 byte (unexpected)")
	}

	// Wait for the boot handler to register the client (has_boot_relay true).
	deadline := time.Now().Add(5 * time.Second)
	for {
		rr.mu.RLock()
		_, ok := rr.clientStreams[clientH.ID()]
		rr.mu.RUnlock()
		if ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("client uplink never registered at boot over QUIC")
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Log("✓ client uplink registered at boot over QUIC")

	// Write a self-addressed heartbeat, mirroring node.bootRelayWriteLoop.
	hb, err := routing.PackBootRelayFrame(netA, routing.BootRelayKindControl, "", clientH.ID(), clientH.ID(), 1, []byte("ping"))
	if err != nil {
		t.Fatalf("pack heartbeat: %v", err)
	}
	_ = up.SetWriteDeadline(time.Now().Add(3 * time.Second))
	if err := writeFrame(up, hb); err != nil {
		t.Fatalf("write heartbeat over QUIC: %v", err)
	}

	// Wait for the boot's read loop to observe the frame.
	deadline = time.Now().Add(5 * time.Second)
	for {
		if atomic.LoadUint64(&rr.framesFromClients) > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("boot read 0 frames from QUIC client uplink — heartbeat NOT delivered (production matches: frames_up=0)")
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Logf("✓ boot read %d frame(s) from QUIC client uplink", atomic.LoadUint64(&rr.framesFromClients))
}
