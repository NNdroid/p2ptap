package main

import (
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/libp2p/go-libp2p/core/test"

	"p2ptap/pkg/routing"
)

// --- relayRouter.route unit tests ------------------------------------------
//
// relayRouter.route is the single choke point that decides whether a boot-relay
// frame is delivered to a locally attached client or pushed onto the boot-relay
// backbone. The relay-over-backbone topology stays loop-free only because TWO
// asymmetries hold in this one function:
//
//  1. A frame that arrived FROM the backbone is local-delivery-only.
//  2. A self-addressed uplink frame is delivered locally but never flooded.
//
// Asymmetry 1 caps every backbone frame at exactly one hop; asymmetry 2 is what
// stops a client from injecting a frame that every peer boot re-delivers back to
// the sender.
//
// Both are asserted against fakeStream (mesh_test.go), which counts every byte
// written, so a regression that re-floods a frame shows up as a write count of
// 2 instead of 1 rather than as a silent connectivity change.

func newTestRelayRouter(t *testing.T) (*relayRouter, *pskACLFilter) {
	t.Helper()
	acl := newPSKACLFilter(true)
	return newRelayRouter(acl, true), acl
}

func packTestFrame(t *testing.T, netID string, kind byte, proto protocol.ID,
	finalDst, src peer.ID, ttl uint8, payload []byte) []byte {
	t.Helper()
	frame, err := routing.PackBootRelayFrame(netID, kind, proto, finalDst, src, ttl, payload)
	if err != nil {
		t.Fatalf("PackBootRelayFrame: %v", err)
	}
	return frame
}

// TestRelayRouterEchoesUplinkHeartbeat locks the second asymmetry: a client's
// own loopback heartbeat (finalDst == srcPeer == the sender) is handed back to
// that client's uplink and is NEVER placed on the backbone.
//
// Replaying this BEFORE the fix would fail: route() returned at
// `finalDst == srcPeer` ahead of the local-delivery block, so the heartbeat was
// dropped and the client's downlink reader never saw a byte. The node sizes its
// downlink read deadline at 4x the 15s heartbeat expecting exactly this echo, so
// the drop silently capped every boot-relay uplink at 60 seconds.
func TestRelayRouterEchoesUplinkHeartbeat(t *testing.T) {
	rr, acl := newTestRelayRouter(t)
	netID := "test-net"

	client := test.RandPeerIDFatal(t)
	acl.AddAuthenticated(client, netID)
	uplink := &fakeStream{}
	rr.registerClient(client, uplink)

	meshX := &fakeStream{}
	rr.registerMesh(test.RandPeerIDFatal(t), meshX)

	frame := packTestFrame(t, netID, routing.BootRelayKindControl, "", client, client, 1, []byte("ping"))
	rr.route(frame, false, client)

	if got := uplink.count(); got != 1 {
		t.Fatalf("self-addressed heartbeat must be delivered to its own client once, got %d writes", got)
	}
	// The record is the wire form: a 4-byte length prefix followed by the
	// frame, so the echo must be the frame body with that prefix prefixed.
	if got := uplink.written(0); len(got) != len(frame)+4 || string(got[4:]) != string(frame) {
		t.Fatalf("echoed heartbeat must be the unmodified frame (got %d bytes, want %d + 4-byte prefix)",
			len(got), len(frame))
	}
	if meshX.count() != 0 {
		t.Fatalf("heartbeat must not be placed on the backbone, got %d writes", meshX.count())
	}
}

// TestRelayRouterNeverFloodsSelfAddressedFrames is the loop guard side of the
// same change: a self-addressed frame is dropped from the flood, not turned
// into backbone traffic. Without the `finalDst == srcPeer` return the frame
// would be written to every peer boot and come back around the ring.
func TestRelayRouterNeverFloodsSelfAddressedFrames(t *testing.T) {
	rr, acl := newTestRelayRouter(t)
	netID := "test-net"

	client := test.RandPeerIDFatal(t)
	acl.AddAuthenticated(client, netID)
	// The client's uplink is NOT registered: this exercises the branch where the
	// frame cannot be delivered locally and must therefore be dropped outright.
	meshX := &fakeStream{}
	meshY := &fakeStream{}
	rr.registerMesh(test.RandPeerIDFatal(t), meshX)
	rr.registerMesh(test.RandPeerIDFatal(t), meshY)

	frame := packTestFrame(t, netID, routing.BootRelayKindData, "", client, client, 5, []byte("loop"))
	rr.route(frame, false, client)

	if meshX.count() != 0 || meshY.count() != 0 {
		t.Fatalf("self-addressed frame must not be flooded (X=%d Y=%d writes)",
			meshX.count(), meshY.count())
	}
}

// TestRelayRouterBackboneFramesNeverReflooded locks the first asymmetry. A frame
// that arrived over the backbone is delivered to a local client at most once and
// is never pushed back out, which is what bounds the relay to one backbone hop
// even in a full mesh of boots.
func TestRelayRouterBackboneFramesNeverReflooded(t *testing.T) {
	rr, acl := newTestRelayRouter(t)
	netID := "test-net"

	client := test.RandPeerIDFatal(t)
	acl.AddAuthenticated(client, netID)
	downlink := &fakeStream{}
	rr.registerClient(client, downlink)

	meshX := &fakeStream{}
	meshY := &fakeStream{}
	rr.registerMesh(test.RandPeerIDFatal(t), meshX)
	rr.registerMesh(test.RandPeerIDFatal(t), meshY)

	remoteOrigin := test.RandPeerIDFatal(t)
	acl.AddAuthenticated(remoteOrigin, netID)
	frame := packTestFrame(t, netID, routing.BootRelayKindData, "", client, remoteOrigin, 5, []byte("data"))
	rr.route(frame, true, remoteOrigin)

	if downlink.count() != 1 {
		t.Fatalf("local client must receive the backbone frame once, got %d writes", downlink.count())
	}
	if meshX.count() != 0 || meshY.count() != 0 {
		t.Fatalf("backbone frame must never be re-flooded (X=%d Y=%d writes)",
			meshX.count(), meshY.count())
	}
}

// TestRelayRouterFloodsUplinkDataAcrossBackbone is the positive control: a real
// data frame from a local client with no local destination must go out to every
// peer boot, so that a frame can reach a client attached to a different boot.
func TestRelayRouterFloodsUplinkDataAcrossBackbone(t *testing.T) {
	rr, acl := newTestRelayRouter(t)
	netID := "test-net"

	sender := test.RandPeerIDFatal(t)
	acl.AddAuthenticated(sender, netID)
	rr.registerClient(sender, &fakeStream{})
	// The destination is NOT a local client of this boot.
	dest := test.RandPeerIDFatal(t)

	meshX := &fakeStream{}
	meshY := &fakeStream{}
	rr.registerMesh(test.RandPeerIDFatal(t), meshX)
	rr.registerMesh(test.RandPeerIDFatal(t), meshY)

	frame := packTestFrame(t, netID, routing.BootRelayKindData, "", dest, sender, 2, []byte("data"))
	rr.route(frame, false, sender)

	if meshX.count() != 1 || meshY.count() != 1 {
		t.Fatalf("data frame must be flooded to both peer boots (X=%d Y=%d writes)",
			meshX.count(), meshY.count())
	}
	// The flooded envelope must be forwarded verbatim: the destination boot
	// re-reads the length prefix, netID, kind, proto and TTL from it.
	if got := meshX.written(0); len(got) != len(frame)+4 || string(got[4:]) != string(frame) {
		t.Fatalf("flooded frame must be forwarded verbatim (got %d bytes, want %d + 4-byte prefix)",
			len(got), len(frame))
	}
}

// TestRelayRouterDropsSpoofedUplinkSource guards the anti-spoof check that must
// stay ahead of local delivery: a client may not claim a srcPeer other than the
// transport-authenticated peer, or it could forge traffic into the network as a
// legitimate member.
func TestRelayRouterDropsSpoofedUplinkSource(t *testing.T) {
	rr, acl := newTestRelayRouter(t)
	netID := "test-net"

	sender := test.RandPeerIDFatal(t)
	acl.AddAuthenticated(sender, netID)
	uplink := &fakeStream{}
	rr.registerClient(sender, uplink)

	victim := test.RandPeerIDFatal(t)
	acl.AddAuthenticated(victim, netID)
	victimStream := &fakeStream{}
	rr.registerClient(victim, victimStream)

	// srcPeer claims to be `victim` while the stream is authenticated as `sender`.
	frame := packTestFrame(t, netID, routing.BootRelayKindData, "", victim, victim, 2, []byte("forge"))
	rr.route(frame, false, sender)

	if uplink.count() != 0 || victimStream.count() != 0 {
		t.Fatalf("spoofed srcPeer frame must be dropped (sender=%d victim=%d writes)",
			uplink.count(), victimStream.count())
	}
}
