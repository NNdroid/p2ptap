package main

import (
	"errors"
	"sync/atomic"
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/test"

	"p2ptap/pkg/routing"
)

// relayStream wraps fakeStream to add the two things relayRouter.route calls that
// fanout does not: Close (so a teardown can be observed) and an injectable write
// error (so the write-failure branch can be reached without a live libp2p host).
// fakeStream itself is left strict on purpose — it embeds a nil network.Stream so
// any accidental new dependency in fanout panics loudly instead of passing.
type relayStream struct {
	*fakeStream
	writeErr error
	closed   atomic.Bool
	attempts atomic.Int64
}

func (s *relayStream) Write(p []byte) (int, error) {
	s.attempts.Add(1)
	if s.writeErr != nil {
		return 0, s.writeErr
	}
	return s.fakeStream.Write(p)
}

func (s *relayStream) Close() error {
	s.closed.Store(true)
	return nil
}

// TestRelayRouterStaleUnregisterCannotEvictLiveMeshStream locks the guarded
// unregister on the mesh side. Both the dial side (runBootRelayMeshUplink) and
// the server side (makeBootRelayBackboneHandler) run in a reconnect loop, so a
// flapped backbone yields two concurrent handler instances for the same boot:
// the newcomer registers second and overwrites the map entry, then the stale
// instance finally errors out of its read loop — which can be up to a 10-minute
// read deadline later — and defers its unregister.
//
// Replaying this BEFORE the fix would fail: unregisterMesh deleted unconditionally,
// so the stale defer removed the LIVE stream's registration. route() then silently
// `continue`d past that boot and every frame destined for a client attached to it
// was dropped, until the stream timed out and re-registered — up to 10 minutes of
// one-directional blackhole in a multi-boot mesh.
func TestRelayRouterStaleUnregisterCannotEvictLiveMeshStream(t *testing.T) {
	rr, acl := newTestRelayRouter(t)
	netID := "test-net"

	sender := test.RandPeerIDFatal(t)
	acl.AddAuthenticated(sender, netID)
	rr.registerClient(sender, &relayStream{fakeStream: &fakeStream{}})
	dest := test.RandPeerIDFatal(t)

	meshBoot := test.RandPeerIDFatal(t)
	stale := &relayStream{fakeStream: &fakeStream{}}
	live := &relayStream{fakeStream: &fakeStream{}}
	rr.registerMesh(meshBoot, stale)
	rr.registerMesh(meshBoot, live)

	rr.unregisterMesh(meshBoot, stale) // must be a no-op

	frame := packTestFrame(t, netID, routing.BootRelayKindData, "", dest, sender, 2, []byte("data"))
	rr.route(frame, false, sender)

	if live.count() != 1 {
		t.Fatalf("live backbone stream must still receive the flood after a stale unregister, got %d writes",
			live.count())
	}
	if stale.count() != 0 {
		t.Fatalf("stale stream must not be written, got %d writes", stale.count())
	}
}

// TestRelayRouterMeshWriteFailureClosesAndUnregisters covers the second half of
// the same fix: when the flood write to a peer boot fails, the boot must both
// drop the stream from the flood set and close it. Unregistering alone left the
// REMOTE boot's handler for that stream parked in its read loop for up to 10
// minutes; closing is what makes the remote reader return and re-register.
func TestRelayRouterMeshWriteFailureClosesAndUnregisters(t *testing.T) {
	rr, acl := newTestRelayRouter(t)
	netID := "test-net"

	sender := test.RandPeerIDFatal(t)
	acl.AddAuthenticated(sender, netID)
	rr.registerClient(sender, &relayStream{fakeStream: &fakeStream{}})
	dest := test.RandPeerIDFatal(t)

	meshBoot := test.RandPeerIDFatal(t)
	broken := &relayStream{fakeStream: &fakeStream{}, writeErr: errors.New("backbone down")}
	rr.registerMesh(meshBoot, broken)

	frame := packTestFrame(t, netID, routing.BootRelayKindData, "", dest, sender, 2, []byte("data"))
	rr.route(frame, false, sender)

	if !broken.closed.Load() {
		t.Fatal("a failing backbone stream must be closed so the remote boot's reader returns")
	}
	if got := broken.attempts.Load(); got != 1 {
		t.Fatalf("the broken stream must have been attempted exactly once, got %d", got)
	}

	// It must be out of the flood set: a second frame must not be attempted on
	// the dead stream.
	rr.route(frame, false, sender)
	if got := broken.attempts.Load(); got != 1 {
		t.Fatalf("unregistered backbone stream must not receive further floods, got %d attempts", got)
	}
}

// TestRelayRouterMeshStreamsSnapshotIsLocked is a data-race regression test:
// route() used to read len(r.meshStreams) outside the RLock, which is an unlocked
// map read racing the register/unregister writers. The race detector flags the
// unlocked len() even though the snapshot loop right after it is properly locked.
func TestRelayRouterMeshStreamsSnapshotIsLocked(t *testing.T) {
	rr, acl := newTestRelayRouter(t)
	netID := "test-net"

	sender := test.RandPeerIDFatal(t)
	acl.AddAuthenticated(sender, netID)
	rr.registerClient(sender, &relayStream{fakeStream: &fakeStream{}})
	dest := peer.ID("12D3KooMeshDestSnapshotTestTargetPeerID")

	done := make(chan struct{})
	go func() {
		defer close(done)
		frame := packTestFrame(t, netID, routing.BootRelayKindData, "", dest, sender, 2, []byte("data"))
		for i := 0; i < 2000; i++ {
			rr.route(frame, false, sender)
		}
	}()

	for i := 0; i < 50; i++ {
		rr.registerMesh(test.RandPeerIDFatal(t), &relayStream{fakeStream: &fakeStream{}})
	}
	<-done
}
