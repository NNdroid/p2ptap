package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/test"
	"github.com/multiformats/go-multiaddr"
)

// --- parseMeshPeers ---------------------------------------------------------

// TestParseMeshPeersMergesAddrsAndSkipsSelf covers the two operational mistakes
// that would silently break a boot backbone:
//
//   - Listing one boot under several addresses (its QUIC *and* its TCP address is
//     the normal way to publish a boot) must yield ONE uplink. Two uplinks to the
//     same boot would duplicate every frame for that cluster's clients.
//   - Deploying the same -mesh string to every boot in the cluster means each
//     boot finds itself in its own list. That entry must be dropped instead of
//     becoming a self-dial that fails in the retry loop forever.
func TestParseMeshPeersMergesAddrsAndSkipsSelf(t *testing.T) {
	self := test.RandPeerIDFatal(t)
	other := test.RandPeerIDFatal(t)
	third := test.RandPeerIDFatal(t)

	spec := "" +
		"/ip4/203.0.113.7/udp/4001/quic-v1/p2p/" + other.String() + "," +
		"/ip4/203.0.113.7/tcp/4001/p2p/" + other.String() + "," + // same boot, 2nd addr
		" /ip4/198.51.100.9/tcp/4001/p2p/" + third.String() + " ," + // whitespace padded
		"/ip4/192.0.2.1/tcp/4001/p2p/" + self.String() + "," + // self -> skipped
		"/ip4/192.0.2.2/tcp/4001," + // no /p2p/ -> skipped
		"not-a-multiaddr," + // invalid -> skipped
		""

	got := parseMeshPeers(spec, self)

	if len(got) != 2 {
		t.Fatalf("expected 2 distinct peer boots, got %d: %+v", len(got), got)
	}
	// Order must follow first appearance so operators can reason about it.
	if got[0].ID != other {
		t.Fatalf("first entry should be %s, got %s", other.ShortString(), got[0].ID.ShortString())
	}
	if len(got[0].Addrs) != 2 {
		t.Fatalf("the two addresses of %s must merge into ONE AddrInfo with 2 addrs, got %d: %v",
			other.ShortString(), len(got[0].Addrs), got[0].Addrs)
	}
	if got[1].ID != third {
		t.Fatalf("second entry should be %s, got %s", third.ShortString(), got[1].ID.ShortString())
	}
	for _, ai := range got {
		if ai.ID == self {
			t.Fatalf("self (%s) must never appear in the mesh list", self.ShortString())
		}
	}

	if out := parseMeshPeers("", self); out != nil {
		t.Fatalf("empty spec must yield nil, got %+v", out)
	}
	if out := parseMeshPeers("   ,  ,", self); len(out) != 0 {
		t.Fatalf("blank spec must yield no peers, got %+v", out)
	}
}

// --- hub fanout / loop prevention ------------------------------------------

// fakeStream is the minimum network.Stream needed by peekMapHub.fanout, which
// only calls SetWriteDeadline and Write. Embedding the interface leaves every
// other method nil — any accidental new dependency in fanout will panic loudly
// in tests rather than pass silently.
type fakeStream struct {
	network.Stream
	mu     sync.Mutex
	writes [][]byte
}

func (f *fakeStream) Write(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := make([]byte, len(p))
	copy(cp, p)
	f.writes = append(f.writes, cp)
	return len(p), nil
}

func (f *fakeStream) SetWriteDeadline(time.Time) error { return nil }

func (f *fakeStream) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.writes)
}

// TestPeekMapHubBackboneIsLoopFree pins the forwarding asymmetry that keeps a
// full mesh of boots from circulating frames forever.
//
// A 3-boot full mesh with naive "exclude only the sender" forwarding loops:
// A->B, B->C (excludes only A), C->A (excludes only B), A->B, ... The fix is
// that a frame which ARRIVED FROM the backbone is delivered to local clients
// only, capping it at one backbone hop.
func TestPeekMapHubBackboneIsLoopFree(t *testing.T) {
	hub := newPeekMapHub()

	localA := test.RandPeerIDFatal(t)
	localB := test.RandPeerIDFatal(t)
	meshX := test.RandPeerIDFatal(t)
	meshY := test.RandPeerIDFatal(t)

	sA, sB, sX, sY := &fakeStream{}, &fakeStream{}, &fakeStream{}, &fakeStream{}
	hub.markMesh(meshX)
	hub.markMesh(meshY)
	hub.register(localA, sA)
	hub.register(localB, sB)
	hub.register(meshX, sX)
	hub.register(meshY, sY)

	if !hub.isMesh(meshX) || hub.isMesh(localA) {
		t.Fatalf("mesh classification wrong: meshX=%v localA=%v", hub.isMesh(meshX), hub.isMesh(localA))
	}

	// A frame published by a LOCAL client must go out on the backbone, otherwise
	// the far cluster never learns about that client.
	hub.broadcast([]byte(`{"t":"update","from":"localA"}`), localA, "")
	if sA.count() != 0 {
		t.Fatalf("sender localA must not receive its own frame (got %d writes)", sA.count())
	}
	if sB.count() != 1 {
		t.Fatalf("local peer localB should receive the frame, got %d writes", sB.count())
	}
	if sX.count() != 1 || sY.count() != 1 {
		t.Fatalf("both peer boots must receive a locally-published frame (uplink), got X=%d Y=%d",
			sX.count(), sY.count())
	}

	// A frame that came IN from the backbone must never go back out onto it.
	hub.broadcastToLocalOnly([]byte(`{"t":"update","from":"remoteClient"}`), "")
	if sA.count() != 1 || sB.count() != 2 {
		t.Fatalf("local clients must receive backbone frames, got A=%d B=%d", sA.count(), sB.count())
	}
	if sX.count() != 1 || sY.count() != 1 {
		t.Fatalf("backbone frame was re-forwarded onto the backbone (X=%d Y=%d, expected 1 each) — "+
			"a full mesh of boots will now loop forever", sX.count(), sY.count())
	}
}

// TestPeekMapHubIsolatesNetworks pins the multi-network discovery isolation: in
// PSK mode a frame tagged with a NetID must reach ONLY listeners of the same
// network — never a peer of a different network, never an unauthenticated peer —
// but it MUST still reach backbone (mesh) peers so the remote boot can re-apply
// the same filter for its own clients.
func TestPeekMapHubIsolatesNetworks(t *testing.T) {
	hub := newPeekMapHub()

	netA := test.RandPeerIDFatal(t)
	netB := test.RandPeerIDFatal(t)
	netB2 := test.RandPeerIDFatal(t)
	unauth := test.RandPeerIDFatal(t)
	meshX := test.RandPeerIDFatal(t)

	sA, sB, sB2, sU, sX := &fakeStream{}, &fakeStream{}, &fakeStream{}, &fakeStream{}, &fakeStream{}
	hub.markMesh(meshX)
	hub.register(netA, sA)
	hub.register(netB, sB)
	hub.register(netB2, sB2)
	hub.register(unauth, sU)
	hub.register(meshX, sX)

	hub.netResolver = func(p peer.ID) string {
		switch p {
		case netA:
			return "A"
		case netB, netB2:
			return "B"
		default:
			return "" // unauthenticated / mesh
		}
	}

	// Frame from netA (tagged "A"): only netA's cohort + the backbone peer.
	hub.broadcast([]byte(`{"t":"update","from":"a","net_id":"A"}`), netA, "A")
	if sA.count() != 0 {
		t.Fatalf("sender netA must not receive its own frame (got %d)", sA.count())
	}
	if sB.count() != 0 || sB2.count() != 0 {
		t.Fatalf("netB peers must NOT receive a netA frame (got B=%d B2=%d)", sB.count(), sB2.count())
	}
	if sU.count() != 0 {
		t.Fatalf("unauthenticated peer must NOT receive a netA frame (got %d)", sU.count())
	}
	if sX.count() != 1 {
		t.Fatalf("backbone peer must ALWAYS receive a netA frame (got %d)", sX.count())
	}

	// Frame from netB2 (tagged "B"): netB receives it, netA/unauth do not.
	hub.broadcast([]byte(`{"t":"update","from":"b","net_id":"B"}`), netB2, "B")
	if sA.count() != 0 {
		t.Fatalf("netA must NOT receive a netB frame (got %d)", sA.count())
	}
	if sB.count() != 1 {
		t.Fatalf("netB should receive the netB frame (got %d)", sB.count())
	}
	if sB2.count() != 0 {
		t.Fatalf("sender netB2 must not receive its own frame (got %d)", sB2.count())
	}
	if sU.count() != 0 {
		t.Fatalf("unauthenticated peer must NOT receive a netB frame (got %d)", sU.count())
	}
	if sX.count() != 2 {
		t.Fatalf("backbone peer must receive both frames (got %d)", sX.count())
	}
}

// TestPSKACLAllowConnectSameNetworkOnly pins the relay ACL's network isolation:
// two peers in the SAME network can reserve/connect through each other, but a
// peer in network A is denied when it tries to reach a peer in network B, and any
// unauthenticated peer is denied outright.
func TestPSKACLAllowConnectSameNetworkOnly(t *testing.T) {
	f := newPSKACLFilter(true)
	anyMA, _ := multiaddr.NewMultiaddr("/ip4/127.0.0.1/tcp/4001")

	a := test.RandPeerIDFatal(t)
	b := test.RandPeerIDFatal(t)
	c := test.RandPeerIDFatal(t)

	// Nothing authenticated yet -> deny everything.
	if f.AllowReserve(a, anyMA) {
		t.Fatal("reserve must be denied before auth")
	}
	if f.AllowConnect(a, nil, b) {
		t.Fatal("connect must be denied before auth")
	}

	f.AddAuthenticated(a, "netA")
	f.AddAuthenticated(b, "netA")
	f.AddAuthenticated(c, "netB")

	// Same-network pair: reserve + connect allowed.
	if !f.AllowReserve(a, anyMA) {
		t.Fatal("reserve must be allowed once authenticated")
	}
	if !f.AllowConnect(a, nil, b) {
		t.Fatal("connect a->b (both netA) must be allowed")
	}

	// Cross-network connect: denied both directions.
	if f.AllowConnect(a, nil, c) {
		t.Fatal("connect a(netA)->c(netB) must be DENIED")
	}
	if f.AllowConnect(c, nil, a) {
		t.Fatal("connect c(netB)->a(netA) must be DENIED")
	}

	// Removing auth revokes access.
	f.RemoveAuthenticated(a)
	if f.AllowConnect(a, nil, b) {
		t.Fatal("connect must be denied after RemoveAuthenticated")
	}
	if f.NetworkOf(a) != "" {
		t.Fatal("NetworkOf must be empty after RemoveAuthenticated")
	}
}

// --- end-to-end federation over real hosts ---------------------------------

// TestBootBackboneFederatesDiscoveryAcrossClusters is the acceptance test for
// multi-boot interconnect:
//
//	clientA ── bootA ══ backbone ══ bootB ── clientB
//
// clientA and bootB never talk; clientB and bootA never talk. A discovery frame
// published by clientA must still reach clientB, and must arrive with
// hop_distance == 2 (one increment per boot traversed) so the receiver can cost
// the path correctly instead of treating a two-relay peer as if it were adjacent.
func TestBootBackboneFederatesDiscoveryAcrossClusters(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	newHost := func(name string) host.Host {
		h, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
		if err != nil {
			t.Fatalf("create host %s: %v", name, err)
		}
		t.Cleanup(func() { _ = h.Close() })
		return h
	}

	bootA, bootB := newHost("bootA"), newHost("bootB")
	clientA, clientB := newHost("clientA"), newHost("clientB")

	hubA, hubB := newPeekMapHub(), newPeekMapHub()
	// Each boot knows the other is backbone BEFORE any stream arrives.
	hubA.markMesh(bootB.ID())
	hubB.markMesh(bootA.ID())
	bootA.SetStreamHandler(PeekMapProtocolID, makePeekMapHandler(bootA, hubA, "bootA"))
	bootB.SetStreamHandler(PeekMapProtocolID, makePeekMapHandler(bootB, hubB, "bootB"))

	// Clients subscribe to their own boot, exactly like ensurePeekMapListener.
	subscribe := func(c host.Host, b host.Host) network.Stream {
		if err := c.Connect(ctx, peer.AddrInfo{ID: b.ID(), Addrs: b.Addrs()}); err != nil {
			t.Fatalf("client %s -> boot %s connect: %v", c.ID().ShortString(), b.ID().ShortString(), err)
		}
		s, err := c.NewStream(ctx, b.ID(), PeekMapProtocolID)
		if err != nil {
			t.Fatalf("client %s peek-map stream: %v", c.ID().ShortString(), err)
		}
		t.Cleanup(func() { _ = s.Close() })
		return s
	}
	streamA := subscribe(clientA, bootA)
	streamB := subscribe(clientB, bootB)

	// Drain incoming broadcasts on clientA's stream so bootA's fanout doesn't stall.
	go func() {
		_, _ = io.Copy(io.Discard, streamA)
	}()

	// clientB reads whatever bootB fans out, looking for clientA's announcement.
	type result struct {
		hop int
		err error
	}
	found := make(chan result, 1)
	go func() {
		dec := json.NewDecoder(io.LimitReader(streamB, 1<<20))
		for {
			_ = streamB.SetReadDeadline(time.Now().Add(25 * time.Second))
			var msg PeekMapMessage
			if err := dec.Decode(&msg); err != nil {
				found <- result{err: err}
				return
			}
			// Ignore the boot-identity chatter; we want clientA's own frame.
			if msg.From != clientA.ID().String() {
				continue
			}
			var payload struct {
				PeerID      string `json:"peer_id"`
				NodeName    string `json:"node_name"`
				HopDistance int    `json:"hop_distance"`
			}
			if err := json.Unmarshal(msg.Payload, &payload); err != nil {
				found <- result{err: err}
				return
			}
			if payload.PeerID == clientA.ID().String() {
				found <- result{hop: payload.HopDistance}
				return
			}
		}
	}()

	// Bring up the backbone in BOTH directions, as a full mesh deployment would.
	go meshUplinkLoop(ctx, bootA, hubA, peer.AddrInfo{ID: bootB.ID(), Addrs: bootB.Addrs()}, "bootA")
	go meshUplinkLoop(ctx, bootB, hubB, peer.AddrInfo{ID: bootA.ID(), Addrs: bootA.Addrs()}, "bootB")

	// Wait until each hub has its peer boot registered as a listener; only then
	// is the uplink actually usable.
	waitBackbone := func(hub *peekMapHub, want peer.ID, label string) {
		deadline := time.Now().Add(20 * time.Second)
		for {
			hub.mu.RLock()
			_, ok := hub.listener[want]
			hub.mu.RUnlock()
			if ok {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s: backbone peer %s never registered as a listener", label, want.ShortString())
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	waitBackbone(hubA, bootB.ID(), "hubA")
	waitBackbone(hubB, bootA.ID(), "hubB")
	t.Logf("✓ backbone established in both directions")

	// clientA announces itself repeatedly: the backbone comes up asynchronously
	// and the hub is stateless, so an announcement published before bootB's
	// uplink registered would simply be dropped.
	announce := func() error {
		payload, err := json.Marshal(map[string]any{
			"peer_id":      clientA.ID().String(),
			"node_name":    "clientA",
			"tap_ip":       "10.7.0.1/24",
			"hop_distance": 0,
		})
		if err != nil {
			return err
		}
		msg := PeekMapMessage{Type: PeekMapUpdate, From: clientA.ID().String(), Payload: payload}
		_ = streamA.SetWriteDeadline(time.Now().Add(5 * time.Second))
		return json.NewEncoder(streamA).Encode(msg)
	}

	deadline := time.After(25 * time.Second)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	if err := announce(); err != nil {
		t.Fatalf("clientA announce: %v", err)
	}
	for {
		select {
		case r := <-found:
			if r.err != nil {
				t.Fatalf("clientB never received clientA's announcement across the backbone: %v", r.err)
			}
			// bootA increments 0->1 on ingest, bootB increments 1->2 when it
			// injects the frame into its own cluster.
			if r.hop != 2 {
				t.Fatalf("hop_distance across two boots should be 2, got %d — the receiver would "+
					"mis-cost a two-relay peer as if it were nearly adjacent", r.hop)
			}
			t.Logf("✓ clientA discovered by clientB across the boot backbone (hop_distance=%d)", r.hop)
			return
		case <-ticker.C:
			if err := announce(); err != nil {
				t.Fatalf("clientA re-announce: %v", err)
			}
		case <-deadline:
			t.Fatalf("timed out waiting for clientA's announcement to cross the boot backbone")
		}
	}
}

// TestMeshUplinkIgnoresEchoOfSelf guards a subtle amplification bug: the remote
// boot re-stamps and fans out our own identity publication, and since we are a
// listener there we read it straight back. Re-injecting it locally would make
// this boot advertise itself with an ever-growing hop_distance on every cycle.
func TestMeshUplinkIgnoresEchoOfSelf(t *testing.T) {
	self := test.RandPeerIDFatal(t)
	frame, err := json.Marshal(PeekMapMessage{
		Type:    PeekMapUpdate,
		From:    self.String(),
		Payload: json.RawMessage(`{"peer_id":"x","hop_distance":1}`),
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var msg PeekMapMessage
	if err := json.Unmarshal(frame, &msg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if msg.From != self.String() {
		t.Fatalf("From should round-trip as %s, got %s", self.String(), msg.From)
	}

	// The hop increment must be idempotent-safe on repeated application, i.e.
	// strictly monotonic, which is exactly why the self-echo has to be dropped
	// rather than merely deduplicated.
	once := incrementPeekMapHop(frame)
	twice := incrementPeekMapHop(once)
	hopOf := func(b []byte) int {
		var m PeekMapMessage
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatalf("unmarshal frame: %v", err)
		}
		var p struct {
			Hop int `json:"hop_distance"`
		}
		if err := json.Unmarshal(m.Payload, &p); err != nil {
			t.Fatalf("unmarshal payload: %v", err)
		}
		return p.Hop
	}
	if hopOf(once) != 2 || hopOf(twice) != 3 {
		t.Fatalf("hop increments should be 2 then 3, got %d then %d", hopOf(once), hopOf(twice))
	}
	if bytes.Equal(once, twice) {
		t.Fatalf("increment produced an identical frame — hop_distance is not advancing")
	}
}
