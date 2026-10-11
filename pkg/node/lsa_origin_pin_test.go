package node

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"p2ptap/pkg/routing"
	"p2ptap/pkg/tap"
)

// TestLSASnapshotCannotRepintExistingOrigin locks the seenOrigins pin against
// re-attribution by a snapshot replay.
//
// seenOrigins exists to close the TTL-downgrade bypass: the first time an origin
// is observed it must arrive directly at full TTL, and later sightings are only
// trusted from that origin or from the peer that first introduced it. A
// cached-topology SNAPSHOT bypassed that rule entirely — it unconditionally
// overwrote entry.source with whatever peer carried it. Because lsa.Snapshot is
// a sender-written JSON field, any peer directly connected to us could clobber
// an already-pinned origin to itself, after which every legitimate LSA and
// relayed frame for that origin from any other carrier was dropped for the
// entry's whole 5-minute lifetime. That is a remote DoS against a peer's
// routing and relay reachability, minted from one forged frame.
//
// The first-sighting case is deliberately preserved (pushLSASnapshotToPeer is
// what bootstraps a late joiner through a single StaticPeer), so the gate must
// reject only the RE-attribution. Replaying this test before the fix fails both
// the pin assertion and the topology-poisoning assertion.
func TestLSASnapshotCannotRepintExistingOrigin(t *testing.T) {
	tapA, _ := tap.NewMemTAPPair("pinTapA", "pinPipeA")
	tapB, _ := tap.NewMemTAPPair("pinTapB", "pinPipeB")
	tapC, _ := tap.NewMemTAPPair("pinTapC", "pinPipeC")

	aNode, err := NewNodeWithTAP(createTestNodeConfig("10.6.0.1/24", "fd06::1/64", "best_path"), tapA, nil)
	if err != nil {
		t.Fatalf("create NodeA: %v", err)
	}
	defer aNode.Close()
	bNode, err := NewNodeWithTAP(createTestNodeConfig("10.6.0.2/24", "fd06::2/64", "best_path"), tapB, nil)
	if err != nil {
		t.Fatalf("create NodeB: %v", err)
	}
	defer bNode.Close()
	cNode, err := NewNodeWithTAP(createTestNodeConfig("10.6.0.3/24", "fd06::3/64", "best_path"), tapC, nil)
	if err != nil {
		t.Fatalf("create NodeC: %v", err)
	}
	defer cNode.Close()

	aNode.Start()
	bNode.Start()
	cNode.Start()

	connect := func(a, b *Node) {
		ti := b.Host.Peerstore().PeerInfo(b.Host.ID())
		ti.Addrs = b.Host.Addrs()
		if cerr := a.Host.Connect(a.ctx, ti); cerr != nil {
			t.Fatalf("connect %s->%s: %v", a.Host.ID().ShortString(), b.Host.ID().ShortString(), cerr)
		}
	}
	connect(aNode, bNode)

	// Wait until B has seen A's own LSA and pinned A's origin to A itself.
	aID, bID, cID := aNode.Host.ID(), bNode.Host.ID(), cNode.Host.ID()
	deadline := time.Now().Add(20 * time.Second)
	for {
		if v, ok := bNode.seenOrigins.Load(aID.String()); ok {
			if got := v.(seenOriginEntry).source; got == aID.String() {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("NodeB never pinned NodeA's origin to NodeA directly")
		}
		time.Sleep(50 * time.Millisecond)
	}
	// A's own LSA must have advertised the A-B edge, so there is something for
	// the forged snapshot to overwrite.
	if _, ok := bNode.Router.GetEdge(aID, bID); !ok {
		t.Fatalf("NodeB does not hold the A-B edge from A's LSA; the test premise is wrong")
	}
	t.Log("pinned origin A via A directly; now replaying a snapshot claiming A from C")

	// C connects and replays a topology snapshot that CLAIMS to be A's LSA but
	// lists C as A's only neighbour. Seq is taken from SeedableLSASeq so that
	// ProcessLSA would accept it if it ever reached the router — the only thing
	// that stops it is the seenOrigins gate.
	connect(cNode, bNode)
	seq := bNode.Router.SeedableLSASeq(aID)
	payload, err := json.Marshal(routing.LinkStatePayload{
		Origin:   aID.String(),
		Seq:      seq,
		TTL:      routing.DefaultLSATTL,
		Snapshot: true,
		Neighbors: map[string]int64{
			cID.String(): 1,
		},
	})
	if err != nil {
		t.Fatalf("marshal forged snapshot: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s, err := cNode.Host.NewStream(ctx, bID, LSAProtocolID)
	if err != nil {
		t.Fatalf("open LSA stream C->B: %v", err)
	}
	if werr := WriteFrame(s, payload); werr != nil {
		t.Fatalf("write forged snapshot: %v", werr)
	}
	_ = s.Close()

	// Give B a chance to process it, then verify the pin survived.
	for i := 0; i < 40; i++ {
		if v, ok := bNode.seenOrigins.Load(aID.String()); ok {
			if v.(seenOriginEntry).source != aID.String() {
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	v, ok := bNode.seenOrigins.Load(aID.String())
	if !ok {
		t.Fatal("NodeB lost its pin for NodeA entirely")
	}
	if got := v.(seenOriginEntry).source; got != aID.String() {
		t.Fatalf("snapshot re-pinned origin %s to carrier %q (want the origin itself)",
			aID.ShortString(), got)
	}

	// The pin gate drops the frame before ProcessLSA, so A's neighbour set must
	// not have been overwritten either.
	if _, ok := bNode.Router.GetEdge(aID, cID); ok {
		t.Fatalf("forged snapshot poisoned the topology: edge %s-%s must not exist",
			aID.ShortString(), cID.ShortString())
	}
	if _, ok := bNode.Router.GetEdge(aID, bID); !ok {
		t.Fatalf("forged snapshot destroyed the legitimate A-B edge")
	}
	t.Log("pin held and topology intact after the forged snapshot")
}
