package node

import (
	"fmt"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/test"

	"p2ptap/pkg/routing"
	"p2ptap/pkg/tap"
)

// newTopoTestNode builds a node whose config declares one boot and one static
// peer, with backbone auto-attach disabled so the test stays hermetic (a boot
// discovered over the peek-map would otherwise fire a real dial goroutine and
// race the assertions).
func newTopoTestNode(t *testing.T, bootID, staticID peer.ID) *Node {
	t.Helper()
	dev, _ := tap.NewMemTAPPair("topoTap", "topoPipe")
	cfg := createTestNodeConfig("10.31.0.1/24", "fd31::1/64", "best_path")
	cfg.BootstrapPeers = []string{fmt.Sprintf("/ip4/127.0.0.1/tcp/1/p2p/%s", bootID)}
	cfg.StaticPeers = []string{fmt.Sprintf("/ip4/127.0.0.1/tcp/2/p2p/%s", staticID)}
	cfg.DiscoverBootMesh = false
	n, err := NewNodeWithTAP(cfg, dev, nil)
	if err != nil {
		t.Fatalf("create topology test node: %v", err)
	}
	t.Cleanup(func() { n.Close() })
	return n
}

func topoNodeByID(resp TopologyResponse, id peer.ID) (TopologyNode, bool) {
	for _, tn := range resp.Nodes {
		if tn.PeerID == id.String() {
			return tn, true
		}
	}
	return TopologyNode{}, false
}

// TestGetTopologyAnnotatesClustersAndRoles is the acceptance test for the
// complex-topology view: a deployment with two federated boot clusters plus a
// static-peer entry point must come out of /api/topology with every node
// correctly labelled — which boot cluster it belongs to, how many backbone hops
// away it is, and whether it is a boot / static entry point.
//
// Before this, TopologyNode carried only parent/depth/direct, so a two-cluster
// mesh was indistinguishable from a flat one: a peer federated in from a remote
// cluster looked exactly like a locally relayed peer.
func TestGetTopologyAnnotatesClustersAndRoles(t *testing.T) {
	bootA := test.RandPeerIDFatal(t)
	bootB := test.RandPeerIDFatal(t)
	staticPeer := test.RandPeerIDFatal(t)
	localPeer := test.RandPeerIDFatal(t)  // ordinary peer in our own cluster
	remotePeer := test.RandPeerIDFatal(t) // peer living in bootB's cluster

	n := newTopoTestNode(t, bootA, staticPeer)
	self := n.Host.ID()

	// Local cluster: we are attached to bootA, plus a static peer and a plain
	// peer that we learned through normal LSA flooding.
	n.Router.SetEdge(self, bootA, 20, routing.LinkCircuit)
	n.Router.SetEdge(self, staticPeer, 8, routing.LinkDirect)
	n.Router.SetEdge(self, localPeer, 14, routing.LinkDirect)

	// Federation: bootA's hub rebroadcasts bootB (1 backbone hop) and a client
	// of bootB (2 hops), exactly as the boot mesh uplink does.
	n.ingestPeekMapNodeInfo(PeekMapNodeInfo{
		PeerID:      bootB.String(),
		NodeName:    "boot-b",
		HopDistance: 1,
		IsBoot:      true,
	}, bootA)
	n.ingestPeekMapNodeInfo(PeekMapNodeInfo{
		PeerID:      remotePeer.String(),
		NodeName:    "remote-1",
		TapIP:       "10.31.0.9/24",
		HopDistance: 2,
	}, bootA)

	resp := n.GetTopology()

	// --- self ---------------------------------------------------------------
	selfNode, ok := topoNodeByID(resp, self)
	if !ok {
		t.Fatalf("self missing from topology response")
	}
	if resp.LocalCluster != bootA.String() {
		t.Errorf("local cluster: got %q want %q (our configured boot)", resp.LocalCluster, bootA.String())
	}
	if selfNode.Cluster != bootA.String() {
		t.Errorf("self cluster: got %q want %q", selfNode.Cluster, bootA.String())
	}

	// --- configured boot ----------------------------------------------------
	bootANode, ok := topoNodeByID(resp, bootA)
	if !ok {
		t.Fatalf("configured boot missing from topology response")
	}
	if !bootANode.IsBoot {
		t.Errorf("configured bootstrap peer was not marked is_boot")
	}
	if bootANode.Cluster != bootA.String() {
		t.Errorf("a boot must anchor its OWN cluster, got %q", bootANode.Cluster)
	}

	// --- static peer --------------------------------------------------------
	staticNode, ok := topoNodeByID(resp, staticPeer)
	if !ok {
		t.Fatalf("static peer missing from topology response")
	}
	if !staticNode.Static {
		t.Errorf("configured static peer was not marked static")
	}
	if staticNode.IsBoot {
		t.Errorf("a static peer must not be reported as a boot")
	}
	if staticNode.Cluster != bootA.String() {
		t.Errorf("a locally-known peer should share our cluster, got %q", staticNode.Cluster)
	}
	if staticNode.BootHops != 0 {
		t.Errorf("a locally-known peer must be 0 backbone hops away, got %d", staticNode.BootHops)
	}

	// --- remote boot discovered over the backbone ---------------------------
	bootBNode, ok := topoNodeByID(resp, bootB)
	if !ok {
		t.Fatalf("federated boot missing from topology response")
	}
	if !bootBNode.IsBoot {
		t.Errorf("a peer that announced is_boot over the backbone was not marked is_boot")
	}
	if bootBNode.Cluster != bootB.String() {
		t.Errorf("federated boot should anchor its own cluster, got %q (grouping it under the boot that relayed it would turn a peer-to-peer backbone into a fake hierarchy)", bootBNode.Cluster)
	}

	// --- remote cluster member ---------------------------------------------
	remoteNode, ok := topoNodeByID(resp, remotePeer)
	if !ok {
		t.Fatalf("federated peer missing from topology response")
	}
	if remoteNode.Cluster != bootA.String() {
		t.Errorf("remote peer should be grouped under the boot that announced it (%s), got %q", bootA.ShortString(), remoteNode.Cluster)
	}
	if remoteNode.BootHops != 2 {
		t.Errorf("remote peer boot_hops: got %d want 2 (federated across two boots)", remoteNode.BootHops)
	}
	if remoteNode.NodeName != "remote-1" {
		t.Errorf("remote peer identity not applied: got %q", remoteNode.NodeName)
	}

	// --- edge classes -------------------------------------------------------
	classOf := map[string]string{}
	for _, e := range resp.Edges {
		classOf[e.From+"|"+e.To] = e.Class
		classOf[e.To+"|"+e.From] = e.Class
	}
	if c := classOf[self.String()+"|"+staticPeer.String()]; c != "direct" {
		t.Errorf("static peer edge class: got %q want \"direct\"", c)
	}
	if c := classOf[bootA.String()+"|"+remotePeer.String()]; c != "circuit" {
		t.Errorf("peek-map backfilled edge class: got %q want \"circuit\" (it only exists through a relay)", c)
	}

	// --- cluster summary ----------------------------------------------------
	byBoot := map[string]TopologyCluster{}
	for _, c := range resp.Clusters {
		byBoot[c.BootID] = c
	}
	ca, ok := byBoot[bootA.String()]
	if !ok {
		t.Fatalf("cluster summary missing our own boot; got %+v", resp.Clusters)
	}
	if !ca.Local {
		t.Errorf("our own cluster was not flagged local")
	}
	// self + static + localPeer + remotePeer are grouped under bootA; the boot
	// itself is the anchor and must not be counted as its own member.
	if ca.Members != 4 {
		t.Errorf("cluster %s members: got %d want 4 (self, static, local, remote)", bootA.ShortString(), ca.Members)
	}
	cb, ok := byBoot[bootB.String()]
	if !ok {
		t.Fatalf("cluster summary missing the federated boot; got %+v", resp.Clusters)
	}
	if cb.Local {
		t.Errorf("the remote cluster must not be flagged local")
	}
	if cb.BootName != "boot-b" {
		t.Errorf("federated cluster name: got %q want \"boot-b\"", cb.BootName)
	}
}

// TestRecordPeekMapOriginPrefersClosestBoot covers the ambiguity that a
// federated backbone creates: the SAME node is announced by several boots (its
// own boot, plus every boot that relayed the frame onwards). If the last
// announcement to arrive simply won, a node's displayed cluster would flip on
// every refresh depending on network timing.
func TestRecordPeekMapOriginPrefersClosestBoot(t *testing.T) {
	nearBoot := test.RandPeerIDFatal(t)
	farBoot := test.RandPeerIDFatal(t)
	target := test.RandPeerIDFatal(t)

	n := &Node{}

	// The far announcement lands first, then the closer one supersedes it.
	n.recordPeekMapOrigin(target, farBoot, 3, false)
	n.recordPeekMapOrigin(target, nearBoot, 1, false)
	got, ok := n.lookupPeekMapOrigin(target)
	if !ok {
		t.Fatalf("origin was not recorded")
	}
	if got.Via != nearBoot || got.Hops != 1 {
		t.Fatalf("closer announcement should win: got via=%s hops=%d", got.Via.ShortString(), got.Hops)
	}

	// Now the far one arrives again within the sticky window: it must NOT
	// displace the closer assignment.
	n.recordPeekMapOrigin(target, farBoot, 3, false)
	got, _ = n.lookupPeekMapOrigin(target)
	if got.Via != nearBoot || got.Hops != 1 {
		t.Fatalf("farther announcement displaced the closer one: got via=%s hops=%d", got.Via.ShortString(), got.Hops)
	}

	// Once the assignment goes stale the node can be re-homed, so a peer that
	// genuinely moved clusters is not pinned forever.
	n.peekMapOrigin.Store(target, peekMapOrigin{Via: nearBoot, Hops: 1, At: time.Now().Add(-2 * peekMapOriginStickyFor)})
	n.recordPeekMapOrigin(target, farBoot, 3, false)
	got, _ = n.lookupPeekMapOrigin(target)
	if got.Via != farBoot {
		t.Fatalf("a stale assignment must be replaceable, still via=%s", got.Via.ShortString())
	}
}

// TestRecordPeekMapOriginBootFlagIsSticky guards a subtle demotion bug: only the
// boot's own announcement sets is_boot, while relayed re-announcements of the
// same node may omit it. Letting those clear the flag would make a boot
// intermittently render as an ordinary peer and lose its cluster anchor.
func TestRecordPeekMapOriginBootFlagIsSticky(t *testing.T) {
	via := test.RandPeerIDFatal(t)
	bootPeer := test.RandPeerIDFatal(t)

	n := &Node{}
	n.recordPeekMapOrigin(bootPeer, via, 1, true)
	n.recordPeekMapOrigin(bootPeer, via, 1, false) // relayed copy, flag omitted

	got, ok := n.lookupPeekMapOrigin(bootPeer)
	if !ok {
		t.Fatalf("origin was not recorded")
	}
	if !got.IsBoot {
		t.Fatalf("boot flag was cleared by a relayed announcement that omitted it")
	}
}

// TestLocalBootClusterFallsBackWhenBootless verifies a boot-less deployment (the
// pure static-peer mesh from stage 2) reports no cluster instead of inventing
// one — the WebUI uses the empty value to skip cluster grouping entirely.
func TestLocalBootClusterFallsBackWhenBootless(t *testing.T) {
	dev, _ := tap.NewMemTAPPair("topoTapNB", "topoPipeNB")
	cfg := createTestNodeConfig("10.32.0.1/24", "fd32::1/64", "best_path")
	cfg.DiscoverBootMesh = false
	n, err := NewNodeWithTAP(cfg, dev, nil)
	if err != nil {
		t.Fatalf("create bootless node: %v", err)
	}
	defer n.Close()

	if got := n.localBootCluster(); got != "" {
		t.Fatalf("a node with no boots should report no cluster, got %q", got)
	}
	peerX := test.RandPeerIDFatal(t)
	n.Router.SetEdge(n.Host.ID(), peerX, 11, routing.LinkDirect)
	resp := n.GetTopology()
	if resp.LocalCluster != "" {
		t.Fatalf("bootless topology reported cluster %q", resp.LocalCluster)
	}
	if len(resp.Clusters) != 0 {
		t.Fatalf("bootless topology should have no cluster groups, got %+v", resp.Clusters)
	}
	for _, tn := range resp.Nodes {
		if tn.Cluster != "" {
			t.Fatalf("node %s got cluster %q in a bootless mesh", tn.PeerID, tn.Cluster)
		}
	}
}
