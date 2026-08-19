package routing

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
)

func generateTestPeerID(t *testing.T) peer.ID {
	t.Helper()
	priv, _, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}
	pID, err := peer.IDFromPrivateKey(priv)
	if err != nil {
		t.Fatalf("Failed to generate peer ID: %v", err)
	}
	return pID
}

func TestDijkstraShortestPathRouting(t *testing.T) {
	nodeA := generateTestPeerID(t)
	nodeB := generateTestPeerID(t)
	nodeC := generateTestPeerID(t)
	t.Logf("[dijkstra] nodes A=%s B=%s C=%s", nodeA.ShortString(), nodeB.ShortString(), nodeC.ShortString())

	r := NewRouter(nodeA)

	// Direct link A -> C = 280ms (slow)
	r.UpdateDirectLink(nodeC, 280, LinkDirect)
	// Direct link A -> B = 35ms (fast)
	r.UpdateDirectLink(nodeB, 35, LinkDirect)
	t.Log("[dijkstra] direct links: A->C=280ms A->B=35ms")

	// Process LSA from B showing B -> C = 40ms
	lsaB := &LinkStatePayload{
		Origin: nodeB.String(),
		Seq:    1,
		TTL:    5,
		Neighbors: map[string]int64{
			nodeA.String(): 35,
			nodeC.String(): 40,
		},
	}
	if !r.ProcessLSA(lsaB) {
		t.Fatalf("Failed to process LSA from nodeB")
	}
	t.Log("[dijkstra] processed LSA from B: B->A=35ms B->C=40ms")

	routes := r.ComputeRoutes()

	// Verify route to B is Direct (35ms)
	routeB, ok := routes[nodeB]
	if !ok {
		t.Fatalf("Expected route to nodeB")
	}
	t.Logf("[dijkstra] route to B: isDirect=%v rtt=%dms", routeB.IsDirect, routeB.TotalRTTMs)
	if !routeB.IsDirect || routeB.TotalRTTMs != 35 {
		t.Errorf("NodeB route incorrect: isDirect=%v, rtt=%d", routeB.IsDirect, routeB.TotalRTTMs)
	}

	// Verify route to C is Relayed via B (35 + 40 = 75ms < 280ms)
	routeC, ok := routes[nodeC]
	if !ok {
		t.Fatalf("Expected route to nodeC")
	}
		t.Logf("[dijkstra] route to C: isDirect=%v nextHop=%s totalRTT=%dms directRTT=%dms",
		routeC.IsDirect, routeC.NextHop.ShortString(), routeC.TotalRTTMs, routeC.DirectRTTMs)
	if routeC.IsDirect {
		t.Errorf("Expected nodeC route to be relayed via nodeB, got direct")
	}
	if routeC.NextHop != nodeB {
		t.Errorf("Expected NextHop to be nodeB (%s), got %s", nodeB, routeC.NextHop)
	}
	if routeC.TotalRTTMs != 75 {
		t.Errorf("Expected TotalRTT = 75ms, got %d ms", routeC.TotalRTTMs)
	}
	if routeC.DirectRTTMs != 280 {
		t.Errorf("Expected DirectRTT = 280ms, got %d ms", routeC.DirectRTTMs)
	}

	dtos := r.GetRouteInfoDTOs(func(pID peer.ID) (string, string, string) {
		if pID == nodeB {
			return "Tokyo-Relay", "10.0.0.2", "fd00::2"
		}
		if pID == nodeC {
			return "Frankfurt-Srv", "10.0.0.3", "fd00::3"
		}
		return "", "", ""
	})

	if len(dtos) != 2 {
		t.Fatalf("Expected 2 DTO entries, got %d", len(dtos))
	}

	foundRelayed := false
	for _, dto := range dtos {
		if dto.DestName == "Frankfurt-Srv" {
			foundRelayed = true
			if dto.SavedRTTMs != 205 {
				t.Errorf("Expected SavedRTTMs = 205ms, got %d ms", dto.SavedRTTMs)
			}
			if dto.NextHopName != "Tokyo-Relay" {
				t.Errorf("Expected NextHopName = Tokyo-Relay, got %s", dto.NextHopName)
			}
		}
	}
	if !foundRelayed {
		t.Errorf("Did not find Frankfurt-Srv in DTO list")
	}

	fmt.Println("Dijkstra Shortest Path & LSA test passed successfully!")
}

// TestBuildLSAAdvertisedSubnets guards against regression of the bug where the
// "LSA / Peek-Map" channel dropped advertised subnet routes: NodeIdentity did
// not carry AdvertisedSubnets, so peers learning identity via broadcast LSA saw
// empty subnets (unlike P2P Stream Direct peers). See pkg/routing/router.go
// NodeIdentity.AdvertisedSubnets and BuildLSA mapping.
func TestBuildLSAAdvertisedSubnets(t *testing.T) {
	local := generateTestPeerID(t)
	r := NewRouter(local)

	const (
		name = "r5s-ndjc0"
		ip   = "10.0.0.5"
		mac  = "7a:9a:bc:de:f0:12"
	)
	subnets := []string{"192.168.1.0/24", "10.10.0.0/16"}

	lsa := r.BuildLSA(7, NodeIdentity{
		NodeName:          name,
		TapIP:             ip,
		TapMAC:            mac,
		OS:                "linux",
		Arch:              "arm64",
		Version:           "v1.2.3",
		IsExitNode:        true,
		AdvertisedSubnets: subnets,
	})
	t.Logf("[lsa] built LSA name=%s ip=%s mac=%s subnets=%v", name, ip, mac, subnets)

	if lsa.NodeName != name {
		t.Errorf("LSA NodeName = %q, want %q", lsa.NodeName, name)
	}
	if lsa.TapIP != ip {
		t.Errorf("LSA TapIP = %q, want %q", lsa.TapIP, ip)
	}
	if lsa.IsExitNode != true {
		t.Errorf("LSA IsExitNode = %v, want true", lsa.IsExitNode)
	}
	if len(lsa.AdvertisedSubnets) != len(subnets) {
		t.Fatalf("LSA AdvertisedSubnets len = %d, want %d", len(lsa.AdvertisedSubnets), len(subnets))
	}
	for i, s := range subnets {
		if lsa.AdvertisedSubnets[i] != s {
			t.Errorf("LSA AdvertisedSubnets[%d] = %q, want %q", i, lsa.AdvertisedSubnets[i], s)
		}
	}

	// Empty subnets must still serialize to a present (possibly empty) field,
	// never be silently dropped.
	lsaEmpty := r.BuildLSA(8, NodeIdentity{NodeName: "bare", AdvertisedSubnets: nil})
	if lsaEmpty.AdvertisedSubnets != nil {
		t.Errorf("LSA with nil AdvertisedSubnets should keep nil field, got %v", lsaEmpty.AdvertisedSubnets)
	}
}

func TestCandidatePathsEvaluation(t *testing.T) {
	nodeLocal := generateTestPeerID(t)
	nodeTarget := generateTestPeerID(t)
	nodeRelay1 := generateTestPeerID(t)
	nodeRelay2 := generateTestPeerID(t)

	r := NewRouter(nodeLocal)

	// Direct link to target: 10ms
	r.UpdateDirectLink(nodeTarget, 10, LinkDirect)
	// Direct link to relay1: 20ms, relay1 -> target: 50ms (total 70ms)
	r.UpdateDirectLink(nodeRelay1, 20, LinkDirect)
	r.ProcessLSA(&LinkStatePayload{
		Origin:    nodeRelay1.String(),
		Seq:       1,
		TTL:       5,
		Neighbors: map[string]int64{nodeTarget.String(): 50},
	})
	// Direct link to relay2: 100ms, relay2 -> target: 80ms (total 180ms)
	r.UpdateDirectLink(nodeRelay2, 100, LinkDirect)
	r.ProcessLSA(&LinkStatePayload{
		Origin:    nodeRelay2.String(),
		Seq:       1,
		TTL:       5,
		Neighbors: map[string]int64{nodeTarget.String(): 80},
	})

	dtos := r.GetRouteInfoDTOs(func(pID peer.ID) (string, string, string) {
		switch pID {
		case nodeLocal:
			return "LocalNode", "10.0.0.1", ""
		case nodeTarget:
			return "TargetNode", "10.0.0.2", ""
		case nodeRelay1:
			return "Relay1", "10.0.0.3", ""
		case nodeRelay2:
			return "Relay2", "10.0.0.4", ""
		}
		return "", "", ""
	})

	var targetRouteIndex = -1
	for i := range dtos {
		if dtos[i].DestPeer == nodeTarget.String() {
			targetRouteIndex = i
			break
		}
	}

	if targetRouteIndex < 0 {
		t.Fatalf("TargetNode route not found in DTOs")
	}
	targetRoute := dtos[targetRouteIndex]

	if !targetRoute.IsDirect {
		t.Errorf("Expected direct route to be chosen as optimal (10ms)")
	}

	// Candidates should contain:
	// 1. Direct (10ms, optimal)
	// 2. Via Relay1 (70ms, sub-optimal)
	// 3. Via Relay2 (180ms, sub-optimal)
	if len(targetRoute.Candidates) < 3 {
		t.Fatalf("Expected at least 3 candidates evaluated, got %d", len(targetRoute.Candidates))
	}

	optCount := 0
	for _, c := range targetRoute.Candidates {
		if c.IsOptimal {
			optCount++
			if c.TotalRTT != 10 || !c.IsDirect {
				t.Errorf("Expected optimal candidate to be Direct (10ms), got %v (RTT=%d)", c.PathNames, c.TotalRTT)
			}
		} else {
			if c.TotalRTT <= 10 && c.TotalRTT > 0 {
				t.Errorf("Non-optimal candidate has invalid lower/equal RTT: %d", c.TotalRTT)
			}
		}
	}
	if optCount != 1 {
		t.Errorf("Expected exactly 1 optimal candidate, got %d", optCount)
	}
}


