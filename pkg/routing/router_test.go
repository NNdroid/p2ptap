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

	r := NewRouter(nodeA)

	// Direct link A -> C = 280ms (slow)
	r.UpdateDirectLink(nodeC, 280)
	// Direct link A -> B = 35ms (fast)
	r.UpdateDirectLink(nodeB, 35)

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

	routes := r.ComputeRoutes()

	// Verify route to B is Direct (35ms)
	routeB, ok := routes[nodeB]
	if !ok {
		t.Fatalf("Expected route to nodeB")
	}
	if !routeB.IsDirect || routeB.TotalRTTMs != 35 {
		t.Errorf("NodeB route incorrect: isDirect=%v, rtt=%d", routeB.IsDirect, routeB.TotalRTTMs)
	}

	// Verify route to C is Relayed via B (35 + 40 = 75ms < 280ms)
	routeC, ok := routes[nodeC]
	if !ok {
		t.Fatalf("Expected route to nodeC")
	}
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
