package node

import (
	"testing"
	"time"

	"p2ptap/pkg/observer"
	"p2ptap/pkg/tap"
)

// recordingCollector captures the DTOs the node pushes to the WebUI so a test
// can assert on exactly what the Mesh Quality & Latency matrix would render.
type recordingCollector struct {
	noopCollector
	matrix []observer.MeshMatrixCellDTO
	routes []observer.RouteInfoDTO
}

func (r *recordingCollector) UpdateMeshMatrix(m []observer.MeshMatrixCellDTO) { r.matrix = m }
func (r *recordingCollector) UpdateRoutes(rs []observer.RouteInfoDTO)         { r.routes = rs }

// TAP experience and adjacency estimates have distinct scopes. Panels retain
// measured telemetry while the routing graph uses only connection measurements.
func TestMeshMatrixKeepsTAPTelemetrySeparateFromRoutingRTT(t *testing.T) {
	mk := func(ip, ip6 string) (*Node, *recordingCollector) {
		tapDev, _ := tap.NewMemTAPPair("tap"+ip, "pipe"+ip)
		col := &recordingCollector{}
		n, err := NewNodeWithTAP(createTestNodeConfig(ip+"/24", ip6+"/64", "best_path"), tapDev, col)
		if err != nil {
			t.Fatalf("create node %s: %v", ip, err)
		}
		n.Start()
		return n, col
	}

	nodeA, colA := mk("10.0.0.11", "fd00:1::11")
	nodeB, _ := mk("10.0.0.12", "fd00:1::12")
	defer nodeA.Close()
	defer nodeB.Close()

	ti := nodeB.Host.Peerstore().PeerInfo(nodeB.Host.ID())
	ti.Addrs = nodeB.Host.Addrs()
	if err := nodeA.Host.Connect(nodeA.ctx, ti); err != nil {
		t.Fatalf("connect A->B: %v", err)
	}
	waitOverlayReady(t, nodeA, nodeB)
	waitStreamReady(t, nodeA, nodeB)
	waitStreamReady(t, nodeB, nodeA)

	bID := nodeB.Host.ID()
	// Seed the metadata so the ARP/route annotation path is exercised too.
	nodeA.storePeerMeta(bID, PeerMeta{NodeName: "B", TapIP: "10.0.0.12/24", TapMAC: nodeB.localMAC.String()})
	nodeB.storePeerMeta(nodeA.Host.ID(), PeerMeta{NodeName: "A", TapIP: "10.0.0.11/24", TapMAC: nodeA.localMAC.String()})

	// Stand in for libp2p's smoothed control-plane figure, which is what used to
	// clobber the real measurement: deliberately far from the probe result.
	const staleEWMAMs = 24 * time.Millisecond
	nodeA.Host.Peerstore().RecordLatency(bID, staleEWMAMs)

	// A real 1.7ms round trip over the TAP data path.
	nodeA.recordPeerRTTProbe(bID, rttSourceTAPICMP, 1700*time.Microsecond, true)

	nodeA.updateWebCollectorState()

	// 1. The matrix carries real TAP telemetry independently of route cost.
	var cell *observer.MeshMatrixCellDTO
	for i := range colA.matrix {
		if colA.matrix[i].DstPeerID == bID.String() {
			cell = &colA.matrix[i]
			break
		}
	}
	if cell == nil {
		t.Fatalf("no mesh matrix cell for peer B; got %d cells", len(colA.matrix))
	}
	if !cell.RTTMeasured {
		t.Fatalf("matrix cell does not report a measured RTT: %+v", *cell)
	}
	if cell.MeasuredRTTMs != 1.7 {
		t.Fatalf("matrix measured RTT = %v ms, want 1.7", cell.MeasuredRTTMs)
	}
	if cell.RTTSource != rttSourceTAPICMP {
		t.Fatalf("matrix RTT source = %q, want %q", cell.RTTSource, rttSourceTAPICMP)
	}
	if cell.RTTMs != 24 {
		t.Fatalf("TAP measurement changed adjacency estimate: %dms", cell.RTTMs)
	}

	// 2. The topology graph uses the same adjacency estimate.
	var topoRTT int64
	var found bool
	for _, tn := range nodeA.GetTopology().Nodes {
		if tn.PeerID == bID.String() {
			topoRTT, found = tn.RTT, true
			break
		}
	}
	if !found {
		t.Fatalf("peer B missing from GetTopology()")
	}
	if topoRTT != cell.RTTMs {
		t.Fatalf("topology RTT %d ms disagrees with the matrix %d ms for the same link", topoRTT, cell.RTTMs)
	}

	// 3. Route DTOs preserve both physical path estimates and TAP telemetry.
	var route *observer.RouteInfoDTO
	for i := range colA.routes {
		if colA.routes[i].DestPeer == bID.String() {
			route = &colA.routes[i]
			break
		}
	}
	if route == nil {
		t.Fatalf("no route DTO for peer B")
	}
	if !route.RTTMeasured || route.MeasuredRTTMs != 1.7 || route.TotalRTTMs != 24 {
		t.Fatalf("route DTO disagrees with the matrix: measured=%v %v ms, total=%d ms", route.RTTMeasured, route.MeasuredRTTMs, route.TotalRTTMs)
	}
}
