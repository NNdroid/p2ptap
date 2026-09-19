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

// TestMeshMatrixAgreesWithTopologyRTT is the end-to-end guard for the WebUI
// report that the Mesh Quality & Latency matrix and the topology star chart
// showed different latencies "in many places" for the same link.
//
// The two panels read two different code paths — the matrix reads the routing
// graph, the star prefers PeerInfoDTO.rtt_ms (the probe) — so they only agree if
// the graph weight itself is the probe result. updateWebCollectorState used to
// write that weight from the peerstore EWMA AFTER writing it from the probe, so
// the matrix showed the EWMA while the star showed the probe.
func TestMeshMatrixAgreesWithTopologyRTT(t *testing.T) {
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

	// 1. The matrix must carry the probe, not the EWMA.
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
	// This is the regression: the routing-graph weight must be the measured
	// value, not the 24ms peerstore EWMA that overwrote it.
	if cell.RTTMs != 2 {
		t.Fatalf("matrix routing RTT = %d ms, want 2 ms (1.7 rounded up from the probe, not the %v EWMA)", cell.RTTMs, staleEWMAMs)
	}

	// 2. The topology star must resolve the same link to the same weight, so a
	//    viewer reading both panels sees one number.
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

	// 3. The route table must expose the same measured value, since it is the
	//    third place the same latency is displayed.
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
	if !route.RTTMeasured || route.MeasuredRTTMs != 1.7 || route.TotalRTTMs != 2 {
		t.Fatalf("route DTO disagrees with the matrix: measured=%v %v ms, total=%d ms", route.RTTMeasured, route.MeasuredRTTMs, route.TotalRTTMs)
	}
}
