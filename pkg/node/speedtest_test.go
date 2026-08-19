package node

import (
	"testing"
	"time"

	"p2ptap/pkg/tap"
)

func TestProbePeerSpeedTestRealBenchmark(t *testing.T) {
	tapA, _ := tap.NewMemTAPPair("tapA", "pipeA")
	tapB, _ := tap.NewMemTAPPair("tapB", "pipeB")

	cfgA := createTestNodeConfig("10.0.0.1/24", "fd00::1/64", "best_path")
	cfgB := createTestNodeConfig("10.0.0.2/24", "fd00::2/64", "best_path")

	nodeA, err := NewNodeWithTAP(cfgA, tapA, nil)
	if err != nil {
		t.Fatalf("failed to create node A: %v", err)
	}
	defer nodeA.Close()

	nodeB, err := NewNodeWithTAP(cfgB, tapB, nil)
	if err != nil {
		t.Fatalf("failed to create node B: %v", err)
	}
	defer nodeB.Close()

	nodeA.Start()
	nodeB.Start()

	infoB := nodeB.Host.Peerstore().PeerInfo(nodeB.Host.ID())
	infoB.Addrs = nodeB.Host.Addrs()
	if err := nodeA.Host.Connect(nodeA.ctx, infoB); err != nil {
		t.Fatalf("failed to connect node A to B: %v", err)
	}

	time.Sleep(300 * time.Millisecond)

	// Run real benchmark speed test from nodeA to nodeB
	res := nodeA.ProbePeerSpeedTest(nodeB.Host.ID().String())
	if res == nil {
		t.Fatal("ProbePeerSpeedTest returned nil")
	}

	t.Logf("SpeedTest Result: Peer=%s Mbps=%.2f RTTMin=%.1fms RTTAvg=%.1fms RTTMax=%.1fms Jitter=%.1fms Loss=%.2f Note=%s",
		res.PeerID, res.Mbps, res.RTTMin, res.RTTAvg, res.RTTMax, res.Jitter, res.PacketLoss, res.MeasurementNote)

	if res.Mbps <= 0 {
		t.Errorf("expected measured Mbps > 0, got %.2f", res.Mbps)
	}
	if res.RTTAvg < 0 {
		t.Errorf("expected RTTAvg >= 0, got %.2f", res.RTTAvg)
	}
	if res.PacketLoss > 0 {
		t.Errorf("expected PacketLoss == 0 on local test, got %.2f", res.PacketLoss)
	}
}
