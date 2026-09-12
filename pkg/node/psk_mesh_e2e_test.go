package node

import (
	"bytes"
	"net"
	"testing"
	"time"

	"p2ptap/pkg/tap"
)

// pskPair builds two TCP-connected nodes with the given PSKs and waits for the
// encrypted overlay (SeqSync) to come up in both directions. SeqSync completes
// regardless of whether the PSKs MATCH (the transport authenticates identity,
// not membership) — the difference shows up only at per-frame AEAD open.
func pskPair(t *testing.T, pskA, pskB string) *protocolPair {
	t.Helper()
	tapA, pipeA := tap.NewMemTAPPair("tapA", "pipeA")
	tapB, pipeB := tap.NewMemTAPPair("tapB", "pipeB")

	cfgA := createTestNodeConfig("10.0.0.1/24", "fd00::1/64", "best_path")
	cfgB := createTestNodeConfig("10.0.0.2/24", "fd00::2/64", "best_path")
	cfgA.PSK = pskA
	cfgB.PSK = pskB

	nodeA, err := NewNodeWithTAP(cfgA, tapA, nil)
	if err != nil {
		t.Fatalf("nodeA: %v", err)
	}
	nodeB, err := NewNodeWithTAP(cfgB, tapB, nil)
	if err != nil {
		t.Fatalf("nodeB: %v", err)
	}
	t.Cleanup(func() { nodeA.Close(); nodeB.Close() })
	nodeA.Start()
	nodeB.Start()

	connectNodes(t, nodeA, nodeB)
	waitOverlayReady(t, nodeA, nodeB)
	waitStreamReady(t, nodeA, nodeB)
	waitStreamReady(t, nodeB, nodeA)

	nodeA.storePeerMeta(nodeB.Host.ID(), PeerMeta{NodeName: "B", TapIP: "10.0.0.2/24", TapMAC: nodeB.localMAC.String()})
	nodeB.storePeerMeta(nodeA.Host.ID(), PeerMeta{NodeName: "A", TapIP: "10.0.0.1/24", TapMAC: nodeA.localMAC.String()})
	nodeA.rebuildARPIndex()
	nodeB.rebuildARPIndex()

	return &protocolPair{nodeA: nodeA, nodeB: nodeB, pipeA: pipeA, pipeB: pipeB, macA: nodeA.localMAC, macB: nodeB.localMAC}
}

// pipeSeesMarker reports whether a frame containing marker arrives on pipe
// within the window.
func pipeSeesMarker(pipe *tap.MemTAP, marker []byte, window time.Duration) bool {
	deadline := time.Now().Add(window)
	buf := make([]byte, 2048)
	for time.Now().Before(deadline) {
		n, err := pipe.Read(buf)
		if err == nil && n > 0 && bytes.Contains(buf[:n], marker) {
			return true
		}
	}
	return false
}

// TestPSKMeshIsolation proves the PSK is cryptographically bound to the mesh
// data plane: two nodes with the SAME PSK exchange encrypted TAP frames, while
// two nodes with DIFFERENT PSKs — even though their libp2p transport handshake
// and SeqSync both complete (identity auth ≠ membership) — cannot read each
// other's frames (AEAD open fails, frames are dropped, never sunk to the TAP).
func TestPSKMeshIsolation(t *testing.T) {
	marker := []byte("PSK_MESH_ISOLATION_PROBE")

	// Build an IPv4 ICMP frame A -> B carrying the marker.
	probeFrame := func(macA, macB net.HardwareAddr) []byte {
		return constructICMPv4PacketWithData(macA, macB,
			net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"), 4711, 1, marker)
	}

	t.Run("matching_psk_meshes", func(t *testing.T) {
		pair := pskPair(t, "shared-secret", "shared-secret")
		// Confirm both sides consider the peer PSK-verified (cipher negotiated).
		if !pair.nodeA.hasNegotiatedCipher(pair.nodeB.Host.ID()) {
			t.Fatal("A should hold a negotiated cipher with B")
		}
		if _, err := pair.pipeA.Write(probeFrame(pair.macA, pair.macB)); err != nil {
			t.Fatalf("write: %v", err)
		}
		if !pipeSeesMarker(pair.pipeB, marker, 4*time.Second) {
			t.Fatal("matching PSK: encrypted frame must reach B's TAP")
		}
	})

	t.Run("mismatched_psk_isolated", func(t *testing.T) {
		pair := pskPair(t, "secret-A", "secret-B")
		// Transport + SeqSync completed (both "negotiated"), but keys differ.
		if _, err := pair.pipeA.Write(probeFrame(pair.macA, pair.macB)); err != nil {
			t.Fatalf("write: %v", err)
		}
		// The frame must NOT be delivered to B's TAP: B cannot AEAD-open it, so
		// handleStream drops it as garbage. (A few retransmits are also dropped.)
		if pipeSeesMarker(pair.pipeB, marker, 2*time.Second) {
			t.Fatal("mismatched PSK: frame must NOT reach B's TAP (isolation failed)")
		}
	})
}
