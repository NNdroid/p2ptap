package node

import (
	"errors"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"p2ptap/pkg/tap"
)

func TestRouteTransportPathRequiresLiveTransportEvidence(t *testing.T) {
	tests := []struct {
		name     string
		direct   bool
		signals  peerConnSignals
		expected string
	}{
		{name: "overlay route", direct: false, expected: "overlay-relay"},
		{name: "live direct", direct: true, signals: peerConnSignals{hasDirect: true}, expected: "direct"},
		{name: "relay only", direct: true, signals: peerConnSignals{hasRelay: true}, expected: "circuit-relay"},
		{name: "mixed prefers direct", direct: true, signals: peerConnSignals{hasDirect: true, hasRelay: true}, expected: "direct"},
		{name: "stale route is unknown", direct: true, expected: "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := routeTransportPath(tt.direct, tt.signals); got != tt.expected {
				t.Fatalf("routeTransportPath() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestCandidateRelayRouteDoesNotManufactureConnection(t *testing.T) {
	cfg := createTestNodeConfig("10.77.0.1/24", "fd77::1/64", "best_path")
	dev, _ := tap.NewMemTAPPair("truth-route-tap", "truth-route-pipe")
	n, err := NewNodeWithTAP(cfg, dev, nil)
	if err != nil {
		t.Fatalf("NewNodeWithTAP: %v", err)
	}
	defer n.Close()

	target := peer.ID("candidate-relay-target")
	boot := peer.ID("candidate-relay-boot")
	n.discoveredBoots.Store(boot, true)
	n.bootRelayMu.Lock()
	n.bootRelayConns[boot] = &bootRelayConn{boot: boot}
	n.bootRelayMu.Unlock()
	n.recordPeekMapOrigin(target, boot, 1, false)

	sig := n.deriveConnSignals(target)
	if sig.connCount != 0 || !sig.hasRelayRoute || sig.hasRelay {
		t.Fatalf("candidate route signals = %+v; want route only with zero live connections", sig)
	}
	state, stage, _ := n.derivePeerConnState(target, "Peer")
	if state != connStateConnecting || stage != 0 {
		t.Fatalf("candidate route state = %s stage=%d; want connecting stage=0", state, stage)
	}
	if path, _ := n.describeTransportPath(target); path != "" {
		t.Fatalf("unverified candidate route transport path = %q; want empty", path)
	}

	// Even recent readiness/Rx cannot overrule a newer relay-control failure.
	n.markPeerReady(target)
	n.notePeerRx(target)
	n.recordRelayControlFailure(target, errors.New("relay control timeout"))
	state, stage, detail := n.derivePeerConnState(target, "Peer")
	if state != connStateUnreachable || stage != 0 {
		t.Fatalf("failed route state = %s stage=%d detail=%q; want unreachable stage=0", state, stage, detail)
	}
	if path, _ := n.describeTransportPath(target); path != "" {
		t.Fatalf("failed candidate route transport path = %q; want empty", path)
	}

	// A real response clears the failed verdict; readiness plus recent inbound
	// evidence is what promotes the candidate route to a verified relay path.
	n.clearRelayControlFailure(target)
	if !n.peerRxWithin(target, time.Second) {
		t.Fatal("test setup did not record relay liveness")
	}
	state, stage, detail = n.derivePeerConnState(target, "Peer")
	if state == connStateUnreachable || stage == 0 {
		t.Fatalf("verified relay route state = %s stage=%d detail=%q; want live transport evidence", state, stage, detail)
	}
	if path, hop := n.describeTransportPath(target); path != "overlay-relay" || hop != boot.String() {
		t.Fatalf("verified relay route transport path = %q via %q; want overlay-relay via %q", path, hop, boot)
	}
}

func TestDisconnectedBootstrapIsNotReportedHealthy(t *testing.T) {
	cfg := createTestNodeConfig("10.78.0.1/24", "fd78::1/64", "best_path")
	dev, _ := tap.NewMemTAPPair("truth-boot-tap", "truth-boot-pipe")
	n, err := NewNodeWithTAP(cfg, dev, nil)
	if err != nil {
		t.Fatalf("NewNodeWithTAP: %v", err)
	}
	defer n.Close()

	state, stage, detail := n.derivePeerConnState(peer.ID("disconnected-bootstrap"), "Bootstrap")
	if state != connStateUnreachable || stage != 0 {
		t.Fatalf("disconnected bootstrap state = %s stage=%d detail=%q; want unreachable stage=0", state, stage, detail)
	}
}

func TestComputeReachabilityUsesAutoNATVerdict(t *testing.T) {
	n := &Node{}
	if got := n.computeReachability(); got != "Unknown" {
		t.Fatalf("startup reachability = %q, want Unknown", got)
	}
	n.localReachability.Store(int32(network.ReachabilityPrivate))
	if got := n.computeReachability(); got != "Private" {
		t.Fatalf("private reachability = %q, want Private", got)
	}
	n.localReachability.Store(int32(network.ReachabilityPublic))
	if got := n.computeReachability(); got != "Public" {
		t.Fatalf("public reachability = %q, want Public", got)
	}
}
