package node

import (
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
)

// TestPreferredLinkRTTMs guards the precedence rule that keeps the WebUI's two
// latency panels in agreement.
//
// Regression: updateWebCollectorState wrote the routing graph edge weight twice
// per stats tick — first from a completed probe (real RTT), then unconditionally
// from the peerstore EWMA. The EWMA won, so the Mesh Quality & Latency matrix
// (built from the graph) showed the EWMA value while the topology chart (built
// from PeerInfoDTO, i.e. the probe) showed the measured one. On a LAN link that
// surfaced as "≈24 ms" in the table next to "1.7ms" on the star for the same peer.
func TestPreferredLinkRTTMs(t *testing.T) {
	measured := func(ms float64) peerRTTSnapshot {
		return peerRTTSnapshot{rttMs: ms, rttMeasured: true, source: rttSourceTAPICMP}
	}

	tests := []struct {
		name      string
		snap      peerRTTSnapshot
		ewmaMs    int64
		wantMs    int64
		wantOK    bool
		rationale string
	}{
		{
			name:      "probe outranks a much larger peerstore EWMA",
			snap:      measured(1.7),
			ewmaMs:    24,
			wantMs:    2,
			wantOK:    true,
			rationale: "the whole point of the fix: 1.7ms measured must not become 24ms",
		},
		{
			name:      "probe outranks a smaller peerstore EWMA too",
			snap:      measured(18),
			ewmaMs:    3,
			wantMs:    18,
			wantOK:    true,
			rationale: "precedence is by source, not by whichever number is lower",
		},
		{
			name:      "sub-millisecond probe clamps to 1ms instead of collapsing to no-edge",
			snap:      measured(0.4),
			ewmaMs:    50,
			wantMs:    1,
			wantOK:    true,
			rationale: "0 means 'no edge' in the routing graph",
		},
		{
			name:      "no probe yet falls back to the peerstore EWMA",
			snap:      peerRTTSnapshot{},
			ewmaMs:    24,
			wantMs:    24,
			wantOK:    true,
			rationale: "a freshly connected peer must not sit on the synthetic edge cost forever",
		},
		{
			name:      "failed-only probe window is not a measurement and falls back",
			snap:      peerRTTSnapshot{lossMeasured: true, sampleCount: 3, lossRatePercent: 100},
			ewmaMs:    24,
			wantMs:    24,
			wantOK:    true,
			rationale: "an all-timeout window must not be reported as a measured RTT",
		},
		{
			name:      "neither probe nor EWMA yields no weight at all",
			snap:      peerRTTSnapshot{},
			ewmaMs:    0,
			wantMs:    0,
			wantOK:    false,
			rationale: "no evidence must leave the provisional edge cost untouched",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotMs, gotOK := preferredLinkRTTMs(tc.snap, tc.ewmaMs)
			if gotOK != tc.wantOK || gotMs != tc.wantMs {
				t.Fatalf("%s: got (%d, ok=%v), want (%d, ok=%v)", tc.rationale, gotMs, gotOK, tc.wantMs, tc.wantOK)
			}
		})
	}
}

// TestPeerRTTMeasurementPrefersFreshSources pins down what "a completed probe"
// means, because preferredLinkRTTMs treats that flag as authoritative.
func TestPeerRTTMeasurementPrefersFreshSources(t *testing.T) {
	now := time.Date(2026, 8, 21, 9, 0, 0, 0, time.UTC)
	n := &Node{}

	// A stale TAP ICMP sample must not be presented as current telemetry.
	stale := peer.ID("mesh-rtt-stale")
	n.recordPeerRTTProbeAt(stale, rttSourceTAPICMP, 3*time.Millisecond, true, now.Add(-2*tapRTTPreferredFor))
	if snap := n.peerRTTMeasurement(stale, now); snap.rttMeasured {
		t.Fatalf("stale TAP ICMP sample still reported as measured: %+v", snap)
	}

	// A fresh background echo is measurable telemetry.
	echo := peer.ID("mesh-rtt-echo")
	n.recordPeerRTTProbeAt(echo, rttSourceP2PEcho, 12*time.Millisecond, true, now.Add(-time.Second))
	snap := n.peerRTTMeasurement(echo, now)
	if !snap.rttMeasured || snap.rttMs != 12 || snap.source != rttSourceP2PEcho {
		t.Fatalf("fresh p2p-echo not measured: %+v", snap)
	}

	// A fresh TAP ICMP sample is the real data path, so it outranks the echo.
	both := peer.ID("mesh-rtt-both")
	n.recordPeerRTTProbeAt(both, rttSourceP2PEcho, 12*time.Millisecond, true, now.Add(-time.Second))
	n.recordPeerRTTProbeAt(both, rttSourceTAPICMP, 2*time.Millisecond, true, now.Add(-time.Second))
	snap = n.peerRTTMeasurement(both, now)
	if !snap.rttMeasured || snap.rttMs != 2 || snap.source != rttSourceTAPICMP {
		t.Fatalf("fresh TAP ICMP did not outrank the echo: %+v", snap)
	}

	// The routing weight derived from that snapshot is the measured value — the
	// number both WebUI panels must render — not the peerstore EWMA.
	if ms, ok := preferredLinkRTTMs(snap, 24); !ok || ms != 2 {
		t.Fatalf("expected the measured 2ms to become the link weight, got (%d, ok=%v)", ms, ok)
	}

	// An all-timeout window is loss telemetry, not a measurement: the EWMA
	// fallback must still apply so the link does not look weightless.
	loss := peer.ID("mesh-rtt-loss")
	n.recordPeerRTTProbeAt(loss, rttSourceTAPICMP, 0, false, now.Add(-time.Second))
	snap = n.peerRTTMeasurement(loss, now)
	if snap.rttMeasured || snap.rttMs != 0 {
		t.Fatalf("all-timeout window reported a measured RTT: %+v", snap)
	}
	if !snap.lossMeasured || snap.lossRatePercent != 100 {
		t.Fatalf("all-timeout window must still expose 100%% loss: %+v", snap)
	}
	if ms, ok := preferredLinkRTTMs(snap, 24); !ok || ms != 24 {
		t.Fatalf("expected the EWMA fallback for a loss-only window, got (%d, ok=%v)", ms, ok)
	}
}
