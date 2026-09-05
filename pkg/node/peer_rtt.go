package node

import (
	"math"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
)

const (
	peerRTTWindowSize      = 20
	tapRTTPreferredFor     = 30 * time.Second
	manualPingPreferredFor = 20 * time.Second
	backgroundEchoFreshFor = 30 * time.Second
	unknownRoutingRTTMs    = int64(10)
)

const (
	rttSourceTAPICMP    = "tap-icmp"
	rttSourceLibp2pPing = "libp2p-ping"
	rttSourceP2PEcho    = "p2p-echo"
)

type peerRTTProbeSample struct {
	at      time.Time
	rtt     time.Duration
	success bool
}

type peerRTTState struct {
	bySource map[string][]peerRTTProbeSample
}

type peerRTTSnapshot struct {
	rttMs           float64
	rttMeasured     bool
	source          string
	sampleCount     int
	updatedAt       time.Time
	jitterMs        float64
	jitterMeasured  bool
	lossRatePercent float64
	lossMeasured    bool
}

// recordPeerRTTProbe records one completed measurement attempt. Failed probes
// are first-class samples: omitting them is exactly how a dashboard ends up
// claiming 0% loss while the path is timing out.
func (n *Node) recordPeerRTTProbe(pid peer.ID, source string, rtt time.Duration, success bool) {
	n.recordPeerRTTProbeAt(pid, source, rtt, success, time.Now())
}

func (n *Node) recordPeerRTTProbeAt(pid peer.ID, source string, rtt time.Duration, success bool, at time.Time) {
	if n == nil || pid == "" || source == "" {
		return
	}
	if !success {
		rtt = 0
	}
	n.peerRTTMu.Lock()
	if n.peerRTT == nil {
		n.peerRTT = make(map[peer.ID]*peerRTTState)
	}
	state := n.peerRTT[pid]
	if state == nil {
		state = &peerRTTState{bySource: make(map[string][]peerRTTProbeSample)}
		n.peerRTT[pid] = state
	}
	samples := append(state.bySource[source], peerRTTProbeSample{at: at, rtt: rtt, success: success})
	if len(samples) > peerRTTWindowSize {
		copy(samples, samples[len(samples)-peerRTTWindowSize:])
		samples = samples[:peerRTTWindowSize]
	}
	state.bySource[source] = samples
	n.peerRTTMu.Unlock()
}

// peerRTTMeasurement returns only measured telemetry. A recent real TAP/ICMP
// probe wins over control-stream probes; a recent manual libp2p ping wins over
// the background echo. This prevents the next 10-second keepalive from
// immediately overwriting the full data-plane result the operator just asked
// for.
func (n *Node) peerRTTMeasurement(pid peer.ID, now time.Time) peerRTTSnapshot {
	if n == nil || pid == "" {
		return peerRTTSnapshot{}
	}
	n.peerRTTMu.RLock()
	state := n.peerRTT[pid]
	if state == nil {
		n.peerRTTMu.RUnlock()
		return peerRTTSnapshot{}
	}
	bySource := make(map[string][]peerRTTProbeSample, len(state.bySource))
	for source, samples := range state.bySource {
		bySource[source] = append([]peerRTTProbeSample(nil), samples...)
	}
	n.peerRTTMu.RUnlock()

	chooseRecent := func(source string, maxAge time.Duration) []peerRTTProbeSample {
		samples := bySource[source]
		if len(samples) == 0 || now.Sub(samples[len(samples)-1].at) > maxAge {
			return nil
		}
		return samples
	}

	var source string
	var samples []peerRTTProbeSample
	if samples = chooseRecent(rttSourceTAPICMP, tapRTTPreferredFor); len(samples) > 0 {
		source = rttSourceTAPICMP
	} else if samples = chooseRecent(rttSourceLibp2pPing, manualPingPreferredFor); len(samples) > 0 {
		source = rttSourceLibp2pPing
	} else if samples = chooseRecent(rttSourceP2PEcho, backgroundEchoFreshFor); len(samples) > 0 {
		source = rttSourceP2PEcho
	} else {
		return peerRTTSnapshot{}
	}
	return summarizePeerRTTSamples(source, samples)
}

func summarizePeerRTTSamples(source string, samples []peerRTTProbeSample) peerRTTSnapshot {
	snap := peerRTTSnapshot{source: source, sampleCount: len(samples), lossMeasured: len(samples) > 0}
	if len(samples) == 0 {
		return snap
	}
	var successes []float64
	for _, sample := range samples {
		if sample.success && sample.rtt > 0 {
			successes = append(successes, float64(sample.rtt.Microseconds())/1000.0)
			snap.updatedAt = sample.at
		}
	}
	snap.lossRatePercent = float64(len(samples)-len(successes)) * 100 / float64(len(samples))
	if len(successes) == 0 {
		return snap
	}
	snap.rttMeasured = true
	var rttSum float64
	for _, rttMs := range successes {
		rttSum += rttMs
	}
	snap.rttMs = rttSum / float64(len(successes))
	if len(successes) > 1 {
		var jitterSum float64
		for i := 1; i < len(successes); i++ {
			jitterSum += math.Abs(successes[i] - successes[i-1])
		}
		snap.jitterMs = jitterSum / float64(len(successes)-1)
		snap.jitterMeasured = true
	}
	return snap
}

// routingPeerLatencyMs is intentionally separate from displayed telemetry.
// Dijkstra needs a positive provisional edge cost before the first probe, but
// that cost is an internal estimate and must never be presented as measured
// RTT in /api/stats.
func (n *Node) routingPeerLatencyMs(pid peer.ID) int64 {
	if measured := n.getPeerLatency(pid); measured > 0 {
		return measured
	}
	return unknownRoutingRTTMs
}

func formatMeasurementTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}
