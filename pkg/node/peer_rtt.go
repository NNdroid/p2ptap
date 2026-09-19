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

// routingRTTMsFromSnapshot converts a COMPLETED probe into the integral
// millisecond edge weight the link-state graph stores. It returns ok=false when
// no probe has completed, so the caller can install a provisional estimate
// instead of a fabricated measurement.
//
// The weight is clamped to >=1ms because the graph encodes "no edge" as an
// absent entry and 0 as a meaningless cost: a genuine sub-millisecond LAN RTT
// must not collapse into the "unknown" zero.
func routingRTTMsFromSnapshot(snap peerRTTSnapshot) (int64, bool) {
	if !snap.rttMeasured || snap.rttMs <= 0 {
		return 0, false
	}
	ms := int64(math.Round(snap.rttMs))
	if ms < 1 {
		ms = 1
	}
	return ms, true
}

// preferredLinkRTTMs picks the authoritative link weight for one peer.
//
// A completed probe outranks the peerstore EWMA: the EWMA is a smoothed
// control-plane figure that libp2p only updates on its own schedule, while the
// probe is a real round trip over the path the operator is looking at. The EWMA
// is therefore a provisional fallback, used only until the first probe returns
// so a freshly connected peer is not stuck on the synthetic edge cost.
//
// This precedence is the single source of truth for the routing graph's view of
// a link: inverting it made the Mesh Quality matrix (fed by the graph) and the
// topology chart (fed by PeerInfoDTO) report different latencies for the same
// link in the same stats tick.
func preferredLinkRTTMs(snap peerRTTSnapshot, peerstoreEWMAMs int64) (int64, bool) {
	if ms, ok := routingRTTMsFromSnapshot(snap); ok {
		return ms, true
	}
	if peerstoreEWMAMs > 0 {
		return peerstoreEWMAMs, true
	}
	return 0, false
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
