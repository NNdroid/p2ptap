package node

import (
	"github.com/libp2p/go-libp2p/core/network"
	"time"
)

const (
	// streamQualityFreshFor is how long a per-path write-quality sample stays
	// usable for the DWRR weight (and best_path selection) after its last write.
	// Under low traffic a path can go a long time between its min-share frames;
	// expiring the measurement after 30 s made it fall back to the coarse
	// topology-score nominal on every sparse burst, so the weight saw-toothed
	// and multipath assigned the wrong share of the budget. 5 minutes keeps the
	// measured weight stable across low-traffic gaps while still decaying a
	// sample whose path was genuinely replaced.
	streamQualityFreshFor   = 300 * time.Second
	streamSelectionInterval = time.Second
	streamSelectionHold     = 3 * time.Second
)

// Protected by PeerStreams.writeMu. Write completion measures local service
// cost/backpressure, not an acknowledgement of remote delivery. Comparisons
// require several substantial samples and a 20% improvement.
type streamWriteQuality struct {
	nanosPerByte float64
	bytes        int64
	samples      int
	updated      time.Time
}

func (ps *PeerStreams) recordStreamWrite(s network.Stream, bytes int, elapsed time.Duration, now time.Time) {
	if bytes <= 0 || elapsed <= 0 {
		return
	}
	ps.qualityMu.Lock()
	defer ps.qualityMu.Unlock()
	if ps.writeQuality == nil {
		ps.writeQuality = make(map[network.Stream]streamWriteQuality)
	}
	q := ps.writeQuality[s]
	value := float64(elapsed) / float64(bytes)
	if q.samples == 0 || now.Sub(q.updated) > streamQualityFreshFor {
		q = streamWriteQuality{nanosPerByte: value}
	} else {
		q.nanosPerByte = .75*q.nanosPerByte + .25*value
	}
	q.samples++
	q.bytes += int64(bytes)
	q.updated = now
	ps.writeQuality[s] = q
}

// qualityFor reads one stream's write-quality sample. It takes qualityMu
// itself so both writeMu-holding schedulers and the lock-free writer
// goroutines can call it safely.
func (ps *PeerStreams) qualityFor(s network.Stream) streamWriteQuality {
	ps.qualityMu.Lock()
	defer ps.qualityMu.Unlock()
	return ps.writeQuality[s]
}

func (q streamWriteQuality) usable(now time.Time) bool {
	return q.samples >= 3 && q.bytes >= 32*1024 && now.Sub(q.updated) <= streamQualityFreshFor && q.nanosPerByte > 0
}

// selectStreamIndex uses the stable topology order as its initial policy.
// Exploration sends one real batch per interval on another eligible stream;
// it creates no duplicate traffic or synthetic load. The single-stream caller
// bypasses this entire mechanism.
func (ps *PeerStreams) selectStreamIndex(streams []network.Stream, now time.Time) int {
	preferred := -1
	for i, s := range streams {
		if s == ps.preferredStream {
			preferred = i
			break
		}
	}
	if preferred >= 0 && now.Before(ps.nextStreamSelection) && ps.selectionSnapshot == ps.snapshot.Load() {
		return preferred
	}
	ps.selectionSnapshot = ps.snapshot.Load()
	initial := preferred < 0
	if preferred < 0 || scoreStreamTransport(streams[preferred], ps.peerID) > scoreStreamTransport(streams[0], ps.peerID) {
		preferred = 0
		ps.preferredStream = streams[0]
		ps.streamSelectedAt = now
	}
	if initial {
		ps.nextStreamSelection = now.Add(streamSelectionInterval)
		return preferred
	}
	// Bound retained metrics when topology replaces streams.
	ps.qualityMu.Lock()
	for s := range ps.writeQuality {
		active := false
		for _, current := range streams {
			if s == current {
				active = true
				break
			}
		}
		if !active {
			delete(ps.writeQuality, s)
		}
	}
	ps.qualityMu.Unlock()
	score := scoreStreamTransport(streams[preferred], ps.peerID)
	// Snapshot every stream's quality under one lock: the loop below otherwise
	// re-reads the map through qualityFor up to three times per candidate, each
	// a separate mutex acquisition on a hot scheduling path.
	ps.qualityMu.Lock()
	incumbent := ps.writeQuality[streams[preferred]]
	best := preferred
	bestQ := incumbent
	for i, s := range streams {
		q := ps.writeQuality[s]
		if scoreStreamTransport(s, ps.peerID) != score || !q.usable(now) {
			continue
		}
		if !bestQ.usable(now) || q.nanosPerByte < bestQ.nanosPerByte {
			best = i
			bestQ = q
		}
	}
	if best != preferred && now.Sub(ps.streamSelectedAt) >= streamSelectionHold && (!incumbent.usable(now) || bestQ.nanosPerByte < incumbent.nanosPerByte*.8) {
		preferred = best
		ps.preferredStream = streams[best]
		ps.streamSelectedAt = now
	}
	ps.qualityMu.Unlock()
	ps.nextStreamSelection = now.Add(streamSelectionInterval)
	// Rotate the exploratory batch. A failed probe is retired by the normal
	// deadline/reset/retry path; it does not replace the healthy incumbent.
	for i := 0; i < len(streams); i++ {
		ps.streamProbeCursor = (ps.streamProbeCursor + 1) % len(streams)
		candidate := ps.streamProbeCursor
		if candidate != preferred && scoreStreamTransport(streams[candidate], ps.peerID) == score {
			return candidate
		}
	}
	return preferred
}
