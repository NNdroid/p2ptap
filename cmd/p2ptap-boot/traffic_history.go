package main

import (
	"context"
	"sync"
	"time"
)

// trafficSample is one time-series data point recorded every minute.
type trafficSample struct {
	At         time.Time
	PeerCount  int
	RelayCount int
}

// trafficHistory is a fixed-capacity ring buffer of per-minute traffic samples.
// The background sampler goroutine calls Record() on a ticker; the WebUI reads
// GetAll() on each dashboard poll without blocking the sampler.
type trafficHistory struct {
	mu     sync.RWMutex
	buf    []trafficSample
	maxLen int
}

func newTrafficHistory(maxLen int) *trafficHistory {
	if maxLen <= 0 {
		maxLen = 60
	}
	return &trafficHistory{
		buf:    make([]trafficSample, 0, maxLen),
		maxLen: maxLen,
	}
}

// Record appends a sample, evicting the oldest entry when the buffer is full.
func (h *trafficHistory) Record(peerCount, relayCount int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.buf) >= h.maxLen {
		h.buf = h.buf[1:]
	}
	h.buf = append(h.buf, trafficSample{
		At:         time.Now(),
		PeerCount:  peerCount,
		RelayCount: relayCount,
	})
}

// GetAll returns a chronological copy of all buffered samples.
func (h *trafficHistory) GetAll() []trafficSample {
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := make([]trafficSample, len(h.buf))
	copy(out, h.buf)
	return out
}

// runTrafficSampler starts a background goroutine that calls Record() every
// minute using peerCountFn and relayCountFn to obtain current values.
// It records an initial sample immediately before starting the ticker so the
// chart has at least one point even before the first minute elapses.
func runTrafficSampler(ctx context.Context, h *trafficHistory, peerCountFn func() int, relayCountFn func() int) {
	go func() {
		h.Record(peerCountFn(), relayCountFn())
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				h.Record(peerCountFn(), relayCountFn())
			}
		}
	}()
}
