package main

import (
	"sync"
	"sync/atomic"
	"time"
)

// UnauthEvent represents a single rejected/dropped unauthenticated data event.
type UnauthEvent struct {
	Timestamp string // "15:04:05"
	Type      string // event category
	PeerID    string // short peer ID
	Detail    string // human-readable detail
}

// UnauthStats holds aggregate counters and recent events for unauthenticated data.
type UnauthStats struct {
	TotalDropped int64            // total frames/events dropped due to auth failure
	ByType       map[string]int64 // per-category counters
	RecentEvents []UnauthEvent    // newest-first ring buffer (capped)
}

// UnauthTracker is a thread-safe tracker for unauthenticated data events.
// It maintains atomic per-category counters and a ring buffer of recent events.
type UnauthTracker struct {
	mu       sync.RWMutex
	ring     []UnauthEvent // fixed-capacity ring, written in place
	start    int           // index of the OLDEST live event
	count    int           // live events, <= len(ring)
	counters map[string]*atomic.Int64
	total    atomic.Int64
}

// Unauth event type constants.
const (
	unauthTypeRelayFrame = "relay_frame" // data frame dropped: unauth source
	unauthTypeRelayCtrl  = "relay_ctrl"  // relay-ctrl tunnel dropped
	unauthTypeBootRelay  = "boot_relay"  // boot-relay client rejected
	unauthTypeMeta       = "meta"        // meta request rejected
	unauthTypeEcho       = "echo"        // echo request rejected
	unauthTypeSeqSync    = "seqsync"     // seqsync request rejected
	unauthTypePeekMap    = "peek_map"    // peek-map request rejected
	unauthTypeAuthFail   = "auth_fail"   // PSK authentication failure
	unauthTypeSpoofed    = "spoofed"     // spoofed frame dropped
)

var unauthTracker = newUnauthTracker(200)

func newUnauthTracker(max int) *UnauthTracker {
	// The ring is indexed with %len, so it must never be zero-length.
	if max <= 0 {
		max = 200
	}
	t := &UnauthTracker{
		ring:     make([]UnauthEvent, max),
		counters: make(map[string]*atomic.Int64),
	}
	for _, typ := range []string{
		unauthTypeRelayFrame, unauthTypeRelayCtrl, unauthTypeBootRelay,
		unauthTypeMeta, unauthTypeEcho, unauthTypeSeqSync,
		unauthTypePeekMap, unauthTypeAuthFail, unauthTypeSpoofed,
	} {
		t.counters[typ] = &atomic.Int64{}
	}
	return t
}

// Record adds an event to the tracker. It is safe for concurrent use.
func (t *UnauthTracker) Record(eventType, peerID, detail string) {
	now := time.Now().Format("15:04:05")
	ev := UnauthEvent{Timestamp: now, Type: eventType, PeerID: peerID, Detail: detail}

	t.total.Add(1)
	if c, ok := t.counters[eventType]; ok {
		c.Add(1)
	}

	t.mu.Lock()
	// Write into the preallocated ring in place; start marks the oldest live
	// slot and count how many slots are live, so both move with the write.
	if t.count < len(t.ring) {
		t.ring[(t.start+t.count)%len(t.ring)] = ev
		t.count++
	} else {
		t.ring[t.start] = ev
		t.start = (t.start + 1) % len(t.ring)
	}
	t.mu.Unlock()
}

// Stats returns the current aggregate statistics and recent events.
func (t *UnauthTracker) Stats() UnauthStats {
	stats := UnauthStats{
		TotalDropped: t.total.Load(),
		ByType:       make(map[string]int64),
	}
	for typ, c := range t.counters {
		stats.ByType[typ] = c.Load()
	}

	t.mu.RLock()
	// Newest first, matching the previous slice-backed buffer.
	n := t.count
	if n > 0 {
		stats.RecentEvents = make([]UnauthEvent, n)
		for i := range stats.RecentEvents {
			stats.RecentEvents[n-1-i] = t.ring[(t.start+i)%len(t.ring)]
		}
	}
	t.mu.RUnlock()

	return stats
}
