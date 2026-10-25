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
	mu      sync.RWMutex
	events  []UnauthEvent
	max     int
	counters map[string]*atomic.Int64
	total   atomic.Int64
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
	t := &UnauthTracker{
		events: make([]UnauthEvent, 0, max),
		max:    max,
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
	if len(t.events) >= t.max {
		t.events = t.events[1:]
	}
	t.events = append(t.events, ev)
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
	n := len(t.events)
	if n > 0 {
		stats.RecentEvents = make([]UnauthEvent, n)
		for i := range t.events {
			stats.RecentEvents[n-1-i] = t.events[i]
		}
	}
	t.mu.RUnlock()

	return stats
}
