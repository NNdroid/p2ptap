package main

import (
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
)

// relaySession holds metadata about one active Circuit Relay v2 connection.
type relaySession struct {
	SrcPeer   peer.ID
	DstPeer   peer.ID
	NetworkID string
	StartTime time.Time
}

// sessionTracker keeps a live map of in-flight relay sessions keyed by
// "src→dst". AllowConnect records a session on success; DisconnectedF prunes
// all sessions for a disconnecting peer. All operations are O(n) in the number
// of sessions but that number is bounded by MaxReservations (≤1024).
type sessionTracker struct {
	mu       sync.RWMutex
	sessions map[string]*relaySession
}

func newSessionTracker() *sessionTracker {
	return &sessionTracker{
		sessions: make(map[string]*relaySession),
	}
}

func sessionKey(src, dst peer.ID) string {
	return src.String() + "->" + dst.String()
}

// Add records a new relay session between src and dst. If a session for the
// same pair already exists (e.g. a rapid retry) it is overwritten.
func (t *sessionTracker) Add(src, dst peer.ID, netID string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.sessions[sessionKey(src, dst)] = &relaySession{
		SrcPeer:   src,
		DstPeer:   dst,
		NetworkID: netID,
		StartTime: time.Now(),
	}
}

// RemoveForPeer removes all sessions where p is either the source or destination.
// Called when a peer fully disconnects so stale sessions don't pile up.
func (t *sessionTracker) RemoveForPeer(p peer.ID) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for k, s := range t.sessions {
		if s.SrcPeer == p || s.DstPeer == p {
			delete(t.sessions, k)
		}
	}
}

// GetAll returns a snapshot of all current sessions (copy, safe to read after unlock).
func (t *sessionTracker) GetAll() []*relaySession {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make([]*relaySession, 0, len(t.sessions))
	for _, s := range t.sessions {
		cp := *s
		out = append(out, &cp)
	}
	return out
}

// Count returns the number of currently tracked sessions.
func (t *sessionTracker) Count() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.sessions)
}

// PruneStale evicts sessions that have exceeded maxAge (e.g. 10 minutes)
// so expired relay circuits don't linger indefinitely during long-term 24/7 operation.
func (t *sessionTracker) PruneStale(maxAge time.Duration) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()
	pruned := 0
	for k, s := range t.sessions {
		if now.Sub(s.StartTime) > maxAge {
			delete(t.sessions, k)
			pruned++
		}
	}
	return pruned
}
