package main

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
)

// SecurityManager coordinates defensive protections for public-facing p2ptap-boot.
type SecurityManager struct {
	Auth    *AuthRateLimiter
	PeekMap *PeerRateLimiter
}

func newSecurityManager() *SecurityManager {
	return &SecurityManager{
		Auth:    newAuthRateLimiter(),
		PeekMap: newPeerRateLimiter(20, 40), // 20 msgs/sec, burst 40
	}
}

func (sm *SecurityManager) Cleanup() {
	if sm == nil {
		return
	}
	sm.Auth.Cleanup()
	sm.PeekMap.Cleanup()
}

// authFailureRecord tracks failed authentication attempts for an IP or Peer.
type authFailureRecord struct {
	count     int
	firstSeen time.Time
	lastSeen  time.Time
	bannedTo  time.Time
}

// AuthRateLimiter mitigates brute-force attacks on PSK authentication endpoints.
type AuthRateLimiter struct {
	mu          sync.Mutex
	ipFailures  map[string]*authFailureRecord
	pidFailures map[peer.ID]*authFailureRecord
}

func newAuthRateLimiter() *AuthRateLimiter {
	return &AuthRateLimiter{
		ipFailures:  make(map[string]*authFailureRecord),
		pidFailures: make(map[peer.ID]*authFailureRecord),
	}
}

// IsBanned reports whether an IP address or Peer ID is currently in a temporary ban state.
func (l *AuthRateLimiter) IsBanned(ipStr string, pid peer.ID) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()

	if ipStr != "" {
		if rec, ok := l.ipFailures[ipStr]; ok && now.Before(rec.bannedTo) {
			return true
		}
	}
	if rec, ok := l.pidFailures[pid]; ok && now.Before(rec.bannedTo) {
		return true
	}
	return false
}

// RecordFailure records a failed authentication attempt and calculates backoff / ban state.
func (l *AuthRateLimiter) RecordFailure(ipStr string, pid peer.ID) (banned bool, delay time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()

	updateRec := func(rec *authFailureRecord) (bool, time.Duration) {
		if now.Sub(rec.lastSeen) > 5*time.Minute {
			rec.count = 1
			rec.firstSeen = now
		} else {
			rec.count++
		}
		rec.lastSeen = now

		// After 10 failures within 5 minutes, ban for 5 minutes
		if rec.count >= 10 {
			rec.bannedTo = now.Add(5 * time.Minute)
			return true, 1 * time.Second
		}
		// Progressive exponential delay between 3 and 9 failures
		if rec.count >= 3 {
			d := time.Duration(rec.count-2) * 250 * time.Millisecond
			if d > 2*time.Second {
				d = 2 * time.Second
			}
			return false, d
		}
		return false, 0
	}

	if ipStr != "" {
		rec, ok := l.ipFailures[ipStr]
		if !ok {
			rec = &authFailureRecord{firstSeen: now}
			l.ipFailures[ipStr] = rec
		}
		banned, delay = updateRec(rec)
	}

	if pid != "" {
		rec, ok := l.pidFailures[pid]
		if !ok {
			rec = &authFailureRecord{firstSeen: now}
			l.pidFailures[pid] = rec
		}
		b, d := updateRec(rec)
		if b {
			banned = true
		}
		if d > delay {
			delay = d
		}
	}

	return banned, delay
}

// RecordSuccess clears failure history on a successful authentication.
func (l *AuthRateLimiter) RecordSuccess(ipStr string, pid peer.ID) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if ipStr != "" {
		delete(l.ipFailures, ipStr)
	}
	if pid != "" {
		delete(l.pidFailures, pid)
	}
}

// Cleanup removes expired ban and failure records.
func (l *AuthRateLimiter) Cleanup() {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()

	for ip, rec := range l.ipFailures {
		if now.After(rec.bannedTo) && now.Sub(rec.lastSeen) > 10*time.Minute {
			delete(l.ipFailures, ip)
		}
	}
	for pid, rec := range l.pidFailures {
		if now.After(rec.bannedTo) && now.Sub(rec.lastSeen) > 10*time.Minute {
			delete(l.pidFailures, pid)
		}
	}
}

// tokenBucket implements a standard token bucket for rate-limiting messages per peer.
type tokenBucket struct {
	tokens     float64
	capacity   float64
	rate       float64 // tokens per second
	lastRefill time.Time
}

func (tb *tokenBucket) allow() bool {
	now := time.Now()
	elapsed := now.Sub(tb.lastRefill).Seconds()
	tb.lastRefill = now

	tb.tokens += elapsed * tb.rate
	if tb.tokens > tb.capacity {
		tb.tokens = tb.capacity
	}

	if tb.tokens >= 1.0 {
		tb.tokens -= 1.0
		return true
	}
	return false
}

// PeerRateLimiter limits message rates per connected peer ID to prevent broadcast flooding and CPU exhaustion.
type PeerRateLimiter struct {
	mu      sync.Mutex
	buckets map[peer.ID]*tokenBucket
	rate    float64
	burst   float64
}

func newPeerRateLimiter(rate, burst float64) *PeerRateLimiter {
	return &PeerRateLimiter{
		buckets: make(map[peer.ID]*tokenBucket),
		rate:    rate,
		burst:   burst,
	}
}

// Allow reports whether an incoming message from peer p is within the allowed rate limit.
func (prl *PeerRateLimiter) Allow(p peer.ID) bool {
	prl.mu.Lock()
	defer prl.mu.Unlock()

	tb, ok := prl.buckets[p]
	if !ok {
		tb = &tokenBucket{
			tokens:     prl.burst,
			capacity:   prl.burst,
			rate:       prl.rate,
			lastRefill: time.Now(),
		}
		prl.buckets[p] = tb
	}
	return tb.allow()
}

// Remove removes tracking state for a disconnected peer.
func (prl *PeerRateLimiter) Remove(p peer.ID) {
	prl.mu.Lock()
	defer prl.mu.Unlock()
	delete(prl.buckets, p)
}

// Cleanup evicts stale token buckets for peers that have been idle for > 15 minutes.
func (prl *PeerRateLimiter) Cleanup() {
	prl.mu.Lock()
	defer prl.mu.Unlock()
	now := time.Now()
	for pid, tb := range prl.buckets {
		if now.Sub(tb.lastRefill) > 15*time.Minute {
			delete(prl.buckets, pid)
		}
	}
}

// cleanIP extracts and validates IP from string, ignoring port or loopback/private nuances.
func cleanIPStr(raw string) string {
	ip := net.ParseIP(raw)
	if ip == nil {
		return ""
	}
	return ip.String()
}

// formatSecurityAlert creates human-readable alert message
func formatSecurityAlert(reason, src string) string {
	return fmt.Sprintf("⚠️ 安全防护: %s (来源: %s)", reason, src)
}
