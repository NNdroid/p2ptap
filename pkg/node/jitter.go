package node

import (
	"time"

	randv2 "math/rand/v2"
)

// keepaliveJitterFrac is the ± fraction applied to the wire-visible periodic
// timers (peer ping-pong keepalive, LSA flood, metadata sync, bootstrap
// reconnect, discovery tick). These are the loops whose FIXED cadence is a
// passive-fingerprint tell: a node that does the exact same thing every 10s /
// 15s / 20s is trivially distinguished from real application traffic and can be
// identified by timing alone, independent of the encrypted payload.
//
// Jittering each interval by ±20% (≈±2-4s on these periods) breaks the periodic
// signature while leaving the loops' function intact: keepalive still detects a
// dead peer within a couple of periods, LSA/meta still converge, discovery still
// finds peers. The spread is deliberately well under the interval so no loop
// ever meaningfully slows relative to its designed period, and it is per-node
// random so two nodes never lock into a shared beat.
const keepaliveJitterFrac = 0.20

// jitterInterval returns base ± a uniformly random keepaliveJitterFrac fraction.
// Values <= 0 are returned unchanged so callers never jitter a zero/disabled
// timer into a busy loop.
func jitterInterval(base time.Duration) time.Duration {
	if base <= 0 {
		return base
	}
	delta := float64(base) * keepaliveJitterFrac
	return time.Duration(float64(base) + (randv2.Float64()*2-1)*delta)
}

// newJitterTimer is a drop-in for time.NewTicker in a `select` loop that re-arms
// with fresh jitter after every fire:
//
//	timer := newJitterTimer(period)
//	defer timer.Stop()
//	for {
//	    select {
//	    case <-ctx.Done(): return
//	    case <-timer.C:
//	        ...work...
//	        timer.Reset(jitterInterval(period))
//	    }
//	}
func newJitterTimer(period time.Duration) *time.Timer {
	return time.NewTimer(jitterInterval(period))
}
