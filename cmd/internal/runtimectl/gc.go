// Package runtimectl applies process-wide Go runtime tuning for the daemons.
//
// The data plane pools tens of MiB of frame buffers (dispatchCh 16K × 2KB +
// tapWriteCh 4K × 2KB alone ≈ 40 MiB) on top of the libp2p host, so the default
// GOGC=100 makes the collector run roughly once per daemon-sized heap — at
// throughput that is a constant background tax. A higher GOGC plus a soft
// GOMEMLIMIT is the Go team's recommended pairing: the collector stays lazy at
// normal load while the limit keeps the heap from growing into physical OOM on
// small boxes (OpenWrt, Android).
//
// Standard environment variables always win: when the operator sets GOGC or
// GOMEMLIMIT explicitly the corresponding programmatic default is skipped, so
// existing deployments that already tune the runtime keep their exact values.
package runtimectl

import (
	"os"
	"runtime/debug"

	"github.com/pbnjay/memory"
)

// envOrBlank returns the environment variable's value, treating an empty
// setting as unset.
func envOrBlank(key string) string {
	return os.Getenv(key)
}

const (
	// defaultGOGCPercent raises the collector target to 3x the live heap.
	// The frame pools keep the live heap small and flat, so this primarily
	// reduces GC *frequency*; allocation latency per frame is unchanged.
	defaultGOGCPercent = 300
	// defaultMemLimitFraction caps the Go heap at 80% of physical RAM as a
	// SOFT limit: as the process approaches it the collector runs harder
	// instead of the kernel running out of memory. 80% leaves headroom for
	// the non-Go parts of the process (cgo, kernel socket buffers) and for
	// co-located services on the same box.
	defaultMemLimitFraction = 0.8
)

// ApplyGCTuning installs the defaults above unless the operator has already
// spoken through the environment. info receives one line describing what was
// applied so the effective values are visible in the log at startup.
func ApplyGCTuning(info func(format string, args ...any)) {
	if info == nil {
		info = func(string, ...any) {}
	}
	if env := envOrBlank("GOGC"); env != "" {
		info("GC: honoring GOGC=%s from the environment", env)
	} else {
		debug.SetGCPercent(defaultGOGCPercent)
		info("GC: GOGC default %d (set GOGC to override)", defaultGOGCPercent)
	}
	if env := envOrBlank("GOMEMLIMIT"); env != "" {
		info("GC: honoring GOMEMLIMIT=%s from the environment", env)
		return
	}
	if total := memory.TotalMemory(); total > 0 {
		limit := int64(float64(total) * defaultMemLimitFraction)
		debug.SetMemoryLimit(limit)
		info("GC: GOMEMLIMIT default %d MiB (80%% of %d MiB RAM; set GOMEMLIMIT to override)",
			limit>>20, total>>20)
	}
	// Unknown total memory (some containers/embedded targets): leave the
	// runtime's infinite default limit in place rather than guessing.
}
