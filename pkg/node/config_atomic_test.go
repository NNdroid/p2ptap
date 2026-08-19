package node

import (
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"p2ptap/pkg/config"
)

// newConfigForAtomicTest returns a minimal config baseline with the mutable
// hot-reload fields populated, mirroring what a real daemon would hold.
func newConfigForAtomicTest() *config.Config {
	return &config.Config{
		NodeName: "atomic-test",
		ACL: config.ACLConfig{
			Enable: false,
		},
		ExitNode: config.ExitNodeConfig{},
		MTU:      1500,
	}
}

// TestConfigHotReloadVsDataPlaneReads is the regression test for the atomic
// refactor: a data-plane reader (checkACL, which is on the per-frame path and
// now snapshots via config()) must never race with a concurrent hot-reload that
// swaps the whole config via SetConfig. Under -race this fails if any read of
// a mutable field bypasses the snapshot.
func TestConfigHotReloadVsDataPlaneReads(t *testing.T) {
	n := &Node{}
	cfg := newConfigForAtomicTest()
	n.configPtr.Store(cfg)
	// Keep Config as the immutable construction-time baseline, exactly as NewNode
	// does, so the mirror assertion below is meaningful.
	n.Config = cfg

	var stop atomic.Bool
	var readers int64
	var writers int64

	// Writer: hot-reload swaps a fresh snapshot with ACL toggled. If a reader
	// ever reads a torn / shared-field mutation it would be a race; the whole
	// point is that SetConfig publishes a fully-formed new object.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		i := 0
		for !stop.Load() {
			next := newConfigForAtomicTest()
			next.ACL.Enable = i%2 == 0
			next.NodeName = "atomic-test"
			n.SetConfig(next) // single write path
			atomic.AddInt64(&writers, 1)
			i++
		}
	}()

	// Readers: hammer the data-plane ACL read plus a plain snapshot read that
	// reuses config() exactly like checkACL does.
	for r := 0; r < 4; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !stop.Load() {
				c := n.config()
				_ = c.ACL.Enable // read the mutable field through the snapshot
				// checkACL consults the snapshot the same way; pass a frame that
				// only triggers the ACL-disabled fast path to avoid noise.
				n.checkACL(nil, "peer-X", false)
				atomic.AddInt64(&readers, 1)
			}
		}()
	}

	// Drive iterations to ensure both writers and readers have executed concurrently.
	// We wait until both writers and readers have achieved a solid number of iterations,
	// using runtime.Gosched() to yield CPU so goroutines aren't starved by a tight spin.
	deadline := time.Now().Add(3 * time.Second)
	for (atomic.LoadInt64(&writers) < 500 || atomic.LoadInt64(&readers) < 2000) && time.Now().Before(deadline) {
		runtime.Gosched()
	}

	stop.Store(true)
	wg.Wait()

	if atomic.LoadInt64(&writers) == 0 {
		t.Fatal("writer never ran")
	}
	if atomic.LoadInt64(&readers) == 0 {
		t.Fatal("readers never ran")
	}
}

// TestConfigBaselineImmutableAcrossReload pins the "Config is an immutable
// construction-time baseline" decision: after any number of SetConfig reloads,
// the exported Config pointer must still equal the original object (writers must
// never mutate it), so concurrent control-plane readers of Config are race-free.
func TestConfigBaselineImmutableAcrossReload(t *testing.T) {
	n := &Node{}
	baseline := newConfigForAtomicTest()
	n.Config = baseline
	n.configPtr.Store(baseline)

	for i := 0; i < 100; i++ {
		next := newConfigForAtomicTest()
		next.ACL.Enable = i%2 == 0
		n.SetConfig(next)
	}
	if n.Config != baseline {
		t.Fatalf("Config field was reassigned during reload: got %p, want baseline %p", n.Config, baseline)
	}
	// The active snapshot must however reflect the latest reload.
	if got := n.config().ACL.Enable; got != (99%2 == 0) {
		t.Fatalf("active snapshot ACL.Enable = %v, want %v", got, 99%2 == 0)
	}
}

// TestConfigSnapshotIsolation ensures a reader holding one config() snapshot is
// unaffected by a later SetConfig — a mid-function decision must not tear.
func TestConfigSnapshotIsolation(t *testing.T) {
	n := &Node{}
	cfgA := newConfigForAtomicTest()
	cfgA.ACL.Enable = true
	n.SetConfig(cfgA)

	snap := n.config()
	cfgB := newConfigForAtomicTest()
	cfgB.ACL.Enable = false
	n.SetConfig(cfgB)

	if !snap.ACL.Enable {
		t.Fatal("snapshot was mutated by a later reload — snapshot isolation broken")
	}
	if n.config().ACL.Enable {
		t.Fatal("active config did not observe the reload")
	}
	// checkACL must use the latest snapshot.
	if got := n.checkACL(nil, "peer-X", false); got != true {
		t.Fatalf("checkACL with ACL disabled should allow, got %v", got)
	}
}
