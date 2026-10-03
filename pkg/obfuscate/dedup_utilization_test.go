package obfuscate

import (
	"math/bits"
	"math/rand"
	"testing"
)

// Compare telemetry with the actual replay bitmap across every mutation path.
// Acceptance decisions remain covered by the existing dedup/replay tests.
func TestDedupUtilizationMatchesBitmap(t *testing.T) {
	d := NewDeduplicator()
	check := func() {
		t.Helper()
		d.mu.Lock()
		var population uint64
		for _, word := range d.recvd {
			population += uint64(bits.OnesCount64(word))
		}
		d.mu.Unlock()
		want := float64(population) / float64(counterWindow*64)
		if got := d.WindowUtilization(); got != want {
			t.Fatalf("utilization = %v, bitmap population = %d (want %v)", got, population, want)
		}
	}
	check()
	d.SyncFrom(buildSeqID(1, 65500))
	check()
	for counter := uint64(65501); counter < 100000; counter++ {
		d.IsDuplicate(buildSeqID(1, counter))
		if counter%257 == 0 {
			check()
		}
	}
	check()
	rng := rand.New(rand.NewSource(42))
	for i := 0; i < 3000; i++ {
		// Reordering, exact duplicates, and forward/backward re-anchors.
		d.IsDuplicate(buildSeqID(1, uint64(rng.Intn(150000))))
		check()
	}
	d.SetConnEpoch(2)
	check()
	d.IsDuplicate(buildSeqID(1, 100)) // rejected epoch must not add a bit
	check()
	d.IsDuplicate(buildSeqID(2, 100))
	check()
	d.SyncFrom(buildSeqID(2, 200))
	check()
}
