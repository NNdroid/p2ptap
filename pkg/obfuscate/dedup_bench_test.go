package obfuscate

import "testing"

// Match the receive loop: advance the window and read its utilization for
// telemetry on every accepted packet, including after the 16-bit ring wraps.
func BenchmarkDedupReceiveTelemetry(b *testing.B) {
	d := NewDeduplicator()
	var counter uint64
	b.ReportAllocs()
	for b.Loop() {
		counter++
		if d.IsDuplicate(buildSeqID(1, counter)) {
			b.Fatal("fresh sequence rejected")
		}
		_ = d.WindowUtilization()
	}
}
