package vswitch

import (
	"net"
	"sync"
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
)

// TestMACTable_LearnConcurrentDistinctMACs verifies the fix for the lost-update
// race in LearnWithIP: concurrent learners of DISTINCT new MACs, each under its
// OWN peer (so the MaxMACsPerPeer circuit breaker is never tripped), must all
// be present and each counted exactly once — no lost entries and no over-count.
func TestMACTable_LearnConcurrentDistinctMACs(t *testing.T) {
	t.Parallel()
	table := NewMACTable()
	const goroutines = 32

	macs := make([]net.HardwareAddr, goroutines)
	peers := make([]peer.ID, goroutines)
	for i := 0; i < goroutines; i++ {
		m := make(net.HardwareAddr, 6)
		m[5] = byte(i + 1)
		macs[i] = m
		peers[i] = peer.ID("peer-" + string(rune('A'+i)))
	}

	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			table.Learn(macs[i], peers[i])
		}(i)
	}
	wg.Wait()

	// Every distinct (mac, peer) must be present with no lost updates.
	for i := 0; i < goroutines; i++ {
		if pid, ok := table.Lookup(macs[i]); !ok || pid != peers[i] {
			t.Fatalf("Lookup(mac[%d]) = (%v, %v), want (%v, true)", i, pid, ok, peers[i])
		}
	}
	// No peer may be over-counted: each registered exactly one MAC.
	table.peerCountsMu.Lock()
	for i := 0; i < goroutines; i++ {
		if c := table.peerCounts[peers[i]]; c != 1 {
			t.Fatalf("peerCounts[%q] = %d, want 1", peers[i], c)
		}
	}
	table.peerCountsMu.Unlock()
}

// TestMACTable_LearnConcurrentSameMAC verifies that concurrent learners of the
// SAME new MAC do not clobber each other's IP field and do not double-count the
// single MAC (the race this fix targets).
func TestMACTable_LearnConcurrentSameMAC(t *testing.T) {
	t.Parallel()
	table := NewMACTable()
	mac := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x09}

	const iters = 100
	var wg sync.WaitGroup
	for i := 0; i < iters; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			table.LearnWithIP(mac, "10.0.0.9", peer.ID("peer"))
		}()
	}
	wg.Wait()

	pid, ok := table.Lookup(mac)
	if !ok {
		t.Fatal("MAC not present after concurrent Learn")
	}
	if pid != peer.ID("peer") {
		t.Errorf("Lookup = %q, want peer", pid)
	}

	table.peerCountsMu.Lock()
	got := table.peerCounts[peer.ID("peer")]
	table.peerCountsMu.Unlock()
	if got != 1 {
		t.Fatalf("peerCounts = %d, want 1 (same MAC must count once)", got)
	}
}
