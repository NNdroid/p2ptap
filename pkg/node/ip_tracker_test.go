package node

import (
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"p2ptap/pkg/observer"
)

func TestIPTrackerEvictsIdleEntries(t *testing.T) {
	tr := NewIPTrafficTracker()
	tr.RecordTx("1.2.3.4", 100)

	// Force the entry to look idle for > 24h.
	item, ok := tr.stats.Load("1.2.3.4")
	if !ok {
		t.Fatal("expected 1.2.3.4 to be tracked")
	}
	item.(*ipStatItem).lastActive.Store(time.Now().Unix() - 100000)

	dtos := tr.GetDTOs(&sync.Map{}, "", "", "", "", nil, "")
	for i := range dtos {
		if dtos[i].IP == "1.2.3.4" {
			t.Fatalf("idle IP 1.2.3.4 should have been evicted (got %d DTOs)", len(dtos))
		}
	}
}

func TestIPTrackerKeepsActiveEntries(t *testing.T) {
	tr := NewIPTrafficTracker()
	tr.RecordTx("9.9.9.9", 50)
	tr.RecordRx("9.9.9.9", 30)

	dtos := tr.GetDTOs(&sync.Map{}, "", "", "", "", nil, "")
	var found *observer.IPInfoDTO
	for i := range dtos {
		if dtos[i].IP == "9.9.9.9" {
			found = &dtos[i]
		}
	}
	if found == nil {
		t.Fatal("active IP 9.9.9.9 should be present")
	}
	if found.TotalBytes != 80 {
		t.Fatalf("expected total 80 bytes, got %d", found.TotalBytes)
	}
}

func TestIPTrackerPeerMapping(t *testing.T) {
	tr := NewIPTrafficTracker()
	tr.RecordRx("10.0.0.5", 200)

	pm := &sync.Map{}
	pm.Store(peer.ID("peerA1234567890abcdef"), PeerMeta{
		NodeName: "peerA",
		TapIP:    "10.0.0.5",
		TapMAC:   "02:00:00:00:00:aa",
	})

	dtos := tr.GetDTOs(pm, "", "", "", "", nil, "")
	var found *observer.IPInfoDTO
	for i := range dtos {
		if dtos[i].IP == "10.0.0.5" {
			found = &dtos[i]
		}
	}
	if found == nil {
		t.Fatal("IP 10.0.0.5 should be present")
	}
	if found.NodeName != "peerA" {
		t.Fatalf("expected node name peerA, got %q", found.NodeName)
	}
	if found.IPType != "peer" {
		t.Fatalf("expected ipType peer, got %q", found.IPType)
	}
	if found.MAC != "02:00:00:00:00:aa" {
		t.Fatalf("expected MAC from peer meta, got %q", found.MAC)
	}
}

func TestIPTrackerNoDuplicateGrowth(t *testing.T) {
	tr := NewIPTrafficTracker()
	// Recording the same IP many times must not create multiple entries.
	for i := 0; i < 100; i++ {
		tr.RecordTx("5.5.5.5", 10)
	}
	dtos := tr.GetDTOs(&sync.Map{}, "", "", "", "", nil, "")
	count := 0
	for i := range dtos {
		if dtos[i].IP == "5.5.5.5" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected exactly 1 entry for 5.5.5.5, got %d", count)
	}
	if dtos[0].TotalBytes != 1000 {
		t.Fatalf("expected cumulative 1000 bytes, got %d", dtos[0].TotalBytes)
	}
}
