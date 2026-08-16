package vswitch

import (
	"bytes"
	"net"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
)

var (
	BroadcastMAC = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
)

type MACEntry struct {
	IP       string
	PeerID   peer.ID
	LastSeen time.Time
}

// ShardedMACTable reduces lock contention under high multi-core packet throughput
type ShardedMACTable struct {
	shards [16]struct {
		mu      sync.RWMutex
		entries map[string]MACEntry
	}
	// peerCounts caps how many distinct source MACs a single peer may register,
	// preventing a misbehaving/synthetic-MAC peer from exploding the table.
	peerCountsMu sync.Mutex
	peerCounts   map[peer.ID]int
}

// MaxMACsPerPeer bounds the number of source MACs a single peer may learn.
// A healthy peer uses exactly one (its configured TapMAC), so this is purely a
// circuit-breaker against peers that emit a different random/EUI-64 SrcMAC per
// frame.
const MaxMACsPerPeer = 8

func NewMACTable() *ShardedMACTable {
	table := &ShardedMACTable{}
	for i := 0; i < 16; i++ {
		table.shards[i].entries = make(map[string]MACEntry)
	}
	table.peerCounts = make(map[peer.ID]int)
	return table
}

func (t *ShardedMACTable) getShardIndex(macStr string) int {
	var hash uint32
	for i := 0; i < len(macStr); i++ {
		hash = 31*hash + uint32(macStr[i])
	}
	return int(hash % 16)
}

// IsBroadcastOrMulticast checks if MAC is Ethernet Broadcast or IPv4/IPv6 Multicast
func IsBroadcastOrMulticast(mac net.HardwareAddr) bool {
	if len(mac) < 6 {
		return true
	}
	// Broadcast FF:FF:FF:FF:FF:FF
	if bytes.Equal(mac, BroadcastMAC) {
		return true
	}
	// Multicast bit (Least significant bit of first octet is 1)
	if (mac[0] & 0x01) != 0 {
		return true
	}
	return false
}

// Learn updates or inserts a MAC -> PeerID mapping
func (t *ShardedMACTable) Learn(mac net.HardwareAddr, peerID peer.ID) {
	t.LearnWithIP(mac, "", peerID)
}

// LearnWithIP updates or inserts a MAC + IP -> PeerID mapping
func (t *ShardedMACTable) LearnWithIP(mac net.HardwareAddr, ip string, peerID peer.ID) {
	if len(mac) < 6 || IsBroadcastOrMulticast(mac) {
		return
	}
	macKey := mac.String()
	idx := t.getShardIndex(macKey)

	shard := &t.shards[idx]
	// The entire existence-check + insert + per-peer circuit-breaker must run
	// under a SINGLE shard lock. The original code released the lock between
	// the RLock read of `exists` and the write, which let two concurrent
	// learners of the same new MAC both see exists==false and both bump
	// peerCounts (over-counting it and tripping the breaker early), and let the
	// second writer clobber the first's IP field. Lock order here (shard.mu ->
	// peerCountsMu) matches deleteEntryLocked to avoid deadlock.
	shard.mu.Lock()
	entry, exists := shard.entries[macKey]
	if !exists {
		t.peerCountsMu.Lock()
		if t.peerCounts[peerID] >= MaxMACsPerPeer {
			t.peerCountsMu.Unlock()
			shard.mu.Unlock()
			return
		}
		t.peerCounts[peerID]++
		t.peerCountsMu.Unlock()
		entry = MACEntry{PeerID: peerID}
	}
	if ip != "" {
		entry.IP = ip
	}
	entry.PeerID = peerID
	entry.LastSeen = time.Now()
	shard.entries[macKey] = entry
	shard.mu.Unlock()
}

// Lookup finds the peer.ID for a given unicast MAC address
func (t *ShardedMACTable) Lookup(mac net.HardwareAddr) (peer.ID, bool) {
	if len(mac) < 6 || IsBroadcastOrMulticast(mac) {
		return "", false
	}
	macKey := mac.String()
	idx := t.getShardIndex(macKey)

	shard := &t.shards[idx]
	shard.mu.RLock()
	entry, found := shard.entries[macKey]
	shard.mu.RUnlock()

	if found {
		return entry.PeerID, true
	}
	return "", false
}

// GetAllEntries returns a copy of all active MAC + IP entries
func (t *ShardedMACTable) GetAllEntries() map[string]MACEntry {
	res := make(map[string]MACEntry)
	for i := 0; i < 16; i++ {
		shard := &t.shards[i]
		shard.mu.RLock()
		for k, v := range shard.entries {
			res[k] = v
		}
		shard.mu.RUnlock()
	}
	return res
}

// deleteEntryLocked removes a single MAC entry from its shard and decrements the
// owning peer's count. The shard mutex must already be held by the caller.
func (t *ShardedMACTable) deleteEntryLocked(idx int, macKey string) {
	shard := &t.shards[idx]
	if entry, ok := shard.entries[macKey]; ok {
		delete(shard.entries, macKey)
		t.peerCountsMu.Lock()
		if t.peerCounts[entry.PeerID] > 0 {
			t.peerCounts[entry.PeerID]--
			if t.peerCounts[entry.PeerID] == 0 {
				delete(t.peerCounts, entry.PeerID)
			}
		}
		t.peerCountsMu.Unlock()
	}
}

// CleanStale removes entries older than maxAge
func (t *ShardedMACTable) CleanStale(maxAge time.Duration) {
	now := time.Now()
	for i := 0; i < 16; i++ {
		shard := &t.shards[i]
		shard.mu.Lock()
		for mac := range shard.entries {
			if now.Sub(shard.entries[mac].LastSeen) > maxAge {
				t.deleteEntryLocked(i, mac)
			}
		}
		shard.mu.Unlock()
	}
}

// Forget removes a single MAC -> PeerID mapping. Used as a circuit-breaker when
// a unicast target peer has no dialable addresses (e.g. it went offline): rather
// than repeatedly dialing a dead peer for every frame, we drop the stale mapping
// so subsequent frames to that MAC fall back to broadcast/flood.
func (t *ShardedMACTable) Forget(mac net.HardwareAddr) {
	if len(mac) < 6 || IsBroadcastOrMulticast(mac) {
		return
	}
	macKey := mac.String()
	idx := t.getShardIndex(macKey)
	shard := &t.shards[idx]
	shard.mu.Lock()
	t.deleteEntryLocked(idx, macKey)
	shard.mu.Unlock()
}

// CleanPeer immediately purges all MAC entries associated with a disconnected peer
func (t *ShardedMACTable) CleanPeer(target peer.ID) {
	for i := 0; i < 16; i++ {
		shard := &t.shards[i]
		shard.mu.Lock()
		for mac, entry := range shard.entries {
			if entry.PeerID == target {
				t.deleteEntryLocked(i, mac)
			}
		}
		shard.mu.Unlock()
	}
}

// ExtractEthernetMACs parses source and destination MACs from a raw Ethernet frame
func ExtractEthernetMACs(frame []byte) (dstMAC net.HardwareAddr, srcMAC net.HardwareAddr, err bool) {
	if len(frame) < 14 {
		return nil, nil, true
	}
	dstMAC = net.HardwareAddr(frame[0:6])
	srcMAC = net.HardwareAddr(frame[6:12])
	return dstMAC, srcMAC, false
}
