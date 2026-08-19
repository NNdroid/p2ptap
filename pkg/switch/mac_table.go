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

type macKey [6]byte

func toMacKey(mac net.HardwareAddr) macKey {
	var k macKey
	if len(mac) >= 6 {
		copy(k[:], mac[:6])
	}
	return k
}

func (k macKey) String() string {
	return net.HardwareAddr(k[:]).String()
}

type MACEntry struct {
	IP       string
	PeerID   peer.ID
	LastSeen time.Time
}

// ShardedMACTable reduces lock contention under high multi-core packet throughput
type ShardedMACTable struct {
	shards [16]struct {
		mu      sync.RWMutex
		entries map[macKey]MACEntry
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
		table.shards[i].entries = make(map[macKey]MACEntry)
	}
	table.peerCounts = make(map[peer.ID]int)
	return table
}

func (t *ShardedMACTable) getShardIndex(k macKey) int {
	return int((uint32(k[0]) ^ uint32(k[1]) ^ uint32(k[2]) ^ uint32(k[3]) ^ uint32(k[4]) ^ uint32(k[5])) % 16)
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

// IsBroadcastOrMulticastArray checks if a [6]byte MAC is Ethernet Broadcast or Multicast
func IsBroadcastOrMulticastArray(mac [6]byte) bool {
	if mac == [6]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff} {
		return true
	}
	return (mac[0] & 0x01) != 0
}

// Learn updates or inserts a MAC -> PeerID mapping
func (t *ShardedMACTable) Learn(mac net.HardwareAddr, peerID peer.ID) {
	t.LearnWithIP(mac, "", peerID)
}

// macLastSeenInterval throttles how often an already-known, UNCHANGED MAC entry
// has its LastSeen timestamp refreshed. LastSeen feeds only CleanStale(300s)
// and the WebUI (which renders it at second granularity), so a 1s refresh is
// orders of magnitude more precise than either consumer needs — while sparing
// every frame in between a time.Now() call and a write lock.
const macLastSeenInterval = time.Second

// LearnWithIP updates or inserts a MAC + IP -> PeerID mapping
func (t *ShardedMACTable) LearnWithIP(mac net.HardwareAddr, ip string, peerID peer.ID) {
	if len(mac) < 6 || IsBroadcastOrMulticast(mac) {
		return
	}
	k := toMacKey(mac)
	idx := t.getShardIndex(k)

	shard := &t.shards[idx]
	// Fast path (the steady state): the mapping exists and is UNCHANGED. Take
	// only a read lock so concurrent receive goroutines refresh in parallel
	// instead of serialising on a write lock every frame, and skip the
	// timestamp write unless the interval elapsed.
	//
	// The lock is released before any upgrade — sync.RWMutex cannot be
	// upgraded in place, and taking a write lock while holding a read lock
	// deadlocks.
	shard.mu.RLock()
	entry, exists := shard.entries[k]
	if exists && entry.PeerID == peerID && (ip == "" || ip == entry.IP) {
		refresh := time.Since(entry.LastSeen) >= macLastSeenInterval
		shard.mu.RUnlock()
		if !refresh {
			return
		}
		shard.mu.Lock()
		// Re-read under the write lock: another goroutine may have changed the
		// mapping (or purged it) in the window we were unlocked.
		entry, exists = shard.entries[k]
		if exists && entry.PeerID == peerID && (ip == "" || ip == entry.IP) {
			entry.LastSeen = time.Now()
			shard.entries[k] = entry
		}
		shard.mu.Unlock()
		return
	}
	shard.mu.RUnlock()

	// Slow path: new or changed mapping — full write lock, as before.
	shard.mu.Lock()
	entry, exists = shard.entries[k]
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
	shard.entries[k] = entry
	shard.mu.Unlock()
}

// Lookup finds the peer.ID for a given unicast MAC address
func (t *ShardedMACTable) Lookup(mac net.HardwareAddr) (peer.ID, bool) {
	if len(mac) < 6 || IsBroadcastOrMulticast(mac) {
		return "", false
	}
	k := toMacKey(mac)
	idx := t.getShardIndex(k)

	shard := &t.shards[idx]
	shard.mu.RLock()
	entry, found := shard.entries[k]
	shard.mu.RUnlock()

	if found {
		return entry.PeerID, true
	}
	return "", false
}

// LookupArray finds the peer.ID for a given [6]byte MAC address with zero allocations
func (t *ShardedMACTable) LookupArray(mac [6]byte) (peer.ID, bool) {
	if IsBroadcastOrMulticastArray(mac) {
		return "", false
	}
	k := macKey(mac)
	idx := t.getShardIndex(k)

	shard := &t.shards[idx]
	shard.mu.RLock()
	entry, found := shard.entries[k]
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
			res[k.String()] = v
		}
		shard.mu.RUnlock()
	}
	return res
}

// deleteEntryLocked removes a single MAC entry from its shard and decrements the
// owning peer's count. The shard mutex must already be held by the caller.
func (t *ShardedMACTable) deleteEntryLocked(idx int, k macKey) {
	shard := &t.shards[idx]
	if entry, ok := shard.entries[k]; ok {
		delete(shard.entries, k)
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
		for k := range shard.entries {
			if now.Sub(shard.entries[k].LastSeen) > maxAge {
				t.deleteEntryLocked(i, k)
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
	k := toMacKey(mac)
	idx := t.getShardIndex(k)
	shard := &t.shards[idx]
	shard.mu.Lock()
	t.deleteEntryLocked(idx, k)
	shard.mu.Unlock()
}

// CleanPeer immediately purges all MAC entries associated with a disconnected peer
func (t *ShardedMACTable) CleanPeer(target peer.ID) {
	for i := 0; i < 16; i++ {
		shard := &t.shards[i]
		shard.mu.Lock()
		for k, entry := range shard.entries {
			if entry.PeerID == target {
				t.deleteEntryLocked(i, k)
			}
		}
		shard.mu.Unlock()
	}
}

// ExtractEthernetMACs parses source and destination MACs from a raw Ethernet frame.
// Returns ok == true if frame length >= 14, false otherwise.
func ExtractEthernetMACs(frame []byte) (dstMAC net.HardwareAddr, srcMAC net.HardwareAddr, ok bool) {
	if len(frame) < 14 {
		return nil, nil, false
	}
	dstMAC = net.HardwareAddr(frame[0:6])
	srcMAC = net.HardwareAddr(frame[6:12])
	return dstMAC, srcMAC, true
}

// ExtractEthernetMACArray parses source and destination MACs from a raw Ethernet frame into fixed arrays with 0 allocations.
// Returns ok == true if frame length >= 14, false otherwise.
func ExtractEthernetMACArray(frame []byte) (dstMAC [6]byte, srcMAC [6]byte, ok bool) {
	if len(frame) < 14 {
		return dstMAC, srcMAC, false
	}
	copy(dstMAC[:], frame[0:6])
	copy(srcMAC[:], frame[6:12])
	return dstMAC, srcMAC, true
}
