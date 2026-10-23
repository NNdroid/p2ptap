// peer_addr_store.go — persistent record of the public source addresses this
// boot observes from directly-connected peers.
//
// Why this exists: when a peer connects to the boot over a hole-punched
// direct link the boot sees the peer's REAL post-NAT public source address
// (conn.RemoteMultiaddr). That is information no one else in the mesh can
// learn — a peer whose STUN is fully blocked can never advertise its own
// public address, so every other peer is stuck dialing it through the relay
// forever. The boot is the only component that can see past that NAT, so it
// is the only component that may remember it.
//
// Before this file every piece of peer address state was wiped on disconnect
// (DisconnectedF cleared the peerstore and peerInfoCache, the 1-minute
// sweeper did the same) and nothing survived a boot restart.
//
// Circuit-relay inbound connections are deliberately excluded: their source
// address is the boot's own relay IP, not the peer's. See observedPeerAddrs.

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
)

// peerAddrFileVersion is written into the file so a future writer can refuse
// to silently overwrite state it does not understand.
const peerAddrFileVersion = 1

// peerAddrFlushDelay coalesces bursts of peer activity into a single disk
// write. A boot that accepts a large join wave otherwise rewrites the whole
// file once per connection event.
const peerAddrFlushDelay = 5 * time.Second

// peerAddrDefaultMaxPeers caps the in-memory (and on-disk) entry count. It is
// a growth guard, not a policy: real deployments are orders of magnitude
// below it.
const peerAddrDefaultMaxPeers = 10000

// peerAddrEntry is one peer's observed public address record.
type peerAddrEntry struct {
	PeerID string `json:"peer_id"`
	// NodeName is the name the peer announced, so the WebUI can label rows
	// without needing a live peerInfoCache hit.
	NodeName string `json:"node_name,omitempty"`
	// NetworkID is the PSK network the peer authenticated into; empty in open
	// mode. Kept so a network can be reconstructed after a restart, when the
	// in-memory ACL filter is gone.
	NetworkID string `json:"network_id,omitempty"`
	// Addrs are full multiaddrs carrying the /p2p/<id> suffix. The suffix is
	// mandatory: pkg/node's registerPeekMapAddrs rejects addrs without a
	// matching /p2p/ component.
	Addrs []string `json:"addrs"`
	// Transports are the distinct transport labels the addresses were seen on.
	Transports []string  `json:"transports,omitempty"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
	// SeenCount counts how many connection events were recorded for this peer.
	SeenCount int `json:"seen_count"`
}

type peerAddrFile struct {
	Version   int              `json:"version"`
	UpdatedAt time.Time        `json:"updated_at"`
	Peers     []*peerAddrEntry `json:"peers"`
}

// peerAddrStore is the in-memory view plus a debounced atomic writer.
//
// The disk keeps every entry forever. Only the STARTUP REBROADCAST is filtered
// by a window, because a NAT mapping learned days ago is almost certainly dead
// and replaying it floods the mesh with unreachable endpoints. Disk retention
// is for operators (forensics, WebUI history) and must not expire with the
// mapping.
type peerAddrStore struct {
	mu       sync.Mutex
	path     string // "" disables disk persistence entirely
	maxPeers int
	entries  map[peer.ID]*peerAddrEntry
	dirty    bool
	timer    *time.Timer
	closed   bool
}

// LoadStore opens path (or creates it empty), then returns a store that
// coalesces writes. A missing file is not an error. A malformed file is not
// fatal either — this is derived, repairable state, and bricking the boot
// server because the cache was truncated would be worse than losing it — so
// the bad file is renamed to a timestamped backup and an empty store is
// returned.
func LoadStore(path string, maxPeers int) (*peerAddrStore, error) {
	if maxPeers <= 0 {
		maxPeers = peerAddrDefaultMaxPeers
	}
	s := &peerAddrStore{
		path:     path,
		maxPeers: maxPeers,
		entries:  make(map[peer.ID]*peerAddrEntry),
	}
	if path == "" {
		return s, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var f peerAddrFile
	if err := json.Unmarshal(data, &f); err != nil {
		if berr := os.Rename(path, fmt.Sprintf("%s.corrupt-%s", path, time.Now().Format("20060102T150405Z"))); berr == nil {
			log.Error("peer address store %s was unreadable and has been moved to a .corrupt- backup; starting with an empty store: %v",
				path, err)
		} else {
			log.Error("peer address store %s was unreadable and could NOT be backed up; starting with an empty store: %v (backup: %v)",
				path, err, berr)
		}
		return s, nil
	}
	if f.Version != peerAddrFileVersion {
		log.Warn("peer address store %s has version %d, expected %d; ignoring its contents", path, f.Version, peerAddrFileVersion)
		return s, nil
	}
	for _, e := range f.Peers {
		if e == nil || e.PeerID == "" {
			continue
		}
		pID, err := peer.Decode(e.PeerID)
		if err != nil {
			continue
		}
		if pID == "" {
			continue
		}
		cp := cloneEntry(e)
		s.entries[pID] = cp
	}
	log.Info("Loaded %d peer address record(s) from %s", len(s.entries), path)
	return s, nil
}

func cloneEntry(e *peerAddrEntry) *peerAddrEntry {
	cp := *e
	cp.Addrs = append([]string(nil), e.Addrs...)
	cp.Transports = append([]string(nil), e.Transports...)
	return &cp
}

// RecordPeerAddrs replaces pID's endpoint list with addrs and returns the
// addresses that were recorded before and are no longer present — the ones
// that must now be retracted from the rest of the mesh.
//
// addrs is a REPLACEMENT, not a merge. It is always called with the peer's
// complete set of current direct connections, so old minus new is exactly what
// went stale: a dropped QUIC link, a peer that moved networks. Empty addrs is
// a no-op, since it would retract everything on the basis of a connection set
// that simply was not observed.
func (s *peerAddrStore) RecordPeerAddrs(pID peer.ID, addrs, transports []string, netID, nodeName string) []string {
	if s == nil || len(addrs) == 0 {
		return nil
	}
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}

	e, ok := s.entries[pID]
	if !ok {
		e = &peerAddrEntry{PeerID: pID.String(), FirstSeen: now}
		if len(s.entries) >= s.maxPeers {
			s.evictOldestLocked()
		}
		s.entries[pID] = e
	}

	var superseded []string
	if len(e.Addrs) > 0 {
		kept := make(map[string]bool, len(addrs))
		for _, a := range addrs {
			if a != "" {
				kept[a] = true
			}
		}
		for _, a := range e.Addrs {
			if !kept[a] {
				superseded = append(superseded, a)
			}
		}
	}

	e.Addrs = append([]string(nil), addrs...)

	seenT := make(map[string]bool, len(e.Transports))
	for _, t := range e.Transports {
		seenT[t] = true
	}
	for _, t := range transports {
		if t == "" || seenT[t] {
			continue
		}
		seenT[t] = true
		e.Transports = append(e.Transports, t)
	}
	if nodeName != "" {
		e.NodeName = nodeName
	}
	if netID != "" {
		e.NetworkID = netID
	}
	e.LastSeen = now
	e.SeenCount++
	s.markDirtyLocked()
	return superseded
}

// evictOldestLocked drops the least-recently-seen entry to make room. The
// caller holds s.mu.
func (s *peerAddrStore) evictOldestLocked() {
	var worst peer.ID
	var worstAt time.Time
	for p, e := range s.entries {
		if e == nil || worst == "" || e.LastSeen.Before(worstAt) {
			worst, worstAt = p, e.LastSeen
		}
	}
	if worst == "" {
		return
	}
	delete(s.entries, worst)
	log.Warn("peer address store at capacity (%d); evicting least recently seen %s", s.maxPeers, worst.ShortString())
}

// MarkGone records that pID is no longer connected and returns the address
// list that should now be retracted from peers. The entry is NOT deleted —
// that is exactly what persistence is for: the WebUI keeps showing it and a
// future reconnect refreshes it in place.
func (s *peerAddrStore) MarkGone(pID peer.ID) []string {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	e, ok := s.entries[pID]
	if !ok {
		return nil
	}
	e.LastSeen = time.Now()
	e.SeenCount++
	out := append([]string(nil), e.Addrs...)
	s.markDirtyLocked()
	return out
}

// Entry returns a copy of pID's record, or nil if the peer is unknown.
func (s *peerAddrStore) Entry(pID peer.ID) *peerAddrEntry {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.entries[pID]
	if e == nil {
		return nil
	}
	return cloneEntry(e)
}

// SnapshotWithin returns copies of every record seen within the last window,
// most recent first. Deep copies so a caller holding the snapshot cannot
// observe or mutate live state.
func (s *peerAddrStore) SnapshotWithin(window time.Duration) []*peerAddrEntry {
	if s == nil {
		return nil
	}
	cutoff := time.Now().Add(-window)
	return s.snapshotLockedBy(func(e *peerAddrEntry) bool {
		return !e.LastSeen.Before(cutoff)
	})
}

// Snapshot returns copies of every record, most recent first, with no time
// filter. Used by the WebUI, which wants the full history.
func (s *peerAddrStore) Snapshot() []*peerAddrEntry {
	if s == nil {
		return nil
	}
	return s.snapshotLockedBy(func(*peerAddrEntry) bool { return true })
}

func (s *peerAddrStore) snapshotLockedBy(keep func(*peerAddrEntry) bool) []*peerAddrEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*peerAddrEntry, 0, len(s.entries))
	for _, e := range s.entries {
		if e != nil && keep(e) {
			out = append(out, cloneEntry(e))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].LastSeen.Equal(out[j].LastSeen) {
			return out[i].LastSeen.After(out[j].LastSeen)
		}
		return out[i].PeerID < out[j].PeerID
	})
	return out
}

// PruneOver keeps at most n entries, dropping the least recently seen.
func (s *peerAddrStore) PruneOver(max int) int {
	if s == nil || max <= 0 {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := 0
	for len(s.entries) > max {
		s.evictOldestLocked()
		removed++
	}
	if removed > 0 {
		s.markDirtyLocked()
	}
	return removed
}

// markDirtyLocked schedules a debounced write. Caller holds s.mu.
func (s *peerAddrStore) markDirtyLocked() {
	if s.path == "" {
		return
	}
	s.dirty = true
	if s.timer != nil {
		s.timer.Stop()
	}
	s.timer = time.NewTimer(peerAddrFlushDelay)
	go func() {
		<-s.timer.C
		s.Flush()
	}()
}

// Flush writes the store to disk if it has changed since the last write.
// Safe to call concurrently. Once Closed the store is read-only, so a plain
// Flush is a no-op; only the flush Close performs is allowed to write.
func (s *peerAddrStore) Flush() error {
	if s == nil {
		return nil
	}
	return s.flush(false)
}

func (s *peerAddrStore) flush(allowClosed bool) error {
	s.mu.Lock()
	if !allowClosed && s.closed {
		s.mu.Unlock()
		return nil
	}
	if s.path == "" || !s.dirty {
		s.mu.Unlock()
		return nil
	}
	data, err := s.marshalLocked()
	s.mu.Unlock()
	if err != nil {
		return err
	}
	if err := atomicWriteStore(s.path, data); err != nil {
		log.Error("failed to persist peer address store %s: %v", s.path, err)
		return err
	}
	s.mu.Lock()
	s.dirty = false
	s.mu.Unlock()
	return nil
}

// marshalLocked builds the on-disk payload. Caller holds s.mu.
func (s *peerAddrStore) marshalLocked() ([]byte, error) {
	f := peerAddrFile{
		Version:   peerAddrFileVersion,
		UpdatedAt: time.Now(),
		Peers:     make([]*peerAddrEntry, 0, len(s.entries)),
	}
	for _, e := range s.entries {
		if e != nil {
			f.Peers = append(f.Peers, cloneEntry(e))
		}
	}
	sort.Slice(f.Peers, func(i, j int) bool {
		return f.Peers[i].LastSeen.After(f.Peers[j].LastSeen)
	})
	return json.MarshalIndent(f, "", "  ")
}

// Close flushes and stops accepting new records. Records already held stay
// readable, so the WebUI still shows them during the shutdown sequence.
func (s *peerAddrStore) Close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	// allowClosed is the only way this final write can happen: Flush bails on
	// the closed flag, so a plain Flush here would silently drop everything
	// recorded since the last debounced write.
	_ = s.flush(true)
}

// peerAddrCount returns the number of records held.
func (s *peerAddrStore) peerAddrCount() int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries)
}

// atomicWriteStore writes data to path atomically: temp file in the same
// directory, fsync, chmod, rename. Mirrors pkg/config.atomicWriteFile so a
// crash mid-write cannot truncate the store.
func atomicWriteStore(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		if tmpName != "" {
			_ = os.Remove(tmpName)
		}
	}()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, 0600); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	tmpName = ""
	return nil
}
