package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/test"
	"github.com/multiformats/go-multiaddr"
)

// fakePeerConn is the smallest network.Conn the observedPeerAddrs/directPhysicalIP
// helpers can be tested with. Only the methods the helpers actually call are
// overridden; embedding the real interface makes every other method a nil
// panicker, which is enough of a tripwire to notice if a helper ever starts
// reaching for something else on the connection.
type fakePeerConn struct {
	network.Conn
	ma        multiaddr.Multiaddr
	transport string
	id        string
}

func (f fakePeerConn) RemoteMultiaddr() multiaddr.Multiaddr {
	return f.ma
}

func (f fakePeerConn) ID() string {
	return f.id
}

func (f fakePeerConn) ConnState() network.ConnectionState {
	return network.ConnectionState{Transport: f.transport}
}

func maOrFatal(t *testing.T, s string) multiaddr.Multiaddr {
	t.Helper()
	ma, err := multiaddr.NewMultiaddr(s)
	if err != nil {
		t.Fatalf("NewMultiaddr(%q): %v", s, err)
	}
	return ma
}

func storePath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "boot.addrs.json")
}

// --- observedPeerAddrs / directPhysicalIP -----------------------------------

func TestObservedPeerAddrsDropsCircuitAndSkipsConn(t *testing.T) {
	pID := test.RandPeerIDFatal(t)
	circuit := fakePeerConn{ma: maOrFatal(t, "/p2p/"+pID.String()+"/p2p-circuit/p2p/"+pID.String()), transport: "circuit", id: "c"}
	direct := fakePeerConn{ma: maOrFatal(t, "/ip4/203.0.113.5/udp/443/quic-v1"), transport: "quic-v1", id: "d"}
	leaving := fakePeerConn{ma: maOrFatal(t, "/ip4/198.51.100.9/tcp/4001"), transport: "tcp", id: "l"}
	dup := fakePeerConn{ma: maOrFatal(t, "/ip4/203.0.113.5/udp/443/quic-v1"), transport: "quic-v1", id: "d2"}

	// A circuit connection must never contribute: its source IP is the boot's
	// own relay address, not the peer's.
	addrs, transports := observedPeerAddrs([]network.Conn{circuit}, pID, nil)
	if len(addrs) != 0 || len(transports) != 0 {
		t.Fatalf("circuit-only conn produced %v / %v, want both empty", addrs, transports)
	}

	addrs, transports = observedPeerAddrs([]network.Conn{direct, leaving, dup}, pID, nil)
	if len(addrs) != 2 {
		t.Fatalf("got %d addrs, want 2: %v", len(addrs), addrs)
	}
	for _, a := range addrs {
		if !strings.Contains(a, "/p2p/"+pID.String()) {
			t.Fatalf("addr %q lacks the /p2p/%s suffix required by registerPeekMapAddrs", a, pID.String())
		}
	}

	// skip is the connection DisconnectedF is firing for; libp2p may still list
	// it in ConnsToPeer at that moment, so it must be excluded.
	addrs, transports = observedPeerAddrs([]network.Conn{direct, leaving, dup}, pID, leaving)
	if len(addrs) != 1 || len(transports) != 1 {
		t.Fatalf("got %v / %v, want one addr on one transport", addrs, transports)
	}
	if transports[0] != "quic" {
		t.Fatalf("transport = %q, want quic", transports[0])
	}

	// Duplicate transports collapse to one label.
	_, transports = observedPeerAddrs([]network.Conn{direct, dup}, pID, nil)
	if len(transports) != 1 {
		t.Fatalf("transports = %v, want one deduped entry", transports)
	}
}

func TestObservedPeerAddrsKeepsPreexistingSuffix(t *testing.T) {
	pID := test.RandPeerIDFatal(t)
	suffixed := fakePeerConn{ma: maOrFatal(t, "/ip4/203.0.113.5/udp/443/quic-v1/p2p/"+pID.String()), transport: "quic-v1"}
	addrs, _ := observedPeerAddrs([]network.Conn{suffixed}, pID, nil)
	if len(addrs) != 1 || addrs[0] != suffixed.ma.String() {
		t.Fatalf("got %v, want the addr passed through unchanged", addrs)
	}
}

func TestDirectPhysicalIPIgnoresCircuit(t *testing.T) {
	pID := test.RandPeerIDFatal(t)
	circuit := fakePeerConn{ma: maOrFatal(t, "/ip4/192.0.2.1/udp/4001/quic-v1/p2p/"+pID.String()+"/p2p-circuit/p2p/"+pID.String()), transport: "circuit", id: "c"}
	direct := fakePeerConn{ma: maOrFatal(t, "/ip4/203.0.113.5/udp/443/quic-v1"), transport: "quic-v1", id: "d"}

	if got := directPhysicalIP([]network.Conn{circuit}, nil); got != "" {
		t.Fatalf("circuit-only conns gave IP %q, want empty", got)
	}
	// A circuit listed first must not shadow the real address behind it.
	if got := directPhysicalIP([]network.Conn{circuit, direct}, nil); got != "203.0.113.5" {
		t.Fatalf("got %q, want 203.0.113.5", got)
	}
	if got := directPhysicalIP([]network.Conn{circuit, direct}, direct); got != "" {
		t.Fatalf("skipping the only direct conn gave %q, want empty", got)
	}
}

// --- recording and retraction ------------------------------------------------

func TestRecordPeerAddrsReportsSuperseded(t *testing.T) {
	s, err := LoadStore(storePath(t), 0)
	if err != nil {
		t.Fatal(err)
	}
	pID := test.RandPeerIDFatal(t)

	if got := s.RecordPeerAddrs(pID, nil, nil, "", ""); got != nil {
		t.Fatalf("empty addrs must be a no-op, got %v", got)
	}
	if got := s.RecordPeerAddrs(pID, nil, nil, "", ""); got != nil {
		t.Fatalf("nil addrs must be a no-op, got %v", got)
	}
	if s.Entry(pID) != nil {
		t.Fatalf("empty record created an entry")
	}

	a1 := "/ip4/203.0.113.5/udp/443/quic-v1/p2p/" + pID.String()
	a2 := "/ip4/198.51.100.9/tcp/4001/p2p/" + pID.String()
	if got := s.RecordPeerAddrs(pID, []string{a1, a2}, []string{"quic", "tcp"}, "netA", "n1"); got != nil {
		t.Fatalf("first record reported %v as superseded", got)
	}

	// a2 went stale: the peer dropped its TCP link and kept only QUIC.
	got := s.RecordPeerAddrs(pID, []string{a1}, []string{"quic"}, "", "n2")
	if len(got) != 1 || got[0] != a2 {
		t.Fatalf("superseded = %v, want [%s]", got, a2)
	}

	e := s.Entry(pID)
	if e == nil {
		t.Fatal("entry missing")
	}
	if len(e.Addrs) != 1 || e.Addrs[0] != a1 {
		t.Fatalf("addrs = %v, want replacement not merge", e.Addrs)
	}
	if e.SeenCount != 2 {
		t.Fatalf("seen_count = %d, want 2", e.SeenCount)
	}
	if e.NetworkID != "netA" {
		t.Fatalf("network_id = %q, want netA (an empty update must not blank it)", e.NetworkID)
	}
	// Transports are a running union: a dropped link must not erase its history.
	if len(e.Transports) != 2 {
		t.Fatalf("transports = %v, want both quic and tcp", e.Transports)
	}
	if e.NodeName != "n2" {
		t.Fatalf("node_name = %q, want the latest non-empty value", e.NodeName)
	}
	if e.FirstSeen.IsZero() || e.LastSeen.Before(e.FirstSeen) {
		t.Fatalf("bad timestamps first=%v last=%v", e.FirstSeen, e.LastSeen)
	}
}

func TestMarkGoneRetainsEntryAndReturnsAddrs(t *testing.T) {
	s, err := LoadStore("", 0)
	if err != nil {
		t.Fatal(err)
	}
	pID := test.RandPeerIDFatal(t)
	a1 := "/ip4/203.0.113.5/udp/443/quic-v1/p2p/" + pID.String()
	s.RecordPeerAddrs(pID, []string{a1}, []string{"quic"}, "", "n1")

	if got := s.MarkGone(test.RandPeerIDFatal(t)); got != nil {
		t.Fatalf("MarkGone on an unknown peer returned %v", got)
	}
	got := s.MarkGone(pID)
	if len(got) != 1 || got[0] != a1 {
		t.Fatalf("MarkGone = %v, want the recorded addrs", got)
	}
	// The whole point of persistence: the record must still be there.
	e := s.Entry(pID)
	if e == nil {
		t.Fatal("MarkGone deleted the entry")
	}
	if len(e.Addrs) != 1 {
		t.Fatalf("addrs = %v", e.Addrs)
	}
	if e.SeenCount != 2 {
		t.Fatalf("seen_count = %d, want 2 (record + gone)", e.SeenCount)
	}

	// Marking a peer gone twice must keep returning the address list, so a
	// repeated notification cannot silently fail to retract.
	if got := s.MarkGone(pID); len(got) != 1 || got[0] != a1 {
		t.Fatalf("second MarkGone = %v", got)
	}
}

func TestSnapshotOrderingAndWindow(t *testing.T) {
	// Hand-built file: the load path is what is under test here, and setting
	// last_seen by hand is the only way to control the window deterministically.
	// All three timestamps are relative to now so the window arithmetic holds
	// no matter when the test runs.
	now := time.Now()
	path := storePath(t)
	p1 := test.RandPeerIDFatal(t)
	p2 := test.RandPeerIDFatal(t)
	p3 := test.RandPeerIDFatal(t)
	const payload = `{
  "version": 1,
  "updated_at": "2026-01-01T00:00:00Z",
  "peers": [
    {"peer_id": "__P1__", "node_name": "old", "addrs": ["/ip4/1.1.1.1/tcp/4001/p2p/__P1__"], "first_seen": "__F1__", "last_seen": "__L1__", "seen_count": 1},
    {"peer_id": "__P2__", "node_name": "recent", "addrs": ["/ip4/2.2.2.2/tcp/4001/p2p/__P2__"], "first_seen": "__F2__", "last_seen": "__L2__", "seen_count": 3},
    {"peer_id": "__P3__", "node_name": "today", "addrs": ["/ip4/3.3.3.3/tcp/4001/p2p/__P3__"], "first_seen": "__F3__", "last_seen": "__L3__", "seen_count": 5},
    {"peer_id": "not-a-peer-id", "addrs": ["/ip4/4.4.4.4/tcp/4001"]},
    {"peer_id": "", "addrs": ["/ip4/5.5.5.5/tcp/4001"]}
  ]
}`
	at := func(d time.Duration) string { return now.Add(-d).Format(time.RFC3339Nano) }
	src := strings.NewReplacer(
		"__P1__", p1.String(), "__P2__", p2.String(), "__P3__", p3.String(),
		"__F1__", at(1100*24*time.Hour), "__L1__", at(900*24*time.Hour),
		"__F2__", at(500*24*time.Hour), "__L2__", at(400*24*time.Hour),
		"__F3__", at(6*time.Hour), "__L3__", at(5*time.Minute),
	).Replace(payload)
	if err := os.WriteFile(path, []byte(src), 0600); err != nil {
		t.Fatal(err)
	}

	s, err := LoadStore(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	// The two junk entries must have been skipped.
	if n := s.peerAddrCount(); n != 3 {
		t.Fatalf("loaded %d entries, want 3 (bad peer IDs skipped)", n)
	}

	all := s.Snapshot()
	if len(all) != 3 {
		t.Fatalf("Snapshot = %d entries", len(all))
	}
	if all[0].PeerID != p3.String() || all[1].PeerID != p2.String() || all[2].PeerID != p1.String() {
		t.Fatalf("Snapshot not sorted newest first: %s, %s, %s", all[0].PeerID, all[1].PeerID, all[2].PeerID)
	}
	if all[0].SeenCount != 5 || all[1].NodeName != "recent" {
		t.Fatalf("field loss on load: %+v / %+v", all[0], all[1])
	}

	// The window must slice the history without ever re-sorting it.
	if got := s.SnapshotWithin(1 * time.Hour); len(got) != 1 || got[0].PeerID != p3.String() {
		t.Fatalf("1h window = %v, want only %s", recentIDs(got), p3.String())
	}
	if got := s.SnapshotWithin(500 * 24 * time.Hour); len(got) != 2 || got[0].PeerID != p3.String() || got[1].PeerID != p2.String() {
		t.Fatalf("500d window = %v, want %s and %s", recentIDs(got), p3.String(), p2.String())
	}
	if got := s.SnapshotWithin(1000 * 24 * time.Hour); len(got) != 3 {
		t.Fatalf("1000d window = %v, want all three", recentIDs(got))
	}
	// A nanosecond window is past everything recorded: the empty case.
	if got := s.SnapshotWithin(time.Nanosecond); len(got) != 0 {
		t.Fatalf("%s window = %v, want empty", time.Nanosecond, recentIDs(got))
	}

	// Snapshots must be deep copies: mutating one must not touch live state.
	recent := s.SnapshotWithin(1 * time.Hour)
	if len(recent) != 1 {
		t.Fatalf("setup: %v", recentIDs(recent))
	}
	recent[0].Addrs[0] = "mutated"
	recent[0].NodeName = "mutated"
	if e := s.Entry(p3); e == nil || e.Addrs[0] != "/ip4/3.3.3.3/tcp/4001/p2p/"+p3.String() || e.NodeName != "today" {
		t.Fatalf("snapshot mutation leaked into the store: %+v", e)
	}
}

func recentIDs(entries []*peerAddrEntry) []string {
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.PeerID)
	}
	return out
}

// --- disk persistence --------------------------------------------------------

func TestLoadStoreRoundTrip(t *testing.T) {
	path := storePath(t)
	pID := test.RandPeerIDFatal(t)
	a1 := "/ip4/203.0.113.5/udp/443/quic-v1/p2p/" + pID.String()
	a2 := "/ip4/198.51.100.9/tcp/4001/p2p/" + pID.String()

	s, err := LoadStore(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	// A missing file is not an error: this is the first boot.
	if s.peerAddrCount() != 0 {
		t.Fatalf("missing file loaded %d entries", s.peerAddrCount())
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("LoadStore created the file: %v", err)
	}

	s.RecordPeerAddrs(pID, []string{a1, a2}, []string{"quic", "tcp"}, "netA", "node-1")
	if err := s.Flush(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// Windows has no POSIX mode bits: os.Chmod there only toggles read-only, so
	// a 0600 request comes back as the default 0666. The chmod is still issued
	// (and still matters on Linux, where the cache holds node addresses) — it is
	// just unverifiable in this environment.
	if runtime.GOOS != "windows" {
		if mode := info.Mode().Perm(); mode != 0600 {
			t.Fatalf("file mode = %o, want 0600", mode)
		}
	}

	// A crash leaves no temp file behind.
	for _, name := range mustGlob(t, filepath.Join(filepath.Dir(path), "*")) {
		if strings.Contains(name, ".tmp-") {
			t.Fatalf("leftover temp file %s", name)
		}
	}

	reloaded, err := LoadStore(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	e := reloaded.Entry(pID)
	if e == nil {
		t.Fatal("entry lost across restart")
	}
	if len(e.Addrs) != 2 || e.Addrs[0] != a1 || e.Addrs[1] != a2 {
		t.Fatalf("addrs = %v", e.Addrs)
	}
	if len(e.Transports) != 2 || e.NodeName != "node-1" || e.NetworkID != "netA" || e.SeenCount != 1 {
		t.Fatalf("fields lost: %+v", e)
	}
	if e.FirstSeen.IsZero() || e.LastSeen.Before(e.FirstSeen) {
		t.Fatalf("timestamps not preserved: %+v", e)
	}

	// Nothing changed since the last write, so Flush must not rewrite the file.
	mtime := info.ModTime()
	if err := reloaded.Flush(); err != nil {
		t.Fatal(err)
	}
	if info2, err := os.Stat(path); err == nil && !info2.ModTime().Equal(mtime) {
		t.Fatalf("Flush rewrote an unmodified file")
	}

	reloaded.Close()
}

func mustGlob(t *testing.T, pattern string) []string {
	t.Helper()
	names, err := filepath.Glob(pattern)
	if err != nil {
		t.Fatal(err)
	}
	return names
}

func TestLoadStoreMalformedBacksUpAndContinues(t *testing.T) {
	path := storePath(t)
	if err := os.WriteFile(path, []byte("{ this is not json"), 0600); err != nil {
		t.Fatal(err)
	}

	s, err := LoadStore(path, 0)
	if err != nil {
		t.Fatalf("a truncated cache must not fail the boot: %v", err)
	}
	if s.peerAddrCount() != 0 {
		t.Fatalf("malformed file loaded %d entries", s.peerAddrCount())
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("original file was not moved aside: %v", err)
	}
	backups := mustGlob(t, filepath.Join(filepath.Dir(path), "boot.addrs.json.corrupt-*"))
	if len(backups) != 1 {
		t.Fatalf("want exactly one .corrupt- backup, got %v", backups)
	}

	// The store must still be fully usable afterwards.
	pID := test.RandPeerIDFatal(t)
	s.RecordPeerAddrs(pID, []string{"/ip4/1.1.1.1/tcp/4001/p2p/" + pID.String()}, nil, "", "n")
	if err := s.Flush(); err != nil {
		t.Fatal(err)
	}
	if s.Entry(pID) == nil {
		t.Fatal("store unusable after recovery")
	}
}

func TestLoadStoreVersionMismatchIsIgnored(t *testing.T) {
	path := storePath(t)
	if err := os.WriteFile(path, []byte(`{"version": 99, "peers": [
		{"peer_id": "QmTEST", "addrs": ["/ip4/1.1.1.1/tcp/4001"]},
		{"peer_id": "12D3KooWTEST", "addrs": ["/ip4/2.2.2.2/tcp/4001"]}
	]}`), 0600); err != nil {
		t.Fatal(err)
	}
	s, err := LoadStore(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	if s.peerAddrCount() != 0 {
		t.Fatalf("foreign-version file loaded %d entries", s.peerAddrCount())
	}
	// The file is left in place: an operator may still want to read it.
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("foreign-version file was destroyed: %v", err)
	}
}

func TestCapacityEviction(t *testing.T) {
	s, err := LoadStore("", 2)
	if err != nil {
		t.Fatal(err)
	}
	p1, p2, p3 := test.RandPeerIDFatal(t), test.RandPeerIDFatal(t), test.RandPeerIDFatal(t)
	s.RecordPeerAddrs(p1, []string{"a1"}, nil, "", "")
	time.Sleep(2 * time.Millisecond)
	s.RecordPeerAddrs(p2, []string{"a2"}, nil, "", "")

	if n := s.peerAddrCount(); n != 2 {
		t.Fatalf("count = %d, want 2", n)
	}
	// Filling the store must evict the least recently seen entry, which is p1.
	s.RecordPeerAddrs(p3, []string{"a3"}, nil, "", "")
	if n := s.peerAddrCount(); n != 2 {
		t.Fatalf("count after overflow = %d, want 2", n)
	}
	if s.Entry(p1) != nil {
		t.Fatalf("p1 should have been evicted")
	}
	if s.Entry(p3) == nil {
		t.Fatalf("p3 was lost")
	}

	// PruneOver trims from the bottom too.
	removed := s.PruneOver(1)
	if removed != 1 {
		t.Fatalf("PruneOver removed %d, want 1", removed)
	}
	if n := s.peerAddrCount(); n != 1 {
		t.Fatalf("count after prune = %d, want 1", n)
	}
	if removed := s.PruneOver(0); removed != 0 {
		t.Fatalf("PruneOver(0) removed %d, want 0", removed)
	}
}

func TestCloseStopsRecording(t *testing.T) {
	path := storePath(t)
	s, err := LoadStore(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	pID := test.RandPeerIDFatal(t)
	s.RecordPeerAddrs(pID, []string{"a1"}, nil, "", "n")
	s.Close()

	if e := s.Entry(pID); e == nil {
		t.Fatalf("Entry() returned nil after Close; want the record to stay readable: %v", s)
	}
	if got := s.RecordPeerAddrs(pID, []string{"a2"}, nil, "", "n"); got != nil {
		t.Fatalf("RecordPeerAddrs after Close returned %v", got)
	}
	if got := s.MarkGone(pID); got != nil {
		t.Fatalf("MarkGone after Close returned %v", got)
	}
	// Close must have flushed despite the dirty flag still being set.
	reloaded, err := LoadStore(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	e := reloaded.Entry(pID)
	if e == nil || len(e.Addrs) != 1 || e.Addrs[0] != "a1" {
		t.Fatalf("Close did not flush: %+v", e)
	}
}

func TestRecordPeerAddrsNilStoreIsSafe(t *testing.T) {
	var s *peerAddrStore
	pID := test.RandPeerIDFatal(t)
	if got := s.RecordPeerAddrs(pID, []string{"a"}, nil, "", ""); got != nil {
		t.Fatalf("nil store RecordPeerAddrs = %v", got)
	}
	if got := s.MarkGone(pID); got != nil {
		t.Fatalf("nil store MarkGone = %v", got)
	}
	if e := s.Entry(pID); e != nil {
		t.Fatalf("nil store Entry = %v", e)
	}
	if snap := s.Snapshot(); snap != nil {
		t.Fatalf("nil store Snapshot = %v", snap)
	}
	if snap := s.SnapshotWithin(time.Hour); snap != nil {
		t.Fatalf("nil store SnapshotWithin = %v", snap)
	}
	if n := s.PruneOver(1); n != 0 {
		t.Fatalf("nil store PruneOver = %d", n)
	}
	if n := s.peerAddrCount(); n != 0 {
		t.Fatalf("nil store peerAddrCount = %d", n)
	}
	if err := s.Flush(); err != nil {
		t.Fatalf("nil store Flush = %v", err)
	}
	s.Close()
	var disabled *peerAddrStore
	if n := disabled.peerAddrCount(); n != 0 {
		t.Fatalf("disabled store count = %d", n)
	}
}

func TestAppendUniqueTransport(t *testing.T) {
	if got := appendUniqueString(nil, "quic"); len(got) != 1 || got[0] != "quic" {
		t.Fatalf("got %v", got)
	}
	if got := appendUniqueString([]string{"quic"}, "quic"); len(got) != 1 {
		t.Fatalf("duplicate kept: %v", got)
	}
	if got := appendUniqueString([]string{"quic"}, "tcp"); len(got) != 2 || got[1] != "tcp" {
		t.Fatalf("got %v", got)
	}
	// An empty label is rejected so a broken transport detector cannot
	// accumulate blank entries.
	if got := appendUniqueString([]string{"quic"}, ""); len(got) != 1 {
		t.Fatalf("empty transport accepted: %v", got)
	}
}

func TestReseedPeerAddrs(t *testing.T) {
	if got := reseedPeerAddrs(nil, test.RandPeerIDFatal(t), nil); got != 0 {
		t.Fatalf("empty input reseeded %d addrs", got)
	}

	h, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Skipf("libp2p.New: %v", err)
	}
	defer h.Close()

	pID := test.RandPeerIDFatal(t)
	good := "/ip4/203.0.113.5/udp/443/quic-v1/p2p/" + pID.String()
	if got := reseedPeerAddrs(h, pID, []string{good, "not-a-multiaddr", ""}); got != 1 {
		t.Fatalf("reseeded %d addrs, want 1 (unparseable input skipped)", got)
	}
	if got := h.Peerstore().Addrs(pID); len(got) != 1 {
		t.Fatalf("peerstore holds %d addrs for the peer: %v", len(got), got)
	}
}

// waitForStoreFile blocks until the writer produces the file, or the deadline
// expires. Every deadline below is deliberately looser than the interval being
// tested, so a broken writer fails loudly instead of passing on an empty file.
func waitForStoreFile(t *testing.T, path string, limit time.Duration) {
	t.Helper()
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("store writer never reached %s within %s", path, limit)
}

// TestDebouncedWriteFiresUnderSilence drives the coalesced-write path. Every
// other test calls Flush by hand, which bypasses the goroutine that is the
// whole reason the debounce exists.
func TestDebouncedWriteFiresUnderSilence(t *testing.T) {
	path := storePath(t)
	s, err := LoadStore(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	pID := test.RandPeerIDFatal(t)
	s.RecordPeerAddrs(pID, []string{"/ip4/203.0.113.5/tcp/4001/p2p/" + pID.String()},
		[]string{"tcp"}, "netA", "node-1")

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("store file exists before the debounce fires: %v", err)
	}
	waitForStoreFile(t, path, 20*time.Second)
}

// TestWriterPersistsUnderContinuousChurn is the regression for the real
// production failure: a boot whose peer traffic never left a full debounce
// window quiet held every record in memory until a restart. Records are added
// every 1s here, so the debounce keeps getting rescheduled and only the
// bounded fallback write can land the file.
func TestWriterPersistsUnderContinuousChurn(t *testing.T) {
	path := storePath(t)
	s, err := LoadStore(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	// Peer IDs are generated here rather than in the worker: calling a
	// testing.T-bound helper from another goroutine is undefined behaviour.
	ids := make([]peer.ID, 64)
	for i := range ids {
		ids[i] = test.RandPeerIDFatal(t)
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			pID := ids[i%len(ids)]
			s.RecordPeerAddrs(pID,
				[]string{fmt.Sprintf("/ip4/203.0.113.%d/tcp/4001/p2p/%s", i%250+1, pID.String())},
				[]string{"tcp"}, "", "")
			time.Sleep(1000 * time.Millisecond)
		}
	}()
	// Deferred after wg.Wait so close runs first: the churn must outlast the
	// whole observation window, or the debounce wins instead of the fallback.
	defer wg.Wait()
	defer close(stop)

	// The debounce never wins here, so this must exceed the fallback interval
	// or the test cannot pass by construction.
	waitForStoreFile(t, path, peerAddrFlushMinInterval+10*time.Second)

	// The writer must have landed at least the first record.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("cannot read the flushed store: %v", err)
	}
	var f peerAddrFile
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("flushed store is not decodable: %v", err)
	}
	if len(f.Peers) == 0 {
		t.Fatalf("flushed store has no peer records")
	}
}

// TestNotifyBundleRecordsOnConnect is a wiring check rather than a unit test:
// the notify callbacks in main() cannot be exercised without standing up a full
// boot, and the whole feature is silent about being unwired.
//
// RecordPeerAddrs is only reachable from ConnectedF. The two DisconnectedF
// paths are retraction-only, and MarkGone returns early for a peer that was
// never recorded, so a boot whose ConnectedF lost this call would accept
// connections all day, never fill the store, never write boot.addrs.json, and
// never emit an error. The regression was real — it shipped once.
func TestNotifyBundleRecordsOnConnect(t *testing.T) {
	// Source assertions are read through here so they normalize CRLF to LF.
	// The GitHub Actions windows-latest runner checks out with autocrlf=true
	// while ubuntu and macos stay LF, so a multi-line Contains check written
	// with "\n" passes on Linux and fails in CI unless the input is folded.
	readSource := func(name string) string {
		b, err := os.ReadFile(name)
		if err != nil {
			t.Skipf("cannot read %s: %v", name, err)
		}
		return strings.ReplaceAll(string(b), "\r\n", "\n")
	}

	src := readSource("main.go")
	body := strings.Split(src, "ConnectedF: func")
	if len(body) < 2 {
		t.Fatal("ConnectedF callback not found")
	}
	connectBody := strings.SplitN(body[1], "DisconnectedF: func", 2)
	if len(connectBody) < 2 {
		t.Fatal("DisconnectedF callback not found after ConnectedF")
	}
	if !strings.Contains(connectBody[0], "onPeerAddrChange(") {
		t.Fatal("ConnectedF does not call onPeerAddrChange: the address store is " +
			"never written, because DisconnectedF only retracts and MarkGone is a " +
			"no-op for a peer that was never recorded")
	}

	// MarkGone's early return is what makes the above fatal rather than slow.
	// Assert against the function's own body rather than the whole file, so the
	// check cannot be satisfied by an unrelated early return elsewhere.
	storeSrc := readSource("peer_addr_store.go")
	start := strings.Index(storeSrc, "func (s *peerAddrStore) MarkGone(")
	if start < 0 {
		t.Fatal("MarkGone not found in peer_addr_store.go")
	}
	rel := strings.Index(storeSrc[start:], "\nfunc ")
	if rel < 0 {
		t.Fatal("end of MarkGone not found in peer_addr_store.go")
	}
	markGoneBody := storeSrc[start : start+rel]
	if !strings.Contains(markGoneBody, "e, ok := s.entries[pID]") ||
		!strings.Contains(markGoneBody, "if !ok {\n\t\treturn nil\n\t}") {
		t.Fatal("MarkGone no-longer returns early for an unknown peer; the wiring " +
			"guard above may no longer describe reality")
	}
}
