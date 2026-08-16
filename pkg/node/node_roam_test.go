package node

import (
	"sync"
	"testing"
	"time"

	"github.com/multiformats/go-multiaddr"
)

func mustMaddr(t *testing.T, s string) multiaddr.Multiaddr {
	t.Helper()
	m, err := multiaddr.NewMultiaddr(s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return m
}

func TestNormKey(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"/ip4/10.0.0.5/tcp/4001", "/ip4/10.0.0.5/tcp/0"},
		{"/ip4/10.0.0.5/udp/4001/quic-v1", "/ip4/10.0.0.5/udp/0/quic-v1"},
		{"/ip6/fe80::1/tcp/9000", "/ip6/fe80::1/tcp/0"},
	}
	for _, c := range cases {
		if got := normKey(mustMaddr(t, c.in)); got != c.want {
			t.Fatalf("normKey(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	// Same NIC+transport, different ports -> equal keys, so a port-0 desired
	// address matches a real-port bound one.
	if normKey(mustMaddr(t, "/ip4/10.0.0.5/tcp/4001")) != normKey(mustMaddr(t, "/ip4/10.0.0.5/tcp/1234")) {
		t.Fatal("expected equal keys for same NIC/transport, different ports")
	}
}

func TestDiffListeners(t *testing.T) {
	tcp5 := mustMaddr(t, "/ip4/10.0.0.5/tcp/0")
	tcp5bound := mustMaddr(t, "/ip4/10.0.0.5/tcp/4001")
	tcp6 := mustMaddr(t, "/ip4/10.0.0.6/tcp/0")
	quic5 := mustMaddr(t, "/ip4/10.0.0.5/udp/0/quic-v1")
	quic5bound := mustMaddr(t, "/ip4/10.0.0.5/udp/4001/quic-v1")
	tcp7bound := mustMaddr(t, "/ip4/10.0.0.7/tcp/5001")

	cases := []struct {
		name    string
		desired []multiaddr.Multiaddr
		current []multiaddr.Multiaddr
		wantAdd int
		wantDel int
	}{
		{"no-op (port0 matches real port)", []multiaddr.Multiaddr{tcp5}, []multiaddr.Multiaddr{tcp5bound}, 0, 0},
		{"add new NIC", []multiaddr.Multiaddr{tcp5, tcp6}, []multiaddr.Multiaddr{tcp5bound}, 1, 0},
		{"remove gone NIC", []multiaddr.Multiaddr{tcp5}, []multiaddr.Multiaddr{tcp5bound, tcp7bound}, 0, 1},
		{"tcp+quic same NIC both match", []multiaddr.Multiaddr{tcp5, quic5}, []multiaddr.Multiaddr{tcp5bound, quic5bound}, 0, 0},
		{"current only -> remove all", nil, []multiaddr.Multiaddr{tcp5bound}, 0, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			add, del := diffListeners(c.desired, c.current)
			if len(add) != c.wantAdd {
				t.Fatalf("toAdd = %d, want %d", len(add), c.wantAdd)
			}
			if len(del) != c.wantDel {
				t.Fatalf("toRemove = %d, want %d", len(del), c.wantDel)
			}
		})
	}
}

type fakeListenerStore struct {
	mu      sync.Mutex
	current []multiaddr.Multiaddr
	added   [][]multiaddr.Multiaddr
	removed [][]multiaddr.Multiaddr
	egressN int
}

func (f *fakeListenerStore) CurrentListenAddrs() []multiaddr.Multiaddr {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]multiaddr.Multiaddr, len(f.current))
	copy(out, f.current)
	return out
}
func (f *fakeListenerStore) AddListenAddrs(addrs ...multiaddr.Multiaddr) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.added = append(f.added, addrs)
	f.current = append(f.current, addrs...)
	return nil
}
func (f *fakeListenerStore) CloseListenAddrs(addrs ...multiaddr.Multiaddr) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.removed = append(f.removed, addrs)
	drop := map[string]bool{}
	for _, a := range addrs {
		drop[normKey(a)] = true
	}
	keep := f.current[:0]
	for _, c := range f.current {
		if !drop[normKey(c)] {
			keep = append(keep, c)
		}
	}
	f.current = keep
}
func (f *fakeListenerStore) RefreshEgress() {
	f.mu.Lock()
	f.egressN++
	f.mu.Unlock()
}

func TestReconcileRoamAdds(t *testing.T) {
	f := &fakeListenerStore{}
	base := []multiaddr.Multiaddr{
		mustMaddr(t, "/ip4/10.0.0.5/tcp/0"),
		mustMaddr(t, "/ip4/10.0.0.6/tcp/0"),
	}
	changed := reconcileRoam(f, base)
	if !changed {
		t.Fatalf("reconcileRoam returned changed=false, want true (listeners should be added)")
	}
	if f.egressN != 1 {
		t.Fatalf("RefreshEgress called %d times, want 1", f.egressN)
	}
	if len(f.added) != 1 || len(f.added[0]) != 2 {
		t.Fatalf("AddListenAddrs batches = %d (want 1 of 2 addrs), got %+v", len(f.added), f.added)
	}
	if len(f.removed) != 0 {
		t.Fatalf("unexpected CloseListenAddrs: %+v", f.removed)
	}
}

func TestReconcileRoamRemoves(t *testing.T) {
	gone := mustMaddr(t, "/ip4/10.0.0.7/tcp/5001")
	f := &fakeListenerStore{
		current: []multiaddr.Multiaddr{
			mustMaddr(t, "/ip4/10.0.0.5/tcp/4001"),
			gone,
		},
	}
	// desired keeps .5 but drops .7
	base := []multiaddr.Multiaddr{mustMaddr(t, "/ip4/10.0.0.5/tcp/0")}
	changed := reconcileRoam(f, base)
	if !changed {
		t.Fatalf("reconcileRoam returned changed=false, want true (listener should be removed)")
	}
	if f.egressN != 1 {
		t.Fatalf("RefreshEgress called %d times, want 1", f.egressN)
	}
	if len(f.added) != 0 {
		t.Fatalf("unexpected AddListenAddrs: %+v", f.added)
	}
	if len(f.removed) != 1 || len(f.removed[0]) != 1 {
		t.Fatalf("CloseListenAddrs = %+v, want 1 batch of 1", f.removed)
	}
	if !f.removed[0][0].Equal(gone) {
		t.Fatalf("removed addr %s, want %s", f.removed[0][0], gone)
	}
}

func TestRoamDebouncerCoalesces(t *testing.T) {
	old := roamDebounce
	roamDebounce = 30 * time.Millisecond
	defer func() { roamDebounce = old }()

	var mu sync.Mutex
	var calls int
	d := newRoamDebouncer(func() {
		mu.Lock()
		calls++
		mu.Unlock()
	})
	d.start()
	for i := 0; i < 5; i++ {
		d.trigger()
	}
	time.Sleep(roamDebounce + 80*time.Millisecond)
	mu.Lock()
	c := calls
	mu.Unlock()
	if c != 1 {
		t.Fatalf("expected exactly 1 coalesced reconcile, got %d", c)
	}
}

func TestSignaturesEqual(t *testing.T) {
	if !signaturesEqual([]string{"1.1.1.1", "2.2.2.2"}, []string{"1.1.1.1", "2.2.2.2"}) {
		t.Fatal("expected equal for identical sorted signatures")
	}
	if signaturesEqual([]string{"1.1.1.1"}, []string{"1.1.1.1", "2.2.2.2"}) {
		t.Fatal("expected unequal for different lengths")
	}
	if signaturesEqual([]string{"1.1.1.1", "2.2.2.2"}, []string{"1.1.1.1", "3.3.3.3"}) {
		t.Fatal("expected unequal for different content")
	}
}
