package node

import (
	"bytes"
	"encoding/binary"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"p2ptap/pkg/config"
)

// --- epoch authority ---

// The per-peer epoch is read from TWO places: txEpochForPeer stamps it into the
// outbound frame counter, and ensureLocalEpoch supplies it to the SeqSync /
// epochSync messages we advertise to the peer. Those two must always agree.
// removePeerObf drops the peerLocalEpochs map entry on every transport loss
// while deliberately keeping the negotiated cipher, and a PeerObf can also be
// garbage-collected on its own while the map entry survives. Either transition
// used to let the map and the cipher drift apart: we would then advertise one
// epoch and stamp another, so the peer anchored its dedup window to an epoch
// our frames never carry. The frames decrypt fine, so the decrypt-fail self-heal
// never fires and the link is a permanent one-way black hole that every
// liveness probe reads as healthy.
func TestEpochAccessorsNeverDiverge(t *testing.T) {
	n := &Node{}
	p := peer.ID("epoch-peer")

	// No cipher yet: the map entry is the source of truth.
	if got := n.ensureLocalEpoch(p); got == 0 {
		t.Fatal("ensureLocalEpoch minted epoch 0")
	}
	if tx := n.txEpochForPeer(p); tx != n.ensureLocalEpoch(p) {
		t.Fatalf("no cipher: txEpochForPeer=%d ensureLocalEpoch=%d", tx, n.ensureLocalEpoch(p))
	}

	// A retained, negotiated cipher becomes authoritative for both.
	tbl := map[peer.ID]*PeerObf{p: {negotiated: true, localEpoch: 42}}
	n.perPeerObf.Store(&tbl)
	if got := n.ensureLocalEpoch(p); got != 42 {
		t.Fatalf("ensureLocalEpoch = %d, want the retained cipher's epoch 42", got)
	}
	if tx := n.txEpochForPeer(p); tx != 42 {
		t.Fatalf("txEpochForPeer = %d, want 42", tx)
	}

	// The map can hold a stale value left behind by an earlier session:
	// ensureLocalEpoch must repair it, and txEpochForPeer must not report the
	// stale one.
	n.peerLocalEpochs.Store(p, uint64(7))
	if got := n.txEpochForPeer(p); got != 42 {
		t.Fatalf("txEpochForPeer = %d, want 42 (the retained cipher wins)", got)
	}
	if got := n.ensureLocalEpoch(p); got != 42 {
		t.Fatalf("ensureLocalEpoch = %d, want 42", got)
	}
	if v, ok := n.peerLocalEpochs.Load(p); !ok || v.(uint64) != 42 {
		t.Fatalf("ensureLocalEpoch did not repair the stale map entry: %v", v)
	}

	// Transport loss: the map entry is dropped, the cipher is kept. The epoch
	// must survive the churn untouched.
	n.peerLocalEpochs.Delete(p)
	if got := n.ensureLocalEpoch(p); got != 42 {
		t.Fatalf("epoch did not survive a map-entry drop: got %d, want 42", got)
	}
	if tx := n.txEpochForPeer(p); tx != 42 {
		t.Fatalf("txEpochForPeer after churn = %d, want 42", tx)
	}

	// The mirror-image churn: the cipher is gone and the map entry survived.
	// Both accessors fall back to the same entry, so they still agree.
	n.perPeerObf.Store(&map[peer.ID]*PeerObf{})
	if got := n.ensureLocalEpoch(p); got != 42 {
		t.Fatalf("cipher GC'd: ensureLocalEpoch = %d, want the cached 42", got)
	}
	if tx := n.txEpochForPeer(p); tx != 42 {
		t.Fatalf("cipher GC'd: txEpochForPeer = %d, want 42", tx)
	}
}

// --- dedup-desync recovery ---

func TestRecordPeerDedupDesyncWindow(t *testing.T) {
	n := &Node{}
	p := peer.ID("dedup-desync-peer")

	for i := 0; i < 3; i++ {
		n.recordPeerDedupDesync(p, true)
	}
	v, ok := n.peerDedupDesyncErrs.Load(p)
	if !ok || v.(*atomic.Uint64).Load() != 3 {
		t.Fatalf("counter = %v, want 3", v)
	}

	// One accepted frame resets the window so a healed link cannot keep
	// re-firing the resync forever.
	n.recordPeerDedupDesync(p, false)
	if v.(*atomic.Uint64).Load() != 0 {
		t.Fatalf("counter = %d after an accepted frame, want 0", v.(*atomic.Uint64).Load())
	}

	// Resetting an already-zero window must be a no-op, not a panic.
	n.recordPeerDedupDesync(p, false)

	// The reset path creates the entry when it does not exist yet.
	q := peer.ID("never-seen-peer")
	n.recordPeerDedupDesync(q, false)
	if v, ok := n.peerDedupDesyncErrs.Load(q); !ok || v.(*atomic.Uint64).Load() != 0 {
		t.Fatalf("lazy entry = %v, want an initialised counter at 0", v)
	}

	// Peer churn drops the window.
	n.peerLocalEpochs.Delete(p)
	n.peerDedupDesyncErrs.Delete(p)
	if _, ok := n.peerDedupDesyncErrs.Load(p); ok {
		t.Fatal("peerDedupDesyncErrs entry survived peer churn")
	}
}

func TestMaybeResyncPeerThresholdAndCooldown(t *testing.T) {
	n := &Node{}
	p := peer.ID("resync-threshold-peer")
	counts := func(v uint64) *atomic.Uint64 { a := &atomic.Uint64{}; a.Store(v); return a }

	if n.maybeResyncPeer(&n.peerDedupDesyncErrs, p) {
		t.Error("fired with no error record")
	}

	n.peerDedupDesyncErrs.Store(p, counts(15))
	if n.maybeResyncPeer(&n.peerDedupDesyncErrs, p) {
		t.Error("fired below the threshold of 16")
	}

	n.peerDedupDesyncErrs.Store(p, counts(16))
	if !n.maybeResyncPeer(&n.peerDedupDesyncErrs, p) {
		t.Fatal("did not fire at the threshold of 16")
	}
	// The cooldown then suppresses every further retry.
	if n.maybeResyncPeer(&n.peerDedupDesyncErrs, p) {
		t.Error("fired again inside the cooldown")
	}

	// Recently re-keyed and below the escalation cap: give the new key a chance
	// to settle instead of immediately tearing it down.
	n.peerDedupDesyncErrs.Store(p, counts(16))
	n.lastRekeySuccess.Store(p, time.Now())
	if n.maybeResyncPeer(&n.peerDedupDesyncErrs, p) {
		t.Error("fired inside the settle window below the escalation cap")
	}

	// Above the escalation cap the same peer must be resynced anyway: the link
	// has proven it cannot settle on the new key. The cooldown is cleared here
	// so the assertion is on the cap itself, not on timer expiry.
	n.lastRekeySuccess.Delete(p)
	if n.maybeResyncPeer(&n.peerDedupDesyncErrs, p) {
		t.Error("fired again inside the cooldown")
	}
	n.decryptResyncCooldown.Delete(p)
	n.peerDedupDesyncErrs.Store(p, counts(64))
	if !n.maybeResyncPeer(&n.peerDedupDesyncErrs, p) {
		t.Fatal("did not escalate past the cap after a fresh key failed too")
	}

	// Once the settle window has elapsed a normal-sized count fires again.
	n.peerDedupDesyncErrs.Store(p, counts(16))
	n.lastRekeySuccess.Store(p, time.Now().Add(-120*time.Second))
	n.decryptResyncCooldown.Delete(p)
	if !n.maybeResyncPeer(&n.peerDedupDesyncErrs, p) {
		t.Fatal("did not fire after the settle window elapsed")
	}
}

// --- mesh-local / local-subnet predicates ---

func TestIsMeshLocalIPMulticastScope(t *testing.T) {
	n := bareMeshNode(t)

	meshLocal := []string{
		"224.0.0.1",       // IGMP all hosts
		"224.0.0.2",       // IGMP all routers
		"224.0.0.22",      // ICMPv4 router discovery
		"224.0.0.251",     // mDNS
		"224.0.0.252",     // LLMNR
		"239.255.255.250", // SSDP / UPnP
		"239.0.0.1",       // 239/8: reserved private
		"240.0.0.1",       // 240/4: reserved
		"255.255.255.255",
		"ff01::1",   // interface-local
		"ff02::1",   // link-local all-nodes
		"ff05::1:3", // site-local: all DHCP agents
		"ff06::1",   // organization-local
	}
	for _, s := range meshLocal {
		if !n.isMeshLocalIP(net.ParseIP(s)) {
			t.Errorf("isMeshLocalIP(%s) = false, want true", s)
		}
	}

	// Genuinely global multicast and everything routable still leaves the mesh.
	notMesh := []string{
		"232.0.1.1", // Class D global (232-238)
		"238.1.1.1",
		"ff08::8001",
		"ff0e::8002",
		"8.8.8.8",
		"2001:4860:4860::8888",
	}
	for _, s := range notMesh {
		if n.isMeshLocalIP(net.ParseIP(s)) {
			t.Errorf("isMeshLocalIP(%s) = true, want false", s)
		}
	}
}

// isMeshLocalIP must not outgrow isLocalSubnetIP: it decides "does this belong
// to the mesh", the other "is this for me". Widening the wrong one pulls other
// peers' traffic into this node's TAP.
func TestIsLocalSubnetIPIsNarrower(t *testing.T) {
	n := bareMeshNode(t)
	n.localV4IP = net.ParseIP("10.9.9.1")
	n.localV6IP = net.ParseIP("fd00:99::1")
	n.peerLocalEpochs.Store(peer.ID("narrow-peer"), uint64(1))
	// A node-configured advertised subnet, not a peer's announcement.
	cfg := config.DefaultConfig()
	cfg.AdvertisedSubnets = []string{"172.20.0.0/16"}
	ptr := new(atomic.Pointer[config.Config])
	ptr.Store(cfg)
	n.configPtr = ptr

	own := []string{"10.9.9.1", "10.9.9.55", "fd00:99::1", "fd00:99::9", "172.20.7.7"}
	for _, s := range own {
		if !n.isLocalSubnetIP(net.ParseIP(s)) {
			t.Errorf("isLocalSubnetIP(%s) = false, want true", s)
		}
	}

	// Group addresses are mesh-local but never addressed at us specifically:
	// their Dst MAC is already the group/broadcast MAC and must not be
	// rewritten to the interface MAC.
	otherPeers := []string{"255.255.255.255", "224.0.0.251", "239.255.255.250", "ff02::1", "ff05::1:3", "169.254.9.9", "fe80::5"}
	for _, s := range otherPeers {
		if n.isLocalSubnetIP(net.ParseIP(s)) {
			t.Errorf("isLocalSubnetIP(%s) = true, want false", s)
		}
	}

	// The decisive case: another peer's TAP address is mesh-local but not ours.
	// Treating it as local would inject every frame for it into our TAP.
	installAdvertisedSubnet(t, n, peer.ID("other-peer"), "172.16.0.0/24")
	ip := net.ParseIP("172.16.0.9")
	if n.isLocalSubnetIP(ip) {
		t.Error("isLocalSubnetIP reported another peer's TAP IP as local")
	}
	if !n.isMeshLocalIP(ip) {
		t.Error("isMeshLocalIP stopped reporting that peer's subnet as mesh-local")
	}
	if n.isLocalSubnetIP(nil) {
		t.Error("isLocalSubnetIP(nil) = true")
	}
}

func TestIsMeshLocalIPv4PeerTAP(t *testing.T) {
	n := bareMeshNode(t)
	mac := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x09}
	ip := net.ParseIP("192.168.7.9")
	n.arpIndexMu.Lock()
	idx := n.arpIndex
	if idx == nil {
		idx = &arpIndex{}
	}
	idx.v4 = map[uint32]arpIndexEntry{
		binary.BigEndian.Uint32(ip.To4()): {mac: mac, pid: peer.ID("v4-tap-peer")},
	}
	n.arpIndex = idx
	n.arpIndexMu.Unlock()

	if !n.isMeshLocalIP(ip) {
		t.Error("a peer's TAP IP outside our own subnet is not mesh-local — that peer " +
			"is unreachable as a destination whenever its MAC is unknown or group-addressed")
	}
	if n.isLocalSubnetIP(ip) {
		t.Error("that peer's TAP IP must not be treated as our own")
	}
}

// rewriteRxDstMAC used to test "is this frame mine" with a narrower predicate
// than isMeshLocalIP, so 169.254/16, 255.255.255.255 and every group address
// were Exit-hijacked whenever an exit node was configured — a pre-DHCP host and
// a DHCP unicast-broadcast reply disappeared out of the mesh entirely.
func TestRewriteRxDstMACDoesNotExitHijackMeshTraffic(t *testing.T) {
	synthetic := net.HardwareAddr{0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01}
	newDst := func(dstIP net.IP) []byte {
		f := make([]byte, 74)
		copy(f[0:6], synthetic)
		copy(f[6:12], []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x02})
		f[12], f[13] = 0x08, 0x00 // EtherType IPv4
		f[14], f[15] = 0x45, 0x00
		binary.BigEndian.PutUint16(f[16:18], 60)
		f[20], f[21] = 0x40, 0x01
		f[22] = 0x01
		copy(f[26:30], net.ParseIP("10.9.9.2").To4())
		copy(f[30:34], dstIP.To4())
		return f
	}

	n := bareMeshNode(t)
	n.localMAC = []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	n.localV4IP = net.ParseIP("10.9.9.1")
	n.localV6IP = net.ParseIP("fd00:99::1")
	cfg := config.DefaultConfig()
	cfg.ExitNode.Enable = true
	ptr := new(atomic.Pointer[config.Config])
	ptr.Store(cfg)
	n.configPtr = ptr

	stayInMesh := []net.IP{net.ParseIP("224.0.0.251"), net.ParseIP("239.255.255.250"), net.ParseIP("169.254.9.9")}
	for _, dst := range stayInMesh {
		f := newDst(dst)
		n.rewriteRxDstMAC(f)
		if !bytes.Equal(f[0:6], synthetic) {
			t.Errorf("%s was Exit-hijacked: Dst MAC %s != the original %s", dst, net.HardwareAddr(f[0:6]), synthetic)
		}
	}

	// A genuinely public destination IS pulled into the exit path, which is the
	// whole point of the rewrite. With no active exit peer the rewrite falls
	// back to our own MAC.
	f := newDst(net.ParseIP("8.8.8.8"))
	n.rewriteRxDstMAC(f)
	if !bytes.Equal(f[0:6], n.localMAC) {
		t.Errorf("exit transit rewrite did not run for %s: Dst MAC %s", net.IP(f[30:34]), net.HardwareAddr(f[0:6]))
	}

	// A frame to our own subnet is rewritten to the interface MAC and never
	// leaves the mesh.
	f = newDst(net.ParseIP("10.9.9.1"))
	n.rewriteRxDstMAC(f)
	if !bytes.Equal(f[0:6], n.localMAC) {
		t.Errorf("local-dst rewrite FAILED: Dst MAC %s", net.HardwareAddr(f[0:6]))
	}
}

// --- IPv6 extension headers ---

// extSpec describes one IPv6 extension header: kind is its next-header value
// and hlc its length field.
type extSpec struct {
	kind byte
	hlc  byte
}

func extSpecLen(e extSpec) int {
	switch e.kind {
	case 0, 43, 60: // Hop-by-Hop, Routing, Destination Options
		return (int(e.hlc)&0x0f + 1) * 8
	case 44: // Fragment
		return 8
	case 51: // AH
		return (int(e.hlc)&0x3f + 1) * 4
	default:
		return 8
	}
}

// buildIPv6NS assembles a full Ethernet frame carrying an ICMPv6 Neighbor
// Solicitation behind an optional extension-header chain, with the NS target at
// fd00::9.
func buildIPv6NS(t *testing.T, exts []extSpec) []byte {
	t.Helper()
	total := 14 + 40
	for _, e := range exts {
		total += extSpecLen(e)
	}
	total += 28 // ICMPv6 NS: type, code, cksum, 16-byte target, 8-byte target info

	f := make([]byte, total)
	copy(f[0:6], []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01})
	copy(f[6:12], []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x02})
	f[12], f[13] = 0x86, 0xdd
	f[14] = 0x60
	if len(exts) > 0 {
		f[20] = exts[0].kind
	} else {
		f[20] = 58 // ICMPv6
	}
	f[21] = 64
	copy(f[22:38], net.ParseIP("fd00::2").To16())
	copy(f[38:54], net.ParseIP("ff02::1").To16())

	off := 54
	for i, e := range exts {
		l := extSpecLen(e)
		f[off], f[off+1] = e.kind, e.hlc
		nxt := byte(58)
		if i+1 < len(exts) {
			nxt = exts[i+1].kind
		}
		f[off+l-1] = nxt
		off += l
	}
	f[off], f[off+1] = 135, 0 // Neighbor Solicitation
	copy(f[off+8:off+24], net.ParseIP("fd00::9").To16())
	return f
}

func TestICMPv6OffsetExtensionHeaders(t *testing.T) {
	target := net.ParseIP("fd00::9").To16()

	cases := []struct {
		name string
		exts []extSpec
		want int
	}{
		{"no extension headers", nil, 54},
		{"hop-by-hop", []extSpec{{0, 0}}, 62},
		{"routing", []extSpec{{43, 0}}, 62},
		{"destination options 16B", []extSpec{{60, 1}}, 70},
		{"fragment", []extSpec{{44, 0}}, 62},
		{"ah", []extSpec{{51, 0}}, 58},
		{"ah 8B", []extSpec{{51, 1}}, 62},
		{"hop-by-hop then destination options", []extSpec{{0, 0}, {60, 0}}, 70},
		{"fragment then ah", []extSpec{{44, 0}, {51, 0}}, 66},
	}
	for _, tc := range cases {
		f := buildIPv6NS(t, tc.exts)
		got := icmpv6Offset(f)
		if got != tc.want {
			t.Errorf("%s: icmpv6Offset = %d, want %d", tc.name, got, tc.want)
			continue
		}
		// The NS target is a full 16 bytes past the ICMPv6 header start, so the
		// offset must be exact: the old payload[20]==58 shortcut both failed to
		// detect the NS and misread the target.
		if !net.IP(f[got+8 : got+24]).Equal(target) {
			t.Errorf("%s: the resolved offset does not reach the NS target", tc.name)
		}
	}
}

func TestICMPv6OffsetRejectsMalformed(t *testing.T) {
	if got := icmpv6Offset(nil); got != -1 {
		t.Errorf("nil payload: got %d, want -1", got)
	}
	if got := icmpv6Offset(make([]byte, 40)); got != -1 {
		t.Errorf("short payload: got %d, want -1", got)
	}

	// Not IPv6 at all.
	f := buildIPv6NS(t, nil)
	f[12], f[13] = 0x08, 0x00
	if got := icmpv6Offset(f); got != -1 {
		t.Errorf("IPv4 ethertype: got %d, want -1", got)
	}

	// An extension header whose declared length overruns the frame.
	f = buildIPv6NS(t, []extSpec{{60, 2}})
	if got := icmpv6Offset(f[:70]); got != -1 {
		t.Errorf("truncated extension header: got %d, want -1", got)
	}

	// A next header this walker does not support stops the walk rather than
	// guessing: ESP in particular hides the real next header in its trailer.
	f = buildIPv6NS(t, nil)
	f[20] = 50
	if got := icmpv6Offset(f); got != -1 {
		t.Errorf("unsupported next header: got %d, want -1", got)
	}

	// An extension chain that never reaches ICMPv6.
	f = buildIPv6NS(t, nil)
	f[20] = 59
	if got := icmpv6Offset(f); got != -1 {
		t.Errorf("next header is ICMPv6 but the frame has no ICMPv6 at 54: got %d, want -1", got)
	}
}

// --- advertised subnet resolution ---

func subnetOf(t *testing.T, cidr string) *net.IPNet {
	t.Helper()
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatal(err)
	}
	return ipNet
}

func entry(t *testing.T, cidr string, pid peer.ID, macs ...net.HardwareAddr) arpSubnetEntry {
	t.Helper()
	var mac net.HardwareAddr
	if len(macs) > 0 {
		mac = macs[0]
	}
	return arpSubnetEntry{net: subnetOf(t, cidr), pid: pid, mac: mac}
}

func TestResolveSubnetConflictsStrictContainment(t *testing.T) {
	n := &Node{}
	a, b := peer.ID("subnet-a"), peer.ID("subnet-b")
	macA := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0xa0}
	macB := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0xb0}

	surviving, conflicts := n.resolveSubnetConflicts([]arpSubnetEntry{
		entry(t, "10.0.0.0/16", a, macA),
		entry(t, "10.0.1.0/24", b, macB),
	}, []string{a.String()})

	if len(surviving) != 2 {
		t.Fatalf("both overlapping prefixes must survive, got %d: %+v", len(surviving), surviving)
	}
	if len(conflicts) != 1 {
		t.Fatalf("got %d conflicts, want 1", len(conflicts))
	}
	c := conflicts[0]
	if c.ResourceType != "advertised_subnet_overlap" {
		t.Errorf("resource type = %q, want advertised_subnet_overlap", c.ResourceType)
	}
	if len(c.Losers) != 0 {
		t.Errorf("containment reports %v as losers; isSubnetRouteSuppressed would withdraw "+
			"an OS route that is actually correct", c.Losers)
	}

	// Longest prefix first: this ordering is what makes the first-match scan a
	// longest-prefix lookup, so the contained /24 wins over the /16.
	n.arpIndexMu.Lock()
	n.arpIndex = &arpIndex{subnets: surviving}
	n.arpIndexMu.Unlock()

	if got := n.lookupPeerIDByAdvertisedSubnet(net.ParseIP("10.0.1.5")); got != b {
		t.Errorf("10.0.1.5 resolved to %s, want %s (the more specific prefix)", got, b)
	}
	if got := n.lookupPeerIDByAdvertisedSubnet(net.ParseIP("10.0.9.5")); got != a {
		t.Errorf("10.0.9.5 resolved to %s, want %s", got, a)
	}
	if got := n.lookupPeerMACByAdvertisedSubnet(net.ParseIP("10.0.1.5")); !bytes.Equal(got, macB) {
		t.Errorf("10.0.1.5 resolved to MAC %s, want %s (the contained /24)", got, macB)
	}
}

func TestResolveSubnetConflictsIdenticalCIDRSuppressesLoser(t *testing.T) {
	n := &Node{}
	a, b := peer.ID("dup-a"), peer.ID("dup-b")

	surviving, conflicts := n.resolveSubnetConflicts([]arpSubnetEntry{
		entry(t, "192.168.5.0/24", a),
		entry(t, "192.168.5.0/24", b),
	}, []string{a.String()})

	if len(surviving) != 1 {
		t.Fatalf("an exact duplicate must suppress one entry, got %d: %+v", len(surviving), surviving)
	}
	if surviving[0].pid != a {
		t.Errorf("the higher-priority peer lost its duplicate subnet: got %s", surviving[0].pid)
	}
	if len(conflicts) != 1 || conflicts[0].ResourceType != "advertised_subnet" {
		t.Fatalf("expected one advertised_subnet conflict, got %+v", conflicts)
	}
	if len(conflicts[0].Losers) != 1 || conflicts[0].Losers[0] != b.String() {
		t.Errorf("losers = %v, want [%s]", conflicts[0].Losers, b.String())
	}
}

func TestResolveSubnetConflictsLongestPrefixWins(t *testing.T) {
	n := &Node{}
	a, b, c := peer.ID("lpm-a"), peer.ID("lpm-b"), peer.ID("lpm-c")

	// Order intentionally reversed: the /16 and /25 are added first.
	surviving, _ := n.resolveSubnetConflicts([]arpSubnetEntry{
		entry(t, "10.0.0.0/16", a),
		entry(t, "10.0.1.0/25", c),
		entry(t, "10.0.1.0/24", b),
	}, []string{a.String(), b.String(), c.String()})

	if len(surviving) != 3 {
		t.Fatalf("all three prefixes must survive, got %d: %+v", len(surviving), surviving)
	}
	prefixes := make([]int, 0, len(surviving))
	for _, e := range surviving {
		p, _ := e.net.Mask.Size()
		prefixes = append(prefixes, p)
	}
	if prefixes[0] != 25 || prefixes[1] != 24 || prefixes[2] != 16 {
		t.Errorf("prefixes are not in descending order: %v", prefixes)
	}

	n.arpIndexMu.Lock()
	n.arpIndex = &arpIndex{subnets: surviving}
	n.arpIndexMu.Unlock()

	if got := n.lookupPeerIDByAdvertisedSubnet(net.ParseIP("10.0.1.1")); got != c {
		t.Errorf("10.0.1.1 (inside the /25) resolved to %s, want %s", got, c)
	}
	if got := n.lookupPeerIDByAdvertisedSubnet(net.ParseIP("10.0.1.128")); got != b {
		t.Errorf("10.0.1.128 (outside the /25) resolved to %s, want %s", got, b)
	}
	if got := n.lookupPeerIDByAdvertisedSubnet(net.ParseIP("10.0.9.1")); got != a {
		t.Errorf("10.0.9.1 resolved to %s, want %s", got, a)
	}
}
