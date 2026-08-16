package node

import (
	"net"
	"runtime"
	"testing"
)

// fakeRouteBackend is an in-memory implementation of routeBackend used to
// exercise SetExitNode / ClearExitNode / subnet-route orchestration without
// touching the host routing table. It records every call so tests can assert
// on ordering and side effects.
type fakeRouteBackend struct {
	gw     string
	gw6    string
	addDef []string
	delDef []string
	// delDefErr, when true, makes delDefaultRouteOS return an error so tests
	// can verify flag teardown is independent of route-deletion success.
	delDefErr bool
	addHost   [][2]string
	delHost   [][2]string
	addCIDR   [][3]string
	delCIDR   [][3]string
	swept     int
	restored  int
	wfpOn     int
	wfpOff    int
	// onLink marks endpoints that the (fake) host can reach directly on a
	// connected subnet of a physical NIC, i.e. without a router hop.
	onLink map[string]bool
}

func (f *fakeRouteBackend) GetOriginalPhysicalGateway() (string, error) { return f.gw, nil }

// GetOriginalPhysicalGatewayFor mirrors the real implementation's contract: the
// returned gateway always belongs to the same address family as the endpoint,
// and a missing gateway of that family is an error (which is exactly the case
// that used to produce bogus /128 routes).
func (f *fakeRouteBackend) GetOriginalPhysicalGatewayFor(endpointIP string) (string, error) {
	ip := net.ParseIP(endpointIP)
	if ip != nil && ip.To4() == nil {
		if f.gw6 == "" {
			return "", errFake
		}
		return f.gw6, nil
	}
	if f.gw == "" {
		return "", errFake
	}
	return f.gw, nil
}

func (f *fakeRouteBackend) isOnLinkEndpoint(endpointIP string) bool {
	return f.onLink[endpointIP]
}
func (f *fakeRouteBackend) addDefaultRouteOS(exitTapIP, tapDevName string, metric int) error {
	f.addDef = append(f.addDef, exitTapIP)
	return nil
}
func (f *fakeRouteBackend) delDefaultRouteOS(exitTapIP, tapDevName string) error {
	f.delDef = append(f.delDef, exitTapIP)
	if f.delDefErr {
		return errFake
	}
	return nil
}
func (f *fakeRouteBackend) addHostRouteOS(endpointIP, gwIP string) error {
	f.addHost = append(f.addHost, [2]string{endpointIP, gwIP})
	return nil
}
func (f *fakeRouteBackend) delHostRouteOS(endpointIP, gwIP string) error {
	f.delHost = append(f.delHost, [2]string{endpointIP, gwIP})
	return nil
}
func (f *fakeRouteBackend) addCIDRRouteOS(cidrStr, gatewayIP, tapDevName string) error {
	f.addCIDR = append(f.addCIDR, [3]string{cidrStr, gatewayIP, tapDevName})
	return nil
}
func (f *fakeRouteBackend) delCIDRRouteOS(cidrStr, gatewayIP, tapDevName string) error {
	f.delCIDR = append(f.delCIDR, [3]string{cidrStr, gatewayIP, tapDevName})
	return nil
}
func (f *fakeRouteBackend) sweepTapDefaultRoutesUnlocked() error {
	f.swept++
	return nil
}
func (f *fakeRouteBackend) restorePhysicalDefaultGatewayOS() { f.restored++ }
func (f *fakeRouteBackend) enableProcessBypass() error {
	f.wfpOn++
	return nil
}
func (f *fakeRouteBackend) disableProcessBypass() error {
	f.wfpOff++
	return nil
}

// errFake is a sentinel error returned by the fake backend to simulate a
// failing OS route operation.
var errFake = &fakeErr{}

type fakeErr struct{}

func (e *fakeErr) Error() string { return "fake route backend error" }

func newFakeGM(t *testing.T) (*GatewayManager, *fakeRouteBackend) {
	t.Helper()
	gm := NewGatewayManager("tap0")
	fb := &fakeRouteBackend{
		gw:     "192.168.1.1",
		gw6:    "fe80::1",
		onLink: make(map[string]bool),
	}
	gm.route = fb
	// Keep the host-route code path exercised on every platform (the Windows
	// build disables it in favour of socket-level IP_UNICAST_IF binding; the
	// dedicated test below pins that socket-only behaviour).
	gm.hostRouteBypass = true
	return gm, fb
}

// hostRouteFor returns the next hop of the recorded addHostRouteOS call for
// endpointIP, plus whether such a call happened at all.
func (f *fakeRouteBackend) hostRouteFor(endpointIP string) (string, bool) {
	for _, h := range f.addHost {
		if h[0] == endpointIP {
			return h[1], true
		}
	}
	return "", false
}

// delHostRouteFor is the teardown counterpart of hostRouteFor.
func (f *fakeRouteBackend) delHostRouteFor(endpointIP string) (string, bool) {
	for _, h := range f.delHost {
		if h[0] == endpointIP {
			return h[1], true
		}
	}
	return "", false
}

// TestSetExitNodeActivates verifies that activating an Exit Node sets the
// active flags, flips the atomic exitActive mirror, installs the TAP default
// route, installs a per-endpoint bypass host route, and enables WFP.
func TestSetExitNodeActivates(t *testing.T) {
	gm, fb := newFakeGM(t)

	if err := gm.SetExitNode("peer-A", "10.0.0.2", "", []string{"1.2.3.4"}); err != nil {
		t.Fatalf("SetExitNode returned error: %v", err)
	}

	if !gm.IsExitNodeActive() {
		t.Fatal("IsExitNodeActive() should be true after SetExitNode")
	}
	if got := gm.ActiveExitPeerID(); got != "peer-A" {
		t.Fatalf("ActiveExitPeerID = %q, want peer-A", got)
	}
	if got := gm.ActiveExitIP(); got != "10.0.0.2" {
		t.Fatalf("ActiveExitIP = %q, want 10.0.0.2", got)
	}
	if len(fb.addDef) != 1 || fb.addDef[0] != "10.0.0.2" {
		t.Fatalf("addDefaultRouteOS calls = %v, want [10.0.0.2]", fb.addDef)
	}
	if fb.wfpOn != 1 {
		t.Fatalf("enableProcessBypass called %d times, want 1", fb.wfpOn)
	}
	if len(fb.addHost) == 0 {
		t.Fatal("expected a bypass host route to be installed for the physical endpoint")
	}
	if fb.addHost[0][0] != "1.2.3.4" {
		t.Fatalf("bypass host route installed for %q, want 1.2.3.4", fb.addHost[0][0])
	}
}

// TestClearExitNodeCleansUp verifies that clearing an Exit Node resets the
// flags, flips the atomic mirror off, removes the TAP default route (using the
// remembered exit IP), disables WFP, and tears down every bypass host route.
func TestClearExitNodeCleansUp(t *testing.T) {
	gm, fb := newFakeGM(t)
	if err := gm.SetExitNode("peer-A", "10.0.0.2", "", []string{"1.2.3.4"}); err != nil {
		t.Fatalf("SetExitNode returned error: %v", err)
	}

	if err := gm.ClearExitNode(); err != nil {
		t.Fatalf("ClearExitNode returned error: %v", err)
	}

	if gm.IsExitNodeActive() {
		t.Fatal("IsExitNodeActive() should be false after ClearExitNode")
	}
	if got := gm.ActiveExitIP(); got != "" {
		t.Fatalf("ActiveExitIP = %q, want empty", got)
	}
	if len(fb.delDef) != 1 || fb.delDef[0] != "10.0.0.2" {
		t.Fatalf("delDefaultRouteOS calls = %v, want [10.0.0.2]", fb.delDef)
	}
	if fb.wfpOff != 1 {
		t.Fatalf("disableProcessBypass called %d times, want 1", fb.wfpOff)
	}
	if len(fb.delHost) == 0 {
		t.Fatal("expected the bypass host route to be torn down on clear")
	}
	if len(gm.bypassRoutes) != 0 {
		t.Fatalf("bypassRoutes not reset: %v", gm.bypassRoutes)
	}
}

// TestSetExitNodeSwitchTearsDownOldBypass verifies the MEDIUM fix: switching to
// a different Exit Node removes the previous Exit Node's default route AND its
// per-endpoint bypass host routes (previously only the default route was
// removed, leaving stale /32 routes behind).
func TestSetExitNodeSwitchTearsDownOldBypass(t *testing.T) {
	gm, fb := newFakeGM(t)

	if err := gm.SetExitNode("peer-A", "10.0.0.2", "", []string{"1.2.3.4"}); err != nil {
		t.Fatalf("first SetExitNode: %v", err)
	}
	if err := gm.SetExitNode("peer-B", "10.0.0.3", "", []string{"5.6.7.8"}); err != nil {
		t.Fatalf("second SetExitNode (switch): %v", err)
	}

	if got := gm.ActiveExitIP(); got != "10.0.0.3" {
		t.Fatalf("ActiveExitIP = %q, want 10.0.0.3 after switch", got)
	}
	if !gm.IsExitNodeActive() {
		t.Fatal("still active after switch")
	}
	// New default route added, old default route removed exactly once.
	if len(fb.addDef) != 2 {
		t.Fatalf("addDefaultRouteOS calls = %v, want both exits added", fb.addDef)
	}
	if len(fb.delDef) != 1 || fb.delDef[0] != "10.0.0.2" {
		t.Fatalf("delDefaultRouteOS calls = %v, want old 10.0.0.2 removed", fb.delDef)
	}
	// Old bypass route for 1.2.3.4 must have been torn down during the switch.
	foundOld := false
	for _, h := range fb.delHost {
		if h[0] == "1.2.3.4" {
			foundOld = true
		}
	}
	if !foundOld {
		t.Fatal("old bypass host route 1.2.3.4 was not torn down during switch")
	}
	// Both current endpoints are now installed.
	if len(gm.bypassRoutes) != 2 {
		t.Fatalf("bypassRoutes = %v, want both endpoints re-installed", gm.bypassRoutes)
	}
}

// TestClearExitNodeClearsFlagEvenIfRouteDeleteFails verifies the MEDIUM timing
// fix: clearExitNodeUnlocked clears the active flags (and atomic mirror) BEFORE
// removing the route, so the data plane stops forwarding even if the OS route
// deletion subsequently fails.
func TestClearExitNodeClearsFlagEvenIfRouteDeleteFails(t *testing.T) {
	gm, fb := newFakeGM(t)
	fb.delDefErr = true
	if err := gm.SetExitNode("peer-A", "10.0.0.2", "", nil); err != nil {
		t.Fatalf("SetExitNode: %v", err)
	}

	if err := gm.ClearExitNode(); err != nil {
		t.Fatalf("ClearExitNode returned error: %v", err)
	}

	if gm.IsExitNodeActive() {
		t.Fatal("IsExitNodeActive() must be false even when route deletion fails")
	}
	if gm.ActiveExitIP() != "" {
		t.Fatalf("ActiveExitIP = %q, want empty", gm.ActiveExitIP())
	}
}

// TestClearExitNodeIdempotent verifies ClearExitNode is a safe no-op when no
// Exit Node is active (it can be called repeatedly, e.g. from Node.Close).
func TestClearExitNodeIdempotent(t *testing.T) {
	gm, fb := newFakeGM(t)

	if err := gm.ClearExitNode(); err != nil {
		t.Fatalf("ClearExitNode (no active) returned error: %v", err)
	}
	if gm.IsExitNodeActive() {
		t.Fatal("IsExitNodeActive() should be false")
	}
	if len(fb.delDef) != 0 {
		t.Fatalf("delDefaultRouteOS called %v on empty clear, want none", fb.delDef)
	}
	// A second call must also be safe.
	if err := gm.ClearExitNode(); err != nil {
		t.Fatalf("second ClearExitNode returned error: %v", err)
	}
}

// TestSetExitNodeSkipsWrongFamilyEndpoints is the regression test for the bug
// that knocked every peer offline the moment an Exit Node was enabled.
//
// addDefaultRouteOS only hijacks the split-default routes of ONE address family
// (0.0.0.0/1 + 128.0.0.0/1 for an IPv4 exit). The old code nevertheless pushed
// a metric-1 bypass host route at *every* known endpoint, so an IPv4 exit also
// wrote a /128 for every IPv6 peer — via an IPv6 gateway that frequently did
// not exist or was unreachable — black-holing those peers.
func TestSetExitNodeSkipsWrongFamilyEndpoints(t *testing.T) {
	gm, fb := newFakeGM(t)

	endpoints := []string{"1.2.3.4", "2001:db8::10", "2001:db8::11"}
	if err := gm.SetExitNode("peer-A", "10.0.0.2", "", endpoints); err != nil {
		t.Fatalf("SetExitNode: %v", err)
	}

	if _, ok := fb.hostRouteFor("1.2.3.4"); !ok {
		t.Fatal("IPv4 endpoint must get a bypass host route for an IPv4 exit")
	}
	for _, v6 := range []string{"2001:db8::10", "2001:db8::11"} {
		if gwUsed, ok := fb.hostRouteFor(v6); ok {
			t.Fatalf("IPv6 endpoint %s must NOT get a host route for an IPv4 exit (got next hop %q)", v6, gwUsed)
		}
		if _, tracked := gm.bypassRoutes[v6]; tracked {
			t.Fatalf("IPv6 endpoint %s must not be recorded in bypassRoutes", v6)
		}
	}
	// All endpoints are still remembered so they can be protected later if an
	// IPv6 exit or an overlapping subnet route shows up.
	for _, ep := range endpoints {
		if !gm.knownEndpoints[ep] {
			t.Fatalf("endpoint %s should still be tracked in knownEndpoints", ep)
		}
	}
}

// TestSetExitNodeIPv6ExitSkipsIPv4Endpoints is the mirror image: an IPv6 exit
// hijacks ::/1 + 8000::/1, so only IPv6 endpoints need a bypass route.
func TestSetExitNodeIPv6ExitSkipsIPv4Endpoints(t *testing.T) {
	gm, fb := newFakeGM(t)

	if err := gm.SetExitNode("peer-A", "", "fd00::2", []string{"1.2.3.4", "2001:db8::10"}); err != nil {
		t.Fatalf("SetExitNode: %v", err)
	}

	gwUsed, ok := fb.hostRouteFor("2001:db8::10")
	if !ok {
		t.Fatal("IPv6 endpoint must get a bypass host route for an IPv6 exit")
	}
	if gwUsed != "fe80::1" {
		t.Fatalf("IPv6 endpoint next hop = %q, want the IPv6 physical gateway fe80::1", gwUsed)
	}
	if _, ok := fb.hostRouteFor("1.2.3.4"); ok {
		t.Fatal("IPv4 endpoint must NOT get a host route for an IPv6 exit")
	}
}

// TestOnLinkEndpointSkipsBypassRoute covers the second half of the outage: a
// peer sitting on the same LAN segment as one of our physical NICs is already
// covered by that NIC's connected subnet route, which is more specific than the
// /1 split-defaults. Forcing it through the physical gateway breaks the peer on
// any router that refuses to hairpin traffic back onto the same segment.
func TestOnLinkEndpointSkipsBypassRoute(t *testing.T) {
	gm, fb := newFakeGM(t)
	fb.onLink["192.168.1.50"] = true

	if err := gm.SetExitNode("peer-A", "10.0.0.2", "", []string{"192.168.1.50", "8.8.8.8"}); err != nil {
		t.Fatalf("SetExitNode: %v", err)
	}

	if gwUsed, ok := fb.hostRouteFor("192.168.1.50"); ok {
		t.Fatalf("on-link endpoint must not be routed via the gateway (got next hop %q)", gwUsed)
	}
	if _, tracked := gm.bypassRoutes["192.168.1.50"]; tracked {
		t.Fatal("on-link endpoint must not be recorded as an installed bypass route")
	}
	// A genuinely off-link endpoint still goes through the physical gateway.
	if gwUsed, ok := fb.hostRouteFor("8.8.8.8"); !ok || gwUsed != "192.168.1.1" {
		t.Fatalf("off-link endpoint next hop = (%q,%v), want (192.168.1.1,true)", gwUsed, ok)
	}
}

// TestOnLinkEndpointInsideSubnetUsesOnLinkRoute verifies the one case where an
// on-link endpoint still needs an explicit host route — an overlapping TAP
// Subnet Route would otherwise swallow it — and that the route stays *on-link*
// (unspecified next hop) instead of being handed to the router.
func TestOnLinkEndpointInsideSubnetUsesOnLinkRoute(t *testing.T) {
	gm, fb := newFakeGM(t)
	fb.onLink["192.168.1.50"] = true

	// Endpoint observed before anything is installed: tracked, no route.
	if err := gm.ProtectEndpoint("192.168.1.50"); err != nil {
		t.Fatalf("ProtectEndpoint: %v", err)
	}
	if len(fb.addHost) != 0 {
		t.Fatalf("no host route should exist yet, got %v", fb.addHost)
	}

	// A peer now advertises 192.168.1.0/24 through the tunnel, which would
	// capture the endpoint — so an on-link host route becomes necessary.
	if _, err := gm.AddSubnetRoute("192.168.1.0/24", "10.0.0.2"); err != nil {
		t.Fatalf("AddSubnetRoute: %v", err)
	}

	gwUsed, ok := fb.hostRouteFor("192.168.1.50")
	if !ok {
		t.Fatal("endpoint overlapping a Subnet Route must get a host route")
	}
	if gwUsed != "0.0.0.0" {
		t.Fatalf("host route next hop = %q, want the unspecified address (on-link)", gwUsed)
	}
	if got := gm.bypassRoutes["192.168.1.50"]; got != "0.0.0.0" {
		t.Fatalf("bypassRoutes[192.168.1.50] = %q, want 0.0.0.0", got)
	}
}

// TestOnLinkIPv6EndpointInsideSubnetUsesIPv6Unspecified is the IPv6 counterpart
// of the on-link route: the unspecified next hop must be "::" so the platform
// backend writes an IPv6 on-link route rather than a cross-family one.
func TestOnLinkIPv6EndpointInsideSubnetUsesIPv6Unspecified(t *testing.T) {
	gm, fb := newFakeGM(t)
	fb.onLink["2001:db8:1::50"] = true

	if err := gm.ProtectEndpoint("2001:db8:1::50"); err != nil {
		t.Fatalf("ProtectEndpoint: %v", err)
	}
	if _, err := gm.AddSubnetRoute("2001:db8:1::/64", "fd00::2"); err != nil {
		t.Fatalf("AddSubnetRoute: %v", err)
	}

	gwUsed, ok := fb.hostRouteFor("2001:db8:1::50")
	if !ok {
		t.Fatal("IPv6 endpoint overlapping a Subnet Route must get a host route")
	}
	if gwUsed != "::" {
		t.Fatalf("host route next hop = %q, want :: (IPv6 on-link)", gwUsed)
	}
}

// TestClearExitNodeRemovesRoutesWithExactNextHop is the "no network until I
// reset the NIC" regression test: every bypass host route must be deleted with
// the exact next hop it was installed with (including the unspecified next hop
// of an on-link route), otherwise the deletion silently matches nothing and the
// metric-1 route survives the Exit Node being cleared.
func TestClearExitNodeRemovesRoutesWithExactNextHop(t *testing.T) {
	gm, fb := newFakeGM(t)
	fb.onLink["192.168.1.50"] = true

	if _, err := gm.AddSubnetRoute("192.168.1.0/24", "10.0.0.2"); err != nil {
		t.Fatalf("AddSubnetRoute: %v", err)
	}
	if err := gm.SetExitNode("peer-A", "10.0.0.2", "", []string{"8.8.8.8", "192.168.1.50", "2001:db8::10"}); err != nil {
		t.Fatalf("SetExitNode: %v", err)
	}

	installed := make(map[string]string, len(gm.bypassRoutes))
	for ep, gw := range gm.bypassRoutes {
		installed[ep] = gw
	}
	if len(installed) == 0 {
		t.Fatal("expected at least one installed bypass route to tear down")
	}

	if err := gm.ClearExitNode(); err != nil {
		t.Fatalf("ClearExitNode: %v", err)
	}

	for ep, gw := range installed {
		gotGW, ok := fb.delHostRouteFor(ep)
		if !ok {
			t.Fatalf("bypass route for %s was never deleted", ep)
		}
		if gotGW != gw {
			t.Fatalf("delHostRouteOS(%s) next hop = %q, want %q (the exact next hop used on install)", ep, gotGW, gw)
		}
	}
	if len(gm.bypassRoutes) != 0 {
		t.Fatalf("bypassRoutes not reset after clear: %v", gm.bypassRoutes)
	}
	// The physical default route must be re-established so internet returns
	// without a NIC reset.
	if fb.restored != 1 {
		t.Fatalf("restorePhysicalDefaultGatewayOS called %d times, want 1", fb.restored)
	}
	if fb.swept != 1 {
		t.Fatalf("sweepTapDefaultRoutesUnlocked called %d times, want 1", fb.swept)
	}
}

// TestProtectEndpointDefersUntilExitActive verifies endpoints seen before an
// Exit Node exists are only tracked (no routing-table pollution, no spurious
// warnings) and are installed retroactively once an exit of the matching family
// is activated.
func TestProtectEndpointDefersUntilExitActive(t *testing.T) {
	gm, fb := newFakeGM(t)

	if err := gm.ProtectEndpoint("8.8.8.8"); err != nil {
		t.Fatalf("ProtectEndpoint: %v", err)
	}
	if err := gm.ProtectEndpoint("127.0.0.1"); err != nil {
		t.Fatalf("ProtectEndpoint(loopback): %v", err)
	}
	if len(fb.addHost) != 0 {
		t.Fatalf("no host route may be installed before an Exit Node is active, got %v", fb.addHost)
	}
	if gm.knownEndpoints["127.0.0.1"] {
		t.Fatal("loopback endpoints must not be tracked")
	}
	if !gm.knownEndpoints["8.8.8.8"] {
		t.Fatal("endpoint should be tracked for retroactive protection")
	}

	if err := gm.SetExitNode("peer-A", "10.0.0.2", "", nil); err != nil {
		t.Fatalf("SetExitNode: %v", err)
	}
	if gwUsed, ok := fb.hostRouteFor("8.8.8.8"); !ok || gwUsed != "192.168.1.1" {
		t.Fatalf("deferred endpoint not installed retroactively: (%q,%v)", gwUsed, ok)
	}
}

// TestCheckAndUpdatePhysicalGatewayReinstallsEligibleOnly verifies that a
// physical network switch (Wi-Fi -> Ethernet) re-points the bypass routes at
// the new gateway, and that the eligibility rule is applied on re-install too.
// The old code used an inverted condition (!isTunnelDestination), which skipped
// exactly the endpoints overlapping a Subnet Route while re-adding routes for
// endpoints of the wrong address family.
func TestCheckAndUpdatePhysicalGatewayReinstallsEligibleOnly(t *testing.T) {
	gm, fb := newFakeGM(t)

	if err := gm.SetExitNode("peer-A", "10.0.0.2", "", []string{"8.8.8.8", "2001:db8::10"}); err != nil {
		t.Fatalf("SetExitNode: %v", err)
	}
	if gwUsed, _ := fb.hostRouteFor("8.8.8.8"); gwUsed != "192.168.1.1" {
		t.Fatalf("initial next hop = %q, want 192.168.1.1", gwUsed)
	}

	// Simulate switching to a different physical network.
	fb.gw = "10.20.30.1"
	fb.addHost = nil
	fb.delHost = nil
	gm.CheckAndUpdatePhysicalGateway()

	if gwUsed, ok := fb.hostRouteFor("8.8.8.8"); !ok || gwUsed != "10.20.30.1" {
		t.Fatalf("re-installed next hop = (%q,%v), want (10.20.30.1,true)", gwUsed, ok)
	}
	if oldGW, ok := fb.delHostRouteFor("8.8.8.8"); !ok || oldGW != "192.168.1.1" {
		t.Fatalf("stale route deletion = (%q,%v), want (192.168.1.1,true)", oldGW, ok)
	}
	if _, ok := fb.hostRouteFor("2001:db8::10"); ok {
		t.Fatal("IPv6 endpoint must still be skipped after a gateway change (IPv4 exit)")
	}
	if got := gm.bypassRoutes["8.8.8.8"]; got != "10.20.30.1" {
		t.Fatalf("bypassRoutes[8.8.8.8] = %q, want 10.20.30.1", got)
	}
}

// TestInstallBypassRouteIsIdempotent guards the presence-based bookkeeping: an
// on-link route stores the unspecified address as its next hop, so a truthiness
// check ("value != \"\"") would treat it as not installed and re-add it on every
// pass. Presence in the map is what counts.
func TestInstallBypassRouteIsIdempotent(t *testing.T) {
	gm, fb := newFakeGM(t)
	fb.onLink["192.168.1.50"] = true

	if err := gm.ProtectEndpoint("192.168.1.50"); err != nil {
		t.Fatalf("ProtectEndpoint: %v", err)
	}
	if _, err := gm.AddSubnetRoute("192.168.1.0/24", "10.0.0.2"); err != nil {
		t.Fatalf("AddSubnetRoute: %v", err)
	}
	if err := gm.SetExitNode("peer-A", "10.0.0.2", "", []string{"192.168.1.50"}); err != nil {
		t.Fatalf("SetExitNode: %v", err)
	}
	// ProtectEndpointsDynamic runs periodically in production.
	gm.ProtectEndpointsDynamic([]string{"192.168.1.50"})

	count := 0
	for _, h := range fb.addHost {
		if h[0] == "192.168.1.50" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("addHostRouteOS called %d times for the same on-link endpoint, want 1 (%v)", count, fb.addHost)
	}
}

// TestWindowsSocketBindingSuppressesHostRoutes verifies that on platforms where
// host-route bypass is disabled (Windows: socket-level IP_UNICAST_IF binding is
// the sole protection), SetExitNode / ProtectEndpoint / ClearExitNode do NOT
// install or delete any /32 host route — the socket hook is the only mechanism.
// This pins the "manipulate the socket, do not add host routes" design decision.
func TestWindowsSocketBindingSuppressesHostRoutes(t *testing.T) {
	gm := NewGatewayManager("tap0")
	gm.hostRouteBypass = false // simulate the Windows build
	fb := &fakeRouteBackend{
		gw:     "192.168.1.1",
		gw6:    "fe80::1",
		onLink: make(map[string]bool),
	}
	gm.route = fb

	if err := gm.SetExitNode("peer-A", "10.0.0.2", "", []string{"203.0.113.5", "2001:db8::5"}); err != nil {
		t.Fatalf("SetExitNode: %v", err)
	}
	if len(fb.addHost) != 0 {
		t.Fatalf("expected NO host routes in socket-only mode, got %d: %v", len(fb.addHost), fb.addHost)
	}
	// Endpoints are still tracked (needed for capture detection) and the WFP
	// process bypass is still enabled as a safety net.
	if !gm.knownEndpoints["203.0.113.5"] {
		t.Fatalf("endpoint 203.0.113.5 should still be tracked in knownEndpoints")
	}
	if fb.wfpOn != 1 {
		t.Fatalf("expected WFP enable called once, got %d", fb.wfpOn)
	}

	// A later dynamic endpoint must also NOT get a host route.
	gm.ProtectEndpointsDynamic([]string{"198.51.100.7"})
	if _, ok := fb.hostRouteFor("198.51.100.7"); ok {
		t.Fatalf("dynamic endpoint must not get a host route in socket-only mode")
	}

	// Clearing the Exit Node must not attempt to delete any host route.
	if err := gm.ClearExitNode(); err != nil {
		t.Fatalf("ClearExitNode: %v", err)
	}
	if len(fb.delHost) != 0 {
		t.Fatalf("expected NO host route deletions in socket-only mode, got %d: %v", len(fb.delHost), fb.delHost)
	}
}

// TestDefaultHostRouteBypassPolicy pins the platform policy for whether the
// GatewayManager installs /32 host routes or relies solely on socket-level
// interface binding (IP_UNICAST_IF on Windows, SO_BINDTODEVICE on Linux,
// IP_BOUND_IF on darwin). Windows/Linux/darwin use socket binding as the SOLE
// mechanism — so the routing table stays short under an Exit Node. The BSD
// family keeps the /32 fallback because golang.org/x/sys/unix exposes no
// interface-binding socket option for them. This guard fails if the policy is
// accidentally flipped (e.g. Linux/Darwin reverted to host routes).
func TestDefaultHostRouteBypassPolicy(t *testing.T) {
	want := true // default: keep /32 host routes (BSD family)
	switch runtime.GOOS {
	case "windows", "linux", "darwin":
		want = false // socket-only, no host routes
	}
	if got := defaultHostRouteBypass(); got != want {
		t.Fatalf("defaultHostRouteBypass() on %s = %v, want %v", runtime.GOOS, got, want)
	}
}
