//go:build windows

package node

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// defaultHostRouteBypass reports whether the GatewayManager should install /32
// bypass host routes to keep P2P endpoints off the TAP tunnel. Windows relies on
// socket-level IP_UNICAST_IF binding (see protect_windows.go) instead, so it
// returns false and adds no host routes.
func defaultHostRouteBypass() bool { return false }

func getLUIDByName(name string) (winipcfg.LUID, error) {
	adapters, err := winipcfg.GetAdaptersAddresses(windows.AF_UNSPEC, winipcfg.GAAFlagIncludeGateways)
	if err != nil {
		return 0, err
	}
	// 1. Direct match on FriendlyName, AdapterName (GUID), or Description
	for _, a := range adapters {
		if strings.EqualFold(a.FriendlyName(), name) ||
			strings.EqualFold(a.AdapterName(), name) ||
			strings.EqualFold(a.AdapterName(), "{"+name+"}") ||
			strings.EqualFold(a.Description(), name) {
			return a.LUID, nil
		}
	}
	// 2. Fuzzy match on FriendlyName or Description containing the name
	lowerName := strings.ToLower(name)
	for _, a := range adapters {
		friendly := strings.ToLower(a.FriendlyName())
		desc := strings.ToLower(a.Description())
		if strings.Contains(friendly, lowerName) || strings.Contains(desc, lowerName) {
			return a.LUID, nil
		}
	}
	// 3. Fallback: match any active virtual TAP/Wintun adapter
	for _, a := range adapters {
		if isVirtualInterface(a.FriendlyName()) || isVirtualInterface(a.Description()) {
			return a.LUID, nil
		}
	}
	return 0, fmt.Errorf("adapter %q not found", name)
}

// verifyTapLUID is a hard safety guard: it refuses to let any of the
// TAP-interface route operations (default split routes, CIDR subnet routes,
// and the leftover-route sweep) run against a *physical* adapter. Resolving a
// non-virtual LUID here means the configured TAP device name was wrong or
// collided with a real NIC, and touching that interface's routes would
// silently hijack or break the host's real internet egress. We fail closed.
func verifyTapLUID(luid winipcfg.LUID, name string) error {
	adapters, err := winipcfg.GetAdaptersAddresses(windows.AF_UNSPEC, winipcfg.GAAFlagIncludeGateways)
	if err != nil {
		return fmt.Errorf("verifyTapLUID: GetAdaptersAddresses failed: %w", err)
	}
	for _, a := range adapters {
		if a.LUID == luid {
			if isVirtualInterface(a.FriendlyName()) || isVirtualInterface(a.Description()) {
				return nil
			}
			return fmt.Errorf("refusing route op on %q: resolved interface LUID=%d (FriendlyName=%q) is NOT a virtual/TAP adapter", name, luid, a.FriendlyName())
		}
	}
	return fmt.Errorf("refusing route op on %q: resolved LUID=%d not found among adapters", name, luid)
}

// sameRouteAddr compares two routing-table addresses while ignoring the IPv6
// zone (ScopeId) and IPv4-in-IPv6 mapping.
//
// This is load-bearing, not cosmetic. GetIpForwardTable2 hands back IPv6
// link-local next hops with the interface ScopeId filled in, which winipcfg
// turns into a netip.Addr *with* a zone ("fe80::1%15"), whereas the address we
// wrote (or parsed back from our own bookkeeping) usually has no zone at all.
// A plain `==` between the two is therefore false for every IPv6 link-local
// gateway, and that single mismatch caused both halves of the Exit Node
// outage:
//
//   - addHostRouteOS could not find the interface that owns the gateway, fell
//     through to the IPv4 default-egress guess, and installed the peer's /128
//     on an interface that cannot reach that link-local next hop → every IPv6
//     peer black-holed the instant an Exit Node was activated.
//   - delHostRouteOS could not match the route it had just created, so
//     ClearExitNode left those /128s behind → no connectivity until the NIC
//     was reset.
func sameRouteAddr(a, b netip.Addr) bool {
	return a.WithZone("").Unmap() == b.WithZone("").Unmap()
}

// normalizedPrefix strips IPv4-in-IPv6 mapping from a routing-table prefix so
// it can be compared against a prefix we built from a plain address.
func normalizedPrefix(p netip.Prefix) netip.Prefix {
	return netip.PrefixFrom(p.Addr().Unmap().WithZone(""), p.Bits())
}

// isOnLinkNextHop reports whether a routing-table entry is a connected
// (on-link) route, i.e. one where the "gateway" is the interface itself.
func isOnLinkNextHop(nh netip.Addr) bool {
	bare := nh.WithZone("").Unmap()
	return !bare.IsValid() || bare.IsUnspecified()
}

// findOnLinkPhysicalLUID returns the physical interface that has endpointIP on
// one of its connected prefixes (longest-prefix match), meaning the endpoint is
// reachable directly via ARP/ND with no router hop.
func findOnLinkPhysicalLUID(endpointIP string) (winipcfg.LUID, bool) {
	addr, err := netip.ParseAddr(endpointIP)
	if err != nil {
		return 0, false
	}
	addr = addr.Unmap().WithZone("")
	if addr.IsLoopback() {
		return 0, false
	}

	af := winipcfg.AddressFamily(windows.AF_INET)
	if addr.Is6() {
		af = winipcfg.AddressFamily(windows.AF_INET6)
	}
	routes, err := winipcfg.GetIPForwardTable2(af)
	if err != nil {
		return 0, false
	}
	adapters, err := winipcfg.GetAdaptersAddresses(winipcfg.AddressFamily(windows.AF_UNSPEC), winipcfg.GAAFlagIncludeGateways)
	if err != nil {
		return 0, false
	}

	physical := make(map[winipcfg.LUID]bool, len(adapters))
	for _, a := range adapters {
		physical[a.LUID] = a.IfType != windows.IF_TYPE_SOFTWARE_LOOPBACK &&
			!isVirtualInterface(a.FriendlyName()) && !isVirtualInterface(a.Description())
	}

	bestBits := -1
	var bestLUID winipcfg.LUID
	for _, r := range routes {
		if !physical[r.InterfaceLUID] {
			continue
		}
		if !isOnLinkNextHop(r.NextHop.Addr()) {
			continue
		}
		prefix := normalizedPrefix(r.DestinationPrefix.Prefix())
		if !prefix.IsValid() {
			continue
		}
		// A default route is not a segment, and an on-link /32 or /128 is a
		// single-host entry (possibly one we installed ourselves), not evidence
		// that the endpoint shares a link with us.
		if prefix.Bits() <= 0 || prefix.Bits() >= prefix.Addr().BitLen() {
			continue
		}
		if !prefix.Contains(addr) {
			continue
		}
		if prefix.Bits() > bestBits {
			bestBits = prefix.Bits()
			bestLUID = r.InterfaceLUID
		}
	}
	return bestLUID, bestBits >= 0
}

// isOnLinkEndpoint implements routeBackend: true when the endpoint lives on a
// connected subnet of one of our physical NICs.
func (gm *GatewayManager) isOnLinkEndpoint(endpointIP string) bool {
	_, ok := findOnLinkPhysicalLUID(endpointIP)
	return ok
}

// ifIndexForLUID resolves an adapter's interface index, used to attach the
// correct IPv6 zone to a link-local next hop.
func ifIndexForLUID(adapters []*winipcfg.IPAdapterAddresses, luid winipcfg.LUID) uint32 {
	for _, a := range adapters {
		if a.LUID == luid {
			return uint32(a.IfIndex)
		}
	}
	return 0
}

func (gm *GatewayManager) GetOriginalPhysicalGateway() (string, error) {
	return gm.GetOriginalPhysicalGatewayFor("0.0.0.0")
}

func (gm *GatewayManager) GetOriginalPhysicalGatewayFor(endpointIP string) (string, error) {
	af := winipcfg.AddressFamily(windows.AF_INET)
	if ip := net.ParseIP(endpointIP); ip != nil && ip.To4() == nil {
		af = winipcfg.AddressFamily(windows.AF_INET6)
	}

	if gm.originalPhysicalGW != "" && gm.originalPhysicalGW != "0.0.0.0" && gm.originalPhysicalGW != "::" {
		cachedIP := net.ParseIP(gm.originalPhysicalGW)
		if cachedIP != nil {
			if af == windows.AF_INET && cachedIP.To4() != nil {
				return gm.originalPhysicalGW, nil
			}
			if af == windows.AF_INET6 && cachedIP.To4() == nil {
				return gm.originalPhysicalGW, nil
			}
		}
	}

	routes, err := winipcfg.GetIPForwardTable2(af)
	if err != nil {
		return "", fmt.Errorf("winipcfg GetIPForwardTable2 failed: %w", err)
	}
	adapters, err := winipcfg.GetAdaptersAddresses(windows.AF_UNSPEC, winipcfg.GAAFlagIncludeGateways)
	if err != nil {
		return "", fmt.Errorf("winipcfg GetAdaptersAddresses failed: %w", err)
	}

	luidToAdapter := make(map[winipcfg.LUID]*winipcfg.IPAdapterAddresses)
	for _, a := range adapters {
		luidToAdapter[a.LUID] = a
	}

	for _, r := range routes {
		if r.DestinationPrefix.Prefix().Bits() != 0 {
			continue
		}
		a, ok := luidToAdapter[r.InterfaceLUID]
		if !ok || isVirtualInterface(a.FriendlyName()) {
			continue
		}
		// Strip the IPv6 zone/ScopeId so the value we cache, log and later
		// re-parse is canonical. The zone is re-attached from the *target*
		// interface when the route is actually written (see addHostRouteOS);
		// carrying a stale ScopeId around here only breaks comparisons.
		ip := r.NextHop.Addr().WithZone("").Unmap()
		if ip.IsValid() && !ip.IsLoopback() && !ip.IsUnspecified() {
			return ip.String(), nil
		}
		// On-Link default route: try getting gateway IP from adapter's FirstGatewayAddress
		if a.FirstGatewayAddress != nil && a.FirstGatewayAddress.Address.Sockaddr != nil {
			raw := a.FirstGatewayAddress.Address.Sockaddr
			if af == windows.AF_INET {
				in4 := (*windows.RawSockaddrInet4)(unsafe.Pointer(raw))
				gwIP := net.IPv4(in4.Addr[0], in4.Addr[1], in4.Addr[2], in4.Addr[3])
				if gwIP.IsGlobalUnicast() {
					return gwIP.String(), nil
				}
			} else {
				in6 := (*windows.RawSockaddrInet6)(unsafe.Pointer(raw))
				gwIP := net.IP(in6.Addr[:])
				if gwIP.IsGlobalUnicast() || gwIP.IsLinkLocalUnicast() {
					return gwIP.String(), nil
				}
			}
		}
		// On-Link default route fallback
		if af == windows.AF_INET {
			return "0.0.0.0", nil
		}
		return "::", nil
	}

	// Fallback to default egress NIC
	if egressIdx, _, err := GetDefaultEgressInterface(); err == nil && egressIdx != 0 {
		for _, a := range adapters {
			if uint32(a.IfIndex) == egressIdx && !isVirtualInterface(a.FriendlyName()) {
				if a.FirstGatewayAddress != nil && a.FirstGatewayAddress.Address.Sockaddr != nil {
					raw := a.FirstGatewayAddress.Address.Sockaddr
					if af == windows.AF_INET {
						in4 := (*windows.RawSockaddrInet4)(unsafe.Pointer(raw))
						gwIP := net.IPv4(in4.Addr[0], in4.Addr[1], in4.Addr[2], in4.Addr[3])
						if gwIP.IsGlobalUnicast() {
							return gwIP.String(), nil
						}
					}
				}
			}
		}
	}

	return "", fmt.Errorf("no physical default gateway of matching IP family for %s", endpointIP)
}

// addHostRouteOS installs the physical bypass host route (/32 or /128) for a
// peer endpoint. gwIP is either the physical gateway to route via, or the
// unspecified address of the endpoint's family ("0.0.0.0" / "::") to request an
// on-link route (used when the endpoint shares a segment with one of our NICs
// but an overlapping TAP Subnet Route would otherwise capture it).
func (gm *GatewayManager) addHostRouteOS(endpointIP, gwIP string) error {
	ip := net.ParseIP(endpointIP)
	if ip == nil {
		return fmt.Errorf("invalid endpoint IP: %s", endpointIP)
	}

	var afFamily winipcfg.AddressFamily
	var prefixLen string
	if ip.To4() != nil {
		afFamily = winipcfg.AddressFamily(windows.AF_INET)
		prefixLen = "/32"
	} else {
		afFamily = winipcfg.AddressFamily(windows.AF_INET6)
		prefixLen = "/128"
	}

	dstPrefix, err := netip.ParsePrefix(endpointIP + prefixLen)
	if err != nil {
		return err
	}
	dstPrefix = normalizedPrefix(dstPrefix)

	gwAddr, err := netip.ParseAddr(gwIP)
	if err != nil {
		return err
	}
	gwAddr = gwAddr.Unmap()

	// A host route whose next hop belongs to a different address family than
	// its destination is nonsense and Windows will reject it. Fail loudly
	// instead of letting the interface search below wander off.
	if gwAddr.Is4() != dstPrefix.Addr().Is4() {
		return fmt.Errorf("endpoint %s and gateway %s have different IP families", endpointIP, gwIP)
	}
	onLink := isOnLinkNextHop(gwAddr)

	routes, err := winipcfg.GetIPForwardTable2(afFamily)
	if err != nil {
		return err
	}
	adapters, err := winipcfg.GetAdaptersAddresses(windows.AF_UNSPEC, winipcfg.GAAFlagIncludeGateways)
	if err != nil {
		return fmt.Errorf("GetAdaptersAddresses failed: %w", err)
	}
	isVirtualLUID := func(luid winipcfg.LUID) bool {
		for _, a := range adapters {
			if a.LUID == luid {
				return isVirtualInterface(a.FriendlyName()) || isVirtualInterface(a.Description())
			}
		}
		return false
	}

	// NOTE: We deliberately do NOT delete any pre-existing host route here.
	// Removing routes we did not create (a user/admin /32, another VPN's
	// bypass, or a service route that shares this destination) would clobber
	// the host's own routing table. Uniqueness is enforced by the duplicate
	// guard before AddRoute, and only routes p2ptap itself installed are ever
	// removed (see delHostRouteOS, which matches the exact gateway we used).

	var physLUID winipcfg.LUID

	if onLink {
		// On-link route: it must go on the interface that actually owns the
		// endpoint's segment. There is no gateway to search for, and guessing
		// the wrong NIC would black-hole the peer.
		luid, ok := findOnLinkPhysicalLUID(endpointIP)
		if !ok {
			return fmt.Errorf("refusing to add on-link route for %s: no physical interface has it on a connected subnet", endpointIP)
		}
		physLUID = luid
	} else {
		// 1. Prefer the interface that already routes via this exact gateway.
		//    Comparison ignores the IPv6 zone (see sameRouteAddr) — without
		//    that, every link-local gateway missed here and fell through to the
		//    IPv4-biased guesses below.
		for _, r := range routes {
			if sameRouteAddr(r.NextHop.Addr(), gwAddr) && !isVirtualLUID(r.InterfaceLUID) {
				physLUID = r.InterfaceLUID
				break
			}
		}

		// 2. Otherwise the interface whose connected subnet contains the
		//    gateway — still derived from the gateway itself, so it stays
		//    correct for IPv6 even when the IPv4 egress differs.
		if physLUID == 0 {
			if luid, ok := findOnLinkPhysicalLUID(gwAddr.WithZone("").String()); ok {
				physLUID = luid
			}
		}

		// 3. Fall back to the OS default egress interface.
		if physLUID == 0 {
			if egressIdx, _, err := GetDefaultEgressInterface(); err == nil && egressIdx != 0 {
				for _, a := range adapters {
					if uint32(a.IfIndex) == egressIdx && !isVirtualInterface(a.FriendlyName()) {
						physLUID = a.LUID
						break
					}
				}
			}
		}

		// 4. Last resort: any up physical Ethernet/Wi-Fi adapter.
		if physLUID == 0 {
			for _, a := range adapters {
				if a.IfType == windows.IF_TYPE_SOFTWARE_LOOPBACK || a.OperStatus != winipcfg.IfOperStatusUp {
					continue
				}
				if (a.IfType == windows.IF_TYPE_ETHERNET_CSMACD || a.IfType == windows.IF_TYPE_IEEE80211) && !isVirtualInterface(a.FriendlyName()) {
					physLUID = a.LUID
					break
				}
			}
		}
	}

	// ABSOLUTE SAFETY GUARD: Never install a physical bypass host route on a TAP or virtual interface!
	if physLUID == 0 || isVirtualLUID(physLUID) {
		return fmt.Errorf("refusing to add endpoint route for %s: no physical egress adapter found (LUID=%d)", endpointIP, physLUID)
	}

	// An IPv6 link-local next hop is only meaningful together with a scope, so
	// attach the target interface's index as the zone. winipcfg translates the
	// zone into SOCKADDR_IN6.ScopeId; without it the neighbour may fail to
	// resolve and the route silently black-holes.
	writeGW := gwAddr
	if writeGW.Is6() && writeGW.IsLinkLocalUnicast() {
		if idx := ifIndexForLUID(adapters, physLUID); idx != 0 {
			writeGW = writeGW.WithZone(strconv.FormatUint(uint64(idx), 10))
		}
	}

	// Duplicate guard: if an identical host route (same destination, gateway and
	// interface) is already present, skip the add instead of creating a second
	// one. We intentionally never delete unrelated routes to make room.
	for _, r := range routes {
		if r.InterfaceLUID == physLUID &&
			normalizedPrefix(r.DestinationPrefix.Prefix()) == dstPrefix &&
			sameRouteAddr(r.NextHop.Addr(), gwAddr) {
			gwLog.Debug("addHostRouteOS: identical host bypass route for %s already present on LUID %d; skipping", endpointIP, physLUID)
			return nil
		}
	}

	if onLink {
		gwLog.Info("Adding on-link host bypass route for %s on physical adapter LUID %d...", endpointIP, physLUID)
	} else {
		gwLog.Info("Adding host bypass route for %s via physical adapter LUID %d (gw=%s)...", endpointIP, physLUID, writeGW)
	}
	return physLUID.AddRoute(dstPrefix, writeGW, 1)
}

// delHostRouteOS removes the physical /32 (or /128) bypass host route that
// p2ptap installed for endpointIP via gwIP. Deletion is strictly scoped to the
// exact route we created: matching destination prefix, the gateway we used, and
// metric == 1, on a non-virtual interface. We never delete a route the host or
// another application created, even if it happens to share the same destination.
func (gm *GatewayManager) delHostRouteOS(endpointIP, gwIP string) error {
	ip := net.ParseIP(endpointIP)
	if ip == nil {
		return nil
	}
	gwAddr, err := netip.ParseAddr(gwIP)
	if err != nil {
		// Without the exact gateway we cannot safely scope the deletion, so we
		// refuse rather than risk removing an unrelated route.
		gwLog.Warn("delHostRouteOS: invalid gateway %q for %s: %v", gwIP, endpointIP, err)
		return nil
	}

	adapters, _ := winipcfg.GetAdaptersAddresses(winipcfg.AddressFamily(windows.AF_UNSPEC), winipcfg.GAAFlagIncludeGateways)
	isVirtualLUID := func(luid winipcfg.LUID) bool {
		for _, a := range adapters {
			if a.LUID == luid {
				return isVirtualInterface(a.FriendlyName()) || isVirtualInterface(a.Description())
			}
		}
		return false
	}

	targetIP := ip.String()
	var targetBits int
	var afFamily winipcfg.AddressFamily
	if ip.To4() != nil {
		afFamily = winipcfg.AddressFamily(windows.AF_INET)
		targetBits = 32
	} else {
		afFamily = winipcfg.AddressFamily(windows.AF_INET6)
		targetBits = 128
	}

	routes, err := winipcfg.GetIPForwardTable2(afFamily)
	if err != nil {
		gwLog.Warn("delHostRouteOS: GetIPForwardTable2 failed: %v", err)
		return nil
	}

	deleted := 0
	for _, r := range routes {
		// SAFETY CHECK: Never delete routes on virtual/TAP interfaces!
		if isVirtualLUID(r.InterfaceLUID) {
			continue
		}

		prefix := r.DestinationPrefix.Prefix()
		normAddr := prefix.Addr().Unmap()
		// Only remove the exact route p2ptap added: same /32 (or /128)
		// destination, same next hop we used, and the metric (1) we set.
		// The next-hop comparison must ignore the IPv6 zone: Windows reports
		// link-local next hops with a ScopeId attached, so a literal equality
		// check never matched and these routes survived ClearExitNode — the
		// reason the host stayed offline until the NIC was reset.
		if prefix.Bits() == targetBits && normAddr.String() == targetIP &&
			sameRouteAddr(r.NextHop.Addr(), gwAddr) && r.Metric == 1 {
			if derr := r.Delete(); derr != nil {
				gwLog.Warn("delHostRouteOS: failed to delete host route for %s via %s: %v", endpointIP, gwIP, derr)
			} else {
				deleted++
				gwLog.Info("delHostRouteOS: successfully deleted host route for %s via %s", endpointIP, gwIP)
			}
		}
	}
	if deleted == 0 {
		gwLog.Debug("delHostRouteOS: no matching host route found for %s via %s (already gone)", endpointIP, gwIP)
	}
	return nil
}

func (gm *GatewayManager) addDefaultRouteOS(exitTapIP, tapDevName string, metric int) error {
	luid, err := getLUIDByName(tapDevName)
	if err != nil {
		return fmt.Errorf("winipcfg getLUIDByName(%s) failed: %w", tapDevName, err)
	}
	if err := verifyTapLUID(luid, tapDevName); err != nil {
		return err
	}

	exitAddr, err := netip.ParseAddr(exitTapIP)
	if err != nil {
		return err
	}

	if exitAddr.Is4() {
		v4Routes := []netip.Prefix{
			netip.MustParsePrefix("0.0.0.0/1"),
			netip.MustParsePrefix("128.0.0.0/1"),
		}
		var added []netip.Prefix
		for _, dst := range v4Routes {
			if err := luid.AddRoute(dst, exitAddr, uint32(metric)); err != nil {
				for _, prev := range added {
					_ = luid.DeleteRoute(prev, exitAddr)
				}
				return fmt.Errorf("addRoute IPv4 %s failed: %w", dst, err)
			}
			added = append(added, dst)
		}
	} else if exitAddr.Is6() {
		v6Routes := []netip.Prefix{
			netip.MustParsePrefix("::/1"),
			netip.MustParsePrefix("8000::/1"),
		}
		var added []netip.Prefix
		for _, dst := range v6Routes {
			if err := luid.AddRoute(dst, exitAddr, uint32(metric)); err != nil {
				for _, prev := range added {
					_ = luid.DeleteRoute(prev, exitAddr)
				}
				return fmt.Errorf("addRoute IPv6 %s failed: %w", dst, err)
			}
			added = append(added, dst)
		}
	}
	return nil
}

// restorePhysicalDefaultGatewayOS is the Windows safety net invoked on
// ClearExitNode: if disconnecting the Exit Node left the host without a usable
// physical default route of a given family, re-add the original gateway so
// internet returns without requiring a NIC reset. It is a no-op when the
// physical default route is already present (the normal case).
func (gm *GatewayManager) restorePhysicalDefaultGatewayOS() {
	gm.ensurePhysicalDefaultRoute(winipcfg.AddressFamily(windows.AF_INET), gm.originalPhysicalGW)
	if gm.originalPhysicalGW6 != "" {
		gm.ensurePhysicalDefaultRoute(winipcfg.AddressFamily(windows.AF_INET6), gm.originalPhysicalGW6)
	}
}

// ensurePhysicalDefaultRoute guarantees a physical (non-virtual) default route
// for the given address family exists. If one is already present it does
// nothing; otherwise it re-installs it on the egress interface using gw.
//
// Crucially, a physical default route is considered "present" even when its
// NextHop is unspecified (an on-link route, where the gateway IS the interface
// itself — common on many networks). Previously such routes were wrongly
// treated as absent, causing ClearExitNode to install a competing 0.0.0.0/0 via
// a possibly-stale gateway and breaking connectivity until a NIC reset. We now
// only re-add when there is genuinely NO physical default route of that family,
// and we refuse to install via a non-routable gateway.
func (gm *GatewayManager) ensurePhysicalDefaultRoute(af winipcfg.AddressFamily, gw string) {
	if gw == "" || gw == "0.0.0.0" || gw == "::" {
		return
	}
	routes, err := winipcfg.GetIPForwardTable2(af)
	if err != nil {
		gwLog.Warn("ensurePhysicalDefaultRoute: GetIPForwardTable2 failed: %v", err)
		return
	}
	adapters, err := winipcfg.GetAdaptersAddresses(winipcfg.AddressFamily(windows.AF_UNSPEC), winipcfg.GAAFlagIncludeGateways)
	if err != nil {
		gwLog.Warn("ensurePhysicalDefaultRoute: GetAdaptersAddresses failed: %v", err)
		return
	}

	isPhysical := func(luid winipcfg.LUID) bool {
		for _, a := range adapters {
			if a.LUID == luid {
				return !isVirtualInterface(a.FriendlyName()) && !isVirtualInterface(a.Description())
			}
		}
		return false
	}

	// Already have a usable physical default route for this family? A physical
	// default route (prefix length 0) on a real NIC — even an on-link route
	// whose NextHop is unspecified — means the OS can already route to the
	// internet, so we must NOT install a competing default route.
	for _, r := range routes {
		if r.DestinationPrefix.Prefix().Bits() != 0 {
			continue
		}
		if isPhysical(r.InterfaceLUID) {
			return // physical default present; nothing to do
		}
	}

	// No physical default route — re-add it on the physical egress interface,
	// but only via a genuinely routable gateway.
	gwAddr, err := netip.ParseAddr(gw)
	if err != nil {
		return
	}
	if !gwAddr.IsGlobalUnicast() && !gwAddr.IsLinkLocalUnicast() {
		gwLog.Warn("ensurePhysicalDefaultRoute: refusing to re-add default route via non-routable gateway %s", gw)
		return
	}
	physLUID := physicalEgressLUID(adapters)
	if physLUID == 0 {
		gwLog.Warn("ensurePhysicalDefaultRoute: no physical egress adapter found; cannot restore default route via %s", gw)
		return
	}
	var prefix netip.Prefix
	if af == winipcfg.AddressFamily(windows.AF_INET) {
		prefix = netip.MustParsePrefix("0.0.0.0/0")
	} else {
		prefix = netip.MustParsePrefix("::/0")
	}
	gwLog.Info("ensurePhysicalDefaultRoute: re-adding %s via physical gateway %s (LUID=%d)", prefix, gwAddr, physLUID)
	if err := physLUID.AddRoute(prefix, gwAddr, 256); err != nil {
		gwLog.Warn("ensurePhysicalDefaultRoute: failed to re-add %s: %v", prefix, err)
	}
}

// physicalEgressLUID returns the LUID of a real (non-virtual) egress adapter,
// preferring the OS default egress interface, then any up Ethernet/Wi-Fi NIC.
func physicalEgressLUID(adapters []*winipcfg.IPAdapterAddresses) winipcfg.LUID {
	if egressIdx, _, err := GetDefaultEgressInterface(); err == nil && egressIdx != 0 {
		for _, a := range adapters {
			if uint32(a.IfIndex) == egressIdx && !isVirtualInterface(a.FriendlyName()) && !isVirtualInterface(a.Description()) {
				return a.LUID
			}
		}
	}
	for _, a := range adapters {
		if a.IfType == windows.IF_TYPE_SOFTWARE_LOOPBACK || a.OperStatus != winipcfg.IfOperStatusUp {
			continue
		}
		if (a.IfType == windows.IF_TYPE_ETHERNET_CSMACD || a.IfType == windows.IF_TYPE_IEEE80211) &&
			!isVirtualInterface(a.FriendlyName()) && !isVirtualInterface(a.Description()) {
			return a.LUID
		}
	}
	return 0
}

func (gm *GatewayManager) delDefaultRouteOS(exitTapIP, tapDevName string) error {
	luid, err := getLUIDByName(tapDevName)
	if err != nil {
		return nil
	}
	if err := verifyTapLUID(luid, tapDevName); err != nil {
		gwLog.Warn("delDefaultRouteOS: %v", err)
		return nil
	}

	exitAddr, err := netip.ParseAddr(exitTapIP)
	if err != nil {
		return nil
	}

	if exitAddr.Is4() {
		_ = luid.DeleteRoute(netip.MustParsePrefix("0.0.0.0/1"), exitAddr)
		_ = luid.DeleteRoute(netip.MustParsePrefix("128.0.0.0/1"), exitAddr)
		_ = luid.DeleteRoute(netip.MustParsePrefix("::/1"), netip.MustParseAddr("::"))
		_ = luid.DeleteRoute(netip.MustParsePrefix("8000::/1"), netip.MustParseAddr("::"))
	} else if exitAddr.Is6() {
		_ = luid.DeleteRoute(netip.MustParsePrefix("::/1"), exitAddr)
		_ = luid.DeleteRoute(netip.MustParsePrefix("8000::/1"), exitAddr)
		_ = luid.DeleteRoute(netip.MustParsePrefix("0.0.0.0/1"), netip.MustParseAddr("0.0.0.0"))
		_ = luid.DeleteRoute(netip.MustParsePrefix("128.0.0.0/1"), netip.MustParseAddr("0.0.0.0"))
	}
	return nil
}

func (gm *GatewayManager) addCIDRRouteOS(cidrStr, gatewayIP, tapDevName string) error {
	luid, err := getLUIDByName(tapDevName)
	if err != nil {
		return fmt.Errorf("winipcfg getLUIDByName(%s) failed: %w", tapDevName, err)
	}
	if err := verifyTapLUID(luid, tapDevName); err != nil {
		return err
	}

	prefix, err := netip.ParsePrefix(cidrStr)
	if err != nil {
		return err
	}
	gwAddr, err := netip.ParseAddr(gatewayIP)
	if err != nil {
		return err
	}

	return luid.AddRoute(prefix, gwAddr, 10)
}

var (
	modiphlpapi          = windows.NewLazySystemDLL("iphlpapi.dll")
	procFlushIpPathTable = modiphlpapi.NewProc("FlushIpPathTable")
)

func flushSystemIPPathCaches() {
	// Flush Windows IP Path Table for IPv4 (windows.AF_INET = 2) and IPv6 (windows.AF_INET6 = 23)
	_, _, _ = procFlushIpPathTable.Call(uintptr(windows.AF_INET))
	_, _, _ = procFlushIpPathTable.Call(uintptr(windows.AF_INET6))
	gwLog.Info("Flushed Windows IP Path Table caches (IPv4/IPv6)")
}

func (gm *GatewayManager) sweepTapDefaultRoutesUnlocked() error {
	luid, err := getLUIDByName(gm.tapName)
	if err != nil {
		gwLog.Warn("sweepTapDefaultRoutes: getLUIDByName(%s) failed: %v", gm.tapName, err)
		return nil
	}
	if err := verifyTapLUID(luid, gm.tapName); err != nil {
		gwLog.Warn("sweepTapDefaultRoutes: %v", err)
		return nil
	}

	// Unconditionally sweep any remaining split routes across p2ptap TAP interface
	targetSplitCIDRs := map[string]bool{
		"0.0.0.0/1":   true,
		"128.0.0.0/1": true,
		"::/1":        true,
		"8000::/1":    true,
	}

	routes, err := winipcfg.GetIPForwardTable2(winipcfg.AddressFamily(windows.AF_UNSPEC))
	if err != nil {
		gwLog.Warn("sweepTapDefaultRoutes: GetIPForwardTable2 failed: %v", err)
		flushSystemIPPathCaches()
		return nil
	}

	deletedCount := 0
	for _, r := range routes {
		// STRICT SAFETY CHECK: Only delete routes belonging to p2ptap's TAP interface LUID!
		// Deleting split routes on other adapters would break physical Wi-Fi/Ethernet or other VPNs!
		if r.InterfaceLUID != luid {
			continue
		}

		prefix := r.DestinationPrefix.Prefix()
		normPrefix := netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits())
		cidrStr := normPrefix.Masked().String()

		if targetSplitCIDRs[cidrStr] {
			if derr := r.Delete(); derr != nil {
				gwLog.Warn("sweepTapDefaultRoutes: failed to delete split route %s: %v", cidrStr, derr)
			} else {
				deletedCount++
				gwLog.Info("sweepTapDefaultRoutes: successfully deleted split route %s (LUID=%d)", cidrStr, r.InterfaceLUID)
			}
		}
	}

	// 3. Flush Windows IP Path Table cache so tcpip.sys invalidates cached TAP route lookups
	flushSystemIPPathCaches()

	gwLog.Info("sweepTapDefaultRoutes: finished sweeping split routes (deleted %d routes)", deletedCount)
	return nil
}

func (gm *GatewayManager) delCIDRRouteOS(cidrStr, gatewayIP, tapDevName string) error {
	luid, err := getLUIDByName(tapDevName)
	if err != nil {
		return err
	}
	if err := verifyTapLUID(luid, tapDevName); err != nil {
		return err
	}
	prefix, err := netip.ParsePrefix(cidrStr)
	if err != nil {
		return err
	}
	gwAddr, err := netip.ParseAddr(gatewayIP)
	if err != nil {
		return err
	}
	return luid.DeleteRoute(prefix, gwAddr)
}
