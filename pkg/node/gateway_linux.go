//go:build linux

package node

import (
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
)

func (gm *GatewayManager) GetOriginalPhysicalGateway() (string, error) {
	return gm.GetOriginalPhysicalGatewayFor("0.0.0.0")
}

// GetOriginalPhysicalGatewayFor returns the system default gateway whose
// address family matches the given endpoint IP. This avoids the
// "gateway, source, and destination ip are not the same IP family" failure
// that occurred when an IPv6 peer/relay endpoint was protected via an IPv4
// default gateway (or vice-versa).
func (gm *GatewayManager) GetOriginalPhysicalGatewayFor(endpointIP string) (string, error) {
	family := netlink.FAMILY_V4
	if ip := net.ParseIP(endpointIP); ip != nil && ip.To4() == nil {
		family = netlink.FAMILY_V6
	}

	routes, err := netlink.RouteListFiltered(family, &netlink.Route{
		Dst: nil,
	}, netlink.RT_FILTER_DST)
	if err != nil {
		return "", fmt.Errorf("netlink route list (family %d) failed: %w", family, err)
	}

	for _, r := range routes {
		if r.Gw != nil && !r.Gw.IsLoopback() && !r.Gw.IsUnspecified() {
			return r.Gw.String(), nil
		}
	}
	return "", fmt.Errorf("no physical default gateway of matching IP family for %s", endpointIP)
}

func (gm *GatewayManager) addHostRouteOS(endpointIP, gwIP string) error {
	ip := net.ParseIP(endpointIP)
	gw := net.ParseIP(gwIP)
	if ip == nil || gw == nil {
		return fmt.Errorf("invalid IP or gateway")
	}

	// The host route must match the endpoint's address family. A host route is
	// /32 for IPv4 and /128 for IPv6; using the wrong mask (or mixing an IPv6
	// endpoint with an IPv4 gateway) makes netlink reject it with
	// "gateway, source, and destination ip are not the same IP family".
	isV6 := ip.To4() == nil
	if (ip.To4() == nil) != (gw.To4() == nil) {
		return fmt.Errorf("endpoint %s and gateway %s have different IP families", endpointIP, gwIP)
	}
	bits := 32
	if isV6 {
		bits = 128
	}
	dst := &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}

	// An unspecified gateway means "install an on-link route": the endpoint
	// shares a segment with one of our NICs, so the route must be scoped to
	// that link instead of pointing at a router.
	if gw.IsUnspecified() {
		linkIdx, err := gm.onLinkInterfaceIndex(ip)
		if err != nil {
			return err
		}
		return netlink.RouteReplace(&netlink.Route{
			LinkIndex: linkIdx,
			Dst:       dst,
			Scope:     netlink.SCOPE_LINK,
		})
	}

	route := &netlink.Route{
		Dst: dst,
		Gw:  gw,
	}
	return netlink.RouteReplace(route)
}

// onLinkInterfaceIndex returns the index of the non-TAP interface that has ip
// on one of its connected prefixes (longest-prefix match).
func (gm *GatewayManager) onLinkInterfaceIndex(ip net.IP) (int, error) {
	family := netlink.FAMILY_V4
	hostBits := 32
	if ip.To4() == nil {
		family = netlink.FAMILY_V6
		hostBits = 128
	}
	tapIdx := -1
	if link, err := netlink.LinkByName(gm.tapName); err == nil {
		tapIdx = link.Attrs().Index
	}
	routes, err := netlink.RouteList(nil, family)
	if err != nil {
		return 0, err
	}
	bestOnes := -1
	bestIdx := 0
	for _, r := range routes {
		if r.Dst == nil || (tapIdx >= 0 && r.LinkIndex == tapIdx) {
			continue
		}
		if r.Gw != nil && !r.Gw.IsUnspecified() {
			continue
		}
		ones, bits := r.Dst.Mask.Size()
		if bits != hostBits || ones == 0 || ones == bits {
			continue
		}
		if r.Dst.Contains(ip) && ones > bestOnes {
			bestOnes = ones
			bestIdx = r.LinkIndex
		}
	}
	if bestOnes < 0 {
		return 0, fmt.Errorf("no on-link interface found for %s", ip)
	}
	return bestIdx, nil
}

func (gm *GatewayManager) delHostRouteOS(endpointIP, gwIP string) error {
	ip := net.ParseIP(endpointIP)
	if ip == nil {
		return nil
	}
	bits := 32
	if ip.To4() == nil {
		bits = 128
	}
	dst := &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}
	gw := net.ParseIP(gwIP)

	// Resolve the TAP adapter index so we can refuse to delete a route that
	// lives on the virtual interface. Bypass host routes are always installed
	// on a physical egress interface, so a matching route on the TAP adapter is
	// not ours to remove — mirroring the stricter Windows scope (non-virtual +
	// metric==1).
	tapIdx := -1
	if link, err := netlink.LinkByName(gm.tapName); err == nil {
		tapIdx = link.Attrs().Index
	}

	routes, err := netlink.RouteList(nil, netlink.FAMILY_ALL)
	if err != nil {
		return err
	}
	var firstErr error
	for _, r := range routes {
		if tapIdx >= 0 && r.LinkIndex == tapIdx {
			continue
		}
		if r.Dst == nil || !dst.IP.Equal(r.Dst.IP) || dst.Mask.String() != r.Dst.Mask.String() {
			continue
		}
		// An unspecified gateway identifies the on-link routes we install for
		// same-segment endpoints; those have no gateway at all in the kernel,
		// so match them explicitly instead of requiring r.Gw to equal 0.0.0.0
		// (which never happens and used to leave the route behind forever).
		if gw != nil && gw.IsUnspecified() {
			if r.Gw != nil && !r.Gw.IsUnspecified() {
				continue
			}
		} else if gw != nil && (r.Gw == nil || !r.Gw.Equal(gw)) {
			continue
		}
		if derr := netlink.RouteDel(&r); derr != nil && firstErr == nil {
			firstErr = derr
		}
	}
	return firstErr
}

// isOnLinkEndpoint reports whether endpointIP is covered by a connected
// (gateway-less) route on a non-TAP interface, i.e. it is reachable directly
// via ARP/ND. Such endpoints already win over the /1 split-default routes an
// Exit Node installs, so pushing them at the physical gateway is unnecessary
// and breaks peers behind routers that refuse to hairpin.
// defaultHostRouteBypass reports whether the GatewayManager should install /32
// bypass host routes to keep P2P endpoints off the TAP tunnel. On Linux the
// socket hook (SO_BINDTODEVICE, applied to every P2P and WebUI socket via
// net.ListenConfig / net.Dialer Control) binds traffic to the physical NIC at
// the kernel level for BOTH inbound and outbound, so it is the primary
// mechanism and the per-endpoint host routes are unnecessary. Returns false.
func defaultHostRouteBypass() bool { return false }

func (gm *GatewayManager) isOnLinkEndpoint(endpointIP string) bool {
	ip := net.ParseIP(endpointIP)
	if ip == nil || ip.IsLoopback() {
		return false
	}
	family := netlink.FAMILY_V4
	hostBits := 32
	if ip.To4() == nil {
		family = netlink.FAMILY_V6
		hostBits = 128
	}

	tapIdx := -1
	if link, err := netlink.LinkByName(gm.tapName); err == nil {
		tapIdx = link.Attrs().Index
	}

	routes, err := netlink.RouteList(nil, family)
	if err != nil {
		return false
	}
	for _, r := range routes {
		if r.Dst == nil {
			continue
		}
		if tapIdx >= 0 && r.LinkIndex == tapIdx {
			continue
		}
		// Connected routes have no gateway.
		if r.Gw != nil && !r.Gw.IsUnspecified() {
			continue
		}
		ones, bits := r.Dst.Mask.Size()
		// Skip the default route and single-host entries.
		if bits != hostBits || ones == 0 || ones == bits {
			continue
		}
		if r.Dst.Contains(ip) {
			return true
		}
	}
	return false
}

func (gm *GatewayManager) addDefaultRouteOS(exitTapIP, tapDevName string, metric int) error {
	link, err := netlink.LinkByName(tapDevName)
	if err != nil {
		return fmt.Errorf("netlink link by name %q: %w", tapDevName, err)
	}
	linkIdx := link.Attrs().Index
	exitIP := net.ParseIP(exitTapIP)
	if exitIP == nil {
		return fmt.Errorf("invalid exit TAP IP: %s", exitTapIP)
	}
	isV6 := exitIP.To4() == nil

	if !isV6 {
		// IPv4 exit: install split default routes (0.0.0.0/1 and
		// 128.0.0.0/1) instead of 0.0.0.0/0. Like the Windows client and the
		// IPv6 branch below, two /1 routes cover the whole address space but
		// are MORE SPECIFIC than the physical 0.0.0.0/0, so they win without
		// replacing it. netlink.RouteReplace matches on the destination
		// prefix, so installing a bare 0.0.0.0/0 would *replace* the real
		// physical default route; on ClearExitNode the physical route would
		// then be gone with no way to restore it (restorePhysicalDefaultGatewayOS
		// is a no-op on Linux) and the host would lose all internet until a
		// NIC reset / DHCP renew. Split /1 routes avoid that entirely: the
		// physical 0.0.0.0/0 is never touched.
		_, half1, _ := net.ParseCIDR("0.0.0.0/1")
		_, half2, _ := net.ParseCIDR("128.0.0.0/1")
		for _, dst := range []*net.IPNet{half1, half2} {
			route := &netlink.Route{
				LinkIndex: linkIdx,
				Dst:       dst,
				Gw:        exitIP,
				Priority:  metric,
			}
			if err := netlink.RouteReplace(route); err != nil {
				return fmt.Errorf("addRoute %s failed: %w", dst, err)
			}
		}
	} else {
		// IPv6 exit: install split default routes (::/1 and 8000::/1) instead
		// of ::/0. Like the Windows client, two /1 routes cover the whole
		// address space but are more specific than ::/0, so they win without
		// disturbing the physical default route that P2P sockets rely on.
		_, half1, _ := net.ParseCIDR("::/1")
		_, half2, _ := net.ParseCIDR("8000::/1")
		for _, dst := range []*net.IPNet{half1, half2} {
			route := &netlink.Route{
				LinkIndex: linkIdx,
				Dst:       dst,
				Gw:        exitIP,
				Priority:  metric,
			}
			if err := netlink.RouteReplace(route); err != nil {
				return fmt.Errorf("addRoute %s failed: %w", dst, err)
			}
		}
	}
	return nil
}

func (gm *GatewayManager) delDefaultRouteOS(exitTapIP, tapDevName string) error {
	link, err := netlink.LinkByName(tapDevName)
	if err != nil {
		// TAP adapter already gone: nothing to clean up on it, and a wildcard
		// LinkIndex (0) would match routes across ALL interfaces and could
		// delete the host's real default route. Bail instead of sweeping blind.
		return fmt.Errorf("netlink link by name %q: %w", tapDevName, err)
	}
	linkIdx := link.Attrs().Index
	exitIP := net.ParseIP(exitTapIP)
	if exitIP == nil {
		return fmt.Errorf("invalid exit TAP IP: %s", exitTapIP)
	}
	isV6 := exitIP.To4() == nil

	if !isV6 {
		// Remove the split /1 routes installed by addDefaultRouteOS. We also
		// still attempt to delete a bare 0.0.0.0/0 as a backstop for hosts that
		// were configured by an older build; the physical 0.0.0.0/0 is never
		// deleted because SetExitNode never installs it.
		_, half1, _ := net.ParseCIDR("0.0.0.0/1")
		_, half2, _ := net.ParseCIDR("128.0.0.0/1")
		_, full, _ := net.ParseCIDR("0.0.0.0/0")
		for _, dst := range []*net.IPNet{half1, half2, full} {
			route := &netlink.Route{
				LinkIndex: linkIdx,
				Dst:       dst,
				Gw:        exitIP,
			}
			_ = netlink.RouteDel(route)
		}
		return nil
	}

	// IPv6 split default routes (matching addDefaultRouteOS).
	_, half1, _ := net.ParseCIDR("::/1")
	_, half2, _ := net.ParseCIDR("8000::/1")
	for _, dst := range []*net.IPNet{half1, half2} {
		route := &netlink.Route{
			LinkIndex: linkIdx,
			Dst:       dst,
			Gw:        exitIP,
		}
		_ = netlink.RouteDel(route)
	}
	return nil
}

// sweepTapDefaultRoutesUnlocked removes any default routes pointing at the TAP
// adapter without depending on a remembered exit IP. Backstop for ClearExitNode
// so a stale/empty exit IP cannot leave hijacking routes behind. Caller must
// hold gm.mu.
func (gm *GatewayManager) sweepTapDefaultRoutesUnlocked() error {
	link, err := netlink.LinkByName(gm.tapName)
	if err != nil {
		// TAP adapter missing: there are no routes on it to sweep, and a
		// wildcard LinkIndex (0) would match routes on every interface. Return
		// without deleting anything rather than risk the host's real routes.
		return fmt.Errorf("netlink link by name %q: %w", gm.tapName, err)
	}
	linkIdx := link.Attrs().Index

	// IPv4 exit installs 0.0.0.0/1 + 128.0.0.0/1 (split); IPv6 exit installs
	// ::/1 + 8000::/1. Delete all of them from the TAP adapter regardless of
	// remembered exit IP. 0.0.0.0/0 is also swept as a backstop for hosts
	// configured by an older build (the physical 0.0.0.0/0 is never present
	// here because addDefaultRouteOS installs split routes, not a bare /0).
	_, v4Half1, _ := net.ParseCIDR("0.0.0.0/1")
	_, v4Half2, _ := net.ParseCIDR("128.0.0.0/1")
	_, v4Full, _ := net.ParseCIDR("0.0.0.0/0")
	_, v6Half1, _ := net.ParseCIDR("::/1")
	_, v6Half2, _ := net.ParseCIDR("8000::/1")

	for _, dst := range []*net.IPNet{v4Half1, v4Half2, v4Full, v6Half1, v6Half2} {
		route := &netlink.Route{
			LinkIndex: linkIdx,
			Dst:       dst,
		}
		_ = netlink.RouteDel(route)
	}
	return nil
}

func (gm *GatewayManager) addCIDRRouteOS(cidrStr, gatewayIP, tapDevName string) error {
	link, err := netlink.LinkByName(tapDevName)
	if err != nil {
		return fmt.Errorf("netlink link by name %q: %w", tapDevName, err)
	}

	gw := net.ParseIP(gatewayIP)
	if gw == nil {
		// An invalid (or empty) gateway would install an ON-LINK route with a
		// nil Gw — which silently blackholes the ENTIRE dstCIDR subnet through
		// the TAP adapter. Refuse instead of corrupting host routing.
		return fmt.Errorf("invalid gateway IP %q for CIDR route %s", gatewayIP, cidrStr)
	}

	_, dstCIDR, err := net.ParseCIDR(cidrStr)
	if err != nil {
		return err
	}

	route := &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       dstCIDR,
		Gw:        gw,
		Priority:  10,
	}
	return netlink.RouteReplace(route)
}

func (gm *GatewayManager) delCIDRRouteOS(cidrStr, gatewayIP, tapDevName string) error {
	link, err := netlink.LinkByName(tapDevName)
	if err != nil {
		return err
	}
	gw := net.ParseIP(gatewayIP)
	if gw == nil {
		return fmt.Errorf("invalid gateway IP %q for CIDR route %s", gatewayIP, cidrStr)
	}
	_, dstCIDR, err := net.ParseCIDR(cidrStr)
	if err != nil {
		return err
	}
	route := &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       dstCIDR,
		Gw:        gw,
	}
	return netlink.RouteDel(route)
}

// restorePhysicalDefaultGatewayOS is a no-op on Linux; the physical default
// route is never removed by SetExitNode, so nothing needs restoring on clear.
func (gm *GatewayManager) restorePhysicalDefaultGatewayOS() {}
