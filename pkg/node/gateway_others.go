//go:build !linux && !windows && !darwin

package node

import "fmt"

func (gm *GatewayManager) GetOriginalPhysicalGateway() (string, error) {
	return "", fmt.Errorf("unsupported OS for gateway manager")
}

func (gm *GatewayManager) GetOriginalPhysicalGatewayFor(endpointIP string) (string, error) {
	return "", fmt.Errorf("unsupported OS for gateway manager")
}

func (gm *GatewayManager) addHostRouteOS(endpointIP, gwIP string) error {
	return nil
}

func (gm *GatewayManager) delHostRouteOS(endpointIP, gwIP string) error {
	return nil
}

// defaultHostRouteBypass reports whether the GatewayManager should install /32
// bypass host routes to keep P2P endpoints off the TAP tunnel. On the BSD
// family (freebsd / netbsd / openbsd / dragonfly) golang.org/x/sys/unix exposes
// NEITHER SO_BINDTODEVICE (Linux only) NOR IP_BOUND_IF / IPV6_BOUND_IF
// (darwin / solaris only), so there is no socket-level interface-binding option
// to rely on. We therefore KEEP the /32 host-route fallback on these platforms
// rather than leaving P2P sockets unprotected. If a future x/sys release or raw
// syscall constants make binding available, flip this to false like the other
// platforms.
func defaultHostRouteBypass() bool { return true }

// isOnLinkEndpoint falls back to the portable interface-address probe.
func (gm *GatewayManager) isOnLinkEndpoint(endpointIP string) bool {
	return onLinkViaInterfaceAddrs(endpointIP)
}

func (gm *GatewayManager) addDefaultRouteOS(exitTapIP, tapDevName string, metric int) error {
	return nil
}

func (gm *GatewayManager) delDefaultRouteOS(exitTapIP, tapDevName string) error {
	return nil
}

func (gm *GatewayManager) addCIDRRouteOS(cidrStr, gatewayIP, tapDevName string) error {
	return nil
}

func (gm *GatewayManager) delCIDRRouteOS(cidrStr, gatewayIP, tapDevName string) error {
	return nil
}

func (gm *GatewayManager) sweepTapDefaultRoutesUnlocked() error {
	return nil
}

// restorePhysicalDefaultGatewayOS is a no-op on unsupported OSes; only the
// Windows implementation re-establishes the physical default route on clear.
func (gm *GatewayManager) restorePhysicalDefaultGatewayOS() {}
