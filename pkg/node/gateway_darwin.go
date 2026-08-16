//go:build darwin

package node

import (
	"bytes"
	"fmt"
	"net"
	"os/exec"
	"strings"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

func (gm *GatewayManager) GetOriginalPhysicalGatewayFor(endpointIP string) (string, error) {
	// Best-effort: detect IPv6 default gateway via netstat; fall back to the
	// IPv4 gateway detection for non-V6 endpoints.
	if ip := net.ParseIP(endpointIP); ip != nil && ip.To4() == nil {
		cmd := exec.Command("sh", "-c", "netstat -rn -f inet6 | awk '/default/{print $2}' | head -n1")
		if out, err := cmd.Output(); err == nil && len(strings.TrimSpace(string(out))) > 0 {
			return strings.TrimSpace(string(out)), nil
		}
		return "", fmt.Errorf("no IPv6 physical default gateway found on darwin")
	}
	return gm.GetOriginalPhysicalGateway()
}

func (gm *GatewayManager) GetOriginalPhysicalGateway() (string, error) {
	rib, err := route.FetchRIB(unix.AF_INET, route.RIBTypeRoute, 0)
	if err == nil {
		msgs, errParse := route.ParseRIB(route.RIBTypeRoute, rib)
		if errParse == nil {
			for _, msg := range msgs {
				rm, ok := msg.(*route.RouteMessage)
				if !ok {
					continue
				}
				if len(rm.Addrs) > unix.RTAX_GATEWAY {
					if dst, ok := rm.Addrs[unix.RTAX_DST].(*route.Inet4Addr); ok && dst.IP == [4]byte{0, 0, 0, 0} {
						if gw, ok := rm.Addrs[unix.RTAX_GATEWAY].(*route.Inet4Addr); ok {
							ip := net.IP(gw.IP[:]).String()
							if ip != "0.0.0.0" && !strings.HasPrefix(ip, "127.") {
								return ip, nil
							}
						}
					}
				}
			}
		}
	}

	// Fallback to route command
	cmd := exec.Command("sh", "-c", "netstat -rn -f inet | awk '/default/{print $2}' | head -n1")
	out, err := cmd.Output()
	if err == nil && len(out) > 0 {
		return strings.TrimSpace(string(out)), nil
	}
	return "", fmt.Errorf("unable to detect physical default gateway on darwin")
}

func (gm *GatewayManager) addHostRouteOS(endpointIP, gwIP string) error {
	ip := net.ParseIP(endpointIP)
	if ip == nil {
		return fmt.Errorf("invalid endpoint IP: %s", endpointIP)
	}

	// An unspecified gateway requests an on-link route: the endpoint shares a
	// segment with one of our NICs, so bind the route to that interface
	// (-iface) rather than handing the packets to a router.
	if gw := net.ParseIP(gwIP); gw != nil && gw.IsUnspecified() {
		ifName, err := onLinkInterfaceName(ip)
		if err != nil {
			return err
		}
		if ip.To4() != nil {
			return exec.Command("route", "-n", "add", "-host", endpointIP, "-iface", ifName).Run()
		}
		return exec.Command("route", "-n", "add", "-inet6", endpointIP+"/128", "-iface", ifName).Run()
	}

	if ip.To4() != nil {
		cmd := exec.Command("route", "-n", "add", "-host", endpointIP, gwIP)
		return cmd.Run()
	}
	// IPv6 host route: route -n add -inet6 <ip>/128 <gw>
	cmd := exec.Command("route", "-n", "add", "-inet6", endpointIP+"/128", gwIP)
	return cmd.Run()
}

// onLinkInterfaceName returns the name of the up, non-virtual interface that
// has ip on one of its assigned prefixes.
func onLinkInterfaceName(ip net.IP) (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, ifi := range ifaces {
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		if isVirtualInterface(ifi.Name) {
			continue
		}
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok || ipnet.IP == nil {
				continue
			}
			if (ipnet.IP.To4() == nil) != (ip.To4() == nil) {
				continue
			}
			ones, bits := ipnet.Mask.Size()
			if bits == 0 || ones == 0 || ones == bits {
				continue
			}
			if ipnet.Contains(ip) {
				return ifi.Name, nil
			}
		}
	}
	return "", fmt.Errorf("no on-link interface found for %s", ip)
}

func (gm *GatewayManager) delHostRouteOS(endpointIP, gwIP string) error {
	ip := net.ParseIP(endpointIP)
	if ip == nil {
		return nil // nothing to delete
	}
	if ip.To4() != nil {
		cmd := exec.Command("route", "-n", "delete", "-host", endpointIP)
		return cmd.Run()
	}
	cmd := exec.Command("route", "-n", "delete", "-inet6", endpointIP+"/128")
	return cmd.Run()
}

// isOnLinkEndpoint reports whether the endpoint shares a segment with one of
// our physical interfaces, in which case forcing it through the physical
// gateway is both unnecessary and harmful (routers that refuse to hairpin).
// defaultHostRouteBypass reports whether the GatewayManager should install /32
// bypass host routes to keep P2P endpoints off the TAP tunnel. On darwin the
// socket hook (IP_BOUND_IF / IPV6_BOUND_IF, applied to every P2P and WebUI
// socket) binds traffic to the physical NIC for BOTH inbound and outbound, so
// the host route is unnecessary. Returns false.
func defaultHostRouteBypass() bool { return false }

func (gm *GatewayManager) isOnLinkEndpoint(endpointIP string) bool {
	return onLinkViaInterfaceAddrs(endpointIP)
}

func (gm *GatewayManager) addDefaultRouteOS(exitTapIP, tapDevName string, metric int) error {
	// Use split default routes (0.0.0.0/1 and 128.0.0.0/1 for IPv4, plus the IPv6
	// equivalents ::/1 and 8000::/1) instead of replacing 0.0.0.0/0. This mirrors
	// the Windows and Linux implementations:
	// - It does NOT replace the physical adapter's existing default route, so we
	//   avoid "File exists" errors and keep the real gateway intact.
	// - The two /1 routes cover the entire address space but are more specific
	//   than 0.0.0.0/0, so they win for tunneled traffic without disturbing the
	//   physical default route that P2P sockets (bound to the physical NIC via the
	//   protect hook) rely on.
	ip := net.ParseIP(exitTapIP)
	if ip == nil {
		return fmt.Errorf("invalid exit TAP IP: %s", exitTapIP)
	}
	isV6 := ip.To4() == nil

	var cmds [][]string
	if !isV6 {
		cmds = [][]string{
			{"route", "-n", "add", "-net", "0.0.0.0/1", exitTapIP},
			{"route", "-n", "add", "-net", "128.0.0.0/1", exitTapIP},
		}
	} else {
		cmds = [][]string{
			{"route", "-n", "add", "-inet6", "::/1", exitTapIP},
			{"route", "-n", "add", "-inet6", "8000::/1", exitTapIP},
		}
	}

	var firstErr error
	for _, args := range cmds {
		cmd := exec.Command(args[0], args[1:]...)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			// A non-zero exit for "already exists" is acceptable; record the
			// first genuine failure but keep installing the remaining routes.
			if firstErr == nil {
				firstErr = fmt.Errorf("failed to run %v: %v (%s)", args, err, stderr.String())
			}
		}
	}
	return firstErr
}

func (gm *GatewayManager) delDefaultRouteOS(exitTapIP, tapDevName string) error {
	// Delete the split default routes installed by addDefaultRouteOS (best
	// effort — ignore "not found" errors).
	ip := net.ParseIP(exitTapIP)
	if ip == nil {
		return nil
	}
	isV6 := ip.To4() == nil

	var cmds [][]string
	if !isV6 {
		cmds = [][]string{
			{"route", "-n", "delete", "-net", "0.0.0.0/1", exitTapIP},
			{"route", "-n", "delete", "-net", "128.0.0.0/1", exitTapIP},
		}
	} else {
		cmds = [][]string{
			{"route", "-n", "delete", "-inet6", "::/1", exitTapIP},
			{"route", "-n", "delete", "-inet6", "8000::/1", exitTapIP},
		}
	}
	for _, args := range cmds {
		cmd := exec.Command(args[0], args[1:]...)
		_ = cmd.Run()
	}
	return nil
}

// sweepTapDefaultRoutesUnlocked removes any split-default (/1) routes from the
// TAP adapter without depending on a remembered exit IP. Backstop for
// ClearExitNode. Caller must hold gm.mu.
func (gm *GatewayManager) sweepTapDefaultRoutesUnlocked() error {
	cmds := [][]string{
		{"route", "-n", "delete", "-net", "0.0.0.0/1"},
		{"route", "-n", "delete", "-net", "128.0.0.0/1"},
		{"route", "-n", "delete", "-inet6", "::/1"},
		{"route", "-n", "delete", "-inet6", "8000::/1"},
	}
	for _, args := range cmds {
		cmd := exec.Command(args[0], args[1:]...)
		_ = cmd.Run()
	}
	return nil
}

func (gm *GatewayManager) addCIDRRouteOS(cidrStr, gatewayIP, tapDevName string) error {
	_, dstNet, err := net.ParseCIDR(cidrStr)
	if err != nil {
		return err
	}
	// macOS route -n add defaults to -inet (IPv4); for IPv6 we need -inet6.
	if dstNet.IP.To4() != nil {
		cmd := exec.Command("route", "-n", "add", "-net", cidrStr, gatewayIP)
		return cmd.Run()
	}
	cmd := exec.Command("route", "-n", "add", "-inet6", cidrStr, gatewayIP)
	return cmd.Run()
}

func (gm *GatewayManager) delCIDRRouteOS(cidrStr, gatewayIP, tapDevName string) error {
	_, dstNet, err := net.ParseCIDR(cidrStr)
	if err != nil {
		return err
	}
	if dstNet.IP.To4() != nil {
		cmd := exec.Command("route", "-n", "delete", "-net", cidrStr, gatewayIP)
		return cmd.Run()
	}
	cmd := exec.Command("route", "-n", "delete", "-inet6", cidrStr, gatewayIP)
	return cmd.Run()
}

// restorePhysicalDefaultGatewayOS is a no-op on darwin; the physical default
// route is never removed by SetExitNode, so nothing needs restoring on clear.
func (gm *GatewayManager) restorePhysicalDefaultGatewayOS() {}
