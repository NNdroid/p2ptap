//go:build darwin

package node

import (
	"fmt"
	"net"
	"os/exec"
	"strings"

	"golang.org/x/sys/unix"
)

// detectDefaultRouteInterface returns the interface owning the IPv4 default
// route by querying the routing table ("route get default"). The interface name
// appears on the "interface: " line of the output.
func detectDefaultRouteInterface() (uint32, string, error) {
	out, err := exec.Command("route", "get", "default").CombinedOutput()
	if err != nil {
		return 0, "", err
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "interface: ") {
			ifaceName := strings.TrimSpace(strings.TrimPrefix(line, "interface: "))
			iface, err := net.InterfaceByName(ifaceName)
			if err != nil {
				return 0, "", err
			}
			return uint32(iface.Index), ifaceName, nil
		}
	}
	return 0, "", net.InvalidAddrError("no IPv4 default route interface found")
}

func protectSocketOS(fd uintptr, wanIfName string) error {
	ifIndex, _, err := GetDefaultEgressInterface()
	if err != nil || ifIndex == 0 {
		if wanIfName != "" && wanIfName != "auto" {
			iface, errIf := net.InterfaceByName(wanIfName)
			if errIf == nil {
				ifIndex = uint32(iface.Index)
			}
		}
	}
	if ifIndex == 0 {
		return nil
	}

	// Bind the socket to the physical adapter for BOTH address families.
	// On macOS, IP_BOUND_IF (0x19) applies only to IPv4 sockets and
	// IPV6_BOUND_IF (0x7d) only to IPv6 sockets; setting the wrong one returns
	// EINVAL, which we ignore — this mirrors the Windows IP_UNICAST_IF /
	// IPV6_UNICAST_IF dual-bind so every P2P socket (v4 or v6) egresses via the
	// physical interface instead of looping back into the TAP tunnel under Exit
	// Node mode.
	_ = bindBoundIf(fd, ifIndex, false)
	_ = bindBoundIf(fd, ifIndex, true)
	return nil
}

// bindBoundIf binds the socket's outbound interface to the physical adapter via
// IP_BOUND_IF (IPv4) or IPV6_BOUND_IF (IPv6). Applying the v4 option to a v6
// socket (or vice-versa) returns EINVAL, which is expected and ignored.
func bindBoundIf(fd uintptr, ifIndex uint32, ipv6 bool) error {
	var proto, opt int
	if ipv6 {
		proto = unix.IPPROTO_IPV6
		opt = unix.IPV6_BOUND_IF
	} else {
		proto = unix.IPPROTO_IP
		opt = unix.IP_BOUND_IF
	}
	if err := unix.SetsockoptInt(int(fd), proto, opt, int(ifIndex)); err != nil {
		if errno, ok := err.(unix.Errno); ok && errno == unix.EINVAL {
			return nil
		}
		return fmt.Errorf("setsockopt %s failed on ifIndex %d: %w",
			map[bool]string{true: "IPV6_BOUND_IF", false: "IP_BOUND_IF"}[ipv6], ifIndex, err)
	}
	return nil
}
