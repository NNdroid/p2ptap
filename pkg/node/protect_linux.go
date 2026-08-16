//go:build linux && !android

package node

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// detectDefaultRouteInterface returns the interface that owns the IPv4 default
// route (destination 00000000, mask 00000000) by parsing /proc/net/route. This
// is the true egress NIC, which is exactly what we want to bind P2P sockets to
// once an Exit Node hijacks the default gateway.
func detectDefaultRouteInterface() (uint32, string, error) {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return 0, "", err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	// Skip header line.
	if sc.Scan() {
	}
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 4 {
			continue
		}
		ifaceName := fields[0]
		dst := fields[1]
		mask := fields[2]
		if dst == "00000000" && mask == "00000000" {
			iface, err := net.InterfaceByName(ifaceName)
			if err != nil {
				continue
			}
			return uint32(iface.Index), ifaceName, nil
		}
	}
	return 0, "", net.InvalidAddrError("no IPv4 default route found")
}

func protectSocketOS(fd uintptr, wanIfName string) error {
	if wanIfName == "" || wanIfName == "auto" {
		// No interface name configured: use the cached default egress interface
		// detected at process startup (before any Exit Node default route
		// hijacked the TAP device), so P2P sockets still bind away from the
		// tunnel even after the TAP becomes the default gateway.
		_, name, err := GetDefaultEgressInterface()
		if err != nil || name == "" {
			return nil
		}
		wanIfName = name
	}
	err := unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, wanIfName)
	if err != nil {
		return fmt.Errorf("SO_BINDTODEVICE %s failed: %w", wanIfName, err)
	}
	return nil
}
