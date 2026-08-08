package node

import (
	"net"
	"syscall"

	"p2ptap/pkg/logger"
)

var protectLog = logger.New("Protect")

// GetSocketControlHook returns a Control hook for net.Dialer / net.ListenConfig
// that binds outbound P2P transport sockets to the physical network interface,
// preventing routing loops when TAP interface is configured as default gateway.
func GetSocketControlHook(wanIfName string) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		var sockErr error
		err := c.Control(func(fd uintptr) {
			sockErr = protectSocketOS(fd, wanIfName)
		})
		if err != nil {
			return err
		}
		return sockErr
	}
}

// GetPrimaryPhysicalInterfaceIndex finds index of default physical IPv4 interface
func GetPrimaryPhysicalInterfaceIndex() (uint32, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return 0, err
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
				if ipNet.IP.To4() != nil && !ipNet.IP.IsUnspecified() {
					return uint32(iface.Index), nil
				}
			}
		}
	}
	return 0, net.InvalidAddrError("no physical active IPv4 interface found")
}
