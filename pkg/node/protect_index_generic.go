//go:build !windows

package node

import "net"

// GetPrimaryPhysicalInterfaceIndex finds the interface index of the active
// physical (non-virtual) interface that has an IPv4 address. It is used to bind
// P2P sockets to the physical NIC so they are not routed through the TAP device
// when an Exit Node default route is installed.
func GetPrimaryPhysicalInterfaceIndex() (uint32, error) {
	idx, _, err := getPrimaryPhysicalInterface()
	if err != nil {
		return 0, err
	}
	return idx, nil
}

// GetPrimaryPhysicalInterfaceName returns the friendly name of the primary
// physical interface (used for logging/diagnostics).
func GetPrimaryPhysicalInterfaceName() (string, error) {
	_, name, err := getPrimaryPhysicalInterface()
	if err != nil {
		return "", err
	}
	return name, nil
}

// getPrimaryPhysicalInterface iterates over system interfaces and returns the
// first active physical interface that has an IPv4 address. Point-to-point /
// tunnel devices (TAP, Wintun) typically lack the broadcast flag; physical
// Ethernet/Wi-Fi adapters have it.
func getPrimaryPhysicalInterface() (index uint32, name string, err error) {
	ifaces, e := net.Interfaces()
	if e != nil {
		return 0, "", e
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		// Skip virtual/tunnel interfaces such as TAP and Wintun so that P2P
		// sockets are bound to a real physical NIC, not the tunnel itself.
		if iface.Flags&net.FlagBroadcast == 0 {
			continue
		}
		addrs, aerr := iface.Addrs()
		if aerr != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip := ipnet.IP.To4()
			if ip == nil {
				continue
			}
			if ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue
			}
			return uint32(iface.Index), iface.Name, nil
		}
	}
	return 0, "", net.InvalidAddrError("no physical active IPv4 interface found")
}
