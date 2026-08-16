//go:build windows

package node

import (
	"fmt"
	"net"
	"net/netip"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

const (
	IP_UNICAST_IF   = 31 // IPPROTO_IP
	IPV6_UNICAST_IF = 31 // IPPROTO_IPV6
)

// getPrimaryPhysicalInterface returns the index and friendly name of the first
// active physical adapter (Ethernet or Wi-Fi) that has a global IPv4 address.
//
// Windows does NOT expose the BSD-style FlagBroadcast flag on its adapters, so
// the generic net.Interfaces()-based lookup (which relies on FlagBroadcast to
// tell physical NICs from TAP/Wintun) never matched anything and silently
// returned an error. As a result every P2P socket was left unbound and, once an
// Exit Node default route points at the TAP device, those sockets looped back
// into the tunnel and the P2P connection dropped — making in-mesh peers
// (e.g. 10.0.0.2) unreachable. Here we identify the physical NIC by IfType and
// explicitly exclude TAP/Wintun via isVirtualInterface.
func getPrimaryPhysicalInterface() (index uint32, name string, err error) {
	adapters, err := winipcfg.GetAdaptersAddresses(windows.AF_UNSPEC, winipcfg.GAAFlagDefault)
	if err != nil {
		return 0, "", fmt.Errorf("GetAdaptersAddresses: %w", err)
	}
	for _, a := range adapters {
		if a.IfType == windows.IF_TYPE_SOFTWARE_LOOPBACK {
			continue
		}
		if a.OperStatus != winipcfg.IfOperStatusUp {
			continue
		}
		// Only real Ethernet or Wi-Fi adapters; tunnels (TAP/Wintun/PPPoE),
		// virtual switches and other pseudo-interfaces are skipped.
		if a.IfType != windows.IF_TYPE_ETHERNET_CSMACD && a.IfType != windows.IF_TYPE_IEEE80211 {
			continue
		}
		if isVirtualInterface(a.FriendlyName()) {
			continue
		}
		// Require at least one global IPv4 unicast address. The Sockaddr is a
		// native-layout sockaddr (family at offset 0), so reinterpret it exactly
		// like wireguard does — via (*windows.RawSockaddrInet4) — instead of the
		// standard-library syscall type, whose field layout does not match.
		hasV4 := false
		for ua := a.FirstUnicastAddress; ua != nil; ua = ua.Next {
			raw := ua.Address.Sockaddr
			if raw == nil {
				continue
			}
			in4 := (*windows.RawSockaddrInet4)(unsafe.Pointer(raw))
			if in4.Family != windows.AF_INET {
				continue
			}
			ip := net.IPv4(in4.Addr[0], in4.Addr[1], in4.Addr[2], in4.Addr[3])
			if ip.IsGlobalUnicast() {
				hasV4 = true
				break
			}
		}
		if !hasV4 {
			continue
		}
		return a.IfIndex, a.FriendlyName(), nil
	}
	return 0, "", net.InvalidAddrError("no physical active IPv4 interface found")
}

// protectSocketOS binds the socket's outbound interface to the physical adapter
// via IP_UNICAST_IF (IPv4) / IPV6_UNICAST_IF (IPv6). This is the Windows
// equivalent of Linux SO_BINDTODEVICE and is the primary P2P-loop prevention on
// this platform: every P2P socket — dial AND listen, since libp2p reuses the
// QUIC listen socket for dialing — is pinned to the real physical NIC, so even
// after an Exit Node installs a /1 default route pointing at the TAP tunnel, the
// P2P control plane still egresses via the physical NIC and never loops back
// into the tunnel. There is no need to also install /32 host routes: the socket
// binding is more specific than any route and cannot be shadowed by the /1 or
// /24 capture routes.
//
// The interface index comes from the startup-cached default egress (see protect.go);
// it is refreshed on roam by CheckAndUpdatePhysicalGateway calling
// RefreshDefaultEgressInterface.
func protectSocketOS(fd uintptr, targetAddress string) error {
	idx, name, err := GetDefaultEgressInterface()
	if err != nil || idx == 0 {
		// No usable physical egress: socket-level protection is unavailable.
		// Do NOT fail the dial — the caller falls through, and the route table
		// may still capture (and loop) the traffic, but we must not break socket
		// creation. Warn so the operator knows protection is currently absent.
		protectLog.Warn("IP_UNICAST_IF socket protect skipped for %s: no default egress interface (%v)", targetAddress, err)
		return nil
	}
	// Bind both families. The inapplicable option returns WSAEINVAL on a
	// single-stack socket and is swallowed by bindUnicastIf, so a dual-stack
	// socket is covered and a single-stack socket is unaffected.
	if e := bindUnicastIf(fd, idx, false); e != nil {
		protectLog.Warn("IP_UNICAST_IF bind failed on %s via %s: %v", targetAddress, name, e)
	}
	if e := bindUnicastIf(fd, idx, true); e != nil {
		protectLog.Warn("IPV6_UNICAST_IF bind failed on %s via %s: %v", targetAddress, name, e)
	}
	return nil
}

// bindUnicastIf binds the socket's outbound interface to the physical adapter
// via IP_UNICAST_IF (IPv4) or IPV6_UNICAST_IF (IPv6). On Windows Winsock, IPv4
// expects the interface index in network byte order, while IPv6 expects it in
// host byte order.
func bindUnicastIf(fd uintptr, ifIndex uint32, ipv6 bool) error {
	var val int
	var proto, opt int
	if ipv6 {
		proto = windows.IPPROTO_IPV6
		opt = IPV6_UNICAST_IF
		val = int(ifIndex) // IPv6 expects host byte order
	} else {
		proto = windows.IPPROTO_IP
		opt = IP_UNICAST_IF
		netOrderIfIndex := ((ifIndex & 0xFF) << 24) |
			((ifIndex & 0xFF00) << 8) |
			((ifIndex & 0xFF0000) >> 8) |
			((ifIndex & 0xFF000000) >> 24)
		val = int(netOrderIfIndex) // IPv4 expects network byte order
	}

	err := windows.SetsockoptInt(
		windows.Handle(fd),
		proto,
		opt,
		val,
	)
	if err != nil {
		// WSAEINVAL (10022) / WSAEADDRNOTAVAIL (10049) / WSAENETUNREACH (10051)
		// means the option or IP family does not apply to this socket/adapter;
		// that is expected on IPv4-only adapters, so ignore it gracefully.
		if errno, ok := err.(windows.Errno); ok {
			if errno == windows.WSAEINVAL || errno == windows.WSAEADDRNOTAVAIL || errno == windows.WSAENETUNREACH {
				return nil
			}
		}
		return fmt.Errorf("setsockopt %s failed on ifIndex %d: %w", protoName(ipv6), ifIndex, err)
	}
	return nil
}

func protoName(ipv6 bool) string {
	if ipv6 {
		return "IPV6_UNICAST_IF"
	}
	return "IP_UNICAST_IF"
}

// detectDefaultRouteInterface returns the interface that owns the system
// default route (0.0.0.0/0). On Windows the most robust source is the IP
// Helper BestRoute API; until that wiring lands we intentionally return an
// error so the caller falls back to getPrimaryPhysicalInterface (first up
// physical NIC with a global IPv4 address), which is correct for the common
// single-homed case and is cached at startup.
// detectDefaultRouteInterface returns the interface that owns the system
// default route (0.0.0.0/0) on Windows. We resolve it authoritatively from the
// live route table: the route whose destination is 0.0.0.0/0 (the real default
// route, present at startup before any Exit Node /1 hijack), excluding the TAP
// tunnel, and picking the lowest metric. This yields the real physical egress
// NIC even on multi-homed machines, where the naive "first up physical adapter"
// heuristic in getPrimaryPhysicalInterface can pick the wrong card. Must be
// called at startup, before an Exit Node installs a /1 default route.
func detectDefaultRouteInterface() (uint32, string, error) {
	routes, err := winipcfg.GetIPForwardTable2(winipcfg.AddressFamily(windows.AF_INET))
	if err != nil {
		return 0, "", fmt.Errorf("GetIPForwardTable2: %w", err)
	}
	adapters, err := winipcfg.GetAdaptersAddresses(windows.AF_UNSPEC, winipcfg.GAAFlagDefault)
	if err != nil {
		return 0, "", fmt.Errorf("GetAdaptersAddresses: %w", err)
	}
	v4Default := netip.MustParsePrefix("0.0.0.0/0")
	var bestLUID winipcfg.LUID
	var bestMetric uint32
	found := false
	for _, r := range routes {
		if r.DestinationPrefix.Prefix() != v4Default {
			continue
		}
		// Skip routes whose interface is the TAP tunnel.
		ifname := luidToFriendlyName(r.InterfaceLUID)
		if ifname != "" && isVirtualInterface(ifname) {
			continue
		}
		if !found || r.Metric < bestMetric {
			found = true
			bestLUID = r.InterfaceLUID
			bestMetric = r.Metric
		}
	}
	if !found {
		return 0, "", net.InvalidAddrError("no non-TAP 0.0.0.0/0 default route found")
	}
	// Resolve the LUID to its interface index for IP_UNICAST_IF binding.
	for _, a := range adapters {
		if a.LUID == bestLUID {
			return uint32(a.IfIndex), a.FriendlyName(), nil
		}
	}
	return 0, "", net.InvalidAddrError("resolved default-route LUID has no matching adapter")
}

// luidToFriendlyName returns the friendly name for a LUID (best-effort).
func luidToFriendlyName(luid winipcfg.LUID) string {
	adapters, err := winipcfg.GetAdaptersAddresses(windows.AF_UNSPEC, winipcfg.GAAFlagDefault)
	if err != nil {
		return ""
	}
	for _, a := range adapters {
		if a.LUID == luid {
			return a.FriendlyName()
		}
	}
	return ""
}
