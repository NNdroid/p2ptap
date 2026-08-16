package node

import (
	"context"
	"net"
	"strings"
	"sync"
	"syscall"

	"p2ptap/pkg/logger"
)

var protectLog = logger.New("Protect")

// defaultEgress holds the physical interface that carries the system's default
// route (0.0.0.0/0). It is detected ONCE at process startup — before any Exit
// Node default route hijacks the TAP device — and then cached for the lifetime
// of the process. Every P2P socket is bound to this interface, so that even
// after an Exit Node installs a /1 default route pointing at the TAP tunnel,
// the P2P control plane still egresses via the real physical NIC and never
// loops back into the tunnel.
//
// Detecting it at startup (rather than lazily on every protect call) is
// important: once the Exit Node route is up, "pick a physical adapter" queries
// can no longer trust the routing table, and recomputing it per-socket is both
// wasteful and racy.
var (
	defaultEgressMu    sync.RWMutex
	defaultEgressIndex uint32
	defaultEgressName  string
	defaultEgressErr   error
	defaultEgressDone  bool
)

// DetectDefaultEgressInterface probes and caches the physical interface that
// owns the system default route. It must be called once during node startup,
// after the TAP device is created (so the virtual tunnel is excluded) but
// before any Exit Node default route is installed. Subsequent calls are cheap
// no-ops once detection has completed.
func DetectDefaultEgressInterface() {
	defaultEgressMu.Lock()
	if defaultEgressDone {
		defaultEgressMu.Unlock()
		return
	}
	defaultEgressMu.Unlock()

	idx, name, err := detectDefaultEgressLocked()
	defaultEgressMu.Lock()
	defaultEgressIndex = idx
	defaultEgressName = name
	defaultEgressErr = err
	defaultEgressDone = true
	defaultEgressMu.Unlock()

	if err != nil {
		protectLog.Warn("failed to detect default egress interface at startup: %v (P2P sockets may loop into the TAP tunnel under Exit Node)", err)
	} else {
		protectLog.Info("default egress interface detected at startup: %s (ifIndex %d)", name, idx)
	}
}

// GetDefaultEgressInterface returns the cached default egress interface. If
// startup detection never ran, it triggers a (best-effort) detection now.
func GetDefaultEgressInterface() (index uint32, name string, err error) {
	defaultEgressMu.RLock()
	if defaultEgressDone {
		idx, n, e := defaultEgressIndex, defaultEgressName, defaultEgressErr
		defaultEgressMu.RUnlock()
		return idx, n, e
	}
	defaultEgressMu.RUnlock()
	DetectDefaultEgressInterface()
	defaultEgressMu.RLock()
	defer defaultEgressMu.RUnlock()
	return defaultEgressIndex, defaultEgressName, defaultEgressErr
}

// RefreshDefaultEgressInterface re-detects the cached default egress interface.
// Call it when the physical network environment changes (e.g. Wi-Fi <-> Ethernet)
// so that P2P sockets created afterwards bind to the new NIC. Existing sockets keep
// their original binding until libp2p reconnects them; this is the inherent trade-off
// of IP_UNICAST_IF (socket-level, not route-level like the /32 host route it replaces).
func RefreshDefaultEgressInterface() {
	defaultEgressMu.Lock()
	defaultEgressDone = false
	defaultEgressMu.Unlock()
	DetectDefaultEgressInterface()
}

// detectDefaultEgressLocked picks the interface that carries the default route.
// It asks the platform for the default-route interface first; if that fails (or
// the platform has no route-table access) it falls back to "first up physical
// adapter with a global IPv4 address" so we always have *some* sane NIC to bind.
func detectDefaultEgressLocked() (uint32, string, error) {
	if idx, name, err := detectDefaultRouteInterface(); err == nil && idx != 0 {
		return idx, name, nil
	}
	return getPrimaryPhysicalInterface()
}

// protectedExcludeIfaces holds the lower-cased names of interfaces that must
// never be selected as the "physical" egress interface for socket protection
// (e.g. the local TAP/Wintun virtual tunnel device). Binding P2P sockets to a
// virtual tunnel interface would route all outbound traffic into the tunnel
// itself and cause "unreachable network" dial errors.
var (
	protectedExcludeMu     sync.RWMutex
	protectedExcludeIfaces = map[string]bool{}
)

// virtualIfacePrefixes are weak hints used to skip virtual/tunnel adapters when
// no interface has been explicitly registered via RegisterProtectedExcludeInterface.
var virtualIfacePrefixes = []string{"p2ptap", "wintun", "tap", "vethernet", "loopback pseudo"}

// RegisterProtectedExcludeInterface excludes a named interface (e.g. the TAP
// device) from being selected as the physical egress interface by the socket
// protection logic. The node must call this right after creating its TAP device.
func RegisterProtectedExcludeInterface(name string) {
	if name != "" {
		protectedExcludeMu.Lock()
		protectedExcludeIfaces[strings.ToLower(name)] = true
		protectedExcludeMu.Unlock()
	}
}

// isVirtualInterface reports whether an interface name looks like a virtual or
// tunnel adapter that should not be used as the physical egress interface.
func isVirtualInterface(name string) bool {
	lower := strings.ToLower(name)
	protectedExcludeMu.RLock()
	excluded := protectedExcludeIfaces[lower]
	protectedExcludeMu.RUnlock()
	if excluded {
		return true
	}
	for _, p := range virtualIfacePrefixes {
		if strings.HasPrefix(lower, p) {
			return true
		}
	}
	return false
}

// shouldProtect reports whether a socket dialing/ listening on the given
// address must be bound to the physical interface. Loopback and link-local
// addresses are local-segment and must NOT be bound to a physical NIC via
// IP_UNICAST_IF / SO_BINDTODEVICE, otherwise the binding would force even
// 127.0.0.1 traffic out the physical adapter and fail with "address not valid
// in its context" (or "unreachable network").
func shouldProtect(address string) bool {
	host := address
	if h, _, err := net.SplitHostPort(address); err == nil {
		host = h
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return true // DNS name: not loopback/link-local, protect it
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}
	// TAP/mesh overlay addresses must NOT be pinned to the physical NIC. A
	// listener explicitly bound to a TAP IP (the "strict" listener-split case)
	// must keep egressing via the TAP device itself, and a socket dialing a
	// mesh peer must be captured by the TAP, not forced onto the physical
	// adapter. p2ptap overlay ranges: 10.0.0.0/8, 172.16.0.0/12, fd00::/8.
	if isOverlayIPAddress(address) {
		return false
	}
	return true
}

// GetSocketControlHook returns a Control hook for net.Dialer / net.ListenConfig
// that binds outbound P2P transport sockets to the physical network interface,
// preventing routing loops when TAP interface is configured as default gateway.
func GetSocketControlHook(wanIfName string) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		if !shouldProtect(address) {
			return nil
		}
		var sockErr error
		err := c.Control(func(fd uintptr) {
			sockErr = protectSocketOS(fd, resolveProtectIfName(wanIfName, address))
		})
		if err != nil {
			return err
		}
		return sockErr
	}
}

// isOverlayIPAddress reports whether the given address falls inside one of
// p2ptap's TAP/mesh overlay ranges (10.0.0.0/8, 172.16.0.0/12, fd00::/8). Such
// addresses are routed through the virtual TAP tunnel, so sockets bound to or
// dialing them must NOT be pinned to the physical NIC via IP_UNICAST_IF /
// SO_BINDTODEVICE — doing so would break tunnel-local traffic.
func isOverlayIPAddress(address string) bool {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	if ip4 := ip.To4(); ip4 != nil {
		if ip4[0] == 10 || (ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31) {
			return true
		}
	} else if ip16 := ip.To16(); ip16 != nil {
		if ip16[0] == 0xfd {
			return true
		}
	}
	return false
}

// GetPrimaryPhysicalInterfaceIndex / GetPrimaryPhysicalInterfaceName /
// getPrimaryPhysicalInterface are provided per-platform: the generic
// implementation lives in protect_index_generic.go (non-Windows) and the
// Windows-specific one in protect_windows.go. On Windows the BSD-style
// FlagBroadcast flag is not exposed by the OS, so a winipcfg-based lookup is
// required to identify the physical NIC.

// listenerProtectControl is a net.ListenConfig Control hook that pins a listen
// socket (TCP via tcpt.WithListenControl, or QUIC via ProtectedListenUDP) to a
// specific network interface. It is "address-driven": if the listen address is
// a concrete IP it binds to the interface that owns that IP; if it is
// 0.0.0.0/:: (unspecified) it falls back to the cached default egress
// interface. This yields true multi-NIC inbound (one listener per physical NIC,
// each bound to its own NIC) while keeping every listener off the TAP tunnel
// under Exit Node. Failures are logged and ignored so a listener always comes
// up (best-effort protection, matching the WebUI listener hook semantics).
func listenerProtectControl(network, address string, c syscall.RawConn) error {
	ifName := listenerInterfaceForAddress(address)
	if ifName == "" {
		return nil
	}
	var sockErr error
	err := c.Control(func(fd uintptr) {
		sockErr = protectSocketOS(fd, ifName)
	})
	if err != nil {
		return err
	}
	if sockErr != nil {
		protectLog.Warn("listener socket protect for %s failed (continuing without bind): %v", address, sockErr)
	}
	return nil
}

// resolveProtectIfName returns the interface name a socket should be pinned to
// via SO_BINDTODEVICE / IP_UNICAST_IF. If an explicit, usable NIC name is
// supplied it is returned as-is; otherwise the interface is derived from the
// socket address (concrete IP -> the interface that owns it; unspecified
// 0.0.0.0 / :: -> the cached default egress interface).
//
// This exists because the dial/tolerant control hooks receive the peer address
// (e.g. "192.168.100.226:34995" or "0.0.0.0:5857"), and passing that string
// straight into SO_BINDTODEVICE makes the kernel treat the IP as a device name,
// which fails with "no such device" and (for the strict dial hook) aborts the
// entire connection attempt. Always resolve to a real NIC name first.
func resolveProtectIfName(wanIfName, address string) string {
	if wanIfName != "" && wanIfName != "auto" {
		return wanIfName
	}
	return listenerInterfaceForAddress(address)
}

// listenerInterfaceForAddress resolves the interface a listen address should be
// pinned to. A concrete IP is pinned to the interface that owns it; an
// unspecified address (0.0.0.0 / ::) falls back to the cached default egress
// interface. Returns "" when no binding is needed or possible.
func listenerInterfaceForAddress(address string) string {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	ip := net.ParseIP(host)
	if ip != nil && !ip.IsUnspecified() {
		if name, ok := interfaceNameByIP(ip); ok {
			return name
		}
		// Concrete IP but not owned by any local interface: fall through.
	}
	if _, name, err := GetDefaultEgressInterface(); err == nil && name != "" {
		return name
	}
	return ""
}

// interfaceNameByIP returns the name of the first up interface that owns the
// given IP. (net has no InterfaceByAddr, so we match against each interface's
// address list ourselves.) Equal() normalizes the 4-byte/16-byte IP forms.
func interfaceNameByIP(target net.IP) (string, bool) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", false
	}
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipNet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			if ipNet.IP.Equal(target) {
				return ifc.Name, true
			}
		}
	}
	return "", false
}

// ProtectedListenUDP creates a UDP PacketConn bound to the physical interface
// via the socket-control hook. It is used as a drop-in replacement for
// net.ListenUDP inside libp2p's QUIC ConnManager (OverrideListenUDP), so that
// every QUIC socket — both listening and dialing — is bound to the physical
// interface and never loops back into the TAP tunnel. The listener hook is
// address-driven so that per-NIC listen addrs each bind to their own NIC.
func ProtectedListenUDP(network string, laddr *net.UDPAddr) (net.PacketConn, error) {
	lc := net.ListenConfig{Control: listenerProtectControl}
	return lc.ListenPacket(context.Background(), network, laddr.String())
}
