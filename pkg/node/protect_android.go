//go:build android

package node

import (
	"fmt"
	"net"
)

// androidProtectFunc is registered by the Android binding layer
// (p2ptap/pkg/android) to call back into android.net.VpnService.protect(fd).
// Every P2P/control socket must be protected so that the Android routing stack
// does not send it through the VPN tunnel itself (which would create a routing
// loop and black-hole all P2P traffic). The app must call
// node.SetAndroidProtectFunc before starting the node.
var androidProtectFunc func(fd int) bool

// SetAndroidProtectFunc registers the Android VpnService socket-protection
// callback used by protectSocketOS.
func SetAndroidProtectFunc(fn func(fd int) bool) {
	androidProtectFunc = fn
}

func protectSocketOS(fd uintptr, wanIfName string) error {
	if androidProtectFunc == nil {
		// No protector registered. On Android this risks a routing loop, but we
		// fall back to a best-effort no-op rather than breaking the dial. The
		// app is expected to register a protector via SetAndroidProtectFunc.
		return nil
	}
	if !androidProtectFunc(int(fd)) {
		return fmt.Errorf("android VpnService.protect(fd=%d) returned false", fd)
	}
	return nil
}

// detectDefaultRouteInterface is unsupported on Android: the default egress
// interface is managed by the OS/VpnService, not by this process. The caller
// treats the error as "no physical interface known" and skips socket binding
// hints accordingly.
func detectDefaultRouteInterface() (uint32, string, error) {
	return 0, "", net.InvalidAddrError("default-route detection unsupported on Android")
}
