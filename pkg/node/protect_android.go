//go:build android

package node

import (
	"fmt"
	"net"
	"syscall"
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
	if androidProtectFunc != nil {
		if !androidProtectFunc(int(fd)) {
			return fmt.Errorf("android VpnService.protect(fd=%d) returned false", fd)
		}
	}
	// Tune socket buffers for high performance throughput on Android (4MB send/recv buffers)
	_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, 4*1024*1024)
	_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUF, 4*1024*1024)
	return nil
}

// detectDefaultRouteInterface is unsupported on Android: the default egress
// interface is managed by the OS/VpnService, not by this process. The caller
// treats the error as "no physical interface known" and skips socket binding
// hints accordingly.
func detectDefaultRouteInterface() (uint32, string, error) {
	return 0, "", net.InvalidAddrError("default-route detection unsupported on Android")
}
