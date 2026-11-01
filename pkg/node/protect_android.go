//go:build android

package node

import (
	"fmt"
	"net"
	"sync"
	"syscall"

	"p2ptap/pkg/logger"
)

// androidProtectFunc is registered by the Android binding layer
// (p2ptap/pkg/android) to call back into android.net.VpnService.protect(fd).
// Every P2P/control socket must be protected so that the Android routing stack
// does not send it through the VPN tunnel itself (which would create a routing
// loop and black-hole all P2P traffic). The app must call
// node.SetAndroidProtectFunc before starting the node.
//
// The callback also receives the dial target (network, address) so a
// network-aware app can additionally bind the socket to a specific
// android.net.Network via Network.bindSocket — the precondition for true
// multipath over Wi-Fi + cellular. Apps that ignore the extra arguments
// degrade to plain VpnService.protect behaviour.
var (
	androidProtectMu   sync.RWMutex
	androidProtectFunc func(fd int, network, address string) bool
)

// SetAndroidProtectFunc registers the Android socket-protection callback used
// by protectSocketOS. The function receives the socket fd plus the dial/listen
// target (network, e.g. "tcp"; address, e.g. "192.168.1.10:4001") so the app
// can pick the underlying android.net.Network for that destination.
func SetAndroidProtectFunc(fn func(fd int, network, address string) bool) {
	androidProtectMu.Lock()
	defer androidProtectMu.Unlock()
	androidProtectFunc = fn
}

func protectSocketOS(fd uintptr, wanIfName, network, address string) error {
	androidProtectMu.RLock()
	protect := androidProtectFunc
	androidProtectMu.RUnlock()
	if protect == nil {
		return fmt.Errorf("android VpnService protector is not registered for fd=%d", fd)
	}
	if !protect(int(fd), network, address) {
		return fmt.Errorf("android VpnService.protect(fd=%d, %s %s) returned false", fd, network, address)
	}
	// Tune socket buffers for high performance throughput on Android (4MB send/recv buffers)
	if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, 4*1024*1024); err != nil {
		logger.New("Protect").Debug("SetsockoptInt SO_RCVBUF failed for fd=%d: %v", fd, err)
	}
	if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUF, 4*1024*1024); err != nil {
		logger.New("Protect").Debug("SetsockoptInt SO_SNDBUF failed for fd=%d: %v", fd, err)
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
