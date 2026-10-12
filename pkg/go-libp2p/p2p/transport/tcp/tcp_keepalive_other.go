//go:build !linux && !darwin && !freebsd && !netbsd && !dragonfly

package tcp

// setKeepAliveParams sets the TCP keepalive idle time on a raw socket. This
// build tag covers Windows and OpenBSD, where the idle option is not available
// through the same socket level and number: on Windows TCP_KEEPIDLE is a winsock
// constant not exported by golang.org/x/sys/unix, and on OpenBSD it is spelled
// TCP_KEEPALIVE with a different numeric value. SO_KEEPALIVE and the probe
// interval are still applied by tryKeepAlive, so keepalive works — only the idle
// delay stays at the OS default, which makes dead-connection detection slower on
// those platforms.
func setKeepAliveParams(fd uintptr, idle int, interval int) error {
	return nil
}
