//go:build darwin

package tcp

import (
	"golang.org/x/sys/unix"
)

// setKeepAliveParams sets the TCP keepalive idle and probe interval on a raw
// socket. Darwin names the idle option TCP_KEEPALIVE rather than TCP_KEEPIDLE,
// so it is set explicitly here instead of being left at the 300 s default.
func setKeepAliveParams(fd uintptr, idle int, interval int) error {
	if err := unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_KEEPALIVE, idle); err != nil {
		return err
	}
	return unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_KEEPINTVL, interval)
}
