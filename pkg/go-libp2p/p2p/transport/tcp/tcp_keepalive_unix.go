//go:build linux || freebsd || netbsd || dragonfly

package tcp

import (
	"golang.org/x/sys/unix"
)

// setKeepAliveParams sets the TCP keepalive idle and probe interval on a raw
// socket.
//
// SO_KEEPALIVE alone is not enough. The kernel only starts probing after
// TCP_KEEPIDLE seconds of no data, and Linux defaults that to 7200 s. Most NATs
// and middleboxes destroy idle TCP mappings far sooner, so a keepalive enabled
// with only SetKeepAlive never fires before the mapping is already gone: the
// connection is a corpse that nobody notices. Setting the idle time to the probe
// period makes the first probe start promptly, which both re-arms the NAT
// mapping on every interval and turns a silently dead link into a readable
// RST/FIN.
func setKeepAliveParams(fd uintptr, idle int, interval int) error {
	if err := unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_KEEPIDLE, idle); err != nil {
		return err
	}
	return unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_KEEPINTVL, interval)
}
