//go:build linux
// +build linux

package tap

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"unsafe"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"p2ptap/pkg/logger"
)

var tapLog = logger.New("TAP")

type LinuxTAPDevice struct {
	name    string
	mac     string
	file    *os.File
	ipCIDR  string
	ipv6    string
	eventFd int // eventfd for epoll cancellation wake-up
}

type ifreq struct {
	name  [16]byte
	flags uint16
	_pad  [22]byte
}

func createOSTAPDevice(tapName string, mtu int) (TAPDevice, error) {
	if _, err := net.InterfaceByName(tapName); err == nil {
		return nil, fmt.Errorf("network interface %q already exists; refusing to attach to an existing TAP queue", tapName)
	}

	tapLog.Debug("Opening /dev/net/tun for TAP device '%s'...", tapName)
	file, err := os.OpenFile("/dev/net/tun", os.O_RDWR|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to open /dev/net/tun: %w", err)
	}

	var req ifreq
	copy(req.name[:], []byte(tapName))
	// IFF_TAP = 0x0002, IFF_NO_PI = 0x1000
	req.flags = unix.IFF_TAP | unix.IFF_NO_PI

	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		file.Fd(),
		uintptr(unix.TUNSETIFF),
		uintptr(unsafe.Pointer(&req)),
	)
	if errno != 0 {
		_ = file.Close()
		return nil, fmt.Errorf("ioctl TUNSETIFF failed: %v", errno)
	}

	realName := cStringToString(req.name[:])
	if realName == "" {
		realName = tapName
	}

	dev := &LinuxTAPDevice{
		name: realName,
		file: file,
	}

	efd, err := unix.Eventfd(0, unix.EFD_NONBLOCK|unix.EFD_CLOEXEC)
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("create eventfd for TAP device: %w", err)
	}
	dev.eventFd = efd

	if err = dev.SetMTU(mtu); err != nil {
		tapLog.Warn("Failed to set MTU %d on '%s': %v", mtu, realName, err)
	}

	tapLog.Info("Linux TAP device '%s' created via /dev/net/tun (fd=%d)", realName, file.Fd())
	return dev, nil
}

// createPlatformTAPDevice is a thin wrapper around createOSTAPDevice on
// non-Windows platforms where driver fallback is not applicable.
func createPlatformTAPDevice(tapName, driverType string, mtu int) (TAPDevice, error) {
	return createOSTAPDevice(tapName, mtu)
}

func cStringToString(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

func (l *LinuxTAPDevice) Name() string {
	return l.name
}

func (l *LinuxTAPDevice) SetMAC(mac string) error {
	if mac == "" {
		return nil
	}
	addr, err := net.ParseMAC(mac)
	if err != nil {
		return fmt.Errorf("invalid MAC address %q: %w", mac, err)
	}
	if len(addr) != 6 {
		return fmt.Errorf("TAP MAC address must contain 6 octets, got %q", mac)
	}

	tapLog.Debug("Configuring MAC %s on '%s' via netlink...", addr.String(), l.name)
	link, err := netlink.LinkByName(l.name)
	if err != nil {
		return fmt.Errorf("netlink find link %q: %w", l.name, err)
	}
	if err := netlink.LinkSetHardwareAddr(link, addr); err != nil {
		return fmt.Errorf("netlink set MAC %s on %q: %w", addr, l.name, err)
	}
	l.mac = addr.String()
	return nil
}

func (l *LinuxTAPDevice) MAC() string {
	return l.mac
}

func (l *LinuxTAPDevice) SetMTU(mtu int) error {
	if mtu <= 0 {
		return nil
	}
	tapLog.Info("Setting MTU %d on TAP device '%s' via netlink...", mtu, l.name)
	link, err := netlink.LinkByName(l.name)
	if err != nil {
		return fmt.Errorf("netlink find link %q: %w", l.name, err)
	}
	if err := netlink.LinkSetMTU(link, mtu); err != nil {
		return fmt.Errorf("netlink set MTU %d on %q: %w", mtu, l.name, err)
	}
	return nil
}

func (l *LinuxTAPDevice) Read(b []byte) (int, error) {
	// Fast path: try a non-blocking read first (fd is O_NONBLOCK).
	// This avoids an unnecessary 50 ms poll when data is already
	// queued — e.g. immediately after epoll signals readability.
	n, err := unix.Read(int(l.file.Fd()), b)
	if err == nil {
		return n, nil
	}
	if err != unix.EAGAIN && err != unix.EWOULDBLOCK && err != unix.EINTR {
		return 0, err
	}

	// Slow path: poll-wait for data.
	for {
		pollFD := []unix.PollFd{{
			Fd:     int32(l.file.Fd()),
			Events: unix.POLLIN,
		}}
		n, err := unix.Poll(pollFD, 50) // 50ms poll for responsive data plane
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return 0, fmt.Errorf("poll TAP device: %w", err)
		}
		if n == 0 {
			return 0, ErrReadTimeout
		}
		if pollFD[0].Revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
			return 0, fmt.Errorf("TAP poll event: %#x", pollFD[0].Revents)
		}

		n, err = unix.Read(int(l.file.Fd()), b)
		if errors.Is(err, unix.EINTR) || errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
			continue
		}
		return n, err
	}
}

func (l *LinuxTAPDevice) Write(b []byte) (int, error) {
	return l.file.Write(b)
}

func (l *LinuxTAPDevice) Close() error {
	tapLog.Info("Closing TAP device '%s'", l.name)
	if l.eventFd >= 0 {
		unix.Close(l.eventFd)
		l.eventFd = -1
	}
	return l.file.Close()
}

// SelfTest verifies the Linux TAP write/read path.
//
// Unlike Windows TAP-Win32 (which echoes written frames back to the read
// queue), a Linux /dev/net/tun IFF_TAP device does NOT loop frames: writes go
// into the kernel network stack and reads return only frames that the kernel
// stack transmits out of the interface. Therefore we treat it like Wintun:
// validate that both Write and Read are callable; a read timeout is normal.
func (l *LinuxTAPDevice) SelfTest() map[string]interface{} {
	return runRealDeviceSelfTest(l, "wintun")
}

func (l *LinuxTAPDevice) ConfigureIP(ipCIDR string, ipv6CIDR string) error {
	l.ipCIDR = ipCIDR
	l.ipv6 = ipv6CIDR

	link, err := netlink.LinkByName(l.name)
	if err != nil {
		return fmt.Errorf("netlink find link %q: %w", l.name, err)
	}

	// Bring interface UP
	tapLog.Debug("Bringing interface '%s' up via netlink...", l.name)
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("netlink link set %q up: %w", l.name, err)
	}

	// Configure IPv4
	if ipCIDR != "" {
		tapLog.Debug("Configuring IPv4 %s on '%s' via netlink...", ipCIDR, l.name)
		addr4, err := netlink.ParseAddr(ipCIDR)
		if err != nil {
			return fmt.Errorf("parse IPv4 CIDR %q: %w", ipCIDR, err)
		}
		if err := netlink.AddrReplace(link, addr4); err != nil {
			return fmt.Errorf("netlink addr replace IPv4 %s on %q: %w", ipCIDR, l.name, err)
		}
	}

	// Configure IPv6
	if ipv6CIDR != "" {
		tapLog.Debug("Configuring IPv6 %s on '%s' via netlink...", ipv6CIDR, l.name)
		addr6, err := netlink.ParseAddr(ipv6CIDR)
		if err != nil {
			return fmt.Errorf("parse IPv6 CIDR %q: %w", ipv6CIDR, err)
		}
		if err := netlink.AddrReplace(link, addr6); err != nil {
			return fmt.Errorf("netlink addr replace IPv6 %s on %q: %w", ipv6CIDR, l.name, err)
		}
	}

	tapLog.Info("TAP '%s' configured via netlink: IPv4=%s IPv6=%s", l.name, ipCIDR, ipv6CIDR)
	return nil
}

// --- EpollPoller implementation (Linux) ------------------------------------

// NewEpollPoller creates an epoll poller that watches the TAP fd for
// readability and an eventfd for context cancellation.
func NewEpollPoller(dev TAPDevice) (*EpollPoller, error) {
	lt, ok := dev.(*LinuxTAPDevice)
	if !ok {
		return nil, errors.New("epoll: device is not a Linux TAP device")
	}

	epfd, err := unix.EpollCreate1(unix.EPOLL_CLOEXEC)
	if err != nil {
		return nil, fmt.Errorf("epoll_create1: %w", err)
	}

	tapFd := int(lt.file.Fd())
	wakeFd := lt.eventFd

	// Register TAP fd for readability
	ev := unix.EpollEvent{Events: unix.EPOLLIN, Fd: int32(tapFd)}
	if err := unix.EpollCtl(epfd, unix.EPOLL_CTL_ADD, tapFd, &ev); err != nil {
		unix.Close(epfd)
		return nil, fmt.Errorf("epoll_ctl add tap fd: %w", err)
	}

	// Register eventfd for cancellation wake-up
	ev = unix.EpollEvent{Events: unix.EPOLLIN, Fd: int32(wakeFd)}
	if err := unix.EpollCtl(epfd, unix.EPOLL_CTL_ADD, wakeFd, &ev); err != nil {
		unix.Close(epfd)
		return nil, fmt.Errorf("epoll_ctl add eventfd: %w", err)
	}

	return &EpollPoller{epfd: epfd, tapFd: tapFd, wakeFd: wakeFd}, nil
}

// Wait blocks until the TAP fd is readable or ctx is cancelled.
// It returns nil when data is available and ctx.Err() on cancellation.
func (p *EpollPoller) Wait(ctx context.Context) error {
	var events [1]unix.EpollEvent
	for {
		nfds, err := unix.EpollWait(p.epfd, events[:], -1)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return fmt.Errorf("epoll_wait: %w", err)
		}
		if nfds == 0 {
			continue
		}
		if int(events[0].Fd) == p.wakeFd {
			// Drain the eventfd to clear it for next time.
			var val [8]byte
			unix.Read(p.wakeFd, val[:]) //nolint:errcheck
			return ctx.Err()
		}
		return nil // TAP fd is readable
	}
}

// Close releases the epoll file descriptor.
func (p *EpollPoller) Close() error {
	return unix.Close(p.epfd)
}

// NotifyOnCancel starts a goroutine that writes to the internal eventfd
// when ctx is cancelled, waking any in-progress EpollWait so Wait()
// returns ctx.Err() promptly.
func (p *EpollPoller) NotifyOnCancel(ctx context.Context) {
	go func() {
		<-ctx.Done()
		var val [8]byte
		val[0] = 1
		unix.Write(p.wakeFd, val[:])
	}()
}
