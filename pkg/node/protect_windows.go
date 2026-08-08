//go:build windows

package node

import (
	"fmt"
	"syscall"

	"golang.org/x/sys/windows"
)

const IP_UNICAST_IF = 31

func protectSocketOS(fd uintptr, wanIfName string) error {
	ifIndex, err := GetPrimaryPhysicalInterfaceIndex()
	if err != nil {
		return nil
	}

	netOrderIfIndex := ((ifIndex & 0xFF) << 24) |
		((ifIndex & 0xFF00) << 8) |
		((ifIndex & 0xFF0000) >> 8) |
		((ifIndex & 0xFF000000) >> 24)

	err = windows.SetsockoptInt(
		windows.Handle(fd),
		windows.IPPROTO_IP,
		IP_UNICAST_IF,
		int(netOrderIfIndex),
	)
	if err != nil {
		return fmt.Errorf("setsockopt IP_UNICAST_IF failed on ifIndex %d: %w", ifIndex, err)
	}
	return nil
}

func ProtectSocketWindows(fd uintptr, ifIndex uint32) error {
	return protectSocketOS(fd, "")
}

func ControlHookForWindowsSocket(ifIndex uint32) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		var sockErr error
		err := c.Control(func(fd uintptr) {
			sockErr = ProtectSocketWindows(fd, ifIndex)
		})
		if err != nil {
			return err
		}
		return sockErr
	}
}
