//go:build darwin

package node

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

func protectSocketOS(fd uintptr, wanIfName string) error {
	ifIndex, err := GetPrimaryPhysicalInterfaceIndex()
	if err != nil {
		if wanIfName != "" && wanIfName != "auto" {
			iface, errIf := net.InterfaceByName(wanIfName)
			if errIf == nil {
				ifIndex = uint32(iface.Index)
			}
		}
	}
	if ifIndex == 0 {
		return nil
	}

	err = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BOUND_IF, int(ifIndex))
	if err != nil {
		return fmt.Errorf("setsockopt IP_BOUND_IF failed on ifIndex %d: %w", ifIndex, err)
	}
	return nil
}
