//go:build linux

package node

import (
	"fmt"

	"golang.org/x/sys/unix"
)

func protectSocketOS(fd uintptr, wanIfName string) error {
	if wanIfName == "" || wanIfName == "auto" {
		return nil
	}
	err := unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, wanIfName)
	if err != nil {
		return fmt.Errorf("SO_BINDTODEVICE %s failed: %w", wanIfName, err)
	}
	return nil
}
