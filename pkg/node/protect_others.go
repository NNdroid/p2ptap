//go:build !linux && !windows && !darwin

package node

import "net"

func protectSocketOS(fd uintptr, wanIfName string) error {
	return nil
}

// detectDefaultRouteInterface is not implemented on this platform; the caller
// falls back to the first up physical interface.
func detectDefaultRouteInterface() (uint32, string, error) {
	return 0, "", net.InvalidAddrError("default-route detection unsupported on this platform")
}
