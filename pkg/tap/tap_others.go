//go:build (!linux && !windows && !darwin) || android
// +build !linux,!windows,!darwin android

package tap

import (
	"errors"
)

func createOSTAPDevice(tapName string, mtu int) (TAPDevice, error) {
	return nil, errors.New("OS TAP requires root/administrator privileges")
}

func createPlatformTAPDevice(tapName, driverType string, mtu int) (TAPDevice, error) {
	return createOSTAPDevice(tapName, mtu)
}
