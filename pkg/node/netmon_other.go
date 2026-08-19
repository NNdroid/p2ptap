//go:build !linux || android
// +build !linux android

package node

// newLinuxNetMonOrNil is the non-Linux stub: there is no netlink monitor, so
// NewNetMon falls through to the Windows monitor (if available) or the
// portable poller. Defined for every non-Linux platform (including Windows),
// which is why it lives in its own file rather than netmon_linux.go.
func newLinuxNetMonOrNil(tapName string) NetMon {
	return nil
}
