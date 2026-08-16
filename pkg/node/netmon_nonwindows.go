//go:build !windows

package node

// newWindowsNetMonOrNil is the non-Windows stub for the Windows address-change
// monitor. On non-Windows platforms NewNetMon uses the Linux netlink monitor
// or the portable poller instead, so this returns nil.
func newWindowsNetMonOrNil(tapName string) NetMon {
	return nil
}
