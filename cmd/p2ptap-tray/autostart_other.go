//go:build !windows

package main

// isAutostartEnabled returns false on non-Windows platforms.
func isAutostartEnabled() bool {
	return false
}

// setAutostart is a no-op stub for non-Windows platforms.
func setAutostart(enable bool) error {
	return nil
}
