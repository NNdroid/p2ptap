//go:build !windows

package driver

// CheckResult describes the state of the available TAP/Wintun drivers.
type CheckResult struct {
	TAPInstalled    bool
	WintunReady     bool
	TAPInstaller    string
	WintunDLL       string
	PreferredDriver string
}

// Check returns dummy results for non-Windows platforms.
func Check() CheckResult {
	return CheckResult{
		TAPInstalled:    true,
		WintunReady:     false,
		PreferredDriver: "tap",
	}
}

// Ensure is a no-op on non-Windows platforms as kernel TUN/TAP is native.
func Ensure(onStatus func(msg string)) string {
	return "tap"
}
