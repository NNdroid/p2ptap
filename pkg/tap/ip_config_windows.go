//go:build windows

package tap

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
	"time"
)

const windowsAddressSettleTimeout = 5 * time.Second

// runNetsh returns the command's diagnostic text instead of silently discarding
// it. Address configuration is a startup invariant: reporting success while the
// requested TAP address was never installed makes the VPN and a WebUI bound to
// that address look healthy even though neither can work.
func runNetsh(args ...string) error {
	out, err := exec.Command("netsh", args...).CombinedOutput()
	if err == nil {
		return nil
	}
	detail := strings.TrimSpace(string(out))
	if detail == "" {
		return fmt.Errorf("netsh %s: %w", strings.Join(args, " "), err)
	}
	return fmt.Errorf("netsh %s: %w: %s", strings.Join(args, " "), err, detail)
}

// waitForWindowsInterfaceAddress waits until the address is observable on the
// named interface. Windows can return from winipcfg/netsh before the address is
// bindable; without this barrier the WebUI immediately falls through to a
// wildcard listener and hides the failed/delayed TAP setup.
func waitForWindowsInterfaceAddress(ifName, ipStr string) error {
	if strings.TrimSpace(ipStr) == "" {
		return nil
	}
	expected := net.ParseIP(strings.Split(ipStr, "/")[0])
	if expected == nil {
		return fmt.Errorf("invalid IP address %q", ipStr)
	}

	deadline := time.Now().Add(windowsAddressSettleTimeout)
	var lastErr error
	for {
		iface, err := net.InterfaceByName(ifName)
		if err == nil {
			addrs, addrErr := iface.Addrs()
			if addrErr == nil {
				for _, addr := range addrs {
					candidate := net.ParseIP(strings.Split(addr.String(), "/")[0])
					if candidate != nil && candidate.Equal(expected) {
						return nil
					}
				}
				lastErr = fmt.Errorf("address %s is not present on interface %q", expected, ifName)
			} else {
				lastErr = addrErr
			}
		} else {
			lastErr = err
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("Windows did not install %s on interface %q within %s: %w", expected, ifName, windowsAddressSettleTimeout, lastErr)
		}
		time.Sleep(100 * time.Millisecond)
	}
}
