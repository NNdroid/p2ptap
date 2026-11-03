//go:build android || (!linux && !windows && !darwin)
// +build android !linux,!windows,!darwin

package node

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"

	"p2ptap/pkg/config"
)

type NFTManager struct {
	mu  sync.Mutex
	cfg *config.ExitNodeConfig
}

func NewNFTManager(cfg *config.ExitNodeConfig) *NFTManager {
	return &NFTManager{cfg: cfg}
}

// UpdateConfig replaces the live config pointer (used after hot-reload)
func (m *NFTManager) UpdateConfig(cfg *config.ExitNodeConfig) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cfg = cfg
}

// EnableIPForwarding enables kernel IP forwarding on non-Linux platforms
// Uses /proc/sys for WSL/FreeBSD-compatible paths, or OS-native commands where needed.
func (m *NFTManager) EnableIPForwarding() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.cfg == nil || !m.cfg.Enable || !m.cfg.NATMasquerade {
		return nil
	}

	var errs []string
	// Try procfs-style sysctl (works on WSL, BSD)
	if err := osWriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0644); err != nil {
		errs = append(errs, fmt.Sprintf("ipv4: %v", err))
	}
	if err := osWriteFile("/proc/sys/net/ipv6/conf/all/forwarding", []byte("1"), 0644); err != nil {
		errs = append(errs, fmt.Sprintf("ipv6: %v", err))
	}

	if len(errs) > 0 {
		return fmt.Errorf("enable IP forwarding warnings: %s", strings.Join(errs, "; "))
	}
	return nil
}

// SetupExitNodeNAT reports that this platform has no NAT implementation.
//
// It used to be a silent no-op, which is worse than a failure: the node came
// up with exit_node.enable=true, reported itself as a working Exit Node, and
// forwarded nothing — no error, no log, no indication that the peer offering
// egress could not possibly deliver it. Returning an error makes
// applyExitNodeNAT log it and keeps the WebUI honest about a capability that
// does not exist here.
//
// Linux, Windows and macOS each have their own implementation; this file now
// only covers the remaining platforms (the BSDs, illumos, Android), where there
// is no NAT backend to drive.
func (m *NFTManager) SetupExitNodeNAT(p ExitNATParams) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cfg == nil || !m.cfg.Enable || !m.cfg.NATMasquerade {
		return nil
	}
	return natUnsupportedError(runtime.GOOS, "exit-node",
		"peers using this node as an Exit Node will get no connectivity")
}

// SetupSubnetRouterNAT reports that this platform has no NAT implementation,
// for the same reason as SetupExitNodeNAT.
func (m *NFTManager) SetupSubnetRouterNAT(tapIfName, tapIPv4, tapIPv6 string) error {
	return natUnsupportedError(runtime.GOOS, "subnet-router",
		"advertised subnets will not be reachable")
}

// CleanupExitNodeNAT is a no-op on non-Linux platforms.
func (m *NFTManager) CleanupExitNodeNAT() error {
	return nil
}

// CleanupSubnetRouterNAT is a no-op on non-Linux platforms.
func (m *NFTManager) CleanupSubnetRouterNAT() error {
	return nil
}

// CleanupAllNAT tears down both NAT rulesets; a no-op on non-Linux platforms.
func (m *NFTManager) CleanupAllNAT() error {
	return nil
}

func osWriteFile(path string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY, perm)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(data)
	return err
}
