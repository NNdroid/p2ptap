//go:build !linux

package node

import (
	"fmt"
	"os"
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

// SetupExitNodeNAT is a no-op on non-Linux platforms.
// On Windows the user should configure ICS or routing manually.
// On macOS the user should enable Internet Sharing or configure pf.
func (m *NFTManager) SetupExitNodeNAT(wanIfName, tapIfName string, mss int) error {
	return nil
}

// CleanupExitNodeNAT is a no-op on non-Linux platforms.
func (m *NFTManager) CleanupExitNodeNAT() error {
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
