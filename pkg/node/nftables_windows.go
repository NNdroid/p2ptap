//go:build windows

package node

import (
	"fmt"
	"os/exec"
	"sync"

	"p2ptap/pkg/config"
)

// winNatName is the WinNat instance this node owns. WinNat allows several
// instances as long as their internal prefixes do not overlap, so the name is
// fixed rather than generated: it makes teardown deterministic and keeps a
// crashed run from leaking an unnamed instance.
const winNatName = "p2ptap-exit"

// NFTManager owns the exit-node NAT instance on Windows.
//
// Windows has no masquerade chain to append to, so the whole job is delegated to
// WinNat (the NetNat module, the same mechanism Docker Desktop uses): it
// installs the NAT, enables forwarding for the internal prefix and handles the
// return path. Only IPv4 is supported — InternalIPInterfaceAddressPrefix has no
// IPv6 equivalent, so client IPv6 traffic through a Windows exit node will be
// dropped, and that is reported rather than hidden.
type NFTManager struct {
	mu  sync.Mutex
	cfg *config.ExitNodeConfig

	exitActive   bool
	subnetActive bool
	prefix       string // internal prefix currently claimed in WinNat
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

// EnableIPForwarding reports that forwarding is WinNat's responsibility here.
// It is not a no-op for the caller's benefit: WinNat refuses to install when the
// IP Helper stack cannot forward, and that surfaces as the setup error with its
// own message, so duplicating a forwarding toggle would add a second, conflicting
// source of truth.
func (m *NFTManager) EnableIPForwarding() error { return nil }

// SetupExitNodeNAT installs (or reinstalls) the WinNat instance for the TAP
// network.
func (m *NFTManager) SetupExitNodeNAT(p ExitNATParams) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.cfg == nil || !m.cfg.Enable || !m.cfg.NATMasquerade {
		return nil
	}
	prefix, ok := natPrefixV4(p.TapIPv4)
	if !ok {
		if p6, ok6 := natPrefixV6(p.TapIPv6); ok6 {
			return fmt.Errorf("exit-node NAT on Windows cannot use the IPv6 network %s: WinNat has no IPv6 internal prefix, so IPv6-only exit nodes are not possible here (run it on Linux or macOS); set tap_ip to an IPv4 network", p6)
		}
		return fmt.Errorf("exit-node NAT on Windows needs the TAP IPv4 network, but tap_ip is %q; WinNat keys on the internal prefix and cannot infer it from the interface name", p.TapIPv4)
	}
	// IPv6 is a real gap on this platform, not an oversight: report it instead
	// of installing IPv4-only NAT and letting the operator assume both families
	// work.
	if reason := natIPv6GapReason("exit-node", "WinNat", false, p.TapIPv6); reason != "" {
		natLog.Warn("%s", reason)
	}
	if err := m.installWinNat(prefix); err != nil {
		return err
	}
	m.exitActive = true
	return nil
}

// SetupSubnetRouterNAT installs a WinNat instance for the advertised-subnet
// case. On Windows it is the same NAT with a different owner, because both
// roles need "traffic entering from the TAP leaves with this host's address".
//
// tapIPv6 is accepted for symmetry with the other platforms and is reported
// when set, because WinNat genuinely cannot masquerade IPv6.
func (m *NFTManager) SetupSubnetRouterNAT(tapIfName, tapIPv4, tapIPv6 string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	prefix, ok := natPrefixV4(tapIPv4)
	if !ok {
		if p6, ok6 := natPrefixV6(tapIPv6); ok6 {
			return fmt.Errorf("subnet-router NAT on Windows cannot use the IPv6 network %s: WinNat has no IPv6 internal prefix, so advertised IPv6 subnets cannot be masqueraded here (run the subnet router on Linux or macOS); set tap_ip to an IPv4 network", p6)
		}
		return fmt.Errorf("subnet-router NAT on Windows needs the TAP IPv4 network, but tap_ip is %q", tapIPv4)
	}
	if reason := natIPv6GapReason("subnet-router", "WinNat", false, tapIPv6); reason != "" {
		natLog.Warn("%s", reason)
	}
	if err := m.installWinNat(prefix); err != nil {
		return err
	}
	m.subnetActive = true
	return nil
}

// installWinNat makes the named WinNat instance match prefix, replacing an
// instance whose prefix changed. It does not touch the role flags: the caller
// owns those, because the exit-node and subnet-router roles share one instance.
//
// The caller holds m.mu.
func (m *NFTManager) installWinNat(prefix string) error {
	if (m.exitActive || m.subnetActive) && m.prefix == prefix {
		return nil // already installed for exactly this prefix
	}
	if err := ensureNetNatAvailable(); err != nil {
		return err
	}
	// Remove first: WinNat rejects a second instance with the same name, and a
	// stale instance would silently keep NATing the previous prefix.
	if err := removeWinNat(); err != nil {
		return err
	}
	out, err := runPowerShell(
		"New-NetNat -Name " + powerShellQuote(winNatName) +
			" -InternalIPInterfaceAddressPrefix " + powerShellQuote(prefix))
	if err != nil {
		return fmt.Errorf("New-NetNat failed for prefix %s: %w: %s", prefix, err, firstLine(out))
	}
	m.prefix = prefix
	natLog.Info("Windows exit-node NAT installed via WinNat (name=%s, internal=%s, IPv4 only)", winNatName, prefix)
	return nil
}

// CleanupExitNodeNAT releases the exit-node role, tearing the instance down only
// once the subnet-router role no longer needs it either.
func (m *NFTManager) CleanupExitNodeNAT() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.exitActive {
		return nil
	}
	m.exitActive = false
	if m.subnetActive {
		return nil // the other role still uses this instance
	}
	return m.teardownWinNat()
}

// CleanupSubnetRouterNAT releases the subnet-router role, mirroring
// CleanupExitNodeNAT.
func (m *NFTManager) CleanupSubnetRouterNAT() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.subnetActive {
		return nil
	}
	m.subnetActive = false
	if m.exitActive {
		return nil
	}
	return m.teardownWinNat()
}

// teardownWinNat removes the instance and forgets the prefix.
func (m *NFTManager) teardownWinNat() error {
	err := removeWinNat()
	m.prefix = ""
	if err != nil {
		return err
	}
	natLog.Info("Windows exit-node NAT removed (WinNat %s)", winNatName)
	return nil
}

func (m *NFTManager) CleanupAllNAT() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.exitActive && !m.subnetActive {
		return nil
	}
	m.exitActive = false
	m.subnetActive = false
	return m.teardownWinNat()
}

// ensureNetNatAvailable fails with an actionable message when the NetNat module
// is missing, instead of letting a bare "command not recognized" bubble up.
func ensureNetNatAvailable() error {
	if _, err := exec.LookPath("powershell.exe"); err != nil {
		return fmt.Errorf("exit-node NAT on Windows needs powershell.exe, which is not on PATH: %w", err)
	}
	if _, err := runPowerShell("Get-Command New-NetNat -ErrorAction Stop"); err != nil {
		return fmt.Errorf("the NetNat PowerShell module is not available, so Windows cannot provide exit-node NAT on this machine (it ships with Windows 10/11 and Windows Server 2016+); run the Exit Node on Linux instead")
	}
	return nil
}

// removeWinNat deletes the instance if it exists. A missing instance is the
// normal case on a first run, so it is not an error.
func removeWinNat() error {
	out, err := runPowerShell(
		"if (Get-NetNat -Name " + powerShellQuote(winNatName) +
			" -ErrorAction SilentlyContinue) { Remove-NetNat -Name " + powerShellQuote(winNatName) + " -Confirm:$false }")
	if err != nil {
		return fmt.Errorf("Remove-NetNat failed: %w: %s", err, firstLine(out))
	}
	return nil
}

// runPowerShell executes a script and returns its combined output. -NoProfile
// and -NonInteractive keep a user's profile from changing the result or a prompt
// from hanging the node; -ExecutionPolicy Bypass is required on hosts whose
// policy forbids unsigned scripts, which would otherwise refuse even an inline
// command.
func runPowerShell(script string) (string, error) {
	cmd := exec.Command("powershell.exe",
		"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script)
	out, err := cmd.CombinedOutput()
	return string(out), err
}
