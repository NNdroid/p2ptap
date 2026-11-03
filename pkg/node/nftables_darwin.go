//go:build darwin

package node

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"

	"p2ptap/pkg/config"
)

// pfConfPath is the main pf ruleset. Our anchor only runs when this file
// references it, which is why Setup rewrites it when the line is missing.
const pfConfPath = "/etc/pf.conf"

// NFTManager owns exit-node NAT on macOS through pf.
//
// pf has no masquerade chain to append to either: an anchor holds the nat rules,
// and the anchor has to be referenced from /etc/pf.conf as a nat-anchor or pf
// silently ignores it. IPv6 is supported (pf handles inet6 nat natively), but
// only for the source prefixes derived from the configured TAP addresses.
type NFTManager struct {
	mu  sync.Mutex
	cfg *config.ExitNodeConfig

	exitActive   bool
	subnetActive bool
	wanIface     string
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

// EnableIPForwarding turns on kernel forwarding. IPv4 is required; IPv6 is best
// effort, matching the Linux implementation's rule that a missing or broken
// IPv6 stack must never take IPv4 down with it.
func (m *NFTManager) EnableIPForwarding() error {
	if out, err := exec.Command("/usr/sbin/sysctl", "-w", "net.inet.ip.forwarding=1").CombinedOutput(); err != nil {
		return fmt.Errorf("enable IPv4 forwarding: %w: %s", err, firstLine(string(out)))
	}
	if out, err := exec.Command("/usr/sbin/sysctl", "-w", "net.inet6.ip6.forwarding=1").CombinedOutput(); err != nil {
		natLog.Warn("IPv6 forwarding could not be enabled (%v: %s) — Exit Node will forward IPv4 only", err, firstLine(string(out)))
	}
	return nil
}

// SetupExitNodeNAT loads the pf anchor that masquerades tunnel traffic.
func (m *NFTManager) SetupExitNodeNAT(p ExitNATParams) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.cfg == nil || !m.cfg.Enable || !m.cfg.NATMasquerade {
		return nil
	}
	wanIface, err := m.resolveWANIface(p.WANInterface)
	if err != nil {
		return err
	}
	rules := pfNatAnchor(wanIface, p.TapIPv4, p.TapIPv6)
	if len(rules) == 0 {
		return fmt.Errorf("exit-node NAT on macOS needs a TAP IPv4 or IPv6 network, but tap_ip=%q tap_ipv6=%q", p.TapIPv4, p.TapIPv6)
	}
	// pf can carry both families, so a gap here always means the configured
	// value is unusable rather than the platform lacking IPv6. Say so: silently
	// loading an inet-only anchor makes the host look IPv6-ready.
	if reason := natIPv6GapReason("exit-node", "pf", true, p.TapIPv6); reason != "" {
		natLog.Warn("%s", reason)
	}
	if err := m.EnableIPForwarding(); err != nil {
		return err
	}
	if err := m.loadAnchor(rules); err != nil {
		return err
	}
	m.exitActive = true
	m.wanIface = wanIface
	natLog.Info("macOS exit-node NAT installed via pf anchor %q (wan=%s, rules=%d)", pfAnchor, wanIface, len(rules))
	return nil
}

// SetupSubnetRouterNAT loads the same anchor for the advertised-subnet role. The
// rules are identical because both roles masquerade traffic arriving from the
// TAP; only the reason the traffic exists differs.
//
// It takes both TAP networks, not just IPv4: pf handles inet and inet6 natively,
// so an advertised IPv6 subnet is equally routable, and dropping the IPv6
// argument here would have made this platform silently IPv4-only.
func (m *NFTManager) SetupSubnetRouterNAT(tapIfName, tapIPv4, tapIPv6 string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// The subnet router has no WAN preference of its own: it forwards towards
	// whatever the host routes to, so the default-route interface is correct.
	wanIface, err := m.resolveWANIface("auto")
	if err != nil {
		return err
	}
	rules := pfNatAnchor(wanIface, tapIPv4, tapIPv6)
	if len(rules) == 0 {
		return fmt.Errorf("subnet-router NAT on macOS needs a TAP IPv4 or IPv6 network, but tap_ip=%q tap_ipv6=%q", tapIPv4, tapIPv6)
	}
	if reason := natIPv6GapReason("subnet-router", "pf", true, tapIPv6); reason != "" {
		natLog.Warn("%s", reason)
	}
	if err := m.EnableIPForwarding(); err != nil {
		return err
	}
	if err := m.loadAnchor(rules); err != nil {
		return err
	}
	m.subnetActive = true
	m.wanIface = wanIface
	natLog.Info("macOS subnet-router NAT installed via pf anchor %q (wan=%s, rules=%d)", pfAnchor, wanIface, len(rules))
	return nil
}

// CleanupExitNodeNAT releases the exit-node role, flushing the anchor only once
// the subnet-router role no longer needs it either.
func (m *NFTManager) CleanupExitNodeNAT() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.exitActive {
		return nil
	}
	m.exitActive = false
	if m.subnetActive {
		return nil // the other role still uses this anchor
	}
	return m.teardownAnchor()
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
	return m.teardownAnchor()
}

// teardownAnchor flushes the anchor.
func (m *NFTManager) teardownAnchor() error {
	if err := m.flushAnchor(); err != nil {
		return err
	}
	m.wanIface = ""
	natLog.Info("macOS exit-node NAT removed (pf anchor %q)", pfAnchor)
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
	return m.teardownAnchor()
}

// resolveWANIface turns the configured value into a concrete interface name.
// "auto" (and empty) mean the default route's interface, because pf cannot
// express "the interface holding the default route" in a rule.
func (m *NFTManager) resolveWANIface(configured string) (string, error) {
	iface := strings.TrimSpace(configured)
	if iface != "" && iface != "auto" {
		return iface, nil
	}
	out, err := exec.Command("/sbin/route", "-n", "get", "default").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("could not determine the default-route interface (set exit_node.wan_interface explicitly): %w: %s", err, firstLine(string(out)))
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "interface:") {
			if iface := strings.TrimSpace(strings.TrimPrefix(line, "interface:")); iface != "" {
				return iface, nil
			}
		}
	}
	return "", fmt.Errorf("could not parse an interface from the default route; set exit_node.wan_interface explicitly")
}

// loadAnchor writes the rules to a file and loads them into our anchor, then
// makes sure pf.conf references it and pf is enabled.
func (m *NFTManager) loadAnchor(rules []string) error {
	body := strings.Join(rules, "\n") + "\n"
	if err := os.WriteFile(m.anchorPath(), []byte(body), 0o644); err != nil {
		return fmt.Errorf("write pf anchor %s: %w (the Exit Node needs root to manage pf)", m.anchorPath(), err)
	}
	if out, err := exec.Command("/sbin/pfctl", "-a", pfAnchor, "-f", m.anchorPath()).CombinedOutput(); err != nil {
		return fmt.Errorf("load pf anchor %q: %w: %s", pfAnchor, err, firstLine(string(out)))
	}
	if err := m.ensurePfConfAnchor(); err != nil {
		return err
	}
	// A disabled pf ignores every rule silently, which looks exactly like a
	// broken exit node, so enable it.
	if out, err := exec.Command("/sbin/pfctl", "-e").CombinedOutput(); err != nil {
		// "pf already enabled" is reported as an error on stderr; that is fine.
		if !strings.Contains(string(out), "already enabled") {
			natLog.Debug("pfctl -e: %v: %s", err, firstLine(string(out)))
		}
	}
	return nil
}

// flushAnchor unloads our rules. pf.conf keeps the reference: removing it would
// mean rewriting a system file on every teardown, and an anchor with no rules is
// harmless.
func (m *NFTManager) flushAnchor() error {
	if out, err := exec.Command("/sbin/pfctl", "-a", pfAnchor, "-F", "all").CombinedOutput(); err != nil {
		return fmt.Errorf("flush pf anchor %q: %w: %s", pfAnchor, err, firstLine(string(out)))
	}
	return nil
}

// ensurePfConfAnchor adds our nat-anchor reference to /etc/pf.conf if it is
// missing. Without it pf loads the anchor and never evaluates it — the exact
// "configured but forwarding nothing" failure this whole change is about.
func (m *NFTManager) ensurePfConfAnchor() error {
	conf, err := os.ReadFile(pfConfPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", pfConfPath, err)
	}
	if pfConfHasAnchor(string(conf), pfAnchor) {
		return nil
	}
	updated := pfConfWithAnchor(string(conf), pfAnchor)
	if err := os.WriteFile(pfConfPath, []byte(updated), 0o644); err != nil {
		return fmt.Errorf("add %q to %s: %w (add this line manually: nat-anchor \"%s\")", pfAnchor, pfConfPath, err, pfAnchor)
	}
	// Reload the main ruleset so the new reference takes effect. The anchor
	// itself stays loaded: an anchor survives a ruleset reload.
	if out, err := exec.Command("/sbin/pfctl", "-f", pfConfPath).CombinedOutput(); err != nil {
		return fmt.Errorf("reload %s after adding the anchor: %w: %s", pfConfPath, err, firstLine(string(out)))
	}
	natLog.Info("added nat-anchor %q to %s", pfAnchor, pfConfPath)
	return nil
}

// anchorPath is where the rule file lives. /etc/pf.anchors is the conventional
// location and is readable by an operator debugging a live node.
func (m *NFTManager) anchorPath() string { return "/etc/pf.anchors/" + pfAnchor }
