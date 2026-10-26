//go:build linux && !android
// +build linux,!android

package node

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"sync"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"

	"p2ptap/pkg/config"
	"p2ptap/pkg/logger"
)

var nftLog = logger.New("NFTables")

type NFTManager struct {
	mu  sync.Mutex
	cfg *config.ExitNodeConfig

	// exitActive and subnetActive are tracked separately: the two rulesets use
	// different tables and different lifecycles. A single shared flag used to
	// make CleanupExitNodeNAT flip active=false on a subnet-router node while
	// leaving p2ptap_subnet_nat installed forever.
	exitActive   bool
	subnetActive bool

	tapIf string // TAP iface name, captured at setup for MSS-clamp cleanup
	mss   int    // configured MSS clamp, 0 = disabled
}

func NewNFTManager(cfg *config.ExitNodeConfig) *NFTManager {
	return &NFTManager{
		cfg: cfg,
	}
}

// UpdateConfig replaces the live config pointer (used after hot-reload)
func (m *NFTManager) UpdateConfig(cfg *config.ExitNodeConfig) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cfg = cfg
}

// EnableIPForwarding enables kernel IPv4 and IPv6 forwarding via procfs.
// IPv6 forwarding must also be on for the Exit Node to route client IPv6
// traffic; a failure here is fatal because without forwarding the Exit Node
// would silently blackhole all client traffic.
func (m *NFTManager) EnableIPForwarding() error {
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0644); err != nil {
		return fmt.Errorf("enable IPv4 forwarding: %w", err)
	}
	if err := os.WriteFile("/proc/sys/net/ipv6/conf/all/forwarding", []byte("1"), 0644); err != nil {
		return fmt.Errorf("enable IPv6 forwarding: %w", err)
	}
	return nil
}

// buildNATTable installs a single postrouting masquerade chain for the given
// address family. Traffic is matched by outgoing interface (WAN) and, when a
// TAP name is supplied, restricted to traffic that entered via the TAP, so
// only client tunnel traffic is masqueraded.
func (m *NFTManager) buildNATTable(c *nftables.Conn, family nftables.TableFamily, tableName, wanIfName, tapIfName string) error {
	table := c.AddTable(&nftables.Table{Family: family, Name: tableName})
	postrouteChain := c.AddChain(&nftables.Chain{
		Name:     "postrouting",
		Table:    table,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPostrouting,
		Priority: nftables.ChainPriorityNATSource,
	})

	exprs := []expr.Any{}
	if tapIfName != "" {
		exprs = append(exprs,
			&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte(tapIfName + "\x00"),
			},
		)
	}
	if wanIfName != "" && wanIfName != "auto" {
		exprs = append(exprs,
			&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte(wanIfName + "\x00"),
			},
		)
	}
	exprs = append(exprs, &expr.Masq{})

	c.AddRule(&nftables.Rule{
		Table: table,
		Chain: postrouteChain,
		Exprs: exprs,
	})
	return nil
}

// SetupExitNodeNAT adds nftables masquerade NAT rules if enabled in config.
// Both IPv4 and IPv6 tables are installed so the Exit Node can masquerade
// client traffic of either family (the Windows client already installs IPv6
// split default routes, so the server must be ready for it).
func (m *NFTManager) SetupExitNodeNAT(wanIfName, tapIfName string, mss int) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.cfg.Enable || !m.cfg.NATMasquerade {
		nftLog.Debug("Exit Node NAT masquerade disabled in config")
		return nil
	}

	// Fatal if forwarding cannot be enabled: the Exit Node would otherwise
	// silently blackhole all client traffic. Writing /proc/sys requires root,
	// so this is exactly how an unprivileged exit node fails — log it loudly
	// rather than letting the caller's error-handling decide whether it is seen.
	if err := m.EnableIPForwarding(); err != nil {
		nftLog.Error("FATAL: IP forwarding enable failed: %v — Exit Node NAT is installed but cannot forward, so all client traffic will be blackholed", err)
		return fmt.Errorf("IP forwarding enable failed: %w", err)
	}

	// Re-install, never append. The kernel accepts a second "add chain" for an
	// existing chain, and every later "add rule" APPENDS a duplicate MASQ rule
	// (verified on kernel 6.12: two identical rules after one re-run). Each WebUI
	// config save, exit-node toggle, or service restart would otherwise add
	// another copy, and changing exit_node.wan_interface would leave the old
	// interface's rule alive forever still masquerading its traffic. Tearing the
	// tables down first also clears the MSS clamp that lives in the same chain,
	// so a changed MTU cannot accumulate stale clamps either.
	m.removeNFTTables(
		&nftables.Table{Family: nftables.TableFamilyIPv4, Name: "p2ptap_nat"},
		&nftables.Table{Family: nftables.TableFamilyIPv6, Name: "p2ptap_nat6"},
	)
	// The iptables fallback clamp lives outside the nft tables, so remove the
	// previous value explicitly when the clamp amount changed.
	if m.tapIf != "" && m.mss > 0 && m.mss != mss {
		m.removeMSSClampIPTables("ip", m.tapIf, m.mss)
		m.removeMSSClampIPTables("ip6", m.tapIf, m.mss)
	}

	c, err := nftables.New()
	if err != nil {
		return fmt.Errorf("nftables connect error: %w", err)
	}

	if err := m.buildNATTable(c, nftables.TableFamilyIPv4, "p2ptap_nat", wanIfName, tapIfName); err != nil {
		return err
	}
	if err := m.buildNATTable(c, nftables.TableFamilyIPv6, "p2ptap_nat6", wanIfName, tapIfName); err != nil {
		return err
	}

	if err := c.Flush(); err != nil {
		// Permission failures here (no CAP_NET_ADMIN) are as fatal as the
		// forwarding failure above: NAT rules partially installed with no
		// matching kernel capability blackhole client traffic.
		nftLog.Error("FATAL: nftables flush failed: %v — Exit Node NAT could not be installed, client traffic will be blackholed", err)
		return fmt.Errorf("nftables flush rules error: %w", err)
	}

	// #1: clamp the TCP MSS advertised by client tunnel sessions so large
	// segments fit the (reduced) tunnel path MTU instead of being fragmented or
	// blackholed. This is the key fix for the slow web-browsing / data-exchange
	// observed on an Exit Node *client* doing global routing. The TAP MTU itself
	// is left untouched (see #2 / computeExitMSS).
	m.tapIf = tapIfName
	m.mss = mss
	if mss > 0 {
		m.addMSSClamp("ip", "p2ptap_nat", tapIfName, mss)
		m.addMSSClamp("ip6", "p2ptap_nat6", tapIfName, mss)
	}

	m.exitActive = true
	nftLog.Info("Successfully configured Exit Node NAT masquerade via nftables (wan=%s, tap=%s, families=v4+v6, mss-clamp=%d)", wanIfName, tapIfName, mss)
	return nil
}

// SetupSubnetRouterNAT configures IP forwarding and postrouting masquerade for nodes
// that advertise LAN subnets to mesh peers, so incoming subnet packets are forwarded
// and replied to correctly by local LAN devices.
func (m *NFTManager) SetupSubnetRouterNAT(tapIfName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if err := m.EnableIPForwarding(); err != nil {
		nftLog.Error("FATAL: IP forwarding enable failed for subnet router: %v — advertised subnets will be blackholed", err)
		return fmt.Errorf("IP forwarding enable failed for subnet router: %w", err)
	}

	// Re-install rather than append, same reason as SetupExitNodeNAT: a re-run
	// otherwise appends duplicate MASQ rules to the same chain.
	m.removeNFTTables(
		&nftables.Table{Family: nftables.TableFamilyIPv4, Name: "p2ptap_subnet_nat"},
		&nftables.Table{Family: nftables.TableFamilyIPv6, Name: "p2ptap_subnet_nat6"},
	)

	c, err := nftables.New()
	if err != nil {
		return fmt.Errorf("nftables connect error: %w", err)
	}

	if err := m.buildNATTable(c, nftables.TableFamilyIPv4, "p2ptap_subnet_nat", "", tapIfName); err != nil {
		return err
	}
	if err := m.buildNATTable(c, nftables.TableFamilyIPv6, "p2ptap_subnet_nat6", "", tapIfName); err != nil {
		return err
	}

	if err := c.Flush(); err != nil {
		nftLog.Error("FATAL: nftables flush failed for subnet router: %v — advertised subnets will be blackholed", err)
		return fmt.Errorf("nftables flush rules error: %w", err)
	}

	m.subnetActive = true
	nftLog.Info("Successfully configured Subnet Router NAT masquerade via nftables (tap=%s, families=v4+v6)", tapIfName)
	return nil
}

// addMSSClamp installs a TCP MSS clamp scoped to client traffic entering via the
// TAP interface, so tunneled TCP sessions negotiate a segment size that fits the
// (reduced) tunnel path MTU instead of being fragmented or blackholed.
//
// Compatibility: the preferred mechanism is the nftables TCPOPT set expression,
// but some kernels (notably minimal/OpenWrt builds) return EOPNOTSUPP for it. In
// that case we transparently fall back to the iptables/ip6tables TCPMSS target,
// which is supported far more widely. The clamp is best-effort: if neither
// mechanism is available we degrade to a Debug log rather than a warning, because
// the Exit Node still routes client traffic via masquerade.
func (m *NFTManager) addMSSClamp(family, tableName, tapIfName string, mss int) {
	if tapIfName == "" || mss <= 0 {
		return
	}
	if m.addMSSClampNFT(family, tableName, tapIfName, mss) {
		return
	}
	if m.addMSSClampIPTables(family, tapIfName, mss) {
		nftLog.Info("added TCP MSS clamp (mss=%d) on %s via iptables TCPMSS fallback (tap=%s)", mss, family, tapIfName)
		return
	}
	nftLog.Debug("TCP MSS clamp (mss=%d) unavailable on %s (nft + iptables both unsupported by kernel); skipping (best-effort optimization)", mss, family)
}

// addMSSClampNFT installs the clamp via the nft CLI. google/nftables v0.3.0
// lacks a TCPOPT set expression, so we shell out. The rule is added
// idempotently (skipped if an identical clamp already exists). Returns false if
// the kernel does not support the expression, so the caller can fall back to
// iptables.
func (m *NFTManager) addMSSClampNFT(family, tableName, tapIfName string, mss int) bool {
	probe := fmt.Sprintf("nft list chain %s %s postrouting 2>/dev/null | grep -q 'maxseg set %d'", family, tableName, mss)
	if out, err := exec.Command("sh", "-c", probe).CombinedOutput(); err == nil && len(out) == 0 {
		nftLog.Debug("MSS clamp (mss=%d) already present on %s/%s", mss, family, tableName)
		return true
	}
	// Run nft directly (NOT via `sh -c`). The rule contains shell metacharacters
	// (&, (), |) that the shell would otherwise interpret as syntax — `(syn|rst)`
	// would be parsed as a subshell pipeline and fail with "Syntax error: word
	// unexpected", leaving the clamp never installed. Passing the rule as discrete
	// argv tokens hands those characters to nft literally.
	args := []string{"add", "rule", family, tableName, "postrouting",
		"iifname", tapIfName,
		"tcp", "flags", "&", "(syn|rst)", "!=", "0",
		"tcp", "option", "maxseg", "set", strconv.Itoa(mss),
	}
	if _, err := exec.Command("nft", args...).CombinedOutput(); err != nil {
		nftLog.Debug("nft MSS clamp (mss=%d) on %s/%s unsupported by kernel: %v", mss, family, tableName, err)
		return false
	}
	nftLog.Info("added TCP MSS clamp (mss=%d) on %s/%s postrouting (tap=%s)", mss, family, tableName, tapIfName)
	return true
}

// addMSSClampIPTables installs the clamp via the iptables/ip6tables TCPMSS
// target — the widely-supported fallback for kernels lacking the nft TCPOPT
// expression. It is scoped identically to the nft variant: forwarded (FORWARD
// chain) TCP SYN/RST packets that entered via the TAP interface. Idempotent via
// a -C existence check.
func (m *NFTManager) addMSSClampIPTables(family, tapIfName string, mss int) bool {
	bin := "iptables"
	if family == "ip6" {
		bin = "ip6tables"
	}
	args := []string{"-t", "mangle", "-C", "FORWARD", "-i", tapIfName,
		"-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
		"-j", "TCPMSS", "--set-mss", strconv.Itoa(mss)}
	if _, err := exec.Command(bin, args...).CombinedOutput(); err == nil {
		nftLog.Debug("%s TCPMSS clamp (mss=%d) already present (tap=%s)", bin, mss, tapIfName)
		return true
	}
	args[2] = "-A" // switch -C (check) to -A (append)
	if _, err := exec.Command(bin, args...).CombinedOutput(); err != nil {
		nftLog.Debug("%s TCPMSS clamp (mss=%d) unsupported by kernel: %v", bin, mss, err)
		return false
	}
	return true
}

// removeMSSClampIPTables best-effort removes the iptables fallback clamp
// installed by addMSSClampIPTables. No-op if it was never installed (e.g. the
// nft path succeeded, or the kernel supported neither).
func (m *NFTManager) removeMSSClampIPTables(family, tapIfName string, mss int) {
	if tapIfName == "" || mss <= 0 {
		return
	}
	bin := "iptables"
	if family == "ip6" {
		bin = "ip6tables"
	}
	args := []string{"-t", "mangle", "-D", "FORWARD", "-i", tapIfName,
		"-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
		"-j", "TCPMSS", "--set-mss", strconv.Itoa(mss)}
	// -D removes the first matching rule; ignore errors (rule may not exist).
	_ = exec.Command(bin, args...).Run()
}

// removeNFTTables deletes the named tables, ignoring ones that do not exist.
// nftables exposes no "delete if exists" form, so the Flush error is
// deliberately unclassified: a non-existent table is the normal case on a
// first run, and a genuine failure (missing CAP_NET_ADMIN) resurfaces on the
// very next add batch, which does surface its error.
func (m *NFTManager) removeNFTTables(tables ...*nftables.Table) {
	c, err := nftables.New()
	if err != nil {
		nftLog.Warn("nftables connect failed while removing NAT tables: %v", err)
		return
	}
	for _, t := range tables {
		c.DelTable(t)
	}
	if err := c.Flush(); err != nil {
		nftLog.Debug("stale NAT table removal: %v", err)
	}
}

// CleanupExitNodeNAT removes both v4 and v6 exit-node NAT tables plus the
// iptables TCPMSS fallback clamp.
func (m *NFTManager) CleanupExitNodeNAT() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.exitActive {
		return nil
	}

	m.removeNFTTables(
		&nftables.Table{Family: nftables.TableFamilyIPv4, Name: "p2ptap_nat"},
		&nftables.Table{Family: nftables.TableFamilyIPv6, Name: "p2ptap_nat6"},
	)
	m.exitActive = false
	// Best-effort removal of the iptables TCPMSS fallback clamp (only present
	// when the kernel lacked the nft TCPOPT expression).
	m.removeMSSClampIPTables("ip", m.tapIf, m.mss)
	m.removeMSSClampIPTables("ip6", m.tapIf, m.mss)
	nftLog.Info("Cleared Exit Node nftables NAT rules")
	return nil
}

// CleanupSubnetRouterNAT removes the subnet-router NAT tables. It used to be
// unreachable: CleanupExitNodeNAT deleted only the exit-node tables while
// sharing the same active flag, so a subnet router whose advertised subnets
// were removed left p2ptap_subnet_nat installed until the host rebooted.
func (m *NFTManager) CleanupSubnetRouterNAT() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.subnetActive {
		return nil
	}

	m.removeNFTTables(
		&nftables.Table{Family: nftables.TableFamilyIPv4, Name: "p2ptap_subnet_nat"},
		&nftables.Table{Family: nftables.TableFamilyIPv6, Name: "p2ptap_subnet_nat6"},
	)
	m.subnetActive = false
	nftLog.Info("Cleared Subnet Router nftables NAT rules")
	return nil
}

// CleanupAllNAT tears down both rulesets. Called on node shutdown so a
// restarting exit node does not accumulate a fresh copy of every rule on each
// start (SetupExitNodeNAT now self-cleans, but an explicit teardown also
// covers a node that was decommissioned between runs).
func (m *NFTManager) CleanupAllNAT() error {
	if err := m.CleanupExitNodeNAT(); err != nil {
		return err
	}
	return m.CleanupSubnetRouterNAT()
}
