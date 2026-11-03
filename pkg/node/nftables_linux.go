//go:build linux && !android
// +build linux,!android

package node

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"

	"p2ptap/pkg/config"
)

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

	// Last failure detail from each MSS-clamp attempt, retained so the
	// addMSSClamp Warn can name the concrete cause of both paths at once.
	// Both are per-family, so the final family processed wins in the log line.
	mssClampNFTFail string
	mssClampIPTFail string
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
// traffic; a failure there degrades to IPv4-only and is reported, but it must
// not abort the whole setup.
func (m *NFTManager) EnableIPForwarding() error {
	// IPv4 is the primary path, and a failure is fatal: without it the Exit
	// Node would silently blackhole every client packet.
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0644); err != nil {
		return fmt.Errorf("enable IPv4 forwarding: %w", err)
	}
	if err := os.WriteFile("/proc/sys/net/ipv6/conf/all/forwarding", []byte("1"), 0644); err != nil {
		// Degrading, not fatal. A host with IPv6 compiled out (ipv6.disable=1)
		// or with /proc/sys/net/ipv6 not mounted simply cannot accept this
		// write, and failing here used to take IPv4 down with it: the exit node
		// came up with no NAT at all because of an address family the operator
		// was not using. IPv6 clients would then be blackholed silently, so it
		// is logged at Warn rather than Debug.
		natLog.Warn("IPv6 forwarding could not be enabled (%v) — Exit Node will forward IPv4 only; client IPv6 traffic will be blackholed", err)
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

	// Masquerade only rewrites the source address on the way out; the packet
	// still has to survive the netfilter FORWARD hook, and a host whose
	// FORWARD policy is DROP swallows every tunneled byte while this NAT table
	// looks perfectly installed. DROP is the default on any host running
	// Docker (it sets "-P FORWARD DROP") and on ufw/firewalld defaults, so the
	// exit node used to report "active", install NAT, and forward nothing.
	// Installing the accept chain here fixes the whole class: the rules match
	// only traffic that entered through our own TAP plus its return path, and
	// fall through with no verdict for everything else.
	m.buildForwardAcceptChain(c, table, tapIfName)
	return nil
}

// exitForwardPriority places the accept chain ahead of every conventional
// filter chain (filter is priority 0, and that is where iptables' filter table,
// Docker's DOCKER-USER/FORWARD jump and firewalld's chains live). Lower runs
// first and an accept verdict is final, so ours wins over a host policy of
// DROP while anything we do not match falls through untouched. It must stay
// after conntrack (-200) or the state test would have nothing to read.
const exitForwardPriority nftables.ChainPriority = -10

// buildForwardAcceptChain installs the platform-neutral forwardAcceptRules as
// a single filter chain. No rule carries a drop verdict: the chain ends by
// falling through to whatever the host already had.
func (m *NFTManager) buildForwardAcceptChain(c *nftables.Conn, table *nftables.Table, tapIfName string) {
	rules := forwardAcceptRules(tapIfName)
	if len(rules) == 0 {
		return
	}
	chain := c.AddChain(&nftables.Chain{
		Name:     "forward",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookForward,
		Priority: nftables.ChainPriorityRef(exitForwardPriority),
	})
	for _, r := range rules {
		exprs := []expr.Any{}
		if r.Dir == forwardIn {
			exprs = append(exprs,
				&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte(r.Iface + "\x00")},
			)
		} else {
			exprs = append(exprs,
				&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte(r.Iface + "\x00")},
			)
		}
		if r.Established {
			// nft "ct state established,related": mask the state word and
			// require any bit to be set.
			exprs = append(exprs,
				&expr.Ct{Register: 1, Key: expr.CtKeySTATE},
				&expr.Bitwise{
					SourceRegister: 1,
					DestRegister:   1,
					Len:            4,
					Mask: binaryutil.NativeEndian.PutUint32(
						expr.CtStateBitESTABLISHED | expr.CtStateBitRELATED),
					Xor: binaryutil.NativeEndian.PutUint32(0),
				},
				&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: []byte{0, 0, 0, 0}},
			)
		}
		// The verdict stays last: expressions evaluate in order, so an accept
		// placed any earlier would skip the matches that follow it.
		exprs = append(exprs, &expr.Verdict{Kind: expr.VerdictAccept})
		c.AddRule(&nftables.Rule{Table: table, Chain: chain, Exprs: exprs})
	}
}

// SetupExitNodeNAT adds nftables masquerade NAT rules if enabled in config.
// Both IPv4 and IPv6 tables are installed so the Exit Node can masquerade
// client traffic of either family. Linux matches by interface name and lets the
// kernel pick the source address, so p.TapIPv4/TapIPv6 are unused here (the
// Windows and macOS implementations need them).
func (m *NFTManager) SetupExitNodeNAT(p ExitNATParams) error {
	wanIfName, tapIfName, mss := p.WANInterface, p.TapName, p.MSS
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.cfg.Enable || !m.cfg.NATMasquerade {
		natLog.Debug("Exit Node NAT masquerade disabled in config")
		return nil
	}

	// Fatal if forwarding cannot be enabled: the Exit Node would otherwise
	// silently blackhole all client traffic. Writing /proc/sys requires root,
	// so this is exactly how an unprivileged exit node fails — log it loudly
	// rather than letting the caller's error-handling decide whether it is seen.
	if err := m.EnableIPForwarding(); err != nil {
		natLog.Error("FATAL: IP forwarding enable failed: %v — Exit Node NAT is installed but cannot forward, so all client traffic will be blackholed", err)
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

	// One transaction per address family, and that is deliberate: a kernel with
	// IPv6 compiled out (ipv6.disable=1) rejects the "table ip6" outright, and a
	// single shared transaction would fail as a whole — taking IPv4 down with
	// it. A host that does not use IPv6 must not lose IPv4 egress because of it.
	if err := m.flushNATFamily(nftables.TableFamilyIPv4, "p2ptap_nat", wanIfName, tapIfName); err != nil {
		// Permission failures here (no CAP_NET_ADMIN) are as fatal as the
		// forwarding failure above: NAT rules partially installed with no
		// matching kernel capability blackhole client traffic.
		natLog.Error("FATAL: nftables flush failed: %v — Exit Node NAT could not be installed, client traffic will be blackholed", err)
		return fmt.Errorf("nftables flush rules error: %w", err)
	}
	v6OK := true
	if err := m.flushNATFamily(nftables.TableFamilyIPv6, "p2ptap_nat6", wanIfName, tapIfName); err != nil {
		v6OK = false
		natLog.Warn("IPv6 NAT table could not be installed (%v) — Exit Node will forward IPv4 only; client IPv6 traffic will be blackholed", err)
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
		if v6OK {
			m.addMSSClamp("ip6", "p2ptap_nat6", tapIfName, mss)
		}
	}

	m.exitActive = true
	families := "v4"
	if v6OK {
		families = "v4+v6"
	}
	natLog.Info("Successfully configured Exit Node NAT masquerade via nftables (wan=%s, tap=%s, families=%s, forward-accept=on, mss-clamp=%d)", wanIfName, tapIfName, families, mss)
	return nil
}

// flushNATFamily installs one family's masquerade chain and forward-accept
// chain in its own netlink transaction.
func (m *NFTManager) flushNATFamily(family nftables.TableFamily, tableName, wanIfName, tapIfName string) error {
	c, err := nftables.New()
	if err != nil {
		return fmt.Errorf("nftables connect error: %w", err)
	}
	if err := m.buildNATTable(c, family, tableName, wanIfName, tapIfName); err != nil {
		return err
	}
	return c.Flush()
}

// SetupSubnetRouterNAT configures IP forwarding and postrouting masquerade for nodes
// that advertise LAN subnets to mesh peers, so incoming subnet packets are forwarded
// and replied to correctly by local LAN devices.
//
// tapIPv4/tapIPv6 are unused on Linux, and deliberately so rather than for
// symmetry alone: this implementation matches by interface name (iifname), so a
// single pair of tables covers every source prefix that can arrive on the TAP,
// v4 and v6 alike. The parameters exist for the platforms that must key NAT on a
// prefix (WinNat, pf), and Linux must ignore them instead of narrowing its rules
// to whatever happens to be configured today.
func (m *NFTManager) SetupSubnetRouterNAT(tapIfName, tapIPv4, tapIPv6 string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if err := m.EnableIPForwarding(); err != nil {
		natLog.Error("FATAL: IP forwarding enable failed for subnet router: %v — advertised subnets will be blackholed", err)
		return fmt.Errorf("IP forwarding enable failed for subnet router: %w", err)
	}

	// Re-install rather than append, same reason as SetupExitNodeNAT: a re-run
	// otherwise appends duplicate MASQ rules to the same chain.
	m.removeNFTTables(
		&nftables.Table{Family: nftables.TableFamilyIPv4, Name: "p2ptap_subnet_nat"},
		&nftables.Table{Family: nftables.TableFamilyIPv6, Name: "p2ptap_subnet_nat6"},
	)

	if err := m.flushNATFamily(nftables.TableFamilyIPv4, "p2ptap_subnet_nat", "", tapIfName); err != nil {
		natLog.Error("FATAL: nftables flush failed for subnet router: %v — advertised subnets will be blackholed", err)
		return fmt.Errorf("nftables flush rules error: %w", err)
	}
	v6OK := true
	if err := m.flushNATFamily(nftables.TableFamilyIPv6, "p2ptap_subnet_nat6", "", tapIfName); err != nil {
		v6OK = false
		natLog.Warn("IPv6 NAT table could not be installed for subnet router (%v) — advertised IPv6 subnets will be unreachable", err)
	}

	m.subnetActive = true
	families := "v4"
	if v6OK {
		families = "v4+v6"
	}
	natLog.Info("Successfully configured Subnet Router NAT masquerade via nftables (tap=%s, families=%s, forward-accept=on)", tapIfName, families)
	return nil
}

// addMSSClamp installs a TCP MSS clamp scoped to client traffic entering via the
// TAP interface, so tunneled TCP sessions negotiate a segment size that fits the
// (reduced) tunnel path MTU instead of being fragmented or blackholed.
//
// Compatibility: the preferred mechanism is the nftables TCPOPT set expression,
// but some kernels (notably minimal/OpenWrt and Debian cloud images, where the
// nft_tcponly module is not shipped) return EOPNOTSUPP for it. In that case we
// transparently fall back to the iptables/ip6tables TCPMSS target, which is
// supported far more widely.
//
// Both paths can still fail together: an nftables-only host (nft installed, no
// iptables userspace) with no nft_tcponly module has NO way to clamp MSS. That
// is degrading, not fatal — the Exit Node still routes client traffic via
// masquerade and RFC 1122 PMTU discovery takes over — but it must be visible.
// A missing clamp is the usual suspect for "large TCP packets fail through the
// exit node", so the failure is logged at Warn with the concrete cause of both
// attempts rather than swallowed at Debug.
func (m *NFTManager) addMSSClamp(family, tableName, tapIfName string, mss int) {
	if tapIfName == "" || mss <= 0 {
		return
	}
	if ok, _ := m.addMSSClampNFT(family, tableName, tapIfName, mss); ok {
		return
	}
	if ok, _ := m.addMSSClampIPTables(family, tapIfName, mss); ok {
		natLog.Info("added TCP MSS clamp (mss=%d) on %s via iptables TCPMSS fallback (tap=%s)", mss, family, tapIfName)
		return
	}
	natLog.Warn("TCP MSS clamp (mss=%d) NOT installed on %s — traffic will rely on PMTU discovery instead of an advertised-clamp. nft: %s | iptables: %s",
		mss, family, m.mssClampNFTFail, m.mssClampIPTFail)
}

// nftErrDetail returns a short, log-friendly summary of an nft/iptables failure:
// the last non-empty output line, else the error string. Keeps one operator-facing
// line per attempt instead of a multi-hundred-byte kernel backtrace in the log.
func nftErrDetail(err error, out []byte) string {
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	last := ""
	for i := len(lines) - 1; i >= 0; i-- {
		if s := strings.TrimSpace(lines[i]); s != "" {
			last = s
			break
		}
	}
	if last == "" {
		last = err.Error()
	}
	if len(last) > 160 {
		last = last[:160] + "..."
	}
	return last
}

// addMSSClampNFT installs the clamp via the nft CLI. google/nftables v0.3.0
// lacks a TCPOPT set expression, so we shell out. The rule is added
// idempotently (skipped if an identical clamp already exists). Returns false if
// the kernel does not support the expression, so the caller can fall back to
// iptables.
func (m *NFTManager) addMSSClampNFT(family, tableName, tapIfName string, mss int) (bool, string) {
	probe := fmt.Sprintf("nft list chain %s %s postrouting 2>/dev/null | grep -q 'maxseg set %d'", family, tableName, mss)
	if out, err := exec.Command("sh", "-c", probe).CombinedOutput(); err == nil && len(out) == 0 {
		natLog.Debug("MSS clamp (mss=%d) already present on %s/%s", mss, family, tableName)
		return true, ""
	}
	// Run nft directly (NOT via `sh -c`). The rule contains shell metacharacters
	// (&, (), |) that the shell would otherwise interpret as syntax — `(syn|rst)`
	// would be parsed as a subshell pipeline and fail with "Syntax error: word
	// unexpected", leaving the clamp never installed. Passing the rule as discrete
	// argv tokens hands those characters to nft literally.
	// `== syn` (not `!= 0`) is what the iptables fallback's `--tcp-flags SYN,RST
	// SYN` actually means: SYN set, RST clear. `!= 0` would also match plain RST
	// packets, and clamping the MSS on a RST is a no-op that just adds an
	// unrelated match to the rule.
	args := []string{"add", "rule", family, tableName, "postrouting",
		"iifname", tapIfName,
		"tcp", "flags", "&", "(syn|rst)", "==", "syn",
		"tcp", "option", "maxseg", "set", strconv.Itoa(mss),
	}
	out, err := exec.Command("nft", args...).CombinedOutput()
	if err != nil {
		m.mssClampNFTFail = nftErrDetail(err, out)
		return false, ""
	}
	natLog.Info("added TCP MSS clamp (mss=%d) on %s/%s postrouting (tap=%s)", mss, family, tableName, tapIfName)
	return true, ""
}

// addMSSClampIPTables installs the clamp via the iptables/ip6tables TCPMSS
// target — the widely-supported fallback for kernels lacking the nft TCPOPT
// expression. It is scoped identically to the nft variant: forwarded (FORWARD
// chain) TCP SYN/RST packets that entered via the TAP interface. Idempotent via
// a -C existence check.
func (m *NFTManager) addMSSClampIPTables(family, tapIfName string, mss int) (bool, string) {
	bin := "iptables"
	if family == "ip6" {
		bin = "ip6tables"
	}
	args := []string{"-t", "mangle", "-C", "FORWARD", "-i", tapIfName,
		"-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
		"-j", "TCPMSS", "--set-mss", strconv.Itoa(mss)}
	if _, err := exec.Command(bin, args...).CombinedOutput(); err == nil {
		natLog.Debug("%s TCPMSS clamp (mss=%d) already present (tap=%s)", bin, mss, tapIfName)
		return true, ""
	}
	args[2] = "-A" // switch -C (check) to -A (append)
	out, err := exec.Command(bin, args...).CombinedOutput()
	if err != nil {
		m.mssClampIPTFail = nftErrDetail(err, out)
		return false, ""
	}
	return true, ""
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
		natLog.Warn("nftables connect failed while removing NAT tables: %v", err)
		return
	}
	for _, t := range tables {
		c.DelTable(t)
	}
	if err := c.Flush(); err != nil {
		natLog.Debug("stale NAT table removal: %v", err)
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
	natLog.Info("Cleared Exit Node nftables NAT rules")
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
	natLog.Info("Cleared Subnet Router nftables NAT rules")
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
