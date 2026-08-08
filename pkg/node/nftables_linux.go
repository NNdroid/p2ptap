//go:build linux

package node

import (
	"fmt"
	"os"
	"sync"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"

	"p2ptap/pkg/config"
	"p2ptap/pkg/logger"
)

var nftLog = logger.New("NFTables")

type NFTManager struct {
	mu     sync.Mutex
	cfg    *config.ExitNodeConfig
	active bool
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

// EnableIPForwarding enables kernel IPv4 forwarding via procfs
func (m *NFTManager) EnableIPForwarding() error {
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0644); err != nil {
		return fmt.Errorf("enable IPv4 forwarding: %w", err)
	}
	if err := os.WriteFile("/proc/sys/net/ipv6/conf/all/forwarding", []byte("1"), 0644); err != nil {
		return fmt.Errorf("enable IPv6 forwarding: %w", err)
	}
	return nil
}

// SetupExitNodeNAT adds nftables masquerade NAT rules if enabled in config
func (m *NFTManager) SetupExitNodeNAT(wanIfName, tapIfName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.cfg.Enable || !m.cfg.NATMasquerade {
		nftLog.Debug("Exit Node NAT masquerade disabled in config")
		return nil
	}

	if err := m.EnableIPForwarding(); err != nil {
		nftLog.Warn("IP forwarding enable failed: %v", err)
	}

	c, err := nftables.New()
	if err != nil {
		return fmt.Errorf("nftables connect error: %w", err)
	}

	table := c.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "p2ptap_nat",
	})

	postrouteChain := c.AddChain(&nftables.Chain{
		Name:     "postrouting",
		Table:    table,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPostrouting,
		Priority: nftables.ChainPriorityNATSource,
	})

	// Add Masquerade rule for outbound WAN traffic
	exprs := []expr.Any{}
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

	if err := c.Flush(); err != nil {
		return fmt.Errorf("nftables flush rules error: %w", err)
	}

	m.active = true
	nftLog.Info("Successfully configured Exit Node NAT masquerade via nftables (wan=%s, tap=%s)", wanIfName, tapIfName)
	return nil
}

// CleanupExitNodeNAT removes p2ptap_nat table
func (m *NFTManager) CleanupExitNodeNAT() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.active {
		return nil
	}

	c, err := nftables.New()
	if err != nil {
		return err
	}

	c.DelTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "p2ptap_nat",
	})

	_ = c.Flush()
	m.active = false
	nftLog.Info("Cleared Exit Node nftables NAT rules")
	return nil
}
