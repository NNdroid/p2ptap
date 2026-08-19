package node

import (
	"p2ptap/pkg/config"
	"p2ptap/pkg/obfuscate"
)

// config returns the current atomic configuration snapshot.
//
// The node configuration can be hot-reloaded at runtime (WebUI save). The data
// plane reads the mutable fields (ExitNode.Enable, ACL.Enable, Obfuscation,
// ...) on a per-frame basis, so those reads MUST go through this snapshot to
// observe a reload without a data race. Call config() once at the top of a
// function that touches config more than once and reuse the returned pointer so
// the whole function observes one consistent configuration version (a mid-frame
// reload must not tear a decision).
func (n *Node) config() *config.Config { return n.configPtr.Load() }

// SetConfig atomically publishes a new configuration snapshot. It is the single
// write path for runtime hot-reload (WebUI save). Only the atomic snapshot is
// written; the exported Config field is intentionally left pointing at the
// construction-time baseline so concurrent readers of Config never race with a
// reload (they observe the immutable start-up configuration). Code that must
// observe a hot-reload reads through config() instead.
func (n *Node) SetConfig(c *config.Config) {
	n.configPtr.Store(c)
}

// applyHotReload publishes cfg as the new configuration snapshot and then
// re-applies the runtime side-effects that depend on the mutable fields
// (exit-node NAT, obfuscation packer). It is invoked by the WebUI save path via
// the OnConfigReload callback. All side-effects read from the cfg argument (not
// the previous snapshot) so a reload is applied atomically and consistently.
func (n *Node) applyHotReload(cfg *config.Config) {
	n.SetConfig(cfg)

	if n.NFTManager != nil {
		n.NFTManager.UpdateConfig(&cfg.ExitNode)
		if cfg.ExitNode.Enable {
			_ = n.NFTManager.SetupExitNodeNAT(cfg.ExitNode.WANInterface, cfg.TapName, computeExitMSS(cfg.MTU, cfg.Obfuscation.Mode))
		} else {
			_ = n.NFTManager.CleanupExitNodeNAT()
		}
	}
	if n.Packer != nil {
		n.Packer.UpdateConfig(&cfg.Obfuscation)
		n.Packer.SetSendAlgo(n.sendAlgo())
		log.Info("Obfuscation config hot-reloaded: mode=%s algo=%s", n.Packer.Mode, obfuscate.AlgoName(n.sendAlgo()))
	}
	// Node info (name, exit-node flag, advertised subnets, obfuscation) may have
	// changed -> re-announce over the peek-map channel.
	go n.publishPeekMapSelf()
}
