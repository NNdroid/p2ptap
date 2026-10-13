package node

import (
	"slices"
	"sync/atomic"

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
func (n *Node) config() *config.Config {
	if n.configPtr != nil {
		if c := n.configPtr.Load(); c != nil {
			return c
		}
	}
	return n.Config
}

// CurrentConfig returns the current atomic configuration snapshot (the one the
// data plane reads). Unlike the exported Config field — which is the immutable
// construction-time baseline — this reflects any runtime hot-reload.
func (n *Node) CurrentConfig() *config.Config {
	if n.configPtr != nil {
		if c := n.configPtr.Load(); c != nil {
			return c
		}
	}
	return n.Config
}

// SetConfig atomically publishes a new configuration snapshot. It is the single
// write path for runtime hot-reload (WebUI save). Only the atomic snapshot is
// written; the exported Config field is intentionally left pointing at the
// construction-time baseline so concurrent readers of Config never race with a
// reload (they observe the immutable start-up configuration). Code that must
// observe a hot-reload reads through config() instead.
//
// NewNode always allocates the slot up front (see node.go); the lazy allocation
// below only serves test Nodes built with a bare &Node{}, where SetConfig is
// never called concurrently with config().
func (n *Node) SetConfig(c *config.Config) {
	if n.configPtr == nil {
		n.configPtr = new(atomic.Pointer[config.Config])
	}
	n.configPtr.Store(c)
}

// loadNodeConfig reads the live snapshot from a shared config slot. The slot is
// always populated before any transport factory can read it, but the fallback
// keeps a not-yet-published slot from panicking inside a connection callback.
func loadNodeConfig(slot *atomic.Pointer[config.Config], fallback *config.Config) *config.Config {
	if c := slot.Load(); c != nil {
		return c
	}
	return fallback
}

// applyObfuscationConfig re-applies the obfuscation settings to the packer and
// keeps its datagram budget in step with the tunnel MTU. The MTU and the
// obfuscation sizes are separate config fields, so either one changing must
// recompute the budget — otherwise a reload of only MTU would leave padding
// capped at the stale budget (and a reload of only obfuscation the other way
// around).
func (n *Node) applyObfuscationConfig(cfg *config.Config) {
	if n.Packer == nil {
		return
	}
	if budget := obfuscate.MaxFrameForPathMTU(cfg.MTU); budget > 0 &&
		(cfg.Obfuscation.FixedSize > budget || cfg.Obfuscation.MaxSize > budget) {
		log.Warn("Obfuscation frame size exceeds the %d-byte datagram budget for MTU %d "+
			"(fixed_size=%d, max_size=%d); padding is capped at the budget so frames "+
			"are not needlessly fragmented.", budget, cfg.MTU,
			cfg.Obfuscation.FixedSize, cfg.Obfuscation.MaxSize)
	}
	n.Packer.UpdateConfig(&cfg.Obfuscation)
	n.Packer.SetFrameBudget(cfg.MTU)
	n.Packer.SetSendAlgo(n.sendAlgo())
	log.Info("Obfuscation config hot-reloaded: mode=%s algo=%s", n.Packer.Mode, obfuscate.AlgoName(n.sendAlgo()))
}

// applyHotReload publishes cfg as the new configuration snapshot and then
// re-applies the runtime side-effects that depend on the mutable fields
// (exit-node NAT, obfuscation packer). It is invoked by the WebUI save path via
// the OnConfigReload callback. All side-effects read from the cfg argument (not
// the previous snapshot) so a reload is applied atomically and consistently.
func (n *Node) applyHotReload(cfg *config.Config) {
	old := n.CurrentConfig()
	n.SetConfig(cfg)

	// The WebRTC transport resolves its ICE server list per connection from this
	// slot, so no re-registration is needed — but report it, because unlike the
	// other reloaded fields there is no observable side effect.
	if !slices.Equal(old.StunServers, cfg.StunServers) || !slices.Equal(old.TurnServers, cfg.TurnServers) {
		log.Info("STUN/TURN server list reloaded: %d STUN, %d TURN (applies to new WebRTC connections)",
			len(cfg.StunServers), len(cfg.TurnServers))
	}

	if n.NFTManager != nil {
		n.NFTManager.UpdateConfig(&cfg.ExitNode)
		if cfg.ExitNode.Enable {
			_ = n.NFTManager.SetupExitNodeNAT(cfg.ExitNode.WANInterface, cfg.TapName, computeExitMSS(cfg.MTU, cfg.Obfuscation.Mode))
		} else {
			_ = n.NFTManager.CleanupExitNodeNAT()
		}
	}
	if n.Packer != nil {
		n.applyObfuscationConfig(cfg)
	}
	// Node info (name, exit-node flag, advertised subnets, obfuscation) may have
	// changed -> re-announce over the peek-map channel.
	go n.publishPeekMapSelf()
}
