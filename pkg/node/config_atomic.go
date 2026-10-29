package node

import (
	"net"
	"slices"
	"sync/atomic"
	"time"

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
	if c == nil {
		return
	}
	// Data-plane knobs are mirrored into atomics the packet path reads, so a
	// WebUI save actually takes effect. Before this, transport_strategy and the
	// reorder window only existed in the construction-time snapshot: the UI
	// reported the new value while the node kept running the old behaviour until
	// a restart, which reads as "the setting does nothing".
	n.applyReorderConfig(c)
	if n.Dispatcher != nil {
		n.Dispatcher.SetMode(c.TransportStrategy)
	}
}

// applyReorderConfig mirrors the multipath receive-side settings into the atomics
// the inbound path reads. Safe to call on every config reload.
func (n *Node) applyReorderConfig(c *config.Config) {
	if c == nil {
		return
	}
	window := c.RxReorderWindow
	if window <= 0 {
		window = 256
	}
	if window > 1024 {
		window = 1024
	}
	delay := c.RxReorderDelayMs
	if delay <= 0 {
		delay = 200
	}
	if delay > 5000 {
		delay = 5000
	}
	n.rxReorderWindow.Store(int32(window))
	n.rxReorderDelayNs.Store(int64(delay) * int64(time.Millisecond))
	n.rxReorderEnabled.Store(c.TransportStrategy == "multipath")
	// Hot-reload the per-peer queues too: rxReorderFor's LoadOrStore reuses an
	// existing queue, so without this the window/delay a queue was created with
	// persisted even after a live config save. Config reload is rare (not the
	// packet path), so iterating the whole map here is free by comparison.
	n.rxReorder.Range(func(k, v any) bool {
		v.(*rxReorderQueue).applyConfig(window, time.Duration(delay)*time.Millisecond)
		return true
	})
}

// reorderSettings returns the current reorder window (frames) and head-of-line
// delay, for creating a per-peer queue.
func (n *Node) reorderSettings() (int, time.Duration) {
	window := int(n.rxReorderWindow.Load())
	if window <= 0 {
		window = 256
	}
	delay := time.Duration(n.rxReorderDelayNs.Load())
	if delay <= 0 {
		delay = 200 * time.Millisecond
	}
	return window, delay
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

// advertisedNetsCache is the parsed form of config.AdvertisedSubnets: the
// operator's CIDR strings are parsed once per configuration snapshot, so the
// per-frame subnet check is a Contains() instead of a ParseCIDR().
//
// It invalidates itself on snapshot identity — SetConfig publishes a new
// *config.Config pointer on every hot reload, so a stale cache is impossible
// and no reload hook has to remember to rebuild it.
type advertisedNetsCache struct {
	cfg  *config.Config
	nets []*net.IPNet
}

// parseAdvertisedSubnets parses a CIDR list once, dropping unparseable entries
// (the old per-frame loop skipped them with the same err == nil test, so a
// typo'd subnet is inert either way).
func parseAdvertisedSubnets(subnets []string) []*net.IPNet {
	if len(subnets) == 0 {
		return nil
	}
	nets := make([]*net.IPNet, 0, len(subnets))
	for _, sub := range subnets {
		if _, cidr, err := net.ParseCIDR(sub); err == nil && cidr != nil {
			nets = append(nets, cidr)
		}
	}
	return nets
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
	// Padding targets are clamped to the datagram budget at Pack time
	// (clampFrameSize), so a rule whose target exceeds the MTU is harmless —
	// it just pads to the budget instead of fragmenting.
	n.Packer.UpdateConfig(&cfg.Obfuscation)
	n.Packer.SetFrameBudget(cfg.MTU)
	n.Packer.SetSendAlgo(n.sendAlgo())
	// Drain pending coalescing buffers: their knobs may have changed, so flushing
	// them under the old rule is cleaner than mixing two generations in one batch.
	if n.coalescer != nil {
		n.coalescer.flushAll()
	}
	log.Info("Obfuscation config hot-reloaded: enable=%t rule=%q algo=%s",
		cfg.Obfuscation.Enable, cfg.Obfuscation.PaddingRules, obfuscate.AlgoName(n.sendAlgo()))
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

	// Both rulesets are reconciled independently: a reload that only touched
	// advertised_subnets must not leave the old subnet NAT tables behind, and
	// one that only toggled exit_node must not tear down a valid subnet ruleset.
	n.applyExitNodeNAT(cfg)
	n.applySubnetRouterNAT(cfg)
	if n.Packer != nil {
		n.applyObfuscationConfig(cfg)
	}
	// Node info (name, exit-node flag, advertised subnets, obfuscation) may have
	// changed -> re-announce over the peek-map channel.
	go n.publishPeekMapSelf()
}
