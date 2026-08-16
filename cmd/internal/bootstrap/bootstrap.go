// Package bootstrap wires a configured p2ptap node together with its web
// collector, TAP frame interceptor and HTTP server. Both the CLI entrypoint
// (cmd/p2ptap) and the tray entrypoint (cmd/p2ptap-tray) share this assembly so
// the collector injection and MakeInterceptor/StartWebServer closures stay in
// lockstep.
package bootstrap

import (
	"syscall"

	"github.com/libp2p/go-libp2p/core/host"
	"p2ptap/pkg/config"
	"p2ptap/pkg/node"
	"p2ptap/pkg/observer"
	"p2ptap/pkg/routing"
	"p2ptap/pkg/web"
)

// Node assembles a fully wired *node.Node from cfg: it creates the shared web
// StatsCollector, injects it into the node, binds the TAP interceptor and the
// HTTP server closures, and calls SetupWebUI. The returned Collector is the same
// instance handed to the node — callers (e.g. a tray dashboard) may read a snapshot
// via observer.Collector.GetResponse.
//
// If SetupWebUI fails it is returned as the third result; the node is still usable
// in that case and the caller decides how to surface the error.
func Node(cfg *config.Config) (*node.Node, observer.Collector, error) {
	collector := web.NewStatsCollector()
	n, err := node.NewNode(cfg, collector)
	if err != nil {
		return nil, nil, err
	}

	// Wire the GatewayManager into the collector so /api/stats can report
	// the real-time exit-node active state (IP + peer ID) instead of always
	// returning the stale initial value.
	if n.Gateway != nil {
		collector.Gateway = n.Gateway
	}

	n.MakeInterceptor = func(virtualIP, virtualIPv6 string, port int, c observer.Collector, cfg *config.Config, cfgPath string) observer.FrameFilter {
		return web.NewTAPInterceptor(virtualIP, virtualIPv6, port, collector, cfg, cfgPath)
	}
	n.StartWebServer = func(c observer.Collector, bindIP, bindIPv6 string, port int, cfg *config.Config, cfgPath string, socketProtectHook func(network, address string, c syscall.RawConn) error) (observer.WebServer, error) {
		srv, err := web.StartServer(collector, bindIP, bindIPv6, port, cfg, cfgPath, socketProtectHook)
		if err != nil {
			return nil, err
		}
		// Inject the topology provider so /api/topology can return the full
		// mesh (link-state graph) rooted at this node for hierarchical rendering.
		srv.SetTopologyProvider(func() any { return n.GetTopology() })
		// Inject the live libp2p host and link-state router so /api/ping can
		// measure real RTTs and /api/traceroute can read the exact forwarding
		// path with per-leg transport class / latency.
		srv.SetHostProvider(func() host.Host { return n.Host })
		srv.SetRouterProvider(func() *routing.Router { return n.Router })
		return srv, nil
	}

	setupErr := n.SetupWebUI()
	return n, collector, setupErr
}
