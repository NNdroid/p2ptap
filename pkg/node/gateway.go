package node

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/libp2p/go-libp2p/core/peer"

	"p2ptap/pkg/logger"
)

// routeBackend abstracts every host-routing operation the GatewayManager
// performs so the orchestration logic (SetExitNode / ClearExitNode / subnet
// routes / bypass host routes) can be unit-tested without touching the real
// routing table. GatewayManager satisfies routeBackend itself: in production
// gm.route points back at gm and delegates to the platform-specific
// *RouteOS / sweep implementations. Tests inject a fake backend instead.
//
// All methods are unexported on purpose — only code in package node may call
// them, and a fake backend (also in package node) can implement them.
type routeBackend interface {
	GetOriginalPhysicalGateway() (string, error)
	GetOriginalPhysicalGatewayFor(endpointIP string) (string, error)
	addDefaultRouteOS(exitTapIP, tapDevName string, metric int) error
	delDefaultRouteOS(exitTapIP, tapDevName string) error
	addHostRouteOS(endpointIP, gwIP string) error
	delHostRouteOS(endpointIP, gwIP string) error
	// isOnLinkEndpoint reports whether endpointIP sits on a connected subnet of
	// one of the host's *physical* interfaces, i.e. it is reachable directly via
	// neighbour discovery / ARP without a router hop.
	isOnLinkEndpoint(endpointIP string) bool
	addCIDRRouteOS(cidrStr, gatewayIP, tapDevName string) error
	delCIDRRouteOS(cidrStr, gatewayIP, tapDevName string) error
	sweepTapDefaultRoutesUnlocked() error
	restorePhysicalDefaultGatewayOS()
	enableProcessBypass() error
	disableProcessBypass() error
}

var gwLog = logger.New("Gateway")

// GatewayManager manages Exit Node default routes and socket bypass (protect socket)
type GatewayManager struct {
	mu                 sync.Mutex
	tapName            string
	activeExitPeerID   string
	activeExitPID      peer.ID
	activeExitIP       string
	// activeExitIP6 is the IPv6 TAP gateway of the currently active Exit Node
	// (empty when the active exit only advertised an IPv4 gateway). Both
	// activeExitIP and activeExitIP6 are tracked so ClearExitNode removes the
	// exact split-default routes each family installed, and so bypass host
	// routes are only created for endpoints of a family whose default route was
	// actually hijacked.
	activeExitIP6      string
	originalPhysicalGW string
	// originalPhysicalGW6 remembers the IPv6 physical default gateway captured
	// at SetExitNode time, so clearExitNodeUnlocked can re-establish it on
	// Windows if disconnecting the Exit Node left the host without a default
	// route of that family (otherwise the host needs a NIC reset to recover).
	originalPhysicalGW6 string
	// bypassRoutes maps endpointIP -> the exact next hop p2ptap used when it
	// installed the /32 (or /128) bypass host route. The value is the physical
	// gateway IP, or the unspecified address of the endpoint's family
	// ("0.0.0.0" / "::") for an on-link route. Presence in the map — not a
	// non-empty value — is what marks a route as installed, so always probe it
	// with the two-value form.
	bypassRoutes map[string]string
	// knownEndpoints tracks every physical peer/relay endpoint seen so far,
	// whether or not a host route is currently installed for it. Endpoints are
	// only turned into real routes while an Exit Node is active.
	knownEndpoints   map[string]bool
	installedSubnets map[string]string // subnetCIDR -> gatewayIP
	disabledSubnets  map[string]bool   // subnetCIDR -> manually disabled
	// disabledSubnetsGW remembers the gateway IP of a manually disabled subnet
	// so that ToggleSubnetRoute can re-install the OS route on re-enable.
	disabledSubnetsGW map[string]string // subnetCIDR -> gatewayIP

	// peerEndpointProvider yields every known direct peer endpoint IP (from the
	// libp2p peerstore) so that activating an Exit Node can protect them all at
	// once. This is the authoritative source of peer endpoints and covers peers
	// that connected via relay, whose direct endpoints ProtectEndpoint would
	// otherwise never observe.
	peerEndpointProvider func() []string

	// route is the OS routing backend. It defaults to the GatewayManager itself
	// (which delegates to the platform-specific *RouteOS / sweep implementations)
	// so production code uses real routes, while tests can inject a fake backend to
	// exercise SetExitNode/ClearExitNode without touching the host routing table.
	route routeBackend

	// hostRouteBypass controls whether the manager installs /32 (or /128) host
	// routes to keep P2P endpoints off the TAP tunnel. Windows, Linux and darwin
	// instead bind every P2P (and WebUI) socket to the physical NIC at the
	// kernel level — IP_UNICAST_IF / SO_BINDTODEVICE / IP_BOUND_IF respectively
	// — which covers BOTH inbound and outbound, so host routes are unnecessary
	// and disabled there (defaultHostRouteBypass returns false). The BSD family
	// has no socket-binding API in golang.org/x/sys/unix, so it keeps the host
	// route fallback (defaultHostRouteBypass returns true). The Exit Node's TAP
	// capture routes (/1 split-default) are installed regardless of this flag.
	hostRouteBypass bool

	// exitActive is an atomic mirror of "an Exit Node is currently active". The
	// data plane (node_tap.go / node_streams.go) reads it on every frame to decide
	// whether to hijack unknown unicast/broadcast traffic, and using an atomic
	// avoids taking gm.mu on that hot path (see IsExitNodeActive).
	exitActive atomic.Bool
}

func NewGatewayManager(tapName string) *GatewayManager {
	gm := &GatewayManager{
		tapName:           tapName,
		bypassRoutes:      make(map[string]string),
		knownEndpoints:    make(map[string]bool),
		installedSubnets:  make(map[string]string),
		disabledSubnets:   make(map[string]bool),
		disabledSubnetsGW: make(map[string]string),
		// Windows, Linux and darwin protect P2P sockets at the socket layer
		// (IP_UNICAST_IF / SO_BINDTODEVICE / IP_BOUND_IF), so they do not
		// install /32 bypass host routes. The BSD family lacks a socket-binding
		// API and keeps the host-route fallback.
		hostRouteBypass: defaultHostRouteBypass(),
	}
	// GatewayManager satisfies routeBackend; point the seam at ourselves so
	// production uses the real platform-specific route operations.
	gm.route = gm
	return gm
}

// SetPeerEndpointProvider registers a callback that returns every known direct
// peer endpoint IP (typically sourced from the libp2p peerstore). It is consulted
// when an Exit Node is activated so that bypass host routes are installed for
// all peers at once, including those reached via relay.
func (gm *GatewayManager) SetPeerEndpointProvider(provider func() []string) {
	gm.mu.Lock()
	defer gm.mu.Unlock()
	gm.peerEndpointProvider = provider
}

func (gm *GatewayManager) ActiveExitPeerID() string {
	gm.mu.Lock()
	defer gm.mu.Unlock()
	return gm.activeExitPeerID
}

func (gm *GatewayManager) ActiveExitPeerPID() peer.ID {
	gm.mu.Lock()
	defer gm.mu.Unlock()
	return gm.activeExitPID
}

func (gm *GatewayManager) ActiveExitIP() string {
	gm.mu.Lock()
	defer gm.mu.Unlock()
	return gm.activeExitIP
}

// ActiveExitIP6 returns the IPv6 TAP gateway of the currently active Exit Node
// (empty if the active exit only advertised an IPv4 gateway). It mirrors
// ActiveExitIP for the v6 family and is used by the status surface so the UI
// can show which gateway each address family is tunnelled through.
func (gm *GatewayManager) ActiveExitIP6() string {
	gm.mu.Lock()
	defer gm.mu.Unlock()
	return gm.activeExitIP6
}

// IsExitNodeActive reports whether an Exit Node default route is currently
// installed, using the atomic mirror so callers on the data-plane hot path do
// not have to take gm.mu (contrast ActiveExitPeerID, which still locks).
func (gm *GatewayManager) IsExitNodeActive() bool {
	return gm.exitActive.Load()
}

// enableProcessBypass / disableProcessBypass wrap the global WFP manager so the
// bypass lifecycle is part of the routeBackend seam and can be faked in tests.
func (gm *GatewayManager) enableProcessBypass() error {
	return GetWFPManager().EnableProcessBypass()
}

func (gm *GatewayManager) disableProcessBypass() error {
	return GetWFPManager().DisableProcessBypass()
}

// ProtectEndpoint remembers a physical peer/relay endpoint that must never be
// routed into the tunnel, and (only while an Exit Node is active) installs a
// host route for it via the physical gateway.
//
// Rationale: every P2P socket this process opens is already bound to the
// physical interface at the kernel level by the socket-protection hook
// (IP_UNICAST_IF on Windows, SO_BINDTODEVICE on Linux, IP_BOUND_IF on darwin),
// so program traffic bypasses the VPN by construction. The per-endpoint host
// route is only a fallback for sockets that may escape that hook, and it is
// only meaningful once the system default route has been hijacked by the Exit
// Node. Installing it when no Exit Node is active pollutes the routing table
// and produces spurious warnings (e.g. IPv6 endpoints on IPv4-only gateways),
// so it is deferred until SetExitNode runs.
func (gm *GatewayManager) ProtectEndpoint(endpointIP string) error {
	gm.mu.Lock()
	defer gm.mu.Unlock()

	ip := net.ParseIP(endpointIP)
	if ip == nil || ip.IsLoopback() {
		return nil
	}

	// Always track the endpoint so it can be protected retroactively the
	// moment an Exit Node or overlapping Subnet Route is activated.
	gm.knownEndpoints[endpointIP] = true

	if gm.bypassNeededForUnlocked(ip) {
		gm.installBypassRouteUnlocked(endpointIP)
	} else {
		gwLog.Debug("Endpoint %s tracked; host route deferred (nothing p2ptap installed can capture it)", endpointIP)
	}
	return nil
}

// bypassNeededForUnlocked reports whether a physical bypass host route is
// actually required for the given endpoint right now. Caller must hold gm.mu.
//
// A bypass route is only meaningful when a route p2ptap itself installed could
// otherwise swallow traffic to that endpoint:
//
//  1. An installed Subnet Route whose CIDR contains the endpoint, or
//  2. An active Exit Node whose split-default routes cover the endpoint's
//     address family.
//
// The address-family test in (2) is essential. addDefaultRouteOS hijacks
// 0.0.0.0/1 + 128.0.0.0/1 for an IPv4 exit and ::/1 + 8000::/1 for an IPv6
// exit — and a dual-stack exit installs BOTH. A bypass route is only needed
// for an endpoint whose family was actually hijacked: an IPv4 endpoint needs it
// only when an IPv4 default route is up, and symmetrically for IPv6. The old
// code installed a bypass route for *every* known endpoint regardless of
// family, so activating an IPv4 Exit Node also pushed a /128 metric-1 route at
// every peer reached over IPv6 — those routes bought nothing (the IPv6 default
// route was never hijacked) but frequently landed on the wrong interface or via
// an unresolvable link-local next hop, black-holing every IPv6 peer the moment
// the Exit Node came up.
func (gm *GatewayManager) bypassNeededForUnlocked(ip net.IP) bool {
	if ip == nil {
		return false
	}
	// A TAP subnet route can capture the endpoint regardless of which family's
	// default route was hijacked, so it always warrants a more-specific route.
	if gm.isInsideSubnet(ip) {
		return true
	}
	if gm.activeExitIP == "" && gm.activeExitIP6 == "" {
		return false
	}
	ipV4 := ip.To4() != nil
	// Only require a bypass for this endpoint's family if we actually hijacked
	// that family's default route.
	if ipV4 {
		return gm.activeExitIP != ""
	}
	return gm.activeExitIP6 != ""
}

// installBypassRouteUnlocked adds the bypass host route for a single endpoint.
// Caller must hold gm.mu.
func (gm *GatewayManager) installBypassRouteUnlocked(endpointIP string) {
	// Windows, Linux and darwin rely on socket-level interface binding
	// (IP_UNICAST_IF / SO_BINDTODEVICE / IP_BOUND_IF) to keep P2P endpoints
	// off the TAP tunnel, so they never install bypass host routes. The BSD
	// family has no such socket option and falls through to add the /32 below.
	if !gm.hostRouteBypass {
		return
	}
	if _, installed := gm.bypassRoutes[endpointIP]; installed {
		return
	}
	ip := net.ParseIP(endpointIP)
	if ip == nil {
		return
	}

	// On-link endpoints (a peer on the same LAN segment as one of our physical
	// NICs) must NOT be forced through the physical gateway. The NIC's own
	// connected subnet route (e.g. /24 or /64) is already far more specific
	// than the /1 split-default routes an Exit Node installs, so it keeps
	// winning on its own; handing those packets to the router instead breaks
	// the peer on any gateway that refuses to hairpin traffic back onto the
	// segment it came from.
	//
	// The one case that still needs an explicit route is an overlapping TAP
	// Subnet Route — and then the host route must stay *on-link* (unspecified
	// next hop) so the neighbour is still resolved directly.
	if gm.route.isOnLinkEndpoint(endpointIP) {
		if !gm.isInsideSubnet(ip) {
			gwLog.Debug("Endpoint %s is on-link on a physical interface; no bypass host route needed", endpointIP)
			return
		}
		onLink := "0.0.0.0"
		if ip.To4() == nil {
			onLink = "::"
		}
		gwLog.Info("Installing on-link bypass host route for %s (overlaps an installed Subnet Route)...", endpointIP)
		if err := gm.route.addHostRouteOS(endpointIP, onLink); err != nil {
			gwLog.Warn("Failed to add on-link host route for %s: %v", endpointIP, err)
			return
		}
		gm.bypassRoutes[endpointIP] = onLink
		return
	}

	gw, err := gm.route.GetOriginalPhysicalGatewayFor(endpointIP)
	if err != nil {
		// No matching-family gateway (e.g. an IPv6 endpoint on a host whose
		// only default gateway is IPv4). The socket-protection host route
		// cannot be installed, but this is non-fatal for the VPN itself.
		gwLog.Warn("Skipping socket-protection host route for %s: %v", endpointIP, err)
		return
	}

	gwLog.Info("Protecting P2P socket route for physical endpoint %s via physical gateway %s...", endpointIP, gw)

	if err := gm.route.addHostRouteOS(endpointIP, gw); err != nil {
		gwLog.Warn("Failed to add host route for %s: %v", endpointIP, err)
		return
	}

	gm.bypassRoutes[endpointIP] = gw
}

// isInsideSubnet reports whether an IP falls inside any installed Subnet Route.
func (gm *GatewayManager) isInsideSubnet(ip net.IP) bool {
	if ip == nil {
		return false
	}
	for cidr := range gm.installedSubnets {
		_, subnet, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if subnet.Contains(ip) {
			return true
		}
	}
	return false
}

// SetExitNode sets the specified peer TAP IP(s) as the system default gateway
// (0.0.0.0/0 / ::/0). exitTapIPv4 and exitTapIPv6 are the peer's TAP gateway
// addresses; either may be empty, but at least one must be set. Each non-empty
// family gets its own split-default (/1) routes installed on the TAP, so a
// dual-stack peer tunnels BOTH IPv4 and IPv6 through the exit while the
// physical default route (and the P2P sockets bound to it) stays intact.
func (gm *GatewayManager) SetExitNode(peerID string, exitTapIPv4 string, exitTapIPv6 string, physicalEndpoints []string) error {
	gm.mu.Lock()
	defer gm.mu.Unlock()

	// Normalise: callers may pass a bare address ("10.0.0.2" / "fd00::2") or a
	// full CIDR ("10.0.0.2/24"). Strip any mask so downstream ParseAddr / route
	// operations always see a plain host address.
	if strings.Contains(exitTapIPv4, "/") {
		exitTapIPv4 = strings.Split(exitTapIPv4, "/")[0]
	}
	if strings.Contains(exitTapIPv6, "/") {
		exitTapIPv6 = strings.Split(exitTapIPv6, "/")[0]
	}

	// Remember any previously active Exit Node so we can remove its default
	// route AFTER the new one is in place. Installing the new TAP default route
	// before tearing down the old one avoids a momentary "no TAP default route"
	// window during a switch, which would otherwise leak real-IP traffic.
	prevExitIP := gm.activeExitIP
	prevExitIP6 := gm.activeExitIP6

	// 1. Detect physical gateway
	gw, err := gm.route.GetOriginalPhysicalGateway()
	if err != nil {
		gwLog.Warn("Failed to auto-detect physical default gateway: %v", err)
	} else {
		gm.originalPhysicalGW = gw
	}
	// Capture the IPv6 physical gateway too (for restoration on clear).
	if gw6, err6 := gm.route.GetOriginalPhysicalGatewayFor("::"); err6 == nil && gw6 != "" && gw6 != "::" {
		gm.originalPhysicalGW6 = gw6
	}

	// 2. Add default route(s) via TAP exit node IP(s) FIRST. Doing this before
	//    the bypass host routes means a failure here leaves no partial TAP state
	//    behind (addDefaultRouteOS rolls back its own routes on error).
	//    Each non-empty family is installed independently; if the IPv6 install
	//    fails after IPv4 succeeded we roll the IPv4 half back so the host is
	//    never left half-tunnelled.
	if exitTapIPv4 != "" {
		gwLog.Info("Configuring IPv4 Exit Node gateway %s (%s) on TAP interface...", exitTapIPv4, peerID)
		if err := gm.route.addDefaultRouteOS(exitTapIPv4, gm.tapName, 5); err != nil {
			return fmt.Errorf("failed to add IPv4 default route via TAP exit node: %w", err)
		}
	}
	if exitTapIPv6 != "" {
		gwLog.Info("Configuring IPv6 Exit Node gateway %s (%s) on TAP interface...", exitTapIPv6, peerID)
		if err := gm.route.addDefaultRouteOS(exitTapIPv6, gm.tapName, 5); err != nil {
			if exitTapIPv4 != "" {
				_ = gm.route.delDefaultRouteOS(exitTapIPv4, gm.tapName)
			}
			return fmt.Errorf("failed to add IPv6 default route via TAP exit node: %w", err)
		}
	}
	// At least one family must be tunnelled; refuse a no-op activation so we
	// never mark the exit "active" without actually installing a route.
	if exitTapIPv4 == "" && exitTapIPv6 == "" {
		return fmt.Errorf("exit node requires at least one gateway IP (IPv4 or IPv6)")
	}

	pPID, _ := peer.Decode(peerID)
	gm.activeExitPeerID = peerID
	gm.activeExitPID = pPID
	gm.activeExitIP = exitTapIPv4
	gm.activeExitIP6 = exitTapIPv6
	gm.exitActive.Store(true)

	// 2b. Now that the new TAP default route(s) are active, remove the previous
	//     Exit Node's default route(s) (no window without a TAP route). Also
	//     drop the previous Exit Node's per-endpoint bypass host routes so they
	//     are not left dangling; they are re-installed below against the current
	//     physical gateway. This fixes stale /32 routes leaking after a switch
	//     (previously only the default route was removed).
	if prevExitIP != "" && prevExitIP != exitTapIPv4 {
		_ = gm.route.delDefaultRouteOS(prevExitIP, gm.tapName)
	}
	if prevExitIP6 != "" && prevExitIP6 != exitTapIPv6 {
		_ = gm.route.delDefaultRouteOS(prevExitIP6, gm.tapName)
	}
	if (prevExitIP != "" && prevExitIP != exitTapIPv4) || (prevExitIP6 != "" && prevExitIP6 != exitTapIPv6) {
		gm.teardownBypassRoutesUnlocked()
	}

	// 3. Protect physical socket endpoints to prevent loopback.
	//    Endpoints observed before the Exit Node was activated had their host
	//    routes deferred by ProtectEndpoint, so install them retroactively here
	//    together with the freshly supplied ones. If any of these fail we have
	//    already committed the default route, so we just warn — the socket
	//    protection fallback keeps control-plane traffic off the tunnel.
	for _, ep := range physicalEndpoints {
		if ep == "" {
			continue
		}
		if ip := net.ParseIP(ep); ip == nil || ip.IsLoopback() {
			continue
		}
		gm.knownEndpoints[ep] = true
	}

	// Also protect every endpoint the libp2p peerstore knows about. The
	// peerstore is the authoritative source of direct peer addresses and covers
	// peers that connected via relay (whose direct endpoints ProtectEndpoint
	// never observed), so dials to them don't get routed into the TAP tunnel.
	if gm.peerEndpointProvider != nil {
		for _, ep := range gm.peerEndpointProvider() {
			ip := net.ParseIP(ep)
			if ip == nil || ip.IsLoopback() {
				continue
			}
			gm.knownEndpoints[ep] = true
		}
	}

	// Only endpoints that something we installed can actually capture get a
	// bypass host route (see bypassNeededForUnlocked). Notably this excludes
	// endpoints of an address family whose default route we did NOT hijack —
	// installing those used to black-hole every IPv6 peer whenever an IPv4
	// Exit Node was activated.
	for ep := range gm.knownEndpoints {
		ip := net.ParseIP(ep)
		if ip == nil {
			continue
		}
		if !gm.bypassNeededForUnlocked(ip) {
			gwLog.Debug("Endpoint %s needs no bypass host route for exit %s/%s (different address family, not on a subnet route)", ep, exitTapIPv4, exitTapIPv6)
			continue
		}
		gm.installBypassRouteUnlocked(ep)
	}

	// Enable WFP process-level bypass on Windows to guarantee all p2ptap traffic
	// (including libp2p, QUIC, TCP, DNS, HTTP, Relay) is excluded from VPN hijacking.
	if err := gm.route.enableProcessBypass(); err != nil {
		gwLog.Warn("WFP process bypass activation failed: %v (falling back to host routes & socket protect)", err)
	} else {
		gwLog.Info("WFP process bypass activated successfully for p2ptap")
	}

	gwLog.Info("Successfully activated Exit Node %s (%s) as system default gateway! (v4=%s v6=%s)", peerID, exitTapIPv4, exitTapIPv4, exitTapIPv6)
	return nil
}

// ClearExitNode removes the TAP default route and restores physical default route
func (gm *GatewayManager) ClearExitNode() error {
	gm.mu.Lock()
	defer gm.mu.Unlock()
	return gm.clearExitNodeUnlocked()
}

func (gm *GatewayManager) clearExitNodeUnlocked() error {
	gwLog.Info("Clearing Exit Node gateway...")

	// Snapshot the active exit identity, then clear the active flags FIRST so
	// the data plane (node_tap.go / node_streams.go) stops forwarding frames
	// into the tunnel before we remove the route from underneath it. This
	// closes the black-hole window where isExitNodeActive() returned true but
	// no Exit Node route existed.
	activeExitIP := gm.activeExitIP
	activeExitIP6 := gm.activeExitIP6
	gm.activeExitPeerID = ""
	gm.activeExitPID = ""
	gm.activeExitIP = ""
	gm.activeExitIP6 = ""
	gm.exitActive.Store(false)

	if activeExitIP != "" {
		_ = gm.route.delDefaultRouteOS(activeExitIP, gm.tapName)
	}
	if activeExitIP6 != "" {
		_ = gm.route.delDefaultRouteOS(activeExitIP6, gm.tapName)
	}
	// Best-effort: sweep any leftover split-default routes on the TAP adapter
	_ = gm.route.sweepTapDefaultRoutesUnlocked()

	// On platforms where disconnecting the Exit Node can leave the host without
	// a usable physical default route (Windows), make sure the real gateway is
	// re-established so internet returns without a NIC reset.
	gm.route.restorePhysicalDefaultGatewayOS()

	// Disable WFP process bypass filter (after the route is gone).
	_ = gm.route.disableProcessBypass()

	// Clean up ONLY the bypass host routes explicitly installed by p2ptap,
	// scoped by the exact gateway each was added with so we never touch a
	// coincidental host route the host or another application created.
	gm.teardownBypassRoutesUnlocked()
	gwLog.Info("Exit Node gateway cleared successfully.")
	return nil
}

// teardownBypassRoutesUnlocked removes every physical bypass host route that
// p2ptap installed and resets the bookkeeping map. Caller must hold gm.mu.
// Unlike clearExitNodeUnlocked it does NOT touch the active Exit Node default
// route, WFP, or the physical default route, so it is safe to call in the
// middle of a SetExitNode switch where a fresh default route is already up.
func (gm *GatewayManager) teardownBypassRoutesUnlocked() {
	for ep, gw := range gm.bypassRoutes {
		_ = gm.route.delHostRouteOS(ep, gw)
	}
	gm.bypassRoutes = make(map[string]string)
}

func (gm *GatewayManager) AddSubnetRoute(subnetCIDR string, gatewayIP string) (bool, error) {
	gm.mu.Lock()
	defer gm.mu.Unlock()

	if gm.installedSubnets == nil {
		gm.installedSubnets = make(map[string]string)
	}

	if gm.disabledSubnets != nil && gm.disabledSubnets[subnetCIDR] {
		gwLog.Debug("Subnet Route %s is manually disabled; skipping OS route installation", subnetCIDR)
		return false, nil
	}

	// Skip duplicate OS route configuration if already installed with identical gateway
	if currentGW, exists := gm.installedSubnets[subnetCIDR]; exists && currentGW == gatewayIP {
		return false, nil
	}

	gwLog.Info("Configuring Subnet Route %s via peer gateway %s on TAP %s...", subnetCIDR, gatewayIP, gm.tapName)
	if err := gm.route.addCIDRRouteOS(subnetCIDR, gatewayIP, gm.tapName); err != nil {
		return false, err
	}

	gm.installedSubnets[subnetCIDR] = gatewayIP

	// Protect any known peer physical endpoints that fall inside the new subnet route
	for ep := range gm.knownEndpoints {
		ip := net.ParseIP(ep)
		if ip != nil && gm.isInsideSubnet(ip) {
			gwLog.Info("Installing physical bypass route for peer endpoint %s overlapping with Subnet Route %s", ep, subnetCIDR)
			gm.installBypassRouteUnlocked(ep)
		}
	}
	return true, nil
}

// ToggleSubnetRoute enables or disables an authorized subnet route in real-time.
// On disable it removes the route from the OS routing table immediately; on
// re-enable it re-installs the route (so the change is effective without waiting
// for a peer-meta refresh).  This fixes the cross-platform toggle being a no-op
// on re-enable (the route was deleted but never written back).
func (gm *GatewayManager) ToggleSubnetRoute(subnetCIDR string, enable bool) (bool, error) {
	gm.mu.Lock()
	defer gm.mu.Unlock()

	if gm.disabledSubnets == nil {
		gm.disabledSubnets = make(map[string]bool)
	}
	if gm.disabledSubnetsGW == nil {
		gm.disabledSubnetsGW = make(map[string]string)
	}

	if !enable {
		// Remember the gateway so we can re-install on re-enable.
		if gw, exists := gm.installedSubnets[subnetCIDR]; exists {
			gm.disabledSubnetsGW[subnetCIDR] = gw
		}
		gm.disabledSubnets[subnetCIDR] = true
		if gw, exists := gm.installedSubnets[subnetCIDR]; exists {
			gwLog.Info("Manually disabling Subnet Route %s via gateway %s on TAP %s...", subnetCIDR, gw, gm.tapName)
			_ = gm.route.delCIDRRouteOS(subnetCIDR, gw, gm.tapName)
			delete(gm.installedSubnets, subnetCIDR)
			return true, nil
		}
		return false, nil
	}

	// Re-enabling: remove the disabled flag and re-install the OS route now.
	delete(gm.disabledSubnets, subnetCIDR)
	gw, exists := gm.disabledSubnetsGW[subnetCIDR]
	delete(gm.disabledSubnetsGW, subnetCIDR)
	if exists && gw != "" {
		gwLog.Info("Manually re-enabling Subnet Route %s via gateway %s on TAP %s...", subnetCIDR, gw, gm.tapName)
		if err := gm.route.addCIDRRouteOS(subnetCIDR, gw, gm.tapName); err != nil {
			gwLog.Warn("Re-enable Subnet Route %s failed to install: %v", subnetCIDR, err)
			return true, err
		}
		gm.installedSubnets[subnetCIDR] = gw
	}
	return true, nil
}

func (gm *GatewayManager) IsSubnetDisabled(subnetCIDR string) bool {
	gm.mu.Lock()
	defer gm.mu.Unlock()
	return gm.disabledSubnets[subnetCIDR]
}

// ReconcileSubnetRoutes removes installed subnet routes whose peers/gateways are no longer active, while keeping active ones.
func (gm *GatewayManager) ReconcileSubnetRoutes(validSubnets map[string]string) {
	gm.mu.Lock()
	defer gm.mu.Unlock()

	for subnet, currentGW := range gm.installedSubnets {
		validGW, exists := validSubnets[subnet]
		if !exists || validGW != currentGW {
			gwLog.Info("Cleaning up stale Subnet Route %s via gateway %s...", subnet, currentGW)
			_ = gm.route.delCIDRRouteOS(subnet, currentGW, gm.tapName)
			delete(gm.installedSubnets, subnet)
		}
	}
}

// ClearSubnetRoutes removes installed subnet routes when peer disconnects or configuration changes
func (gm *GatewayManager) ClearSubnetRoutes() {
	gm.mu.Lock()
	defer gm.mu.Unlock()

	for subnet, gw := range gm.installedSubnets {
		gwLog.Info("Cleaning up Subnet Route %s via gateway %s...", subnet, gw)
		_ = gm.route.delCIDRRouteOS(subnet, gw, gm.tapName)
	}
	gm.installedSubnets = make(map[string]string)
}

// ProtectEndpointsDynamic receives new peer endpoint IPs in real-time (e.g. from libp2p peer connection events)
// and installs physical /32 host routes for them if an Exit Node is active.
func (gm *GatewayManager) ProtectEndpointsDynamic(endpoints []string) {
	gm.mu.Lock()
	defer gm.mu.Unlock()

	for _, ep := range endpoints {
		if ep == "" {
			continue
		}
		ip := net.ParseIP(ep)
		if ip == nil || ip.IsLoopback() {
			continue
		}
		gm.knownEndpoints[ep] = true

		if gm.bypassNeededForUnlocked(ip) {
			gm.installBypassRouteUnlocked(ep)
		}
	}
}

// CheckAndUpdatePhysicalGateway checks if the physical egress gateway IP has changed (e.g. Wi-Fi to Ethernet switch)
// and re-installs active /32 host routes using the new physical gateway.
func (gm *GatewayManager) CheckAndUpdatePhysicalGateway() {
	gm.mu.Lock()
	defer gm.mu.Unlock()

	if gm.activeExitPeerID == "" {
		return
	}

	latestGW, err := gm.route.GetOriginalPhysicalGateway()
	if err != nil || latestGW == "" || latestGW == "0.0.0.0" || latestGW == "::" {
		return
	}

	if gm.originalPhysicalGW != "" && gm.originalPhysicalGW == latestGW {
		return
	}

	gwLog.Info("Physical network environment switch detected: gateway changed from %s -> %s. Refreshing bypass host routes...", gm.originalPhysicalGW, latestGW)
	gm.originalPhysicalGW = latestGW

	// When the underlying NIC changed, refresh the cached default-egress index
	// so P2P sockets created afterwards bind to the new NIC. Socket-level
	// protection (IP_UNICAST_IF / SO_BINDTODEVICE / IP_BOUND_IF) has no route
	// table to re-install the way the old /32 bypass route did, so the cache
	// must be refreshed here or the binding would stick to the now-dead
	// interface.
	RefreshDefaultEgressInterface()

	// Re-install all active bypass host routes with the new physical gateway
	for ep, gw := range gm.bypassRoutes {
		_ = gm.route.delHostRouteOS(ep, gw)
		delete(gm.bypassRoutes, ep)
	}

	// Re-install using the same eligibility rule as SetExitNode. The previous
	// condition (!isTunnelDestination) was inverted: it *skipped* exactly the
	// endpoints that overlap a Subnet Route — the ones that need a
	// more-specific bypass route the most — while re-adding routes for
	// endpoints of the wrong address family.
	for ep := range gm.knownEndpoints {
		ip := net.ParseIP(ep)
		if ip != nil && gm.bypassNeededForUnlocked(ip) {
			gm.installBypassRouteUnlocked(ep)
		}
	}
}

// onLinkViaInterfaceAddrs reports whether endpointIP is directly reachable on
// the same subnet as one of the host's non-loopback interfaces — i.e. it can
// be reached via neighbour discovery / ARP without going through a router. This
// is the cross-platform (Linux / Darwin / other) implementation backing
// isOnLinkEndpoint; the Windows build uses a route-table based check instead
// and does not call this. If the address cannot be parsed or the interface
// list is unavailable we conservatively return false so the caller installs
// the host route rather than risk tunnelling P2P traffic that should stay on
// the physical NIC.
func onLinkViaInterfaceAddrs(endpointIP string) bool {
	ip := net.ParseIP(endpointIP)
	if ip == nil {
		return false
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok || ipnet.IP.IsLoopback() {
			continue
		}
		if ipnet.Contains(ip) {
			return true
		}
	}
	return false
}
