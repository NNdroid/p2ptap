package node

import (
	"fmt"
	"net"
	"sync"

	"p2ptap/pkg/logger"
)

var gwLog = logger.New("Gateway")

// GatewayManager manages Exit Node default routes and socket bypass (protect socket)
type GatewayManager struct {
	mu                 sync.Mutex
	tapName            string
	activeExitPeerID   string
	activeExitIP       string
	originalPhysicalGW string
	bypassRoutes       map[string]bool
	installedSubnets   map[string]string // subnetCIDR -> gatewayIP
}

func NewGatewayManager(tapName string) *GatewayManager {
	return &GatewayManager{
		tapName:          tapName,
		bypassRoutes:     make(map[string]bool),
		installedSubnets: make(map[string]string),
	}
}

func (gm *GatewayManager) ActiveExitPeerID() string {
	gm.mu.Lock()
	defer gm.mu.Unlock()
	return gm.activeExitPeerID
}

func (gm *GatewayManager) ActiveExitIP() string {
	gm.mu.Lock()
	defer gm.mu.Unlock()
	return gm.activeExitIP
}

// ProtectEndpoint adds a specific host route to physical peer/relay IP via the physical gateway to prevent routing loops
func (gm *GatewayManager) ProtectEndpoint(endpointIP string) error {
	gm.mu.Lock()
	defer gm.mu.Unlock()

	ip := net.ParseIP(endpointIP)
	if ip == nil || ip.IsLoopback() || gm.bypassRoutes[endpointIP] {
		return nil
	}

	if gm.originalPhysicalGW == "" {
		gw, err := gm.GetOriginalPhysicalGateway()
		if err != nil {
			return err
		}
		gm.originalPhysicalGW = gw
	}

	gwLog.Info("Protecting P2P socket route for physical endpoint %s via physical gateway %s...", endpointIP, gm.originalPhysicalGW)

	if err := gm.addHostRouteOS(endpointIP, gm.originalPhysicalGW); err != nil {
		gwLog.Warn("Failed to add host route for %s: %v", endpointIP, err)
	}

	gm.bypassRoutes[endpointIP] = true
	return nil
}

// SetExitNode sets the specified peer TAP IP as the system default gateway (0.0.0.0/0)
func (gm *GatewayManager) SetExitNode(peerID string, exitTapIP string, physicalEndpoints []string) error {
	gm.mu.Lock()
	defer gm.mu.Unlock()

	if gm.activeExitPeerID != "" {
		gm.clearExitNodeUnlocked()
	}

	// 1. Detect physical gateway
	gw, err := gm.GetOriginalPhysicalGateway()
	if err != nil {
		gwLog.Warn("Failed to auto-detect physical default gateway: %v", err)
	} else {
		gm.originalPhysicalGW = gw
	}

	// 2. Protect physical socket endpoints to prevent loopback
	for _, ep := range physicalEndpoints {
		if ep != "" && gm.originalPhysicalGW != "" {
			_ = gm.addHostRouteOS(ep, gm.originalPhysicalGW)
			gm.bypassRoutes[ep] = true
		}
	}

	// 3. Add default route via TAP exit node IP
	gwLog.Info("Configuring Exit Node gateway %s (%s) on TAP interface...", exitTapIP, peerID)
	if err := gm.addDefaultRouteOS(exitTapIP, gm.tapName, 5); err != nil {
		return fmt.Errorf("failed to add default route via TAP exit node: %w", err)
	}

	gm.activeExitPeerID = peerID
	gm.activeExitIP = exitTapIP
	gwLog.Info("Successfully activated Exit Node %s (%s) as system default gateway!", exitTapIP, peerID)
	return nil
}

// ClearExitNode removes the TAP default route and restores physical default route
func (gm *GatewayManager) ClearExitNode() error {
	gm.mu.Lock()
	defer gm.mu.Unlock()
	return gm.clearExitNodeUnlocked()
}

func (gm *GatewayManager) clearExitNodeUnlocked() error {
	if gm.activeExitIP != "" {
		gwLog.Info("Clearing Exit Node gateway %s...", gm.activeExitIP)
		_ = gm.delDefaultRouteOS(gm.activeExitIP, gm.tapName)
	}

	// Clean up bypass host routes
	for ep := range gm.bypassRoutes {
		_ = gm.delHostRouteOS(ep)
	}
	gm.bypassRoutes = make(map[string]bool)
	gm.activeExitPeerID = ""
	gm.activeExitIP = ""
	gwLog.Info("Exit Node gateway cleared successfully.")
	return nil
}

func (gm *GatewayManager) AddSubnetRoute(subnetCIDR string, gatewayIP string) (bool, error) {
	gm.mu.Lock()
	defer gm.mu.Unlock()

	if gm.installedSubnets == nil {
		gm.installedSubnets = make(map[string]string)
	}

	// Skip duplicate OS route configuration if already installed with identical gateway
	if currentGW, exists := gm.installedSubnets[subnetCIDR]; exists && currentGW == gatewayIP {
		return false, nil
	}

	gwLog.Info("Configuring Subnet Route %s via peer gateway %s on TAP %s...", subnetCIDR, gatewayIP, gm.tapName)
	if err := gm.addCIDRRouteOS(subnetCIDR, gatewayIP, gm.tapName); err != nil {
		return false, err
	}

	gm.installedSubnets[subnetCIDR] = gatewayIP
	return true, nil
}

// ClearSubnetRoutes removes installed subnet routes when peer disconnects or configuration changes
func (gm *GatewayManager) ClearSubnetRoutes() {
	gm.mu.Lock()
	defer gm.mu.Unlock()

	for subnet, gw := range gm.installedSubnets {
		gwLog.Info("Cleaning up Subnet Route %s via gateway %s...", subnet, gw)
		_ = gm.delCIDRRouteOS(subnet, gw, gm.tapName)
	}
	gm.installedSubnets = make(map[string]string)
}
