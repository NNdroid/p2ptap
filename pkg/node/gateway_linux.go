//go:build linux

package node

import (
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
)

func (gm *GatewayManager) GetOriginalPhysicalGateway() (string, error) {
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{
		Dst: nil,
	}, netlink.RT_FILTER_DST)
	if err != nil {
		return "", fmt.Errorf("netlink route list failed: %w", err)
	}

	for _, r := range routes {
		if r.Gw != nil && !r.Gw.IsLoopback() && !r.Gw.IsUnspecified() {
			return r.Gw.String(), nil
		}
	}
	return "", fmt.Errorf("no physical default gateway found via netlink")
}

func (gm *GatewayManager) addHostRouteOS(endpointIP, gwIP string) error {
	ip := net.ParseIP(endpointIP)
	gw := net.ParseIP(gwIP)
	if ip == nil || gw == nil {
		return fmt.Errorf("invalid IP or gateway")
	}

	route := &netlink.Route{
		Dst: &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)},
		Gw:  gw,
	}
	return netlink.RouteReplace(route)
}

func (gm *GatewayManager) delHostRouteOS(endpointIP string) error {
	ip := net.ParseIP(endpointIP)
	if ip == nil {
		return nil
	}
	route := &netlink.Route{
		Dst: &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)},
	}
	return netlink.RouteDel(route)
}

func (gm *GatewayManager) addDefaultRouteOS(exitTapIP, tapDevName string, metric int) error {
	link, err := netlink.LinkByName(tapDevName)
	if err != nil {
		return fmt.Errorf("netlink link by name %q: %w", tapDevName, err)
	}

	_, defaultDst, _ := net.ParseCIDR("0.0.0.0/0")
	route := &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       defaultDst,
		Gw:        net.ParseIP(exitTapIP),
		Priority:  metric,
	}
	return netlink.RouteReplace(route)
}

func (gm *GatewayManager) delDefaultRouteOS(exitTapIP, tapDevName string) error {
	link, err := netlink.LinkByName(tapDevName)
	var linkIdx int
	if err == nil {
		linkIdx = link.Attrs().Index
	}

	_, defaultDst, _ := net.ParseCIDR("0.0.0.0/0")
	route := &netlink.Route{
		LinkIndex: linkIdx,
		Dst:       defaultDst,
		Gw:        net.ParseIP(exitTapIP),
	}
	return netlink.RouteDel(route)
}

func (gm *GatewayManager) addCIDRRouteOS(cidrStr, gatewayIP, tapDevName string) error {
	link, err := netlink.LinkByName(tapDevName)
	if err != nil {
		return fmt.Errorf("netlink link by name %q: %w", tapDevName, err)
	}

	_, dstCIDR, err := net.ParseCIDR(cidrStr)
	if err != nil {
		return err
	}

	route := &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       dstCIDR,
		Gw:        net.ParseIP(gatewayIP),
		Priority:  10,
	}
	return netlink.RouteReplace(route)
}

func (gm *GatewayManager) delCIDRRouteOS(cidrStr, gatewayIP, tapDevName string) error {
	link, err := netlink.LinkByName(tapDevName)
	if err != nil {
		return err
	}
	_, dstCIDR, err := net.ParseCIDR(cidrStr)
	if err != nil {
		return err
	}
	route := &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       dstCIDR,
		Gw:        net.ParseIP(gatewayIP),
	}
	return netlink.RouteDel(route)
}
