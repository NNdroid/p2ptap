//go:build windows

package node

import (
	"fmt"
	"net"
	"net/netip"
	"strings"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

func getLUIDByName(name string) (winipcfg.LUID, error) {
	adapters, err := winipcfg.GetAdaptersAddresses(windows.AF_UNSPEC, winipcfg.GAAFlagIncludeGateways)
	if err != nil {
		return 0, err
	}
	for _, a := range adapters {
		if strings.EqualFold(a.FriendlyName(), name) {
			return a.LUID, nil
		}
	}
	return 0, fmt.Errorf("adapter %q not found", name)
}

func (gm *GatewayManager) GetOriginalPhysicalGateway() (string, error) {
	routes, err := winipcfg.GetIPForwardTable2(windows.AF_INET)
	if err != nil {
		return "", fmt.Errorf("winipcfg GetIPForwardTable2 failed: %w", err)
	}

	for _, r := range routes {
		ip := r.NextHop.Addr()
		if r.DestinationPrefix.Prefix().Bits() == 0 && ip.IsValid() && !ip.IsLoopback() && !ip.IsUnspecified() {
			return ip.String(), nil
		}
	}
	return "", fmt.Errorf("no physical default gateway found on Windows via winipcfg")
}

func (gm *GatewayManager) addHostRouteOS(endpointIP, gwIP string) error {
	ip := net.ParseIP(endpointIP)
	if ip == nil {
		return fmt.Errorf("invalid endpoint IP: %s", endpointIP)
	}

	var dstPrefix netip.Prefix
	var afFamily winipcfg.AddressFamily
	var prefixLen string
	if ip.To4() != nil {
		afFamily = winipcfg.AddressFamily(windows.AF_INET)
		prefixLen = "/32"
	} else {
		afFamily = winipcfg.AddressFamily(windows.AF_INET6)
		prefixLen = "/128"
	}

	var err error
	dstPrefix, err = netip.ParsePrefix(endpointIP + prefixLen)
	if err != nil {
		return err
	}
	gwAddr, err := netip.ParseAddr(gwIP)
	if err != nil {
		return err
	}

	routes, err := winipcfg.GetIPForwardTable2(afFamily)
	if err != nil {
		return err
	}
	for _, r := range routes {
		if r.DestinationPrefix.Prefix() == dstPrefix {
			_ = r.Delete()
		}
	}

	// Find physical adapter LUID matching physical gateway
	var physLUID winipcfg.LUID
	for _, r := range routes {
		if r.NextHop.Addr() == gwAddr {
			physLUID = r.InterfaceLUID
			break
		}
	}

	if physLUID != 0 {
		return physLUID.AddRoute(dstPrefix, gwAddr, 1)
	}

	// Fallback to searching adapters
	adapters, err := winipcfg.GetAdaptersAddresses(windows.AF_UNSPEC, winipcfg.GAAFlagIncludeGateways)
	if err == nil {
		for _, a := range adapters {
			if a.IfType != windows.IF_TYPE_SOFTWARE_LOOPBACK {
				return a.LUID.AddRoute(dstPrefix, gwAddr, 1)
			}
		}
	}
	return fmt.Errorf("no physical adapter found for endpoint route")
}

func (gm *GatewayManager) delHostRouteOS(endpointIP string) error {
	ip := net.ParseIP(endpointIP)
	if ip == nil {
		return nil
	}

	var prefixLen string
	var afFamily winipcfg.AddressFamily
	if ip.To4() != nil {
		afFamily = winipcfg.AddressFamily(windows.AF_INET)
		prefixLen = "/32"
	} else {
		afFamily = winipcfg.AddressFamily(windows.AF_INET6)
		prefixLen = "/128"
	}

	dstPrefix, err := netip.ParsePrefix(endpointIP + prefixLen)
	if err != nil {
		return nil
	}

	routes, err := winipcfg.GetIPForwardTable2(afFamily)
	if err != nil {
		return nil
	}

	for _, r := range routes {
		if r.DestinationPrefix.Prefix() == dstPrefix {
			_ = r.Delete()
		}
	}
	return nil
}

func (gm *GatewayManager) addDefaultRouteOS(exitTapIP, tapDevName string, metric int) error {
	luid, err := getLUIDByName(tapDevName)
	if err != nil {
		return fmt.Errorf("winipcfg getLUIDByName(%s) failed: %w", tapDevName, err)
	}

	defaultPrefix := netip.MustParsePrefix("0.0.0.0/0")
	exitPrefix, err := netip.ParsePrefix(exitTapIP)
	if err != nil {
		return err
	}
	exitAddr := exitPrefix.Addr()

	return luid.AddRoute(defaultPrefix, exitAddr, uint32(metric))
}

func (gm *GatewayManager) delDefaultRouteOS(exitTapIP, tapDevName string) error {
	luid, err := getLUIDByName(tapDevName)
	if err != nil {
		return nil
	}

	defaultPrefix := netip.MustParsePrefix("0.0.0.0/0")
	exitPrefix, err := netip.ParsePrefix(exitTapIP)
	if err != nil {
		return nil
	}
	exitAddr := exitPrefix.Addr()

	return luid.DeleteRoute(defaultPrefix, exitAddr)
}

func (gm *GatewayManager) addCIDRRouteOS(cidrStr, gatewayIP, tapDevName string) error {
	luid, err := getLUIDByName(tapDevName)
	if err != nil {
		return fmt.Errorf("winipcfg getLUIDByName(%s) failed: %w", tapDevName, err)
	}

	prefix, err := netip.ParsePrefix(cidrStr)
	if err != nil {
		return err
	}
	gwAddr, err := netip.ParseAddr(gatewayIP)
	if err != nil {
		return err
	}

	return luid.AddRoute(prefix, gwAddr, 10)
}

func (gm *GatewayManager) delCIDRRouteOS(cidrStr, gatewayIP, tapDevName string) error {
	luid, err := getLUIDByName(tapDevName)
	if err != nil {
		return err
	}
	prefix, err := netip.ParsePrefix(cidrStr)
	if err != nil {
		return err
	}
	gwAddr, err := netip.ParseAddr(gatewayIP)
	if err != nil {
		return err
	}
	return luid.DeleteRoute(prefix, gwAddr)
}
