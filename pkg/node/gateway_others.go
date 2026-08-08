//go:build !linux && !windows && !darwin

package node

import "fmt"

func (gm *GatewayManager) GetOriginalPhysicalGateway() (string, error) {
	return "", fmt.Errorf("unsupported OS for gateway manager")
}

func (gm *GatewayManager) addHostRouteOS(endpointIP, gwIP string) error {
	return nil
}

func (gm *GatewayManager) delHostRouteOS(endpointIP string) error {
	return nil
}

func (gm *GatewayManager) addDefaultRouteOS(exitTapIP, tapDevName string, metric int) error {
	return nil
}

func (gm *GatewayManager) delDefaultRouteOS(exitTapIP, tapDevName string) error {
	return nil
}

func (gm *GatewayManager) addCIDRRouteOS(cidrStr, gatewayIP, tapDevName string) error {
	return nil
}

func (gm *GatewayManager) delCIDRRouteOS(cidrStr, gatewayIP, tapDevName string) error {
	return nil
}
