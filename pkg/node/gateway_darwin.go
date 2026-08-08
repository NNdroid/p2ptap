//go:build darwin

package node

import (
	"bytes"
	"fmt"
	"net"
	"os/exec"
	"strings"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

func (gm *GatewayManager) GetOriginalPhysicalGateway() (string, error) {
	rib, err := route.FetchRIB(unix.AF_INET, route.RIBTypeRoute, 0)
	if err == nil {
		msgs, errParse := route.ParseRIB(route.RIBTypeRoute, rib)
		if errParse == nil {
			for _, msg := range msgs {
				rm, ok := msg.(*route.RouteMessage)
				if !ok {
					continue
				}
				if len(rm.Addrs) > unix.RTAX_GATEWAY {
					if dst, ok := rm.Addrs[unix.RTAX_DST].(*route.Inet4Addr); ok && dst.IP == [4]byte{0, 0, 0, 0} {
						if gw, ok := rm.Addrs[unix.RTAX_GATEWAY].(*route.Inet4Addr); ok {
							ip := net.IP(gw.IP[:]).String()
							if ip != "0.0.0.0" && !strings.HasPrefix(ip, "127.") {
								return ip, nil
							}
						}
					}
				}
			}
		}
	}

	// Fallback to route command
	cmd := exec.Command("sh", "-c", "netstat -rn -f inet | awk '/default/{print $2}' | head -n1")
	out, err := cmd.Output()
	if err == nil && len(out) > 0 {
		return strings.TrimSpace(string(out)), nil
	}
	return "", fmt.Errorf("unable to detect physical default gateway on darwin")
}

func (gm *GatewayManager) addHostRouteOS(endpointIP, gwIP string) error {
	ip := net.ParseIP(endpointIP)
	if ip == nil {
		return fmt.Errorf("invalid endpoint IP: %s", endpointIP)
	}
	if ip.To4() != nil {
		cmd := exec.Command("route", "-n", "add", "-host", endpointIP, gwIP)
		return cmd.Run()
	}
	// IPv6 host route: route -n add -inet6 <ip>/128 <gw>
	cmd := exec.Command("route", "-n", "add", "-inet6", endpointIP+"/128", gwIP)
	return cmd.Run()
}

func (gm *GatewayManager) delHostRouteOS(endpointIP string) error {
	ip := net.ParseIP(endpointIP)
	if ip == nil {
		return nil // nothing to delete
	}
	if ip.To4() != nil {
		cmd := exec.Command("route", "-n", "delete", "-host", endpointIP)
		return cmd.Run()
	}
	cmd := exec.Command("route", "-n", "delete", "-inet6", endpointIP+"/128")
	return cmd.Run()
}

func (gm *GatewayManager) addDefaultRouteOS(exitTapIP, tapDevName string, metric int) error {
	cmd := exec.Command("route", "-n", "add", "default", exitTapIP)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to add default route on darwin: %v (%s)", err, stderr.String())
	}
	return nil
}

func (gm *GatewayManager) delDefaultRouteOS(exitTapIP, tapDevName string) error {
	cmd := exec.Command("route", "-n", "delete", "default", exitTapIP)
	return cmd.Run()
}

func (gm *GatewayManager) addCIDRRouteOS(cidrStr, gatewayIP, tapDevName string) error {
	_, dstNet, err := net.ParseCIDR(cidrStr)
	if err != nil {
		return err
	}
	// macOS route -n add defaults to -inet (IPv4); for IPv6 we need -inet6.
	if dstNet.IP.To4() != nil {
		cmd := exec.Command("route", "-n", "add", "-net", cidrStr, gatewayIP)
		return cmd.Run()
	}
	cmd := exec.Command("route", "-n", "add", "-inet6", cidrStr, gatewayIP)
	return cmd.Run()
}

func (gm *GatewayManager) delCIDRRouteOS(cidrStr, gatewayIP, tapDevName string) error {
	_, dstNet, err := net.ParseCIDR(cidrStr)
	if err != nil {
		return err
	}
	if dstNet.IP.To4() != nil {
		cmd := exec.Command("route", "-n", "delete", "-net", cidrStr, gatewayIP)
		return cmd.Run()
	}
	cmd := exec.Command("route", "-n", "delete", "-inet6", cidrStr, gatewayIP)
	return cmd.Run()
}
