package node

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/multiformats/go-multiaddr"
	"github.com/pion/stun/v3"
)

// stunReflexiveAddrs holds the server-reflexive addresses discovered via STUN.
// These are injected into the address factory so that QUIC and hole punching
// can use them for NAT traversal — even for CGNAT nodes that have no UPnP/PMP.
var stunReflexiveAddrs atomic.Pointer[[]multiaddr.Multiaddr]

// setSTUNReflexiveAddrs stores the discovered server-reflexive addresses.
func setSTUNReflexiveAddrs(addrs []multiaddr.Multiaddr) {
	if len(addrs) == 0 {
		stunReflexiveAddrs.Store(nil)
		return
	}
	stunReflexiveAddrs.Store(&addrs)
}

// getSTUNReflexiveAddrs returns the current server-reflexive addresses.
func getSTUNReflexiveAddrs() []multiaddr.Multiaddr {
	ptr := stunReflexiveAddrs.Load()
	if ptr == nil {
		return nil
	}
	return *ptr
}

// startSTUNBinder periodically binds to configured STUN servers to discover the
// node's server-reflexive (public) address. For CGNAT nodes that lack UPnP/PMP
// port mapping, this is the only way to obtain a public address suitable for
// QUIC hole punching.
func (n *Node) startSTUNBinder(ctx context.Context) {
	if len(n.config().StunServers) == 0 {
		return
	}

	go func() {
		defer n.wg.Done()
		bindCtx, cancel := context.WithCancel(ctx)
		defer cancel()

		if err := n.stunBindOnce(bindCtx); err != nil {
			log.Debug("STUN binder initial bind failed: %v", err)
		}

		ticker := time.NewTicker(3 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-bindCtx.Done():
				return
			case <-ticker.C:
				if err := n.stunBindOnce(bindCtx); err != nil {
					log.Debug("STUN binder periodic bind failed: %v", err)
				}
			}
		}
	}()
}

func (n *Node) stunBindOnce(ctx context.Context) error {
	cfg := n.config()
	if len(cfg.StunServers) == 0 {
		return nil
	}

	var discovered []multiaddr.Multiaddr

	for _, server := range cfg.StunServers {
		if ctx.Err() != nil {
			break
		}
		addr, err := stunQuery(ctx, server)
		if err != nil {
			log.Debug("STUN query failed for %s: %v", server, err)
			continue
		}
		ma, err := multiaddr.NewMultiaddr(fmt.Sprintf("/ip4/%s/udp/%d", addr.IP.String(), addr.Port))
		if err != nil {
			log.Debug("Failed to create multiaddr for STUN result %v: %v", addr, err)
			continue
		}
		discovered = append(discovered, ma)
		log.Debug("STUN discovered server-reflexive address: %s (via %s)", ma.String(), server)
	}

	if len(discovered) > 0 {
		setSTUNReflexiveAddrs(discovered)
	}
	return nil
}

// stunQuery sends a STUN Binding Request and returns the server-reflexive address.
func stunQuery(ctx context.Context, server string) (net.UDPAddr, error) {
	serverAddr, err := normalizeSTUNServer(server)
	if err != nil {
		return net.UDPAddr{}, err
	}

	conn, err := net.DialUDP("udp", nil, &serverAddr)
	if err != nil {
		return net.UDPAddr{}, fmt.Errorf("dial %s: %w", serverAddr.String(), err)
	}
	defer conn.Close()

	// Build the STUN Binding Request.
	msg := stun.New()
	msg.Type = stun.BindingRequest
	if err := msg.NewTransactionID(); err != nil {
		return net.UDPAddr{}, fmt.Errorf("generate transaction ID: %w", err)
	}
	msg.Encode()

	if err := conn.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return net.UDPAddr{}, err
	}
	if _, err := conn.Write(msg.Raw); err != nil {
		return net.UDPAddr{}, fmt.Errorf("send STUN request: %w", err)
	}

	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return net.UDPAddr{}, err
	}

	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		return net.UDPAddr{}, fmt.Errorf("read STUN response: %w", err)
	}

	resp := &stun.Message{Raw: buf[:n]}
	if err := resp.Decode(); err != nil {
		return net.UDPAddr{}, fmt.Errorf("decode STUN response: %w", err)
	}
	if resp.Type != stun.BindingSuccess {
		return net.UDPAddr{}, fmt.Errorf("unexpected STUN response type: %s", resp.Type)
	}

	var xa stun.XORMappedAddress
	if err := xa.GetFrom(resp); err != nil {
		return net.UDPAddr{}, fmt.Errorf("missing XOR-MAPPED-ADDRESS: %w", err)
	}
	return net.UDPAddr{IP: xa.IP, Port: xa.Port}, nil
}

// normalizeSTUNServer converts various STUN server formats to a UDP address.
func normalizeSTUNServer(s string) (net.UDPAddr, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "/udp/")
	s = strings.TrimPrefix(s, "stun:")
	s = strings.TrimPrefix(s, "turn:")

	if idx := strings.LastIndex(s, ":"); idx >= 0 {
		host := strings.TrimSuffix(strings.TrimPrefix(s[:idx], "["), "]")
		portStr := s[idx+1:]
		var portNum int
		fmt.Sscanf(portStr, "%d", &portNum)
		if portNum == 0 {
			portNum = 3478
		}
		return net.UDPAddr{IP: net.ParseIP(host), Port: portNum}, nil
	}

	port := 3478
	if strings.Contains(s, "google.com") {
		port = 19302
	}
	return net.UDPAddr{IP: net.ParseIP(s), Port: port}, nil
}