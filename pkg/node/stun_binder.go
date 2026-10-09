package node

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/multiformats/go-multiaddr"
	"github.com/pion/stun/v3"
)

// stunAttrNames formats the attribute list for debug logging.
func stunAttrNames(msg *stun.Message) string {
	parts := make([]string, 0, len(msg.Attributes))
	for _, a := range msg.Attributes {
		parts = append(parts, a.Type.String())
	}
	return strings.Join(parts, ", ")
}

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
	servers := n.config().StunServers
	if len(servers) == 0 {
		log.Debug("STUN binder: no STUN servers configured, skipping")
		return
	}

	log.Info("STUN binder starting with %d server(s): %v", len(servers), servers)

	go func() {
		defer n.wg.Done()
		bindCtx, cancel := context.WithCancel(ctx)
		defer cancel()

		log.Debug("STUN binder: performing initial bind")
		if err := n.stunBindOnce(bindCtx); err != nil {
			log.Debug("STUN binder initial bind failed: %v", err)
		}

		const rebindInterval = 3 * time.Minute
		ticker := time.NewTicker(rebindInterval)
		defer ticker.Stop()

		log.Debug("STUN binder: periodic rebind interval set to %v", rebindInterval)

		for {
			select {
			case <-bindCtx.Done():
				log.Debug("STUN binder stopped")
				return
			case <-ticker.C:
				log.Debug("STUN binder: periodic rebind triggered")
				if err := n.stunBindOnce(bindCtx); err != nil {
					log.Debug("STUN binder periodic bind failed: %v", err)
				}
			}
		}
	}()
}

func (n *Node) stunBindOnce(ctx context.Context) error {
	cfg := n.config()
	servers := cfg.StunServers
	if len(servers) == 0 {
		return nil
	}

	log.Debug("STUN bind cycle started (%d server(s) to query)", len(servers))
	startTime := time.Now()

	prevAddrs := getSTUNReflexiveAddrs()

	var discovered []multiaddr.Multiaddr
	var successes, failures int

	for i, server := range servers {
		if ctx.Err() != nil {
			log.Debug("STUN bind cycle aborted: context cancelled")
			break
		}

		log.Debug("STUN bind cycle [%d/%d]: querying %s", i+1, len(servers), server)

		addr, err := stunQuery(ctx, server)
		if err != nil {
			failures++
			log.Debug("STUN query failed for %s: %v", server, err)
			continue
		}
		successes++

		ma, err := multiaddr.NewMultiaddr(fmt.Sprintf("/ip4/%s/udp/%d", addr.IP.String(), addr.Port))
		if err != nil {
			failures++
			log.Debug("Failed to create multiaddr for STUN result %v: %v", addr, err)
			continue
		}
		discovered = append(discovered, ma)
		log.Debug("STUN discovered server-reflexive address: %s (via %s)", ma.String(), server)
	}

	elapsed := time.Since(startTime)
	log.Debug("STUN bind cycle completed in %v: %d success, %d failure(s)", elapsed, successes, failures)

	if len(discovered) > 0 {
		// Check if addresses changed from previous cycle
		addrsChanged := len(prevAddrs) != len(discovered)
		if !addrsChanged {
			for i := range discovered {
				if i < len(prevAddrs) && prevAddrs[i].String() != discovered[i].String() {
					addrsChanged = true
					break
				}
			}
		}

		if addrsChanged {
			log.Info("STUN server-reflexive addresses UPDATED: %v", discovered)
		} else {
			log.Debug("STUN server-reflexive addresses unchanged: %v", discovered)
		}
		setSTUNReflexiveAddrs(discovered)
	} else {
		if len(prevAddrs) > 0 {
			log.Debug("STUN bind cycle produced no results, clearing %d previous address(es)", len(prevAddrs))
			setSTUNReflexiveAddrs(nil)
		} else {
			log.Debug("STUN bind cycle produced no results (no previous addresses to clear)")
		}
	}

	return nil
}

// stunQuery sends a STUN Binding Request and returns the server-reflexive address.
func stunQuery(ctx context.Context, server string) (net.UDPAddr, error) {
	startTime := time.Now()

	serverAddr, err := normalizeSTUNServer(server)
	if err != nil {
		return net.UDPAddr{}, fmt.Errorf("normalize STUN server %q: %w", server, err)
	}
	if serverAddr.IP == nil {
		return net.UDPAddr{}, fmt.Errorf("resolved STUN server %q to nil IP", server)
	}
	log.Debug("STUN query: normalized server %q -> %s:%d", server, serverAddr.IP.String(), serverAddr.Port)

	conn, err := net.DialUDP("udp", nil, &serverAddr)
	if err != nil {
		return net.UDPAddr{}, fmt.Errorf("dial %s: %w", serverAddr.String(), err)
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	log.Debug("STUN query: connected to %s via local socket %s", serverAddr.String(), localAddr.String())

	// Build the STUN Binding Request.
	msg := stun.New()
	msg.Type = stun.BindingRequest
	if err := msg.NewTransactionID(); err != nil {
		return net.UDPAddr{}, fmt.Errorf("generate transaction ID: %w", err)
	}
	log.Debug("STUN query: sending Binding Request (txID=%x)", msg.TransactionID[:4])
	msg.Encode()

	if err := conn.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return net.UDPAddr{}, err
	}
	if _, err := conn.Write(msg.Raw); err != nil {
		return net.UDPAddr{}, fmt.Errorf("send STUN request to %s: %w", serverAddr.String(), err)
	}

	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return net.UDPAddr{}, err
	}

	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		return net.UDPAddr{}, fmt.Errorf("read STUN response from %s: %w", serverAddr.String(), err)
	}

	latency := time.Since(startTime)
	log.Debug("STUN query: received %d bytes response from %s in %v", n, serverAddr.String(), latency)

	resp := &stun.Message{Raw: buf[:n]}
	if err := resp.Decode(); err != nil {
		return net.UDPAddr{}, fmt.Errorf("decode STUN response from %s: %w", serverAddr.String(), err)
	}

	log.Debug("STUN response: type=%s, txID=%x, attrs=[%s]", resp.Type, resp.TransactionID[:4], stunAttrNames(resp))

	if resp.Type != stun.BindingSuccess {
		// Try to extract error code for diagnostics
		errMsg := "unknown"
		if ecBytes, err := resp.Get(stun.AttrErrorCode); err == nil {
			errMsg = string(ecBytes)
		}
		return net.UDPAddr{}, fmt.Errorf("unexpected STUN response type %s from %s: %s", resp.Type, serverAddr.String(), errMsg)
	}

	var xa stun.XORMappedAddress
	if err := xa.GetFrom(resp); err != nil {
		return net.UDPAddr{}, fmt.Errorf("missing XOR-MAPPED-ADDRESS in response from %s: %w", serverAddr.String(), err)
	}

	result := net.UDPAddr{IP: xa.IP, Port: xa.Port}

	// Log NAT type inference: compare local socket address with server-reflexive address
	if localAddr.IP.Equal(result.IP) {
		log.Debug("STUN NAT type: open internet (no NAT) — server-reflexive == local address")
	} else if localAddr.Port == result.Port {
		log.Debug("STUN NAT type: restricted cone NAT (port preserved, IP changed)")
	} else {
		log.Debug("STUN NAT type: restricted full-cone NAT (port changed: local=%d, reflexive=%d)",
			localAddr.Port, result.Port)
	}

	// Log additional STUN attributes for diagnostics
	if swBytes, err := resp.Get(stun.AttrSoftware); err == nil {
		log.Debug("STUN server software: %s (from %s)", string(swBytes), serverAddr.String())
	}
	if ctBytes, err := resp.Get(stun.AttrCacheTimeout); err == nil {
		if len(ctBytes) >= 4 {
			timeout := int32(ctBytes[0])<<24 | int32(ctBytes[1])<<16 | int32(ctBytes[2])<<8 | int32(ctBytes[3])
			log.Debug("STUN cache timeout: %d seconds (from %s)", timeout, serverAddr.String())
		}
	}
	if rsBytes, err := resp.Get(stun.AttrAlternateServer); err == nil {
		log.Debug("STUN alternate server hint: %s (from %s)", string(rsBytes), serverAddr.String())
	}

	log.Debug("STUN query result: %s (via %s, local=%s, latency=%v)",
		result.String(), serverAddr.String(), localAddr.String(), latency)

	return result, nil
}

// normalizeSTUNServer converts various STUN server formats to a UDP address.
func normalizeSTUNServer(s string) (net.UDPAddr, error) {
	original := s
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "/udp/")
	s = strings.TrimPrefix(s, "stun:")
	s = strings.TrimPrefix(s, "turn:")

	if idx := strings.LastIndex(s, ":"); idx >= 0 {
		host := strings.TrimSuffix(strings.TrimPrefix(s[:idx], "["), "]")
		portStr := s[idx+1:]
		portNum, err := strconv.Atoi(portStr)
		if err != nil {
			portNum = 3478
		}
		if portNum == 0 {
			portNum = 3478
		}
		log.Debug("STUN server normalized: %q -> %s:%d", original, host, portNum)
		return net.UDPAddr{IP: net.ParseIP(host), Port: portNum}, nil
	}

	port := 3478
	if strings.Contains(s, "google.com") {
		port = 19302
	}
	log.Debug("STUN server normalized: %q -> %s:%d (hostname-based)", original, s, port)
	return net.UDPAddr{IP: net.ParseIP(s), Port: port}, nil
}
