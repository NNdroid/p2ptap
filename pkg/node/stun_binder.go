package node

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
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

// stunReflexiveAddrs holds the UDP server-reflexive addresses discovered via STUN.
var stunReflexiveAddrs atomic.Pointer[[]multiaddr.Multiaddr]

func setSTUNReflexiveAddrs(addrs []multiaddr.Multiaddr) {
	if len(addrs) == 0 {
		stunReflexiveAddrs.Store(nil)
		return
	}
	stunReflexiveAddrs.Store(&addrs)
}

func getSTUNReflexiveAddrs() []multiaddr.Multiaddr {
	ptr := stunReflexiveAddrs.Load()
	if ptr == nil {
		return nil
	}
	return *ptr
}

// tcpStunReflexiveAddrs holds the TCP server-reflexive addresses discovered via TCP STUN.
var tcpStunReflexiveAddrs atomic.Pointer[[]multiaddr.Multiaddr]

func setTCPStunReflexiveAddrs(addrs []multiaddr.Multiaddr) {
	if len(addrs) == 0 {
		tcpStunReflexiveAddrs.Store(nil)
		return
	}
	tcpStunReflexiveAddrs.Store(&addrs)
}

func getTCPStunReflexiveAddrs() []multiaddr.Multiaddr {
	ptr := tcpStunReflexiveAddrs.Load()
	if ptr == nil {
		return nil
	}
	return *ptr
}

// startSTUNBinder periodically binds to configured STUN servers to discover the
// node's server-reflexive addresses via UDP and TCP STUN (RFC 7675).
func (n *Node) startSTUNBinder(ctx context.Context) {
	servers := n.config().StunServers
	if len(servers) == 0 {
		log.Debug("STUN binder: no STUN servers configured, skipping")
		n.wg.Done()
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

	log.Debug("STUN bind cycle started (%d server(s) to query, max concurrency=10)", len(servers))
	startTime := time.Now()

	// Bound the total cycle time so a large server list with slow/failing
	// servers does not hold the binder for minutes. Individual queries already
	// have a 5 s timeout; this adds a global cap.
	cycleCtx, cycleCancel := context.WithTimeout(ctx, 90*time.Second)
	defer cycleCancel()

	const maxConcurrent = 10
	sem := make(chan struct{}, maxConcurrent)
	var wg sync.WaitGroup
	var mu sync.Mutex

	var udpDiscovered []multiaddr.Multiaddr
	var tcpDiscovered []multiaddr.Multiaddr
	var udpSuccesses, udpFailures int
	var tcpSuccesses, tcpFailures int

	for _, server := range servers {
		if cycleCtx.Err() != nil {
			log.Debug("STUN bind cycle aborted: cycle timeout reached")
			break
		}

		select {
		case sem <- struct{}{}:
		case <-cycleCtx.Done():
			wg.Wait()
			return cycleCtx.Err()
		}
		wg.Add(1)
		go func(server string) {
			defer wg.Done()
			defer func() { <-sem }()

			if cycleCtx.Err() != nil {
				return
			}

			serverAddr, isTCP, err := normalizeSTUNServer(cycleCtx, server)
			if err != nil {
				mu.Lock()
				if isTCP {
					tcpFailures++
				} else {
					udpFailures++
				}
				mu.Unlock()
				return
			}

			addr, err := stunQuery(cycleCtx, server, serverAddr, isTCP)
			if err != nil {
				mu.Lock()
				if isTCP {
					tcpFailures++
				} else {
					udpFailures++
				}
				mu.Unlock()
				return
			}

			ipPrefix := "/ip4/"
			if addr.IP.To4() == nil {
				ipPrefix = "/ip6/"
			}

			var ma multiaddr.Multiaddr
			if isTCP {
				ma, err = multiaddr.NewMultiaddr(fmt.Sprintf("%s%s/tcp/%d", ipPrefix, addr.IP.String(), addr.Port))
				if err != nil {
					mu.Lock()
					tcpFailures++
					mu.Unlock()
					return
				}
				mu.Lock()
				tcpSuccesses++
				tcpDiscovered = append(tcpDiscovered, ma)
				mu.Unlock()
			} else {
				ma, err = multiaddr.NewMultiaddr(fmt.Sprintf("%s%s/udp/%d/quic-v1", ipPrefix, addr.IP.String(), addr.Port))
				if err != nil {
					mu.Lock()
					udpFailures++
					mu.Unlock()
					return
				}
				mu.Lock()
				udpSuccesses++
				udpDiscovered = append(udpDiscovered, ma)
				mu.Unlock()
			}
			log.Debug("STUN discovered server-reflexive address: %s (via %s, tcp=%v)", ma.String(), server, isTCP)
		}(server)
	}

	wg.Wait()

	elapsed := time.Since(startTime)
	log.Debug("STUN bind cycle completed in %v: UDP %d/%d, TCP %d/%d",
		elapsed, udpSuccesses, udpSuccesses+udpFailures, tcpSuccesses, tcpSuccesses+tcpFailures)

	// Merge and store UDP addresses
	mergeAndStoreSTUNAddrs(udpDiscovered, getSTUNReflexiveAddrs(), udpFailures)
	// Merge and store TCP addresses
	mergeAndStoreTCPSTUNAddrs(tcpDiscovered, getTCPStunReflexiveAddrs(), tcpFailures)

	return nil
}

// mergeAndStoreSTUNAddrs merges newly discovered addresses with previous ones (dedup).
func mergeAndStoreSTUNAddrs(newAddrs, prevAddrs []multiaddr.Multiaddr, failures int) {
	var merged []multiaddr.Multiaddr
	seen := make(map[string]bool)

	if failures > 0 && len(prevAddrs) > 0 {
		for _, a := range prevAddrs {
			if !seen[a.String()] {
				merged = append(merged, a)
				seen[a.String()] = true
			}
		}
		for _, a := range newAddrs {
			if !seen[a.String()] {
				merged = append(merged, a)
				seen[a.String()] = true
			}
		}
		log.Debug("STUN partial failure (%d failures): keeping %d prev + %d new = %d total",
			failures, len(prevAddrs), len(newAddrs), len(merged))
	} else {
		for _, a := range newAddrs {
			if !seen[a.String()] {
				merged = append(merged, a)
				seen[a.String()] = true
			}
		}
	}

	if len(merged) > 0 {
		addrsChanged := len(prevAddrs) != len(merged)
		if !addrsChanged {
			for i := range merged {
				if i < len(prevAddrs) && prevAddrs[i].String() != merged[i].String() {
					addrsChanged = true
					break
				}
			}
		}
		if addrsChanged {
			log.Info("UDP STUN server-reflexive addresses UPDATED: %v", merged)
		} else {
			log.Debug("UDP STUN server-reflexive addresses unchanged: %v", merged)
		}
		setSTUNReflexiveAddrs(merged)
	} else {
		if len(prevAddrs) > 0 {
			log.Warn("STUN bind cycle produced no UDP results — keeping %d previous address(es)", len(prevAddrs))
		} else {
			log.Debug("STUN bind cycle produced no UDP results")
		}
	}
}

// mergeAndStoreTCPSTUNAddrs merges TCP STUN addresses with previous ones (dedup).
func mergeAndStoreTCPSTUNAddrs(newAddrs, prevAddrs []multiaddr.Multiaddr, failures int) {
	var merged []multiaddr.Multiaddr
	seen := make(map[string]bool)

	if failures > 0 && len(prevAddrs) > 0 {
		for _, a := range prevAddrs {
			if !seen[a.String()] {
				merged = append(merged, a)
				seen[a.String()] = true
			}
		}
		for _, a := range newAddrs {
			if !seen[a.String()] {
				merged = append(merged, a)
				seen[a.String()] = true
			}
		}
		log.Debug("TCP STUN partial failure (%d failures): keeping %d prev + %d new = %d total",
			failures, len(prevAddrs), len(newAddrs), len(merged))
	} else {
		for _, a := range newAddrs {
			if !seen[a.String()] {
				merged = append(merged, a)
				seen[a.String()] = true
			}
		}
	}

	if len(merged) == 0 {
		if len(prevAddrs) > 0 {
			log.Warn("TCP STUN bind cycle produced no results — keeping %d previous address(es)", len(prevAddrs))
		} else {
			log.Debug("TCP STUN bind cycle produced no results")
		}
		return
	}

	addrsChanged := len(prevAddrs) != len(merged)
	if !addrsChanged {
		for i := range merged {
			if i < len(prevAddrs) && prevAddrs[i].String() != merged[i].String() {
				addrsChanged = true
				break
			}
		}
	}
	if addrsChanged {
		log.Info("TCP STUN server-reflexive addresses UPDATED: %v", merged)
	} else {
		log.Debug("TCP STUN server-reflexive addresses unchanged: %v", merged)
	}
	setTCPStunReflexiveAddrs(merged)
}

// normalizeSTUNServer parses a STUN server string and returns the resolved address.
// Returns (net.Addr, isTCP, error). isTCP is true if the server is a TCP STUN server.
func normalizeSTUNServer(ctx context.Context, s string) (net.Addr, bool, error) {
	original := s
	s = strings.TrimSpace(s)

	isTCP := false
	if strings.HasPrefix(s, "/tcp/") {
		isTCP = true
		s = strings.TrimPrefix(s, "/tcp/")
	} else if strings.HasPrefix(s, "/udp/") {
		s = strings.TrimPrefix(s, "/udp/")
	} else if strings.HasPrefix(s, "stun:") {
		s = strings.TrimPrefix(s, "stun:")
	} else if strings.HasPrefix(s, "turn:") {
		s = strings.TrimPrefix(s, "turn:")
	} else if strings.HasPrefix(s, "tcp:") {
		isTCP = true
		s = strings.TrimPrefix(s, "tcp:")
	}

	// Parse host:port
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
		ip, err := resolveIP(ctx, host)
		if err != nil {
			return nil, isTCP, fmt.Errorf("cannot resolve STUN host %q: %w", host, err)
		}
		log.Debug("STUN server normalized: %q -> %s:%d (tcp=%v)", original, ip.String(), portNum, isTCP)
		if isTCP {
			return &net.TCPAddr{IP: ip, Port: portNum}, isTCP, nil
		}
		return &net.UDPAddr{IP: ip, Port: portNum}, isTCP, nil
	}

	// No port specified, use default
	port := 3478
	if strings.Contains(s, "google.com") {
		port = 19302
	}
	ip, err := resolveIP(ctx, s)
	if err != nil {
		return nil, isTCP, fmt.Errorf("cannot resolve STUN host %q: %w", s, err)
	}
	log.Debug("STUN server normalized: %q -> %s:%d (tcp=%v)", original, ip.String(), port, isTCP)
	if isTCP {
		return &net.TCPAddr{IP: ip, Port: port}, isTCP, nil
	}
	return &net.UDPAddr{IP: ip, Port: port}, isTCP, nil
}

// stunQuery sends a STUN Binding Request and returns the server-reflexive address.
// Supports both UDP and TCP (RFC 7675) based on the isTCP parameter.
func stunQuery(ctx context.Context, server string, serverAddr net.Addr, isTCP bool) (net.UDPAddr, error) {
	if isTCP {
		return stunQueryTCP(ctx, server, serverAddr)
	}
	return stunQueryUDP(ctx, server, serverAddr)
}

// stunQueryUDP performs a UDP STUN query.
func stunQueryUDP(ctx context.Context, server string, serverAddr net.Addr) (net.UDPAddr, error) {
	startTime := time.Now()

	sa := serverAddr.(*net.UDPAddr)
	log.Debug("UDP STUN query: connecting to %s:%d", sa.IP.String(), sa.Port)

	conn, err := net.DialUDP("udp", nil, sa)
	if err != nil {
		return net.UDPAddr{}, fmt.Errorf("dial %s: %w", sa.String(), err)
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	log.Debug("UDP STUN query: connected to %s via local socket %s", sa.String(), localAddr.String())

	addr, err := sendSTUNBindingRequest(conn, localAddr)
	if err != nil {
		return net.UDPAddr{}, fmt.Errorf("UDP STUN query to %s: %w", sa.String(), err)
	}

	latency := time.Since(startTime)
	log.Debug("UDP STUN query result: %s (via %s, local=%s, latency=%v)",
		addr.String(), sa.String(), localAddr.String(), latency)

	return addr, nil
}

// stunQueryTCP performs a TCP STUN query (RFC 7675).
func stunQueryTCP(ctx context.Context, server string, serverAddr net.Addr) (net.UDPAddr, error) {
	startTime := time.Now()

	sa := serverAddr.(*net.TCPAddr)
	log.Debug("TCP STUN query: connecting to %s:%d", sa.IP.String(), sa.Port)

	conn, err := net.DialTCP("tcp", nil, sa)
	if err != nil {
		return net.UDPAddr{}, fmt.Errorf("dial TCP %s: %w", sa.String(), err)
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.TCPAddr)
	log.Debug("TCP STUN query: connected to %s via local socket %s", sa.String(), localAddr.String())

	addr, err := sendSTUNBindingRequestTCP(conn, localAddr)
	if err != nil {
		return net.UDPAddr{}, fmt.Errorf("TCP STUN query to %s: %w", sa.String(), err)
	}

	latency := time.Since(startTime)
	log.Debug("TCP STUN query result: %s (via %s, local=%s, latency=%v)",
		addr.String(), sa.String(), localAddr.String(), latency)

	return addr, nil
}

// sendSTUNBindingRequest sends a UDP STUN Binding Request and parses the response.
func sendSTUNBindingRequest(conn *net.UDPConn, localAddr *net.UDPAddr) (net.UDPAddr, error) {
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

	log.Debug("STUN query: received %d bytes response", n)

	resp := &stun.Message{Raw: buf[:n]}
	if err := resp.Decode(); err != nil {
		return net.UDPAddr{}, fmt.Errorf("decode STUN response: %w", err)
	}

	log.Debug("STUN response: type=%s, txID=%x, attrs=[%s]", resp.Type, resp.TransactionID[:4], stunAttrNames(resp))

	if resp.Type != stun.BindingSuccess {
		errMsg := "unknown"
		if ecBytes, err := resp.Get(stun.AttrErrorCode); err == nil {
			errMsg = string(ecBytes)
		}
		return net.UDPAddr{}, fmt.Errorf("unexpected STUN response type %s: %s", resp.Type, errMsg)
	}

	var xa stun.XORMappedAddress
	if err := xa.GetFrom(resp); err != nil {
		return net.UDPAddr{}, fmt.Errorf("missing XOR-MAPPED-ADDRESS: %w", err)
	}

	result := net.UDPAddr{IP: xa.IP, Port: xa.Port}

	// NAT type inference
	if localAddr.IP.Equal(result.IP) {
		log.Debug("STUN NAT type: open internet (no NAT) — server-reflexive == local address")
	} else if localAddr.Port == result.Port {
		log.Debug("STUN NAT type: restricted cone NAT (port preserved, IP changed)")
	} else {
		log.Debug("STUN NAT type: restricted full-cone NAT (port changed: local=%d, reflexive=%d)",
			localAddr.Port, result.Port)
	}

	return result, nil
}

// sendSTUNBindingRequestTCP sends a TCP STUN Binding Request with RFC 7675 framing.
// TCP STUN uses a 2-byte big-endian length prefix before each message.
func sendSTUNBindingRequestTCP(conn *net.TCPConn, localAddr *net.TCPAddr) (net.UDPAddr, error) {
	msg := stun.New()
	msg.Type = stun.BindingRequest
	if err := msg.NewTransactionID(); err != nil {
		return net.UDPAddr{}, fmt.Errorf("generate transaction ID: %w", err)
	}
	log.Debug("TCP STUN query: sending Binding Request (txID=%x)", msg.TransactionID[:4])
	msg.Encode()

	// Write 2-byte length prefix (RFC 7675)
	lenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuf, uint16(len(msg.Raw)))

	if err := conn.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return net.UDPAddr{}, err
	}
	if _, err := conn.Write(lenBuf); err != nil {
		return net.UDPAddr{}, fmt.Errorf("write length prefix: %w", err)
	}
	if _, err := conn.Write(msg.Raw); err != nil {
		return net.UDPAddr{}, fmt.Errorf("write STUN request: %w", err)
	}

	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return net.UDPAddr{}, err
	}

	// Read 2-byte length prefix
	var respLen uint16
	if err := readFull(conn, lenBuf); err != nil {
		return net.UDPAddr{}, fmt.Errorf("read length prefix: %w", err)
	}
	respLen = binary.BigEndian.Uint16(lenBuf)

	// Read STUN message body
	respBuf := make([]byte, respLen)
	if err := readFull(conn, respBuf); err != nil {
		return net.UDPAddr{}, fmt.Errorf("read STUN message (%d bytes): %w", respLen, err)
	}

	log.Debug("TCP STUN query: received %d bytes response", respLen)

	resp := &stun.Message{Raw: respBuf}
	if err := resp.Decode(); err != nil {
		return net.UDPAddr{}, fmt.Errorf("decode STUN response: %w", err)
	}

	log.Debug("TCP STUN response: type=%s, txID=%x, attrs=[%s]",
		resp.Type, resp.TransactionID[:4], stunAttrNames(resp))

	if resp.Type != stun.BindingSuccess {
		errMsg := "unknown"
		if ecBytes, err := resp.Get(stun.AttrErrorCode); err == nil {
			errMsg = string(ecBytes)
		}
		return net.UDPAddr{}, fmt.Errorf("unexpected STUN response type %s: %s", resp.Type, errMsg)
	}

	var xa stun.XORMappedAddress
	if err := xa.GetFrom(resp); err != nil {
		return net.UDPAddr{}, fmt.Errorf("missing XOR-MAPPED-ADDRESS: %w", err)
	}

	result := net.UDPAddr{IP: xa.IP, Port: xa.Port}

	// NAT type inference (for TCP, this is about the TCP NAT behavior)
	if localAddr.IP.Equal(result.IP) {
		log.Debug("TCP STUN NAT type: open internet (no NAT) — server-reflexive == local address")
	} else {
		log.Debug("TCP STUN NAT type: behind NAT (local=%s, reflexive=%s)", localAddr.String(), result.String())
	}

	return result, nil
}

// readFull reads exactly len(buf) bytes from the connection.
func readFull(conn *net.TCPConn, buf []byte) error {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			if err == io.EOF && total > 0 {
				return io.ErrUnexpectedEOF
			}
			return err
		}
	}
	return nil
}

// resolveIP returns the IP address for a host string, using DNS resolution if
// the host is not already an IP literal.
func resolveIP(ctx context.Context, host string) (net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return ip, nil
	}
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil || len(addrs) == 0 {
		return nil, fmt.Errorf("no IP addresses for %q: %v", host, err)
	}
	return addrs[0].IP, nil
}
