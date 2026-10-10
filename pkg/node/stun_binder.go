package node

import (
	"bytes"
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

// ── NAT Type Detection ───────────────────────────────────────────────────────

// NAT types inferred from STUN responses. Used to decide whether TURN relay
// is needed: open/cone NATs can hole-punch directly, symmetric NATs cannot.
const (
	natOpen      int32 = iota // No NAT — direct connectivity, skip TURN
	natCone                   // Cone NAT — hole punching works, skip TURN
	natSymmetric              // Symmetric NAT — hole punching fails, need TURN
	natUnknown                // Unknown — need TURN as fallback
)

// detectedNATType stores the last detected NAT type from STUN responses.
// Default is natUnknown, which means TURN is always attempted (safe fallback).
var detectedNATType atomic.Int32

func init() {
	detectedNATType.Store(natUnknown)
}

// getNATType returns the currently detected NAT type.
func getNATType() int32 {
	return detectedNATType.Load()
}

// setNATType stores a detected NAT type.
func setNATType(t int32) {
	detectedNATType.Store(t)
}

// needsTURN returns true if the detected NAT type requires TURN relay.
func needsTURN() bool {
	t := detectedNATType.Load()
	return t == natSymmetric || t == natUnknown
}

// stunSuccessThreshold defines how many UDP/TCP successes per cycle are
// sufficient to stop dispatching further STUN queries.
const (
	udpSuccessThreshold = 3
	tcpSuccessThreshold = 2
)

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
//
// Rebind interval is adaptive: when addresses change, the interval shrinks to
// 30s to converge quickly. When addresses are stable for 3+ consecutive cycles,
// the interval expands to 10 minutes to save resources.
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

		// Adaptive rebind: track consecutive stable cycles to decide interval.
		stableCycles := 0
		for {
			interval := adaptiveRebindInterval(stableCycles)
			log.Debug("STUN binder: next rebind in %v (stable cycles: %d)", interval, stableCycles)

			select {
			case <-bindCtx.Done():
				log.Debug("STUN binder stopped")
				return
			case <-time.After(interval):
			}

			log.Debug("STUN binder: periodic rebind triggered")
			changed := n.stunBindOnceChecked(bindCtx)
			if changed {
				stableCycles = 0
			} else {
				stableCycles++
			}
		}
	}()
}

// adaptiveRebindInterval returns the rebind delay based on consecutive stable cycles.
func adaptiveRebindInterval(stableCycles int) time.Duration {
	switch {
	case stableCycles == 0:
		// Addresses just changed — converge quickly.
		return 30 * time.Second
	case stableCycles >= 3:
		// Stable for 3+ cycles — minimize overhead.
		return 10 * time.Minute
	case stableCycles >= 1:
		return 2 * time.Minute
	default:
		return 3 * time.Minute
	}
}

// stunBindOnceChecked runs a STUN bind cycle and reports whether addresses changed.
func (n *Node) stunBindOnceChecked(ctx context.Context) bool {
	prevUDP := getSTUNReflexiveAddrs()
	prevTCP := getTCPStunReflexiveAddrs()

	if err := n.stunBindOnce(ctx); err != nil {
		log.Debug("STUN binder periodic bind failed: %v", err)
		return false
	}

	// Compare before/after to detect changes.
	newUDP := getSTUNReflexiveAddrs()
	newTCP := getTCPStunReflexiveAddrs()
	changed := !equalAddrs(prevUDP, newUDP) || !equalAddrs(prevTCP, newTCP)
	if changed {
		log.Info("STUN addresses changed — rebind interval will shrink to 30s")
	}
	return changed
}

// equalAddrs checks if two multiaddr slices contain the same addresses.
func equalAddrs(a, b []multiaddr.Multiaddr) bool {
	if len(a) != len(b) {
		return false
	}
	if len(a) == 0 {
		return true
	}
	seen := make(map[string]bool, len(a))
	for _, addr := range a {
		seen[addr.String()] = true
	}
	for _, addr := range b {
		if !seen[addr.String()] {
			return false
		}
	}
	return true
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

		// Early termination: once we have enough successes on EITHER transport,
		// stop dispatching further servers. Some deployments have no TCP STUN
		// servers, so requiring both would prevent early termination.
		mu.Lock()
		if udpSuccesses >= udpSuccessThreshold || tcpSuccesses >= tcpSuccessThreshold {
			mu.Unlock()
			log.Debug("STUN early termination: %d UDP + %d TCP successes, skipping remaining %d server(s)",
				udpSuccesses, tcpSuccesses, len(servers))
			break
		}
		mu.Unlock()

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

			serverAddrs, isTCP, err := normalizeSTUNServer(cycleCtx, server)
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

			for _, serverAddr := range serverAddrs {
				if cycleCtx.Err() != nil {
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
					continue
				}

				ipPrefix := "/ip4/"
				if addr.IP.To4() == nil {
					ipPrefix = "/ip6/"
				}

				var ma multiaddr.Multiaddr
				if isTCP {
					// TCP STUN gives us our public IP, but the port is the
					// ephemeral TCP source port — NOT a listening port.
					// Peers can't dial it. Use port 0 so libp2p's DCUtR
					// handles port selection during hole punching.
					ma, err = multiaddr.NewMultiaddr(fmt.Sprintf("%s%s/tcp/0", ipPrefix, addr.IP.String()))
					if err != nil {
						mu.Lock()
						tcpFailures++
						mu.Unlock()
						continue
					}
					mu.Lock()
					tcpSuccesses++
					tcpDiscovered = append(tcpDiscovered, ma)
					mu.Unlock()
				} else {
					// UDP STUN gives us the exact IP:port our NAT maps to —
					// peers can send UDP packets there directly.
					ma, err = multiaddr.NewMultiaddr(fmt.Sprintf("%s%s/udp/%d/quic-v1", ipPrefix, addr.IP.String(), addr.Port))
					if err != nil {
						mu.Lock()
						udpFailures++
						mu.Unlock()
						continue
					}
					mu.Lock()
					udpSuccesses++
					udpDiscovered = append(udpDiscovered, ma)
					mu.Unlock()
				}
				log.Debug("STUN discovered server-reflexive address: %s (via %s, tcp=%v)", ma.String(), server, isTCP)
			}
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

// mergeAndStoreSTUNAddrs merges newly discovered addresses with previous ones,
// deduplicates, and stores the result. If all queries failed and there are
// previous addresses, the old set is kept unchanged.
func mergeAndStoreSTUNAddrs(newAddrs, prevAddrs []multiaddr.Multiaddr, failures int) {
	mergeAndStoreSTUNHelper("UDP STUN", newAddrs, prevAddrs, failures, setSTUNReflexiveAddrs)
}

// mergeAndStoreTCPSTUNAddrs merges TCP STUN addresses with previous ones.
func mergeAndStoreTCPSTUNAddrs(newAddrs, prevAddrs []multiaddr.Multiaddr, failures int) {
	mergeAndStoreSTUNHelper("TCP STUN", newAddrs, prevAddrs, failures, setTCPStunReflexiveAddrs)
}

// mergeAndStoreSTUNHelper is the shared merge/dedup/store logic for both UDP
// and TCP STUN address sets.
func mergeAndStoreSTUNHelper(label string, newAddrs, prevAddrs []multiaddr.Multiaddr, failures int, set func([]multiaddr.Multiaddr)) {
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
		log.Debug("%s partial failure (%d failures): keeping %d prev + %d new = %d total",
			label, failures, len(prevAddrs), len(newAddrs), len(merged))
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
			log.Warn("%s bind cycle produced no results — keeping %d previous address(es)", label, len(prevAddrs))
		} else {
			log.Debug("%s bind cycle produced no results", label)
		}
		return
	}

	addrsChanged := len(prevAddrs) != len(merged)
	if !addrsChanged {
		prevSet := make(map[string]struct{}, len(prevAddrs))
		for _, a := range prevAddrs {
			prevSet[a.String()] = struct{}{}
		}
		for _, a := range merged {
			if _, ok := prevSet[a.String()]; !ok {
				addrsChanged = true
				break
			}
		}
	}
	if addrsChanged {
		log.Info("%s server-reflexive addresses UPDATED: %v", label, merged)
	} else {
		log.Debug("%s server-reflexive addresses unchanged: %v", label, merged)
	}
	set(merged)
}

// normalizeSTUNServer parses a STUN server string and returns resolved addresses
// for all IP versions (IPv4 + IPv6). Returns (addrs, isTCP, error).
func normalizeSTUNServer(ctx context.Context, s string) ([]net.Addr, bool, error) {
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
		ips, err := resolveIPs(ctx, host)
		if err != nil {
			return nil, isTCP, fmt.Errorf("cannot resolve STUN host %q: %w", host, err)
		}
		addrs := make([]net.Addr, len(ips))
		for i, ip := range ips {
			log.Debug("STUN server normalized: %q -> %s:%d (tcp=%v)", original, ip.String(), portNum, isTCP)
			if isTCP {
				addrs[i] = &net.TCPAddr{IP: ip, Port: portNum}
			} else {
				addrs[i] = &net.UDPAddr{IP: ip, Port: portNum}
			}
		}
		return addrs, isTCP, nil
	}

	// No port specified, use default
	port := 3478
	ips, err := resolveIPs(ctx, s)
	if err != nil {
		return nil, isTCP, fmt.Errorf("cannot resolve STUN host %q: %w", s, err)
	}
	addrs := make([]net.Addr, len(ips))
	for i, ip := range ips {
		log.Debug("STUN server normalized: %q -> %s:%d (tcp=%v)", original, ip.String(), port, isTCP)
		if isTCP {
			addrs[i] = &net.TCPAddr{IP: ip, Port: port}
		} else {
			addrs[i] = &net.UDPAddr{IP: ip, Port: port}
		}
	}
	return addrs, isTCP, nil
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

	addr, err := sendSTUNBindingRequest(ctx, conn, localAddr)
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

	addr, err := sendSTUNBindingRequestTCP(ctx, conn, localAddr)
	if err != nil {
		return net.UDPAddr{}, fmt.Errorf("TCP STUN query to %s: %w", sa.String(), err)
	}

	latency := time.Since(startTime)
	log.Debug("TCP STUN query result: %s (via %s, local=%s, latency=%v)",
		addr.String(), sa.String(), localAddr.String(), latency)

	return addr, nil
}

// stunDeadline returns the effective deadline for a STUN operation, respecting
// the caller's context deadline (if earlier than 5s).
func stunDeadline(ctx context.Context) time.Time {
	fallback := time.Now().Add(5 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(fallback) {
		return d
	}
	return fallback
}

// sendSTUNBindingRequest sends a UDP STUN Binding Request and parses the response.
func sendSTUNBindingRequest(ctx context.Context, conn *net.UDPConn, localAddr *net.UDPAddr) (net.UDPAddr, error) {
	msg := stun.New()
	msg.Type = stun.BindingRequest
	if err := msg.NewTransactionID(); err != nil {
		return net.UDPAddr{}, fmt.Errorf("generate transaction ID: %w", err)
	}
	log.Debug("STUN query: sending Binding Request (txID=%x)", msg.TransactionID[:4])
	msg.Encode()

	if err := conn.SetWriteDeadline(stunDeadline(ctx)); err != nil {
		return net.UDPAddr{}, err
	}
	if _, err := conn.Write(msg.Raw); err != nil {
		return net.UDPAddr{}, fmt.Errorf("send STUN request: %w", err)
	}

	if err := conn.SetReadDeadline(stunDeadline(ctx)); err != nil {
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

	// Validate transaction ID to reject spoofed or stale responses.
	if !bytes.Equal(resp.TransactionID[:], msg.TransactionID[:]) {
		return net.UDPAddr{}, fmt.Errorf("STUN transaction ID mismatch: expected %x, got %x",
			msg.TransactionID[:4], resp.TransactionID[:4])
	}

	var xa stun.XORMappedAddress
	if err := xa.GetFrom(resp); err != nil {
		return net.UDPAddr{}, fmt.Errorf("missing XOR-MAPPED-ADDRESS: %w", err)
	}

	result := net.UDPAddr{IP: xa.IP, Port: xa.Port}

	// NAT type inference — stored globally so the TURN binder can decide
	// whether relay allocation is needed. Only set once (first successful
	// query wins) to avoid races across concurrent goroutines. With a
	// single-server STUN test, we can only distinguish open, cone (port
	// preserved), and unknown. Port-changed is ambiguous (could be cone
	// or symmetric), so we use natUnknown to conservatively keep TURN.
	if detectedNATType.Load() == natUnknown {
		if localAddr.IP.Equal(result.IP) {
			log.Debug("STUN NAT type: open internet (no NAT) — server-reflexive == local address")
			setNATType(natOpen)
		} else if localAddr.Port == result.Port {
			log.Debug("STUN NAT type: restricted cone NAT (port preserved, IP changed)")
			setNATType(natCone)
		} else {
			log.Debug("STUN NAT type: unknown — port changed (local=%d, reflexive=%d), may be symmetric",
				localAddr.Port, result.Port)
			// Stay natUnknown — port-changed is ambiguous.
		}
	}

	return result, nil
}

// sendSTUNBindingRequestTCP sends a TCP STUN Binding Request with RFC 7675 framing.
// TCP STUN uses a 2-byte big-endian length prefix before each message.
func sendSTUNBindingRequestTCP(ctx context.Context, conn *net.TCPConn, localAddr *net.TCPAddr) (net.UDPAddr, error) {
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

	if err := conn.SetWriteDeadline(stunDeadline(ctx)); err != nil {
		return net.UDPAddr{}, err
	}
	if _, err := conn.Write(lenBuf); err != nil {
		return net.UDPAddr{}, fmt.Errorf("write length prefix: %w", err)
	}
	if _, err := conn.Write(msg.Raw); err != nil {
		return net.UDPAddr{}, fmt.Errorf("write STUN request: %w", err)
	}

	if err := conn.SetReadDeadline(stunDeadline(ctx)); err != nil {
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

	if !bytes.Equal(resp.TransactionID[:], msg.TransactionID[:]) {
		return net.UDPAddr{}, fmt.Errorf("STUN transaction ID mismatch: expected %x, got %x",
			msg.TransactionID[:4], resp.TransactionID[:4])
	}

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
// resolveIPs returns all resolved IP addresses for a host (IPv4 + IPv6).
func resolveIPs(ctx context.Context, host string) ([]net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil || len(addrs) == 0 {
		return nil, fmt.Errorf("no IP addresses for %q: %v", host, err)
	}
	seen := make(map[string]bool)
	var ips []net.IP
	for _, a := range addrs {
		if !seen[a.IP.String()] {
			seen[a.IP.String()] = true
			ips = append(ips, a.IP)
		}
	}
	return ips, nil
}
