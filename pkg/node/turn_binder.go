package node

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr/net"
	"github.com/pion/logging"
	turn "github.com/pion/turn/v4"
)

// turnRelayAddrs holds the TURN relay multiaddrs discovered via allocation.
var turnRelayAddrs atomic.Pointer[[]multiaddr.Multiaddr]

func setTURNRelayAddrs(addrs []multiaddr.Multiaddr) {
	if len(addrs) == 0 {
		turnRelayAddrs.Store(nil)
		return
	}
	turnRelayAddrs.Store(&addrs)
}

func getTURNRelayAddrs() []multiaddr.Multiaddr {
	ptr := turnRelayAddrs.Load()
	if ptr == nil {
		return nil
	}
	return *ptr
}

// turnRelayConns maps relay address strings to their PacketConn.
var turnRelayConns = struct {
	sync.RWMutex
	m map[string]net.PacketConn
}{m: make(map[string]net.PacketConn)}

func addTURNRelayConn(key string, conn net.PacketConn) {
	turnRelayConns.Lock()
	turnRelayConns.m[key] = conn
	turnRelayConns.Unlock()
}

func getTURNRelayConn(key string) (net.PacketConn, bool) {
	turnRelayConns.RLock()
	conn, ok := turnRelayConns.m[key]
	turnRelayConns.RUnlock()
	return conn, ok
}

func removeTURNRelayConn(key string) {
	turnRelayConns.Lock()
	delete(turnRelayConns.m, key)
	turnRelayConns.Unlock()
}

func removeAllTURNRelayConns() {
	turnRelayConns.Lock()
	for k, conn := range turnRelayConns.m {
		conn.Close()
		delete(turnRelayConns.m, k)
	}
	turnRelayConns.Unlock()
}

// turnClients maps server URL strings to their TURN client.
var turnClients = struct {
	sync.RWMutex
	m map[string]*turn.Client
}{m: make(map[string]*turn.Client)}

func addTURNClient(key string, client *turn.Client) {
	turnClients.Lock()
	turnClients.m[key] = client
	turnClients.Unlock()
}

func getTURNClient(key string) (*turn.Client, bool) {
	turnClients.RLock()
	client, ok := turnClients.m[key]
	turnClients.RUnlock()
	return client, ok
}

func removeTURNClient(key string) {
	turnClients.Lock()
	client, ok := turnClients.m[key]
	if ok {
		client.Close()
		delete(turnClients.m, key)
	}
	turnClients.Unlock()
}

func removeAllTURNClients() {
	turnClients.Lock()
	for k, client := range turnClients.m {
		client.Close()
		delete(turnClients.m, k)
	}
	turnClients.Unlock()
}

// removeTURNClientsNotIn removes TURN clients for servers not in the keep set.
// Used to clean up old clients after a successful allocation cycle.
func removeTURNClientsNotIn(keepServers map[string]bool) {
	turnClients.Lock()
	for key, client := range turnClients.m {
		if !keepServers[key] {
			client.Close()
			delete(turnClients.m, key)
		}
	}
	turnClients.Unlock()
}

// removeTURNRelayConnsNotIn removes relay connections not in the keep set.
func removeTURNRelayConnsNotIn(keepKeys map[string]bool) {
	turnRelayConns.Lock()
	for key, conn := range turnRelayConns.m {
		if !keepKeys[key] {
			conn.Close()
			delete(turnRelayConns.m, key)
		}
	}
	turnRelayConns.Unlock()
}

// turnConfig holds parsed TURN server configuration.
type turnConfig struct {
	ServerAddr string
	Username   string
	Credential string
}

func parseTurnURL(s string) (*turnConfig, error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "turn:") {
		return nil, fmt.Errorf("invalid TURN URL %q: must start with 'turn:'", s)
	}

	u, err := url.Parse(s)
	if err != nil {
		return nil, fmt.Errorf("parse TURN URL %q: %w", s, err)
	}

	serverAddr := u.Host
	if serverAddr == "" {
		raw := strings.TrimPrefix(s, "turn:")
		if idx := strings.Index(raw, "?"); idx > 0 {
			serverAddr = raw[:idx]
		} else {
			serverAddr = raw
		}
	}

	if serverAddr == "" {
		return nil, fmt.Errorf("TURN URL %q: missing server address", s)
	}

	cfg := &turnConfig{ServerAddr: serverAddr}

	if u.RawQuery != "" {
		query := u.Query()
		cfg.Username = query.Get("username")
		cfg.Credential = query.Get("credential")
	}

	return cfg, nil
}

// startTURNBinder periodically allocates TURN relay addresses.
func (n *Node) startTURNBinder(ctx context.Context) {
	go func() {
		defer n.wg.Done()
		defer func() {
			removeAllTURNClients()
			removeAllTURNRelayConns()
			log.Debug("TURN binder stopped")
		}()

		// Delay initial allocation to let the node finish bootstrapping and
		// avoid log spam from servers that require authentication.
		select {
		case <-ctx.Done():
			return
		case <-time.After(10 * time.Second):
		}

		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()

		permTicker := time.NewTicker(60 * time.Second)
		defer permTicker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			if err := n.turnBindOnce(ctx); err != nil {
				log.Warn("TURN bind cycle failed: %v", err)
			}

			select {
			case <-ctx.Done():
				return
			case <-permTicker.C:
				n.refreshTURNPermissions()
			case <-ticker.C:
			}
		}
	}()
}

func (n *Node) turnBindOnce(ctx context.Context) error {
	servers := n.config().TurnServers
	if len(servers) == 0 {
		return nil
	}

	startTime := time.Now()

	const maxConcurrent = 5
	sem := make(chan struct{}, maxConcurrent)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var discovered []multiaddr.Multiaddr
	var successes, failures int
	successServers := make(map[string]bool)

	for _, server := range servers {
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			wg.Wait()
			return ctx.Err()
		}
		wg.Add(1)
		go func(server string) {
			defer wg.Done()
			defer func() { <-sem }()

			select {
			case <-ctx.Done():
				return
			default:
			}

			log.Debug("TURN allocating from %s", server)

			// Per-server timeout so one slow server cannot stall the cycle.
			allocationCtx, allocCancel := context.WithTimeout(ctx, 30*time.Second)
			defer allocCancel()

			relayAddrs, err := n.allocateTURNRelay(allocationCtx, server)
			if err != nil {
				mu.Lock()
				failures++
				mu.Unlock()
				log.Debug("TURN allocation failed for %s: %v", server, err)
				return
			}
			mu.Lock()
			successes++
			discovered = append(discovered, relayAddrs...)
			successServers[server] = true
			mu.Unlock()
		}(server)
	}

	wg.Wait()

	elapsed := time.Since(startTime)
	log.Debug("TURN bind cycle completed in %v: %d success, %d failure(s)", elapsed, successes, failures)

	if len(discovered) > 0 {
		// Two-phase commit: new relays are already in the global maps (added
		// by allocateTURNRelay). Now clean up old clients/conns that are no
		// longer needed, keeping previous relays alive if all new allocations
		// failed (handled in the else branch below).
		removeTURNClientsNotIn(successServers)

		// Build a set of keep-keys from the new relay addresses
		keepConnKeys := make(map[string]bool, len(discovered))
		for _, ma := range discovered {
			if addr, err := manet.ToNetAddr(ma); err == nil {
				keepConnKeys[addr.String()] = true
			}
		}
		removeTURNRelayConnsNotIn(keepConnKeys)

		log.Info("TURN relay addresses UPDATED: %v", discovered)
		setTURNRelayAddrs(discovered)

		for _, ma := range discovered {
			go func(ma multiaddr.Multiaddr) {
				if err := n.Host.Network().Listen(ma); err != nil {
					log.Debug("Failed to add TURN relay listener %s: %v", ma.String(), err)
				} else {
					log.Info("TURN relay listener registered: %s", ma.String())
				}
			}(ma)
		}
	} else {
		prevAddrs := getTURNRelayAddrs()
		if len(prevAddrs) > 0 {
			log.Warn("TURN bind cycle produced no results — keeping %d previous relay address(es)", len(prevAddrs))
		} else {
			log.Debug("TURN bind cycle produced no results")
		}
	}

	if failures == len(servers) {
		return fmt.Errorf("all %d TURN servers failed", len(servers))
	}
	return nil
}

func (n *Node) allocateTURNRelay(ctx context.Context, serverURL string) ([]multiaddr.Multiaddr, error) {
	cfg, err := parseTurnURL(serverURL)
	if err != nil {
		return nil, fmt.Errorf("parse TURN URL: %w", err)
	}

	// Build pion/turn config
	turnCfg := turn.ClientConfig{
		LoggerFactory:  logging.NewDefaultLoggerFactory(),
		STUNServerAddr: cfg.ServerAddr,
		TURNServerAddr: cfg.ServerAddr,
		Username:       cfg.Username,
		Password:       cfg.Credential,
	}

	client, err := turn.NewClient(&turnCfg)
	if err != nil {
		return nil, fmt.Errorf("create TURN client: %w", err)
	}

	if err := client.Listen(); err != nil {
		client.Close()
		return nil, fmt.Errorf("TURN listener: %w", err)
	}

	relay, err := client.Allocate()
	if err != nil {
		client.Close()
		return nil, fmt.Errorf("TURN allocation: %w", err)
	}

	relayAddr := relay.LocalAddr()
	relayAddrStr := relayAddr.String()

	// Extract IP and port from net.Addr
	var relayIP string
	var relayPort string
	if udpAddr, ok := relayAddr.(*net.UDPAddr); ok {
		relayIP = udpAddr.IP.String()
		relayPort = strconv.Itoa(udpAddr.Port)
	}

	if relayIP == "" || relayPort == "" {
		client.Close()
		return nil, fmt.Errorf("failed to extract relay IP:port from %s", relayAddrStr)
	}

	// Build multiaddr with correct IP family prefix and /quic-v1 suffix
	udpRelay, ok := relayAddr.(*net.UDPAddr)
	if !ok {
		client.Close()
		return nil, fmt.Errorf("unexpected relay address type %T (expected *net.UDPAddr)", relayAddr)
	}
	ipPrefix := "/ip4/"
	if udpRelay.IP.To4() == nil {
		ipPrefix = "/ip6/"
	}
	ma, err := multiaddr.NewMultiaddr(fmt.Sprintf("%s%s/udp/%s/quic-v1", ipPrefix, relayIP, relayPort))
	if err != nil {
		client.Close()
		return nil, fmt.Errorf("build multiaddr: %w", err)
	}

	log.Info("TURN relay allocated: %s (relay=%s)", ma.String(), relayAddrStr)

	// Store connection for OverrideListenUDP using "ip:port" key format
	// matching laddr.String() in the OverrideListenUDP callback
	addTURNRelayConn(relayAddrStr, relay)

	// Store client for permission refresh (keyed by server URL)
	addTURNClient(serverURL, client)

	return []multiaddr.Multiaddr{ma}, nil
}

// refreshTURNPermissions creates TURN permissions for known peer addresses.
func (n *Node) refreshTURNPermissions() {
	addrs := n.collectPeerAddresses()
	if len(addrs) == 0 {
		log.Debug("TURN permissions: no peer addresses to authorize")
		return
	}

	log.Debug("TURN permissions: creating permissions for %d peer address(es)", len(addrs))

	turnClients.RLock()
	clients := make(map[string]*turn.Client, len(turnClients.m))
	for k, v := range turnClients.m {
		clients[k] = v
	}
	turnClients.RUnlock()

	for serverURL, client := range clients {
		log.Debug("TURN permissions: refreshing for server %s", serverURL)
		if err := client.CreatePermission(addrs...); err != nil {
			log.Warn("TURN permission refresh failed for %s: %v", serverURL, err)
		} else {
			log.Debug("TURN permissions: success for %s (%d addresses)", serverURL, len(addrs))
		}
	}
}

// collectPeerAddresses gathers known peer addresses for TURN permission creation.
func (n *Node) collectPeerAddresses() []net.Addr {
	cfg := n.config()
	addrs := make([]net.Addr, 0, 16)
	seen := make(map[string]bool)

	// Bootstrap peers
	for _, bStr := range cfg.BootstrapPeers {
		ma, err := multiaddr.NewMultiaddr(bStr)
		if err != nil {
			continue
		}
		addr := extractIPFromMultiaddr(ma)
		if addr != nil && !seen[addr.String()] {
			seen[addr.String()] = true
			addrs = append(addrs, addr)
		}
	}

	// Static peers
	for _, bStr := range cfg.StaticPeers {
		ma, err := multiaddr.NewMultiaddr(bStr)
		if err != nil {
			continue
		}
		addr := extractIPFromMultiaddr(ma)
		if addr != nil && !seen[addr.String()] {
			seen[addr.String()] = true
			addrs = append(addrs, addr)
		}
	}

	// Peerstore
	for _, pid := range n.Host.Peerstore().Peers() {
		for _, ma := range n.Host.Peerstore().Addrs(pid) {
			addr := extractIPFromMultiaddr(ma)
			if addr != nil && !seen[addr.String()] {
				seen[addr.String()] = true
				addrs = append(addrs, addr)
			}
		}
	}

	return addrs
}

// extractIPFromMultiaddr extracts a net.Addr from a multiaddr.
func extractIPFromMultiaddr(ma multiaddr.Multiaddr) net.Addr {
	addr, err := manet.ToNetAddr(ma)
	if err != nil {
		return nil
	}
	return addr
}
