package node

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	manet "github.com/multiformats/go-multiaddr/net"
	"github.com/multiformats/go-multiaddr"
	"github.com/pion/logging"
	"github.com/pion/turn/v4"
)

// ── Exported Getters ─────────────────────────────────────────────────────────

// GetSTUNReflexiveAddrs returns the current UDP STUN reflexive addresses.
// These are discovered by the STUN binder and represent the node's public IP
// as seen by external STUN servers.
func GetSTUNReflexiveAddrs() []multiaddr.Multiaddr {
	return getSTUNReflexiveAddrs()
}

// GetTCPStunReflexiveAddrs returns the current TCP STUN reflexive addresses.
func GetTCPStunReflexiveAddrs() []multiaddr.Multiaddr {
	return getTCPStunReflexiveAddrs()
}

// GetTURNRelayAddrs returns the current TURN relay addresses.
func GetTURNRelayAddrs() []multiaddr.Multiaddr {
	return getTURNRelayAddrs()
}

// ── Standalone Binder Functions ──────────────────────────────────────────────

// StartBootSTUNBinder starts a standalone STUN binder that periodically
// queries the given STUN servers to discover the node's server-reflexive
// addresses. This is designed for use by standalone relay servers (like
// p2ptap-boot) that don't have a Node instance but need NAT traversal.
//
// The binder queries all servers concurrently (max 10 concurrent), with a
// 5-second timeout per query and a 90-second global cycle timeout. It
// rebinds every 3 minutes to pick up IP address changes.
func StartBootSTUNBinder(ctx context.Context, servers []string) {
	if len(servers) == 0 {
		log.Debug("Boot STUN binder: no servers configured, skipping")
		return
	}

	log.Info("Boot STUN binder starting with %d server(s)", len(servers))

	go func() {
		defer log.Debug("Boot STUN binder stopped")

		if err := bootSTUNBindOnce(ctx, servers); err != nil {
			log.Debug("Boot STUN initial bind failed: %v", err)
		}

		const rebindInterval = 3 * time.Minute
		ticker := time.NewTicker(rebindInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := bootSTUNBindOnce(ctx, servers); err != nil {
					log.Debug("Boot STUN periodic bind failed: %v", err)
				}
			}
		}
	}()
}

// StartBootTURNBinder starts a standalone TURN binder that periodically
// allocates TURN relay ports. The relay addresses are published via the
// host's peerstore and available through GetTURNRelayAddrs().
//
// TURN allocations are refreshed every 5 minutes, and TURN permissions
// are refreshed every 60 seconds for connected peers.
func StartBootTURNBinder(ctx context.Context, h host.Host, servers []string) {
	if len(servers) == 0 {
		log.Debug("Boot TURN binder: no servers configured, skipping")
		return
	}

	log.Info("Boot TURN binder starting with %d server(s)", len(servers))

	go func() {
		defer func() {
			removeAllTURNClients()
			removeAllTURNRelayConns()
			log.Debug("Boot TURN binder stopped")
		}()

		// Delay initial allocation to let the host finish bootstrapping.
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

			if err := bootTURNBindOnce(ctx, h, servers); err != nil {
				log.Warn("Boot TURN bind cycle failed: %v", err)
			}

			select {
			case <-ctx.Done():
				return
			case <-permTicker.C:
				bootRefreshTURNPermissions(h)
			case <-ticker.C:
			}
		}
	}()
}

// ── Standalone Bind Cycle Implementations ────────────────────────────────────

func bootSTUNBindOnce(ctx context.Context, servers []string) error {
	if len(servers) == 0 {
		return nil
	}

	startTime := time.Now()
	cycleCtx, cycleCancel := context.WithTimeout(ctx, 90*time.Second)
	defer cycleCancel()

	const maxConcurrent = 10
	sem := make(chan struct{}, maxConcurrent)
	var wg sync.WaitGroup
	var mu sync.Mutex

	var udpDiscovered []multiaddr.Multiaddr
	var tcpDiscovered []multiaddr.Multiaddr
	var udpFailures, tcpFailures int

	for _, server := range servers {
		if cycleCtx.Err() != nil {
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
					ma, _ = multiaddr.NewMultiaddr(fmt.Sprintf("%s%s/tcp/0", ipPrefix, addr.IP.String()))
				} else {
					ma, _ = multiaddr.NewMultiaddr(fmt.Sprintf("%s%s/udp/%d/quic-v1", ipPrefix, addr.IP.String(), addr.Port))
				}
				if ma == nil {
					continue
				}

				mu.Lock()
				if isTCP {
					tcpDiscovered = append(tcpDiscovered, ma)
				} else {
					udpDiscovered = append(udpDiscovered, ma)
				}
				mu.Unlock()
			}
		}(server)
	}

	wg.Wait()

	elapsed := time.Since(startTime)
	if len(udpDiscovered) > 0 || len(tcpDiscovered) > 0 {
		log.Info("Boot STUN bind cycle: %v (UDP: %d addrs, TCP: %d addrs)",
			elapsed, len(udpDiscovered), len(tcpDiscovered))
	}

	udpFailCount := 0
	if udpFailures > 0 && len(udpDiscovered) == 0 {
		udpFailCount = udpFailures
	}
	tcpFailCount := 0
	if tcpFailures > 0 && len(tcpDiscovered) == 0 {
		tcpFailCount = tcpFailures
	}
	mergeAndStoreSTUNHelper("UDP STUN (boot)", udpDiscovered, getSTUNReflexiveAddrs(), udpFailCount, setSTUNReflexiveAddrs)
	mergeAndStoreSTUNHelper("TCP STUN (boot)", tcpDiscovered, getTCPStunReflexiveAddrs(), tcpFailCount, setTCPStunReflexiveAddrs)
	return nil
}

func bootTURNBindOnce(ctx context.Context, h host.Host, servers []string) error {
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

			allocationCtx, allocCancel := context.WithTimeout(ctx, 30*time.Second)
			defer allocCancel()

			relayAddrs, err := bootAllocateTURNRelay(allocationCtx, server)
			if err != nil {
				mu.Lock()
				failures++
				mu.Unlock()
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
	if len(discovered) > 0 {
		removeTURNClientsNotIn(successServers)

		keepConnKeys := make(map[string]bool, len(discovered))
		for _, ma := range discovered {
			if addr, err := manet.ToNetAddr(ma); err == nil {
				keepConnKeys[addr.String()] = true
			}
		}
		removeTURNRelayConnsNotIn(keepConnKeys)

		log.Info("Boot TURN relay addresses UPDATED: %v", discovered)
		setTURNRelayAddrs(discovered)

		for _, ma := range discovered {
			if err := h.Network().Listen(ma); err != nil {
				log.Warn("Boot TURN: failed to listen on relay addr %s: %v", ma, err)
			} else {
				log.Debug("Boot TURN: listening on relay addr %s", ma)
			}
		}
	} else if failures > 0 {
		log.Debug("Boot TURN bind cycle: all %d servers failed", failures)
	}

	log.Debug("Boot TURN bind cycle completed in %v: %d success, %d failure(s)", elapsed, successes, failures)
	return nil
}

// bootAllocateTURNRelay allocates a single TURN relay port, matching the
// logic in Node.allocateTURNRelay but without requiring a Node instance.
func bootAllocateTURNRelay(ctx context.Context, serverURL string) ([]multiaddr.Multiaddr, error) {
	cfg, err := parseTurnURL(serverURL)
	if err != nil {
		return nil, fmt.Errorf("parse TURN URL: %w", err)
	}

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

	var relayIP string
	var relayPort string
	if udpAddr, ok := relayAddr.(*net.UDPAddr); ok {
		relayIP = udpAddr.IP.String()
		relayPort = strconv.Itoa(udpAddr.Port)
	} else if tcpAddr, ok := relayAddr.(*net.TCPAddr); ok {
		relayIP = tcpAddr.IP.String()
		relayPort = strconv.Itoa(tcpAddr.Port)
	} else {
		client.Close()
		return nil, fmt.Errorf("unexpected relay address type: %T", relayAddr)
	}

	ma, err := multiaddr.NewMultiaddr(fmt.Sprintf("/ip4/%s/udp/%s/quic-v1", relayIP, relayPort))
	if err != nil {
		client.Close()
		return nil, fmt.Errorf("build relay multiaddr: %w", err)
	}

	addTURNClient(serverURL, client)
	addTURNRelayConn(relayAddrStr, relay)

	return []multiaddr.Multiaddr{ma}, nil
}

// bootRefreshTURNPermissions creates TURN permissions for all connected peers.
func bootRefreshTURNPermissions(h host.Host) {
	var peerAddrs []net.Addr
	for _, pid := range h.Network().Peers() {
		for _, ma := range h.Peerstore().Addrs(pid) {
			if addr, err := manet.ToNetAddr(ma); err == nil {
				if udpAddr, ok := addr.(*net.UDPAddr); ok {
					peerAddrs = append(peerAddrs, udpAddr)
				}
			}
		}
	}

	if len(peerAddrs) == 0 {
		return
	}

	turnClients.RLock()
	defer turnClients.RUnlock()

	for serverURL, client := range turnClients.m {
		if err := client.CreatePermission(peerAddrs...); err != nil {
			log.Debug("Boot TURN: permission refresh failed for %s: %v", serverURL, err)
		}
	}
}
