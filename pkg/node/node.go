package node

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/libp2p/go-libp2p/p2p/net/swarm"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/libp2p/go-libp2p/p2p/discovery/mdns"
	drouting "github.com/libp2p/go-libp2p/p2p/discovery/routing"
	"github.com/libp2p/go-libp2p/p2p/discovery/util"
	relayClient "github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/client"
	"github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr/net"

	"p2ptap/pkg/config"
	"p2ptap/pkg/logger"
	"p2ptap/pkg/obfuscate"
	"p2ptap/pkg/routing"
	vswitch "p2ptap/pkg/switch"
	"p2ptap/pkg/tap"
	"p2ptap/pkg/web"
)

var log = logger.New("Node")

type PeerMeta struct {
	NodeName     string    `json:"node_name"`
	TapIP        string    `json:"tap_ip"`
	TapIPv6      string    `json:"tap_ipv6"`
	TapMAC       string    `json:"tap_mac"`
	OSArch       string    `json:"os_arch"`
	Version      string    `json:"version"`
	UptimeSec    int64     `json:"uptime_sec"`
	Reachability string    `json:"reachability"`
	IsExitNode   bool      `json:"is_exit_node"`
	ExitNAT      bool      `json:"exit_nat"`
	TxSpeed      uint64    `json:"tx_speed"`
	RxSpeed      uint64    `json:"rx_speed"`
	TotalTx           uint64    `json:"total_tx"`
	TotalRx           uint64    `json:"total_rx"`
	AdvertisedSubnets []string  `json:"advertised_subnets"`
	LastSync          time.Time `json:"last_sync"`
}

type Node struct {
	Host                   host.Host
	DHT                    *dht.IpfsDHT
	Config                 *config.Config
	TAP                    tap.TAPDevice
	MACTable               *vswitch.ShardedMACTable
	Packer                 *obfuscate.FramePacker
	dedupPeers             map[peer.ID]*obfuscate.Deduplicator
	dedupPeersMu           sync.RWMutex
	bcastDedup             bcastDedupRing   // content-based dedup for bcast/mcast frames from multiple peers
	Dispatcher             *StrategyDispatcher
	Collector              *web.StatsCollector
	WebSrv                 *web.Server
	Interceptor            *web.TAPInterceptor
	IPTracker              *IPTrafficTracker
	Router                 *routing.Router
	Gateway                *GatewayManager
	NFTManager             *NFTManager
	virtualWebUIV4IP       net.IP
	virtualWebUIV4IPUint32 uint32
	virtualWebUIV6IP       net.IP
	localV4IP              net.IP
	localV4Net             *net.IPNet
	localV6IP              net.IP
	localMAC               net.HardwareAddr
	peerMeta               sync.Map
	cachedRoutesMu         sync.RWMutex
	cachedRoutes           map[peer.ID]routing.RouteInfo
	cachedRoutesAt         time.Time
	relayLatencyMu         sync.RWMutex
	relayLatency           map[peer.ID]time.Duration // per-relay-peer RTT cache
	relayAuthMu            sync.Mutex
	relayAuthInProgress    map[peer.ID]bool // dedup ConnectedF-triggered relay auth per peer
	ctx                    context.Context
	cancel                 context.CancelFunc
	wg                     sync.WaitGroup

	// Bounded dispatch worker pool to prevent unbounded goroutine explosion
	// in the TAP-to-P2P forwarding path (was root cause of 75% ICMP packet loss).
	dispatchCh       chan dispatchTask
	dispatchDropCount uint64 // atomic: number of frames dropped due to full channel

	// Protect against rapid transport churn: tracks whether we saw a direct
	// (non-relay) connection.  DisconnectedF consults this to avoid purging
	// peer state when only a stray relay transport drops.
	directConnected     map[peer.ID]bool
	directConnectedMu   sync.Mutex

	// Ping-pong keepalive: fail counts for each peer
	pingPongFailCount   map[peer.ID]int
	pingPongFailMu      sync.Mutex

	// Reconnect cooldown per peer to prevent rapid-fire reconnect loops on send failures
	lastReconnectTime   map[peer.ID]time.Time
	reconnectTimeMu     sync.Mutex

	// Persistent relay stream pool — one long-lived OverlayRelayProtocolID
	// stream per relay hop, eliminating per-frame stream open handshakes.
	relayPool *relayStreamPool
}

// dispatchTask represents a single P2P frame send job picked up by a dispatch worker.
type dispatchTask struct {
	kind      uint8   // 0=unicast, 1=broadcast, 2=relay
	target    peer.ID // unicast/relay destination
	relayHop  peer.ID // relay next-hop (only for kind=2)
	data      []byte
	relayData []byte // relay-wrapped data (only for kind=2)
	origLen   int    // original Ethernet frame length (TX bytes to count on success)
}

// bcastDedupRing is a lightweight content-based deduplication ring for
// broadcast/multicast frames that arrive from multiple peers.  Without this,
// the same L2 frame written to TAP N times (once per peer stream) wastes
// kernel CPU and can confuse upper-layer protocols.
type bcastDedupRing struct {
	mu     sync.Mutex
	hashes [128]uint64
	next   int
}

func (r *bcastDedupRing) isDuplicate(h uint64) bool {
	if h == 0 {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range r.hashes {
		if r.hashes[i] == h {
			return true
		}
	}
	r.hashes[r.next] = h
	r.next = (r.next + 1) % len(r.hashes)
	return false
}

// fnvHash64 returns a FNV-1a 64-bit hash of data (fast, good distribution).
func fnvHash64(data []byte) uint64 {
	h := fnv.New64a()
	h.Write(data)
	return h.Sum64()
}

// isBroadcastOrMulticastMAC returns true if mac is a group address
// (broadcast FF:FF:FF:FF:FF:FF, or multicast with bit 0 of first byte set).
func isBroadcastOrMulticastMAC(mac net.HardwareAddr) bool {
	if len(mac) < 1 {
		return false
	}
	return mac[0]&1 == 1
}

type mdnsNotifee struct {
	h host.Host
}

func (m *mdnsNotifee) HandlePeerFound(pi peer.AddrInfo) {
	if pi.ID == m.h.ID() {
		return
	}
	log.Info("mDNS discovered local LAN peer %s, connecting...", pi.ID.String())
	go func(info peer.AddrInfo) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := m.h.Connect(ctx, info); err != nil {
			log.Debug("mDNS connect to peer %s failed: %v", info.ID.String(), err)
		} else {
			log.Info("mDNS connected to peer %s successfully", info.ID.String())
		}
	}(pi)
}

func NewNode(cfg *config.Config) (*Node, error) {
	return NewNodeWithTAP(cfg, nil)
}

func NewNodeWithTAP(cfg *config.Config, overrideTAP tap.TAPDevice) (*Node, error) {
	ctx, cancel := context.WithCancel(context.Background())

	var tapDev tap.TAPDevice
	var err error
	if overrideTAP != nil {
		tapDev = overrideTAP
	} else {
		tapDev, err = tap.CreateTAPDevice(cfg.TapName, cfg.TapIP, cfg.TapIPv6, cfg.TapMAC, cfg.DriverType, cfg.MTU)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("failed to create TAP device: %w", err)
		}
	}

	// Pre-parse bootstrap peers into AddrInfo for relay and connection
	var bootstrapRelays []peer.AddrInfo
	for _, bStr := range cfg.BootstrapPeers {
		ma, err := multiaddr.NewMultiaddr(bStr)
		if err != nil {
			log.Debug("Invalid bootstrap multiaddr '%s': %v", bStr, err)
			continue
		}
		info, err := peer.AddrInfoFromP2pAddr(ma)
		if err != nil {
			log.Debug("Cannot parse AddrInfo from bootstrap '%s': %v", bStr, err)
			continue
		}
		bootstrapRelays = append(bootstrapRelays, *info)
	}
	log.Debug("Parsed %d bootstrap peers as relay candidates", len(bootstrapRelays))

	opts := []libp2p.Option{
		libp2p.NATPortMap(),
		libp2p.EnableNATService(),
		libp2p.EnableRelay(),
		libp2p.EnableHolePunching(),
		// Force reachability to private: ensures relay addresses are always advertised
		// and DCUtR hole punching is used even when AutoNAT is unreliable.
		// Without this, libp2p may misidentify a NAT'd node as "public" and skip
		// relay advertisement, causing connection failures for peers behind NAT.
		libp2p.ForceReachabilityPrivate(),
		libp2p.AddrsFactory(func(addrs []multiaddr.Multiaddr) []multiaddr.Multiaddr {
			var filtered []multiaddr.Multiaddr
			for _, a := range addrs {
				// Exclude 127.0.0.1 / ::1 loopback addresses from external broadcast
				if manet.IsIPLoopback(a) {
					continue
				}
				// Exclude TAP virtual device to avoid circular P2P dialing
				if isTapMultiaddr(a, cfg.TapIP, cfg.TapIPv6, cfg.WebUI.ListenIP, cfg.WebUI.ListenIPv6) {
					continue
				}
				filtered = append(filtered, a)
			}

			if len(filtered) > 0 {
				return filtered
			}
			return addrs
		}),
	}

	// Enable AutoRelay with bootstrap peers as static relay servers
	if len(bootstrapRelays) > 0 {
		opts = append(opts, libp2p.EnableAutoRelayWithStaticRelays(bootstrapRelays))
		log.Info("AutoRelay enabled with %d static relay servers", len(bootstrapRelays))
	} else {
		log.Warn("No bootstrap peers configured — NAT traversal via relay will be unavailable")
	}

	// Persistent Node Identity Key
	if cfg.NodeKeyFile != "" {
		log.Debug("Loading persistent identity key from: %s", cfg.NodeKeyFile)
		privKey, err := loadOrGenerateNodeKey(cfg.NodeKeyFile)
		if err != nil {
			log.Warn("Failed to load key from %s (%v), fallback to ephemeral key", cfg.NodeKeyFile, err)
		} else {
			opts = append(opts, libp2p.Identity(privKey))
			log.Debug("Persistent identity key loaded successfully")
		}
	}

	// Parse listen addrs according to enabled transport flags
	var addrs []multiaddr.Multiaddr
	for _, aStr := range cfg.ListenAddrs {
		if !cfg.Transports.EnableQUICReuse && (containsSub(aStr, "quic-v1") || containsSub(aStr, "quic")) {
			log.Debug("Skipping disabled QUIC listen addr: %s", aStr)
			continue
		}
		if !cfg.Transports.EnableWebRTC && containsSub(aStr, "webrtc-direct") {
			log.Debug("Skipping disabled WebRTC listen addr: %s", aStr)
			continue
		}
		if !cfg.Transports.EnableWebTransport && containsSub(aStr, "webtransport") {
			log.Debug("Skipping disabled WebTransport listen addr: %s", aStr)
			continue
		}
		if !cfg.Transports.EnableTCPReuse && containsSub(aStr, "/tcp/") {
			log.Debug("Skipping disabled TCP listen addr: %s", aStr)
			continue
		}
		ma, err := multiaddr.NewMultiaddr(aStr)
		if err == nil {
			addrs = append(addrs, ma)
		} else {
			log.Warn("Invalid listen multiaddr '%s': %v", aStr, err)
		}
	}
	if len(addrs) > 0 {
		opts = append(opts, libp2p.ListenAddrs(addrs...))
		log.Debug("Configured %d listen addresses", len(addrs))
	}

	// Use NullResourceManager to prevent stream limits from dropping high-rate TAP forwarding frames
	opts = append(opts, libp2p.ResourceManager(&network.NullResourceManager{}))

	h, err := libp2p.New(opts...)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create libp2p host: %w", err)
	}
	log.Info("libp2p host created, PeerID: %s", h.ID().String())

	// Initialize Kademlia DHT for Peer discovery
	kdht, err := dht.New(ctx, h)
	if err != nil {
		log.Warn("DHT init error: %v", err)
	} else {
		_ = kdht.Bootstrap(ctx)
		log.Debug("DHT bootstrapped")
	}

	// Initialize mDNS LAN Auto-Discovery if enabled
	if cfg.EnableMDNS {
		notifee := &mdnsNotifee{h: h}
		s := mdns.NewMdnsService(h, "_p2ptap-discovery._udp.local", notifee)
		if err := s.Start(); err != nil {
			log.Warn("mDNS start error: %v", err)
		} else {
			log.Info("mDNS LAN Auto-Discovery enabled")
		}
	}

	macTable := vswitch.NewMACTable()
	packer := obfuscate.NewFramePacker(cfg.Obfuscation.Enable, cfg.Obfuscation.Mode, cfg.Obfuscation.FixedSize, cfg.Obfuscation.BlockSize)
	dispatcher := NewStrategyDispatcher(h, cfg.TransportStrategy)
	collector := web.NewStatsCollector()

	nodeName := cfg.NodeName
	if nodeName == "" || nodeName == "auto" {
		if hostName, err := os.Hostname(); err == nil && hostName != "" {
			nodeName = hostName
		} else {
			nodeName = "p2ptap-node"
		}
	}

	collector.SetNodeInfo(nodeName, h.ID().String(), cfg.TapIP, cfg.TapIPv6, cfg.TransportStrategy)

	pskStatus := "🌐 Public (Unencrypted)"
	if cfg.PSK != "" {
		pskStatus = "🔐 Encrypted Overlay (Noise/PSK)"
	}

	obfsMode := "Disabled"
	if cfg.Obfuscation.Enable {
		obfsMode = fmt.Sprintf("🛡️ Active (%s mode, %dB)", cfg.Obfuscation.Mode, cfg.Obfuscation.FixedSize)
	}

	collector.Security = web.SecurityStatusDTO{
		PSKStatus:      pskStatus,
		Obfuscation:    obfsMode,
		KeyFingerprint: computeKeyFingerprint(cfg.NodeKeyFile),
	}

	node := &Node{
		Host:         h,
		DHT:          kdht,
		Config:       cfg,
		TAP:          tapDev,
		MACTable:     macTable,
		Packer:       packer,
		dedupPeers:   make(map[peer.ID]*obfuscate.Deduplicator),
		Dispatcher:   dispatcher,
		Collector:    collector,
		IPTracker:    NewIPTrafficTracker(),
		Router:       routing.NewRouter(h.ID()),
		Gateway:      NewGatewayManager(cfg.TapName),
		NFTManager:   NewNFTManager(&cfg.ExitNode),
		relayLatency:      make(map[peer.ID]time.Duration),
		relayAuthInProgress: make(map[peer.ID]bool),
		directConnected:  make(map[peer.ID]bool),
		pingPongFailCount: make(map[peer.ID]int),
		dispatchCh:   make(chan dispatchTask, 256), // bounded buffer: 256 frames
		ctx:          ctx,
		cancel:       cancel,
	}
	node.relayPool = newRelayStreamPool(ctx, h)

	// Populate TAP interface state for WebUI diagnostics
	collector.TAPState = &web.TAPStateDTO{
		InterfaceName: cfg.TapName,
		IPv4:          cfg.TapIP,
		IPv6:          cfg.TapIPv6,
		MAC:           cfg.TapMAC,
		MTU:           cfg.MTU,
		IsUp:          true,
		RouteConfigured: cfg.TapIP != "",
	}

	// Wire collector callbacks so web handlers can resolve peer addresses and
	// trigger Exit Node NAT reconfiguration after hot-reload.
	collector.ResolvePeerAddrs = func(peerIDStr string) []string {
		pid, err := peer.Decode(peerIDStr)
		if err != nil {
			return nil
		}
		var ips []string
		for _, a := range h.Peerstore().Addrs(pid) {
			multiaddr.ForEach(a, func(c multiaddr.Component) bool {
				if c.Protocol().Code == multiaddr.P_IP4 || c.Protocol().Code == multiaddr.P_IP6 {
					ips = append(ips, c.Value())
				}
				return true
			})
		}
		return ips
	}
	collector.OnExitNodeChanged = func() {
		node.NFTManager.UpdateConfig(&node.Config.ExitNode)
		if node.Config.ExitNode.Enable {
			_ = node.NFTManager.SetupExitNodeNAT(node.Config.ExitNode.WANInterface, node.Config.TapName)
		} else {
			_ = node.NFTManager.CleanupExitNodeNAT()
		}
	}
	collector.OnObfuscationChanged = func() {
		if node.Packer != nil {
			node.Packer.UpdateConfig(&node.Config.Obfuscation)
			log.Info("Obfuscation config hot-reloaded: mode=%s", node.Packer.Mode)
		}
	}
	collector.TestPeerMultiaddrs = func(peerIDStr string) []web.MultiaddrTestResultEntry {
		return node.TestMultiaddrLatency(peerIDStr)
	}

	collector.ProbePeerEcho = func(peerIDStr string) *web.PeerEchoResultDTO {
		return node.ProbePeerEcho(peerIDStr)
	}
	collector.ProbePeerEchoAddr = func(peerIDStr string, targetAddrStr string) *web.PeerEchoResultDTO {
		return node.ProbePeerEchoAddr(peerIDStr, targetAddrStr)
	}
	collector.AddStaticPeer = func(multiaddrStr string) error {
		ma, err := multiaddr.NewMultiaddr(multiaddrStr)
		if err != nil {
			return fmt.Errorf("invalid multiaddr: %w", err)
		}
		info, err := peer.AddrInfoFromP2pAddr(ma)
		if err != nil {
			return fmt.Errorf("failed to parse peer info from multiaddr: %w", err)
		}
		node.Host.Peerstore().AddAddrs(info.ID, info.Addrs, peerstore.PermanentAddrTTL)
		go node.connectWithRetry(*info, "static-manual", 3*time.Second, 5)
		return nil
	}

	collector.ProbePeerConnectivity = func(peerIDStr string) *web.PeerConnectivityResult {
		result := &web.PeerConnectivityResult{
			PeerID:   peerIDStr,
			ProbedAt: time.Now(),
		}
		var pid peer.ID
		decodedPID, err := peer.Decode(peerIDStr)
		if err == nil {
			pid = decodedPID
		} else if node.Collector != nil {
			for _, p := range node.Collector.ActivePeers {
				if p.PeerID == peerIDStr || p.TapIP == peerIDStr || p.TapIPv6 == peerIDStr || strings.EqualFold(p.NodeName, peerIDStr) {
					if parsed, err := peer.Decode(p.PeerID); err == nil {
						pid = parsed
						result.PeerID = p.PeerID
						break
					}
				}
			}
		}
		if pid == "" {
			result.Error = fmt.Sprintf("cannot resolve target '%s' to a connected peer ID", peerIDStr)
			return result
		}

		// 1. Multiaddr-level probes (real SYN/TCP-connect RTT per address)
		result.Results = node.TestMultiaddrLatency(peerIDStr)
		for _, r := range result.Results {
			if r.Reachable {
				if r.IsActive {
					result.DirectOk = true
				}
				if r.RTTMs > 0 && (r.RTTMs < result.RTTMs || result.RTTMs == 0) {
					result.RTTMs = r.RTTMs
				}
			}
		}

		// 2. Check if there's a relay path
		if !result.DirectOk {
			relayAddrs := node.SynthesizeRelayCircuitAddrs(pid)
			for _, ra := range relayAddrs {
				ctx, cancel := context.WithTimeout(node.ctx, 3*time.Second)
				start := time.Now()
				err := node.Host.Connect(ctx, peer.AddrInfo{ID: pid, Addrs: []multiaddr.Multiaddr{ra}})
				elapsed := time.Since(start)
				cancel()
				if err == nil {
					result.RelayOk = true
					result.RTTMs = elapsed.Milliseconds()
					result.Reachable = true
					break
				}
			}
		}

		// 3. Stream-level check: open a protocol stream
		checkStream := func() (bool, int64) {
			ctx, cancel := context.WithTimeout(node.ctx, 4*time.Second)
			defer cancel()
			start := time.Now()
			s, err := node.Host.NewStream(ctx, pid, ProtocolID)
			elapsed := time.Since(start).Milliseconds()
			if err != nil {
				return false, 0
			}
			s.Close()
			return true, elapsed
		}

		for i := 0; i < 3; i++ {
			ok, rtt := checkStream()
			if ok {
				result.StreamsOk++
				if rtt > 0 && (rtt < result.RTTMs || result.RTTMs == 0) {
					result.RTTMs = rtt
				}
			} else {
				result.StreamsErr++
			}
		}

		result.Reachable = result.DirectOk || result.RelayOk || result.StreamsOk > 0
		if !result.Reachable {
			result.Error = "peer unreachable via direct or relay paths"
		}
		return result
	}

	if cfg.TapIP != "" {
		cleanIP, _, _ := strings.Cut(cfg.TapIP, "/")
		node.localV4IP = net.ParseIP(cleanIP)
		if _, ipNet, err := net.ParseCIDR(cfg.TapIP); err == nil {
			node.localV4Net = ipNet
		}
	}
	if cfg.TapIPv6 != "" {
		cleanIP, _, _ := strings.Cut(cfg.TapIPv6, "/")
		node.localV6IP = net.ParseIP(cleanIP)
	}
	if cfg.TapMAC != "" {
		if hw, err := net.ParseMAC(cfg.TapMAC); err == nil {
			node.localMAC = hw
		}
	}
	node.Dispatcher.SetOutgoingStreamHandler(node.handleStream)

	// Set libp2p stream handler
	h.SetStreamHandler(ProtocolID, node.handleStream)
	log.Debug("Stream handler registered for protocol: %s", ProtocolID)

	h.SetStreamHandler(LSAProtocolID, node.handleLSAStream)
	log.Debug("Stream handler registered for LSA protocol: %s", LSAProtocolID)

	h.SetStreamHandler(OverlayRelayProtocolID, node.handleRelayStream)
	log.Debug("Stream handler registered for Overlay Relay protocol: %s", OverlayRelayProtocolID)

	h.SetStreamHandler(HealthCheckProtocolID, node.handleHealthCheck)
	log.Debug("Stream handler registered for Health Check protocol: %s", HealthCheckProtocolID)

	h.SetStreamHandler(EchoProtocolID, node.handleEcho)
	log.Debug("Stream handler registered for Echo protocol: %s", EchoProtocolID)

	node.registerMetaStreamHandler()

	// Register network event notifier for connection/disconnection logging & state cleanup
	h.Network().Notify(&network.NotifyBundle{
		ConnectedF: func(netw network.Network, conn network.Conn) {
			pID := conn.RemotePeer()
			addrStr := conn.RemoteMultiaddr().String()
			isCircuitRelay := strings.Contains(addrStr, "/p2p-circuit")

			if isCircuitRelay {
				log.Info("Peer connected via CIRCUIT RELAY: %s via %s", pID.String(), addrStr)
				// p2p-circuit provides transparent L3 connectivity, so register
				// it as a direct link for routing purposes. This ensures unicast
				// frames use ProtocolID (handleStream) instead of incorrectly
				// routing through OverlayRelayProtocolID which has lower throughput.
				rttMs := node.getPeerLatency(pID)
				if rttMs <= 0 {
					rttMs = 30 // relay paths are typically 20-80ms
				}
				node.Router.UpdateDirectLink(pID, rttMs)
				if node.isBootstrapPeer(pID) {
					node.recordRelayLatency(pID, time.Duration(rttMs)*time.Millisecond)
				}
			} else {
				log.Info("Peer connected DIRECT: %s via %s", pID.String(), addrStr)

				node.directConnectedMu.Lock()
				node.directConnected[pID] = true
				node.directConnectedMu.Unlock()

				rttMs := node.getPeerLatency(pID)
				if rttMs <= 0 {
					rttMs = 10
				}
				node.Router.UpdateDirectLink(pID, rttMs)
			}

		if node.isBootstrapPeer(pID) {
			go func() {
				// Dedup: ConnectedF can fire per-connection (multiple
				// transports or connection upgrades).  Only run one
				// auth attempt per bootstrap peer at a time.
				node.relayAuthMu.Lock()
				if node.relayAuthInProgress[pID] {
					node.relayAuthMu.Unlock()
					return
				}
				node.relayAuthInProgress[pID] = true
				node.relayAuthMu.Unlock()

				ok := node.authenticateWithRelay(pID)

				node.relayAuthMu.Lock()
				delete(node.relayAuthInProgress, pID)
				node.relayAuthMu.Unlock()

				if ok {
					addrs := netw.Peerstore().Addrs(pID)
					if len(addrs) > 0 {
						node.reserveRelaySlotWithRetry(peer.AddrInfo{ID: pID, Addrs: addrs}, 2)
					}
				}
			}()
			}
		},
		DisconnectedF: func(netw network.Network, conn network.Conn) {
			pID := conn.RemotePeer()
			addrStr := conn.RemoteMultiaddr().String()
			isCircuitRelay := strings.Contains(addrStr, "/p2p-circuit")
			remaining := len(netw.ConnsToPeer(pID))

			if remaining > 0 {
				if isCircuitRelay {
					log.Debug("Relay transport dropped for %s (direct connection still active, %d remaining)", pID.String(), remaining)
				} else {
					log.Debug("Direct transport dropped for %s (%d other transports still active)", pID.String(), remaining)
				}
				return
			}

			// All transports gone — debounce: if we had a direct connection that just
			// dropped, wait 2s to see if it comes back (e.g. due to dialInParallel race).
			node.directConnectedMu.Lock()
			hadDirect := node.directConnected[pID]
			delete(node.directConnected, pID)
			node.directConnectedMu.Unlock()

			if hadDirect {
				debounceID := pID
				go func() {
					time.Sleep(2 * time.Second)
					if node.Host.Network().Connectedness(debounceID) == network.Connected ||
						len(node.Host.Network().ConnsToPeer(debounceID)) > 0 {
						log.Debug("Peer %s recovered within debounce window, not purging", debounceID.String())
						node.directConnectedMu.Lock()
						node.directConnected[debounceID] = true
						node.directConnectedMu.Unlock()
						return
					}
					log.Info("Peer disconnected: %s (last transport lost, purging links, metadata & MAC table)", debounceID.String())
					node.Router.RemoveDirectLink(debounceID)
					node.peerMeta.Delete(debounceID)
					node.MACTable.CleanPeer(debounceID)
					node.Dispatcher.RemovePeer(debounceID)
					if node.Gateway != nil {
						node.Gateway.ClearSubnetRoutes()
					}
				}()
			} else {
				log.Info("Peer disconnected: %s via %s (last transport lost, purging links, metadata & MAC table)", pID.String(), addrStr)
				node.Router.RemoveDirectLink(pID)
				node.peerMeta.Delete(pID)
				node.MACTable.CleanPeer(pID)
				node.Dispatcher.RemovePeer(pID)
				if node.Gateway != nil {
					node.Gateway.ClearSubnetRoutes()
				}
			}
		},
	})

	// Start Web UI Server if configured
	if cfg.WebUI.Enable {
		listenIP := cfg.WebUI.ListenIP
		listenIPv6 := cfg.WebUI.ListenIPv6

		isVirtualV4 := IsVirtualIP(listenIP, cfg.TapIP)
		isVirtualV6 := IsVirtualIP(listenIPv6, cfg.TapIPv6)

		var virtualIP, virtualIPv6, localIP, localIPv6 string

		if isVirtualV4 {
			virtualIP = listenIP
			v4 := net.ParseIP(strings.Split(listenIP, "/")[0]).To4()
			if v4 != nil {
				node.virtualWebUIV4IP = v4
				node.virtualWebUIV4IPUint32 = binary.BigEndian.Uint32(v4)
			}
		} else {
			localIP = listenIP
		}

		if isVirtualV6 {
			virtualIPv6 = listenIPv6
			node.virtualWebUIV6IP = net.ParseIP(strings.Split(listenIPv6, "/")[0])
		} else {
			localIPv6 = listenIPv6
		}

		// 1. Start Userspace Packet Interceptor for any virtual IPs
		if isVirtualV4 || isVirtualV6 {
			node.Interceptor = web.NewTAPInterceptor(virtualIP, virtualIPv6, cfg.WebUI.Port, collector, cfg, cfg.ConfigPath)
			log.Info("WebUI Virtual IP Interceptor active (v4: %s, v6: %s) on port %d", virtualIP, virtualIPv6, cfg.WebUI.Port)
			if setter, ok := tapDev.(interface{ SetWebUIIP(string) }); ok {
				if virtualIP != "" {
					setter.SetWebUIIP(virtualIP)
				} else if virtualIPv6 != "" {
					setter.SetWebUIIP(virtualIPv6) // Fallback for platforms that need at least one
				}
			}
		}

		// 2. Start Native OS WebServer for any non-virtual, local IPs
		if localIP != "" || localIPv6 != "" {
			bindIP := localIP
			bindIPv6 := localIPv6
			if bindIPv6 == "" || bindIPv6 == "auto" {
				bindIPv6 = "::" // Bind to all IPv6 addresses if not specified
			}
			log.Info("WebUI listening on (v4: %s, v6: %s) on port %d (native OS stack mode)", bindIP, bindIPv6, cfg.WebUI.Port)
			webSrv, err := web.StartServer(collector, bindIP, bindIPv6, cfg.WebUI.Port, cfg, cfg.ConfigPath)
			if err != nil {
				log.Warn("WebServer start failed: %v", err)
			} else {
				node.WebSrv = webSrv
			}
		}
	}

	return node, nil
}

func (n *Node) Start() {
	// Connect to Bootstrap Peers with retry
	for _, bStr := range n.Config.BootstrapPeers {
		ma, err := multiaddr.NewMultiaddr(bStr)
		if err != nil {
			log.Debug("Invalid bootstrap multiaddr '%s': %v", bStr, err)
			continue
		}
		info, err := peer.AddrInfoFromP2pAddr(ma)
		if err == nil {
			n.Host.Peerstore().AddAddrs(info.ID, info.Addrs, peerstore.PermanentAddrTTL)
			go n.connectWithRetry(*info, "bootstrap", 5*time.Second, 10)
		}
	}

	// Connect to Static Peers with retry
	for _, sStr := range n.Config.StaticPeers {
		ma, err := multiaddr.NewMultiaddr(sStr)
		if err != nil {
			log.Debug("Invalid static peer multiaddr '%s': %v", sStr, err)
			continue
		}
		info, err := peer.AddrInfoFromP2pAddr(ma)
		if err == nil {
			n.Host.Peerstore().AddAddrs(info.ID, info.Addrs, peerstore.PermanentAddrTTL)
			go n.connectWithRetry(*info, "static", 5*time.Second, 10)
		}
	}

	// Start TAP Read Pipeline Goroutine
	n.wg.Add(1)
	go n.tapReadLoop()
	log.Debug("TAP read loop started")

	// Start bounded dispatch worker pool for TAP->P2P forwarding
	const dispatchWorkers = 4
	for i := 0; i < dispatchWorkers; i++ {
		n.wg.Add(1)
		go n.dispatchWorker(i)
	}
	log.Debug("Dispatch worker pool started (%d workers, buffer=%d)", dispatchWorkers, cap(n.dispatchCh))

	// Start Background MAC Cleaning Goroutine
	n.wg.Add(1)
	go n.macCleanLoop()
	log.Debug("MAC clean loop started")

	// Start persistent bootstrap/relay reconnection loop
	n.wg.Add(1)
	go n.bootstrapKeepAliveLoop()
	log.Debug("Bootstrap keep-alive loop started")

	// Start connection health check loop (stream-level probing for connected peers)
	n.wg.Add(1)
	go n.peerHealthCheckLoop()
	log.Debug("Peer health check loop started")

	// Start ping-pong keepalive loop (fast 5s echo-based liveness check)
	n.wg.Add(1)
	go n.peerPingPongLoop()
	log.Debug("Peer ping-pong keepalive loop started")

	// Start P2P metadata synchronization loop
	n.wg.Add(1)
	go n.metaSyncLoop()
	log.Debug("Metadata synchronization loop started")

	// Start Link-State Advertisement loop
	n.wg.Add(1)
	go n.lsaLoop()
	log.Debug("Link-State Advertisement loop started")

	// Start DHT Discovery Loop based on PSK
	if n.Config.PSK != "" {
		n.wg.Add(1)
		go n.discoveryLoop()
		log.Info("DHT discovery loop started for PSK network")
	}

	// Setup Exit Node NAT if enabled in config
	if n.Config.ExitNode.Enable {
		_ = n.NFTManager.SetupExitNodeNAT(n.Config.ExitNode.WANInterface, n.Config.TapName)
	}
}

// connectWithRetry attempts to connect to a peer with exponential backoff retry.
// First attempt uses parallel direct+relay racing; subsequent attempts use standard Connect.
func (n *Node) connectWithRetry(pi peer.AddrInfo, peerType string, baseDelay time.Duration, maxRetries int) {
	for attempt := 1; attempt <= maxRetries; attempt++ {
		select {
		case <-n.ctx.Done():
			return
		default:
		}

		// Every attempt uses parallel direct+relay race.
		// For NAT'd peers direct dial often fails, so relay is the only option.
		log.Debug("Connecting to %s peer %s (attempt %d/%d with parallel direct+relay race)...",
			peerType, pi.ID.String(), attempt, maxRetries)
		err := n.dialInParallel(n.ctx, pi, peerType)

		if err != nil {
			delay := baseDelay * time.Duration(attempt)
			if delay > 60*time.Second {
				delay = 60 * time.Second
			}
			log.Debug("%s peer %s connect failed (attempt %d): %v, retrying in %v", peerType, pi.ID.String(), attempt, err, delay)
			select {
			case <-n.ctx.Done():
				return
			case <-time.After(delay):
			}
		} else {
			return
		}
	}
	log.Warn("Failed to connect to %s peer %s after %d attempts", peerType, pi.ID.String(), maxRetries)
}

const relayAuthProtocol = "/p2ptap/auth/1.0.0"

// authenticateWithRelay performs PSK challenge-response with a relay/bootstrap server
func (n *Node) authenticateWithRelay(peerID peer.ID) bool {
	if n.Config.PSK == "" {
		return true
	}
	log.Debug("Authenticating with relay peer %s using PSK...", peerID.String())

	s, err := n.Host.NewStream(n.ctx, peerID, relayAuthProtocol)
	if err != nil {
		log.Debug("Relay auth stream open failed for peer %s: %v (relay does not require PSK)", peerID.String(), err)
		return true
	}
	defer s.Close()

	// Compute auth token: SHA-256("p2ptap-relay-auth:" + PSK)
	token := sha256.Sum256([]byte("p2ptap-relay-auth:" + n.Config.PSK))

	// Send 32-byte auth token
	if _, err := s.Write(token[:]); err != nil {
		log.Debug("Relay auth write failed for peer %s: %v", peerID.String(), err)
		return false
	}

	// Read 1-byte response
	var resp [1]byte
	if _, err := io.ReadFull(s, resp[:]); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			log.Debug("Relay peer %s closed auth stream (relay does not require PSK auth)", peerID.String())
			return true
		}
		log.Debug("Relay auth response read info for peer %s: %v", peerID.String(), err)
		return false
	}

	if resp[0] == 0x01 {
		log.Info("Relay auth SUCCESS with peer %s — relay access granted", peerID.String())
		return true
	}

	log.Warn("Relay auth FAILED with peer %s — PSK mismatch, relay access denied", peerID.String())
	return false
}

func (n *Node) reserveRelaySlot(pi peer.AddrInfo) {
	ctx, cancel := context.WithTimeout(n.ctx, 10*time.Second)
	defer cancel()

	res, err := relayClient.Reserve(ctx, n.Host, pi)
	if err != nil {
		log.Warn("Circuit Relay v2 reservation FAILED on bootstrap %s: %v", pi.ID.String(), err)
		return
	}

	log.Info("Circuit Relay v2 reservation ACTIVE on relay %s (expiration: %v)", pi.ID.String(), res.Expiration)

	circuitComponent, err := multiaddr.NewMultiaddr(fmt.Sprintf("/p2p/%s/p2p-circuit", pi.ID.String()))
	if err != nil {
		return
	}

	var circuitAddrs []multiaddr.Multiaddr
	for _, a := range pi.Addrs {
		if manet.IsIPLoopback(a) {
			continue
		}
		fullAddr := a.Encapsulate(circuitComponent)
		circuitAddrs = append(circuitAddrs, fullAddr)
	}

	if len(circuitAddrs) > 0 {
		n.Host.Peerstore().AddAddrs(n.Host.ID(), circuitAddrs, 1*time.Hour)
		log.Info("Registered %d Circuit Relay v2 multiaddrs on local host", len(circuitAddrs))
	}
}

// bootstrapKeepAliveLoop periodically reconnects to bootstrap/static peers that have disconnected
func (n *Node) bootstrapKeepAliveLoop() {
	defer n.wg.Done()
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-n.ctx.Done():
			return
		case <-ticker.C:
			// Check and reconnect to bootstrap peers
			for _, bStr := range n.Config.BootstrapPeers {
				ma, err := multiaddr.NewMultiaddr(bStr)
				if err != nil {
					continue
				}
				info, err := peer.AddrInfoFromP2pAddr(ma)
				if err != nil {
					continue
				}
				if n.Host.Network().Connectedness(info.ID) != network.Connected {
					log.Debug("Bootstrap peer %s disconnected, reconnecting...", info.ID.String())
					go n.connectWithRetry(*info, "bootstrap", 5*time.Second, 3)
			} else {
				// Peer is connected: refresh/renew Circuit Relay v2 slot reservation
				go func(info peer.AddrInfo) {
					n.relayAuthMu.Lock()
					if n.relayAuthInProgress[info.ID] {
						n.relayAuthMu.Unlock()
						return
					}
					n.relayAuthInProgress[info.ID] = true
					n.relayAuthMu.Unlock()

					ok := n.authenticateWithRelay(info.ID)

					n.relayAuthMu.Lock()
					delete(n.relayAuthInProgress, info.ID)
					n.relayAuthMu.Unlock()

					if ok {
						n.reserveRelaySlotWithRetry(info, 2)
						}
					}(*info)
				}
			}

			// Check and reconnect to static peers
			for _, sStr := range n.Config.StaticPeers {
				ma, err := multiaddr.NewMultiaddr(sStr)
				if err != nil {
					continue
				}
				info, err := peer.AddrInfoFromP2pAddr(ma)
				if err != nil {
					continue
				}
				// Inspired by official libp2p chat example: permanently register static peer addrs in Peerstore
				n.Host.Peerstore().AddAddrs(info.ID, info.Addrs, peerstore.PermanentAddrTTL)

				if n.Host.Network().Connectedness(info.ID) != network.Connected {
					log.Debug("Static peer %s disconnected, reconnecting...", info.ID.String())
					go n.connectWithRetry(*info, "static", 5*time.Second, 3)
				}
			}
		}
	}
}

// peerHealthCheckLoop periodically probes connected peers for stream-level
// reachability and triggers reconnects for persistently unreachable peers.
// This prevents the connected-but-unpingable state where libp2p reports
// Connected but P2P streams/TAP traffic silently fails.
func (n *Node) peerHealthCheckLoop() {
	defer n.wg.Done()
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	// Track consecutive failures per peer
	failCounts := make(map[peer.ID]int)
	const maxFailures = 3

	for {
		select {
		case <-n.ctx.Done():
			return
		case <-ticker.C:
			peers := n.Host.Network().Peers()
			for _, pid := range peers {
				if n.Host.Network().Connectedness(pid) != network.Connected {
					delete(failCounts, pid)
					continue
				}

			// Skip self
			if pid == n.Host.ID() {
				continue
			}

			// Bootstrap relay peers don't run p2ptap health protocol;
			// probing them would always fail and trigger a spurious
			// reconnect+purge cycle every ~90s.
			if n.isBootstrapPeer(pid) {
				delete(failCounts, pid)
				continue
			}

			// Quick stream-level health probe
				ctx, cancel := context.WithTimeout(n.ctx, 5*time.Second)
				start := time.Now()
				s, err := n.Host.NewStream(ctx, pid, HealthCheckProtocolID)
				elapsed := time.Since(start)
				cancel()

				if err != nil {
					failCounts[pid]++
					log.Debug("Health check failed for %s (%d/%d): %v",
						pid.String(), failCounts[pid], maxFailures, err)

					if failCounts[pid] >= maxFailures {
						log.Warn("Peer %s unreachable after %d health checks, triggering reconnect",
							pid.String(), maxFailures)
						n.reconnectPeer(pid)
						delete(failCounts, pid)
					}
				} else {
					s.Close()
					if failCounts[pid] > 0 {
						log.Info("Peer %s recovered after %d failures (RTT=%dms)",
							pid.String(), failCounts[pid], elapsed.Milliseconds())
					}
					delete(failCounts, pid)
				}
			}

			// Clean up stale entries
			for pid := range failCounts {
				if n.Host.Network().Connectedness(pid) != network.Connected {
					delete(failCounts, pid)
				}
			}
		}
	}
}

// HealthCheckProtocolID is a lightweight stream protocol for connectivity probes.
const HealthCheckProtocolID protocol.ID = "/p2ptap/health/1.0.0"

// clearSwarmBackoff aggressively clears the libp2p Swarm dial backoff for a peer
func (n *Node) clearSwarmBackoff(pid peer.ID) {
	if sw, ok := n.Host.Network().(*swarm.Swarm); ok {
		sw.Backoff().Clear(pid)
	}
}

// reconnectPeer disconnects and reconnects to a peer using its known multiaddrs.
func (n *Node) reconnectPeer(pid peer.ID) {
	// Aggressively clear dial backoff
	n.clearSwarmBackoff(pid)

	// Get stored addresses from peerstore
	addrs := n.Host.Peerstore().Addrs(pid)
	if len(addrs) == 0 {
		log.Warn("No stored addrs for peer %s, cannot reconnect", pid.String())
		return
	}

	// Disconnect first
	if err := n.Host.Network().ClosePeer(pid); err != nil {
		log.Debug("ClosePeer %s: %v", pid.String(), err)
	}

	addrInfo := peer.AddrInfo{ID: pid, Addrs: addrs}
	go n.connectWithRetry(addrInfo, "healthcheck", 3*time.Second, 3)
}

// triggerThrottledReconnect triggers peer reconnection on send failures with a 5-second cooldown
func (n *Node) triggerThrottledReconnect(pid peer.ID) {
	n.reconnectTimeMu.Lock()
	if n.lastReconnectTime == nil {
		n.lastReconnectTime = make(map[peer.ID]time.Time)
	}
	last, exists := n.lastReconnectTime[pid]
	if exists && time.Since(last) < 5*time.Second {
		n.reconnectTimeMu.Unlock()
		return
	}
	n.lastReconnectTime[pid] = time.Now()
	n.reconnectTimeMu.Unlock()

	log.Warn("Send failure to peer %s detected, triggering automatic hole-punching / reconnection...", pid.String())
	n.Dispatcher.RemovePeer(pid)
	n.reconnectPeer(pid)
}

// PingPongKeepaliveInterval defines how often we send echo-based liveness probes.
const PingPongKeepaliveInterval = 5 * time.Second
const pingPongStreamTimeout = 3 * time.Second  // stream creation timeout (reduced from 5s)
const pingPongWriteTimeout = 2 * time.Second   // write "PING" timeout (reduced from 3s)
const pingPongReadTimeout = 3 * time.Second    // read echo timeout (reduced from 8s; was > tick interval)
const pingPongMaxFailures = 3
const pingPongMaxConcurrent = 8                // max concurrent peer probes per tick

// resetPingPongFailCountForPeer resets the ping-pong failure counter for a peer.
// This is called from handleStream when data is actively flowing, preventing false
// positives where yamux flow control delays echo streams but the connection is healthy.
func (n *Node) resetPingPongFailCountForPeer(pid peer.ID) {
	n.pingPongFailMu.Lock()
	if count, ok := n.pingPongFailCount[pid]; ok && count > 0 {
		n.pingPongFailCount[pid] = 0
	}
	n.pingPongFailMu.Unlock()
}

// peerPingPongLoop sends echo-based keepalive pings to all connected non-bootstrap
// peers every 5 seconds.  After 3 consecutive timeouts the peer is forcibly
// disconnected and reconnected.  This provides fast dead-connection detection
// (5-15s) vs. the 30s health-check loop which also probes but more slowly.
//
// All peers are probed concurrently (capped at pingPongMaxConcurrent) to prevent
// a single slow peer from blocking the entire probe cycle and causing false
// positive failures on subsequent peers.
func (n *Node) peerPingPongLoop() {
	defer n.wg.Done()
	ticker := time.NewTicker(PingPongKeepaliveInterval)
	defer ticker.Stop()

	for {
		select {
		case <-n.ctx.Done():
			return
		case <-ticker.C:
			peers := n.Host.Network().Peers()
			var probePeers []peer.ID
			for _, pid := range peers {
				if pid == n.Host.ID() {
					continue
				}
				// Include all peers (both normal P2P peers and Bootstrap Relay servers)
				// to maintain active UDP/TCP NAT hole-punch mapping.
				if n.Host.Network().Connectedness(pid) != network.Connected {
					n.pingPongFailMu.Lock()
					delete(n.pingPongFailCount, pid)
					n.pingPongFailMu.Unlock()
					continue
				}
				probePeers = append(probePeers, pid)
			}

			// Probe all peers concurrently (capped by semaphore)
			var wg sync.WaitGroup
			sem := make(chan struct{}, pingPongMaxConcurrent)
			for _, pid := range probePeers {
				wg.Add(1)
				sem <- struct{}{}
				go func(pid peer.ID) {
					defer wg.Done()
					defer func() { <-sem }()
					n.pingPongProbePeer(pid)
				}(pid)
			}
			wg.Wait()

			// Cleanup stale entries
			n.pingPongFailMu.Lock()
			for pid := range n.pingPongFailCount {
				if n.Host.Network().Connectedness(pid) != network.Connected {
					delete(n.pingPongFailCount, pid)
				}
			}
			n.pingPongFailMu.Unlock()
		}
	}
}

// pingPongProbePeer sends a single echo ping to one peer and handles failure counting.
func (n *Node) pingPongProbePeer(pid peer.ID) {
	pingPayload := []byte{0x50, 0x49, 0x4E, 0x47} // "PING"
	ctx, cancel := context.WithTimeout(n.ctx, pingPongStreamTimeout)
	streamCtx := network.WithAllowLimitedConn(ctx, "pingpong")
	start := time.Now()
	s, err := n.Host.NewStream(streamCtx, pid, EchoProtocolID)
	// Release the context immediately — it's only used for stream creation.
	// Keeping it alive during Read/Write can cause unexpected stream resets
	// when the context expires.
	cancel()
	if err != nil {
		n.pingPongFailMu.Lock()
		n.pingPongFailCount[pid]++
		fc := n.pingPongFailCount[pid]
		n.pingPongFailMu.Unlock()

		if fc >= pingPongMaxFailures {
			log.Warn("Ping-pong keepalive failed %d times for %s, forcing reconnect",
				fc, pid.String())
			n.reconnectPeer(pid)
			n.pingPongFailMu.Lock()
			delete(n.pingPongFailCount, pid)
			n.pingPongFailMu.Unlock()
		} else {
			log.Debug("Ping-pong stream open failed for %s (%d/%d): %v",
				pid.String(), fc, pingPongMaxFailures, err)
		}
		return
	}

	// Write ping with dedicated write deadline
	_ = s.SetWriteDeadline(time.Now().Add(pingPongWriteTimeout))
	_, err = s.Write(pingPayload)
	if err != nil {
		s.Close()
		n.pingPongFailMu.Lock()
		n.pingPongFailCount[pid]++
		fc := n.pingPongFailCount[pid]
		n.pingPongFailMu.Unlock()
		if fc >= pingPongMaxFailures {
			log.Warn("Ping-pong write failed %d times for %s, forcing reconnect",
				fc, pid.String())
			n.reconnectPeer(pid)
			n.pingPongFailMu.Lock()
			delete(n.pingPongFailCount, pid)
			n.pingPongFailMu.Unlock()
		}
		return
	}

	// Signal half-close: tell server we're done writing so its io.Copy returns cleanly
	_ = s.CloseWrite()

	// Read echo with read deadline
	_ = s.SetReadDeadline(time.Now().Add(pingPongReadTimeout))
	replyBuf := make([]byte, 8)
	rn, rerr := s.Read(replyBuf)
	s.Close()
	rtt := time.Since(start)

	// Valid echo response: we read at least 4 bytes of "PING" and any read error was nil or EOF
	isValidEcho := (rerr == nil || rerr == io.EOF) && rn >= 4 && bytes.Equal(replyBuf[:4], pingPayload)

	if !isValidEcho {
		n.pingPongFailMu.Lock()
		n.pingPongFailCount[pid]++
		fc := n.pingPongFailCount[pid]
		n.pingPongFailMu.Unlock()
		if fc >= pingPongMaxFailures {
			log.Warn("Ping-pong echo read failed %d times for %s (last err=%v, readBytes=%d), forcing reconnect",
				fc, pid.String(), rerr, rn)
			n.reconnectPeer(pid)
			n.pingPongFailMu.Lock()
			delete(n.pingPongFailCount, pid)
			n.pingPongFailMu.Unlock()
		} else {
			log.Debug("Ping-pong echo read failed for %s (%d/%d) rtt=%dms readBytes=%d err=%v",
				pid.String(), fc, pingPongMaxFailures, rtt.Milliseconds(), rn, rerr)
		}
	} else {
		// Success — reset fail count
		n.pingPongFailMu.Lock()
		n.pingPongFailCount[pid] = 0
		n.pingPongFailMu.Unlock()
		log.Debug("Ping-pong OK for %s RTT=%dms", pid.String(), rtt.Milliseconds())
	}
}

// dialInParallel attempts to dial a peer concurrently via direct connection and
// Circuit Relay, returning whichever succeeds first. This eliminates the sequential
// 3-10s latency penalty when falling back to relay.
// IMPORTANT: When the first goroutine wins, the losing goroutine is explicitly
// cancelled via raceCtx to prevent a second connection from being established
// and causing a libp2p transport conflict/disconnect.
func (n *Node) dialInParallel(ctx context.Context, pi peer.AddrInfo, peerType string) error {
	// Aggressive: Clear any dial backoff and refresh multiaddrs in Peerstore (2 Hours TTL)
	n.clearSwarmBackoff(pi.ID)
	if len(pi.Addrs) > 0 {
		n.Host.Peerstore().ClearAddrs(pi.ID)
		n.Host.Peerstore().AddAddrs(pi.ID, pi.Addrs, 2*time.Hour)
	}

	type result struct {
		err  error
		mode string
	}

	raceCtx, raceCancel := context.WithCancel(ctx)
	defer raceCancel() // ensure both child contexts are cancelled when we return

	ch := make(chan result, 2)

	// Race: direct connection
	go func() {
		directCtx, cancel := context.WithTimeout(raceCtx, 5*time.Second)
		defer cancel()
		err := n.Host.Connect(directCtx, pi)
		select {
		case ch <- result{err: err, mode: "direct"}:
		case <-raceCtx.Done():
			// Losing goroutine — winner already returned, don't send on closed path
		}
	}()

	// Race: Circuit Relay connection via known relay addresses
	// Relay path needs more time: connect to relay (1.5s) + auth (2s) + circuit connect
	go func() {
		relayCtx, cancel := context.WithTimeout(raceCtx, 15*time.Second)
		defer cancel()

		var relayAddrs []multiaddr.Multiaddr
		for _, bStr := range n.Config.BootstrapPeers {
			bMA, berr := multiaddr.NewMultiaddr(bStr)
			if berr != nil {
				continue
			}
			bInfo, berr := peer.AddrInfoFromP2pAddr(bMA)
			if berr != nil {
				continue
			}
			// If not yet connected to relay, try a 3s connection first
			if n.Host.Network().Connectedness(bInfo.ID) != network.Connected {
				bCtx, bCancel := context.WithTimeout(relayCtx, 3*time.Second)
				_ = n.Host.Connect(bCtx, *bInfo)
				bCancel()
			}
			if n.Host.Network().Connectedness(bInfo.ID) == network.Connected {
				circuitMA, cerr := multiaddr.NewMultiaddr(
					fmt.Sprintf("/p2p/%s/p2p-circuit/p2p/%s", bInfo.ID.String(), pi.ID.String()))
				if cerr == nil {
					relayAddrs = append(relayAddrs, circuitMA)
				}
			}
		}

		if len(relayAddrs) == 0 {
			select {
			case ch <- result{err: fmt.Errorf("no active relay available"), mode: "relay"}:
			case <-raceCtx.Done():
			}
			return
		}

		n.Host.Peerstore().AddAddrs(pi.ID, relayAddrs, 15*time.Second)
		err := n.Host.Connect(relayCtx, pi)
		select {
		case ch <- result{err: err, mode: "circuit-relay"}:
		case <-raceCtx.Done():
		}
	}()

	// Wait for first successful result
	var first result
	select {
	case first = <-ch:
	case <-ctx.Done():
		return ctx.Err()
	}

	if first.err == nil {
		log.Info("%s peer %s connected via %s (parallel race winner)", peerType, pi.ID.String(), first.mode)
		if peerType == "bootstrap" {
			go func() {
				if n.authenticateWithRelay(pi.ID) {
					n.reserveRelaySlotWithRetry(pi, 3)
				}
			}()
		}
		// Cancel losing goroutine — prevents double-connect and transport conflict
		raceCancel()
		return nil
	}

	// First attempt failed, wait for the other
	select {
	case second := <-ch:
		if second.err == nil {
			log.Info("%s peer %s connected via %s (parallel race fallback)", peerType, pi.ID.String(), second.mode)
			if peerType == "bootstrap" {
				go func() {
					if n.authenticateWithRelay(pi.ID) {
						n.reserveRelaySlotWithRetry(pi, 3)
					}
				}()
			}
			return nil
		}
		log.Debug("%s peer %s: direct=%v, relay=%v", peerType, pi.ID.String(), first.err, second.err)
		return fmt.Errorf("direct: %v | relay: %v", first.err, second.err)
	case <-ctx.Done():
		return ctx.Err()
	}
}

// reserveRelaySlotWithRetry attempts to reserve a Circuit Relay v2 slot with
// exponential backoff retry, improving reliability for relay-dependent nodes.
func (n *Node) reserveRelaySlotWithRetry(pi peer.AddrInfo, maxRetries int) {
	for attempt := 0; attempt < maxRetries; attempt++ {
		select {
		case <-n.ctx.Done():
			return
		default:
		}

		ctx, cancel := context.WithTimeout(n.ctx, 10*time.Second)
		res, err := relayClient.Reserve(ctx, n.Host, pi)
		cancel()
		if err == nil {
			log.Info("Circuit Relay v2 reservation ACTIVE on relay %s (expiration: %v, attempt %d)",
				pi.ID.String(), res.Expiration, attempt+1)

			circuitComponent, cerr := multiaddr.NewMultiaddr(
				fmt.Sprintf("/p2p/%s/p2p-circuit", pi.ID.String()))
			if cerr == nil {
				for _, addr := range n.Host.Addrs() {
					if !isRelayComponent(addr) {
						n.Host.Peerstore().AddAddrs(n.Host.ID(),
							[]multiaddr.Multiaddr{addr.Encapsulate(circuitComponent)},
							1*time.Hour)
					}
				}
				log.Info("Registered %d Circuit Relay v2 multiaddrs on local host", len(n.Host.Addrs()))
			}
			return
		}

		delay := time.Duration(1<<uint(attempt)) * 5 * time.Second
		if delay > 60*time.Second {
			delay = 60 * time.Second
		}
		log.Warn("Circuit Relay v2 reservation FAILED on bootstrap %s (attempt %d/%d): %v, retrying in %v",
			pi.ID.String(), attempt+1, maxRetries, err, delay)

		select {
		case <-n.ctx.Done():
			return
		case <-time.After(delay):
		}
	}
	log.Warn("Circuit Relay v2 reservation exhausted after %d attempts on bootstrap %s",
		maxRetries, pi.ID.String())
}

// isRelayComponent checks whether a multiaddr already contains a p2p-circuit component.
func isRelayComponent(a multiaddr.Multiaddr) bool {
	found := false
	multiaddr.ForEach(a, func(c multiaddr.Component) bool {
		if c.Protocol().Code == multiaddr.P_CIRCUIT {
			found = true
			return false
		}
		return true
	})
	return found
}

func (n *Node) handleStream(s network.Stream) {
	remotePeer := s.Conn().RemotePeer()
	transportName := s.Conn().RemoteMultiaddr().String()

	log.Debug("Stream active with peer %s via %s", remotePeer.String(), transportName)
	n.Dispatcher.RegisterStream(remotePeer, transportName, s)
	defer n.Dispatcher.UnregisterStream(remotePeer, transportName, s)

	buf := make([]byte, obfuscate.MaxFrameSize)
	frameCount := 0
	for {
		// Read length-prefixed frame from P2P stream
		readN, err := ReadFrame(s, buf)
		if err != nil {
			if err != io.EOF {
				log.Debug("Stream read error from peer %s: %v (after %d frames)", remotePeer.String(), err, frameCount)
			} else {
				log.Debug("Stream EOF from peer %s (after %d frames)", remotePeer.String(), frameCount)
			}
			break
		}
		log.Debug("Rx raw frame: len=%d from peer=%s", readN, remotePeer.String())

		frameData := buf[:readN] // may be reassigned below if reassembled

		if len(frameData) < obfuscate.HeaderLen {
			log.Debug("Short frame (%d bytes) from peer %s, skipping", len(frameData), remotePeer.String())
			continue
		}

		// ── Deobfuscation happens FIRST ──
		seqID, payload, err := obfuscate.Unpack(frameData)
		if err != nil {
			log.Debug("Frame unpack error from peer %s: %v", remotePeer.String(), err)
			continue
		}
		log.Debug("Rx unpacked: seq=%d payloadLen=%d frameLen=%d from peer=%s", seqID, len(payload), len(frameData), remotePeer.String())

		// Per-peer deduplication: each peer has its own seqID space,
		// so seqIDs from different peers never collide (unlike the
		// previous global dedup that could falsely discard frames from
		// peer B whose seqID happened to match peer A's).
		n.dedupPeersMu.RLock()
		peerDedup, ok := n.dedupPeers[remotePeer]
		n.dedupPeersMu.RUnlock()
		if !ok {
			n.dedupPeersMu.Lock()
			peerDedup = n.dedupPeers[remotePeer]
			if peerDedup == nil {
				peerDedup = obfuscate.NewDeduplicator()
				n.dedupPeers[remotePeer] = peerDedup
			}
			n.dedupPeersMu.Unlock()
		}
		if peerDedup.IsDuplicate(seqID) {
			n.Collector.RecordDedup()
			log.Debug("Duplicate frame seq=%d from peer %s", seqID, remotePeer.String())
			continue
		}

		// ACL Firewall Filtering check
		if n.Config.ACL.Enable && !MatchACL(&n.Config.ACL, payload, remotePeer.String(), false) {
			log.Debug("🛡️ ACL Firewall blocked Rx frame seq=%d from peer %s", seqID, remotePeer.String())
			continue
		}
		if n.Config.ACL.Enable {
			log.Debug("ACL passed: seq=%d from peer=%s", seqID, remotePeer.String())
		}

		dstMAC, srcMAC, errExtract := vswitch.ExtractEthernetMACs(payload)
		if !errExtract {
			n.MACTable.Learn(srcMAC, remotePeer)
			if log.IsDebug() {
				log.Debug("Rx frame: seq=%d len=%d src=%s dst=%s from_peer=%s %s",
					seqID, len(payload), net.HardwareAddr(srcMAC[:]).String(), net.HardwareAddr(dstMAC[:]).String(), remotePeer.String(), describeEthernetFrame(payload))
			}

			// Content-based dedup for broadcast/multicast frames:
			// when the same L2 frame arrives from multiple peer
			// streams, only the first copy is written to TAP.
			if isBroadcastOrMulticastMAC(dstMAC) {
				contentHash := fnvHash64(payload)
				if n.bcastDedup.isDuplicate(contentHash) {
					n.Collector.RecordDedup()
					log.Debug("Content-dup bcast/mcast frame hash=0x%x from peer %s dropped", contentHash, remotePeer.String())
					continue
				}
			}
		} else {
			log.Debug("Rx frame: seq=%d len=%d (MAC extract failed) from_peer=%s", seqID, len(payload), remotePeer.String())
		}

		n.Collector.RecordRecv(len(payload))
		n.Collector.RecordPacketDir(payload, false)
		if len(payload) >= 14 {
			n.Collector.RecordFrame(payload)
		}
		n.IPTracker.ExtractAndRecord(payload, false)

		// Data is actively flowing — reset ping-pong fail count for this peer.
		// Prevents spurious reconnects when yamux flow control delays echo streams
		// but the application-level connection is healthy.
		n.resetPingPongFailCountForPeer(remotePeer)

		frameCount++

		if n.Interceptor != nil && n.Interceptor.MatchAndHandle(payload, n.TAP) {
			log.Debug("Frame intercepted by userspace WebUI interceptor from peer %s", remotePeer.String())
			continue
		}

		// If incoming packet is destined for this node's TAP IP, ensure Destination MAC matches local TAP MAC so Linux Kernel accepts IPv4/IPv6 unicast packets
		if len(payload) >= 34 && binary.BigEndian.Uint16(payload[12:14]) == 0x0800 && n.localV4IP != nil && len(n.localMAC) == 6 {
			dstIP := net.IP(payload[30:34])
			if dstIP.Equal(n.localV4IP) {
				log.Debug("MAC rewrite IPv4: dstIP=%s oldDstMAC=%s newDstMAC=%s", dstIP.String(), net.HardwareAddr(payload[0:6]).String(), net.HardwareAddr(n.localMAC).String())
				copy(payload[0:6], n.localMAC)
			}
		} else if len(payload) >= 54 && binary.BigEndian.Uint16(payload[12:14]) == 0x86DD && n.localV6IP != nil && len(n.localMAC) == 6 {
			dstIP := net.IP(payload[38:54])
			if dstIP.Equal(n.localV6IP) {
				log.Debug("MAC rewrite IPv6: dstIP=%s oldDstMAC=%s newDstMAC=%s", dstIP.String(), net.HardwareAddr(payload[0:6]).String(), net.HardwareAddr(n.localMAC).String())
				copy(payload[0:6], n.localMAC)
			}
		}

		// Write unpadded payload Ethernet frame to TAP
		if n.TAP == nil {
			log.Warn("TAP device is nil, cannot write frame")
			continue
		}
		log.Debug("TAP write: seq=%d len=%d dstMAC=%s to %s", seqID, len(payload), net.HardwareAddr(payload[0:6]).String(), n.TAP.Name())
		wn, werr := n.TAP.Write(payload)
		if werr != nil {
			log.Warn("TAP write error: %v", werr)
		} else {
			log.Debug("TAP write ok: %d bytes to %s", wn, n.TAP.Name())
		}
	}
}

func (n *Node) buildLocalARPEntries(nodeName string) []web.ARPInfoDTO {
	entries := make([]web.ARPInfoDTO, 0, 2)
	peerID := ""
	if n.Host != nil {
		peerID = n.Host.ID().String()
	}
	if n.localV4IP != nil && len(n.localMAC) == 6 {
		entries = append(entries, web.ARPInfoDTO{
			IP:       n.localV4IP.String(),
			MAC:      n.localMAC.String(),
			PeerID:   peerID,
			NodeName: nodeName,
			Type:     "Dynamic (ARP)",
			LastSeen: "0s ago",
		})
	}
	if n.localV6IP != nil && len(n.localMAC) == 6 {
		entries = append(entries, web.ARPInfoDTO{
			IP:       n.localV6IP.String(),
			MAC:      n.localMAC.String(),
			PeerID:   peerID,
			NodeName: nodeName,
			Type:     "Dynamic (NDP)",
			LastSeen: "0s ago",
		})
	}
	return entries
}

func (n *Node) tapReadLoop() {
	defer n.wg.Done()

	buf := make([]byte, obfuscate.MaxFrameSize)
	outBuf := make([]byte, obfuscate.MaxOutputSize)

	// Try epoll-based event-driven I/O (Linux).  Falls back to timer-based
	// polling on non-Linux platforms transparently.
	if poller, err := tap.NewEpollPoller(n.TAP); err == nil {
		poller.NotifyOnCancel(n.ctx)
		defer poller.Close()
		n.tapReadLoopEpoll(poller, buf, outBuf)
		return
	}

	// Fallback: timer-based polling (macOS, Windows, others)
	n.tapReadLoopPoll(buf, outBuf)
}

// tapReadLoopEpoll uses epoll to block until the TAP fd is readable,
// then drains all queued frames in a batch.  Zero CPU burn when idle.
func (n *Node) tapReadLoopEpoll(poller *tap.EpollPoller, buf, outBuf []byte) {
	for {
		if err := poller.Wait(n.ctx); err != nil {
			log.Debug("TAP read loop stopped: %v", err)
			return
		}
		n.drainTapBatch(buf, outBuf)
	}
}

// tapReadLoopPoll is the fallback timer-based polling path for platforms
// without epoll (macOS, Windows).  It polls TAP.Read with a short timeout
// and batches up to 32 frames per pass.
func (n *Node) tapReadLoopPoll(buf, outBuf []byte) {
	readErrors := 0
	for {
		select {
		case <-n.ctx.Done():
			log.Debug("TAP read loop stopped (context cancelled)")
			return
		default:
		}

		for batchIdx := 0; batchIdx < 32; batchIdx++ {
			readN, err := n.TAP.Read(buf)
			if err != nil {
				if err == io.EOF {
					log.Debug("TAP read loop stopped (EOF)")
					return
				}
				if errors.Is(err, tap.ErrReadTimeout) {
					break // No more frames available, exit batch
				}
				if errors.Is(err, syscall.EINTR) {
					continue
				}
				readErrors++
				if readErrors == 1 || readErrors%100 == 0 {
					log.Warn("TAP read error on %s (count=%d): %v", n.TAP.Name(), readErrors, err)
				}
				break
			}
			readErrors = 0

			if readN == 0 {
				continue
			}
			if readN < 14 {
				continue
			}

			if !n.processTapFrame(buf[:readN], outBuf) {
				return
			}
		}
	}
}

// drainTapBatch reads up to 32 frames from TAP in a tight loop, calling
// processTapFrame for each.  It expects the fd to be readable (non-blocking
// reads succeed) and stops on the first EAGAIN / timeout.
func (n *Node) drainTapBatch(buf, outBuf []byte) {
	for batchIdx := 0; batchIdx < 32; batchIdx++ {
		readN, err := n.TAP.Read(buf)
		if err != nil {
			if err == io.EOF {
				return
			}
			if errors.Is(err, tap.ErrReadTimeout) {
				break
			}
			if errors.Is(err, syscall.EINTR) {
				continue
			}
			break
		}
		if readN == 0 {
			continue
		}
		if readN < 14 {
			continue
		}
		if !n.processTapFrame(buf[:readN], outBuf) {
			return
		}
	}
}

// processTapFrame handles a single Ethernet frame read from the TAP device.
// It runs ARP/NDP proxy, WebUI intercept, and dispatch to peers.
// Returns false if the read loop should terminate (unrecoverable error).
func (n *Node) processTapFrame(payload, outBuf []byte) bool {
	readN := len(payload)

	// ARP proxy handling
	if len(payload) >= 42 && binary.BigEndian.Uint16(payload[12:14]) == 0x0806 && binary.BigEndian.Uint16(payload[20:22]) == 1 {
		targetIP := net.IP(payload[38:42])
		senderIP := net.IP(payload[28:32])
		senderMAC := net.HardwareAddr(payload[22:28])

		// Case 1: target is a known remote peer → reply with the peer's real MAC
		if peerMAC, peerID := n.lookupPeerMACByIPv4(targetIP); peerMAC != nil {
			reply := tap.BuildARPReplyFrame(peerMAC, senderMAC, targetIP, senderIP)
			if _, err := n.TAP.Write(reply); err != nil {
				log.Debug("ARP proxy reply for peer %s write failed: %v", targetIP, err)
			}
			n.MACTable.Learn(peerMAC, peerID)
			return true
		}

		// Case 1b: target is in a peer's advertised subnet → reply with that peer's MAC
		// This enables ARP proxy for remote LAN subnets (e.g. 192.168.101.0/24
		// advertised by peer 10.0.0.2). Without this, ARP for 192.168.101.2 would
		// fall through to broadcast flooding.
		if peerMAC := n.lookupPeerMACByAdvertisedSubnet(targetIP); peerMAC != nil {
			reply := tap.BuildARPReplyFrame(peerMAC, senderMAC, targetIP, senderIP)
			if _, err := n.TAP.Write(reply); err != nil {
				log.Debug("ARP proxy reply for advertised subnet IP %s write failed: %v", targetIP, err)
			}
			log.Debug("ARP proxy: %s resolved via advertised subnet peer MAC %s", targetIP, peerMAC.String())
			return true
		}

		// Case 2: target is local IP, WebUI virtual IP, or unknown
		// same-subnet IP (proxy-ARP fallback) → reply with local MAC.
		if tap.ShouldRespondToARP(targetIP, n.localV4IP, n.virtualWebUIV4IP, n.localV4Net) {
			localMAC := n.localMAC
			if len(localMAC) != 6 {
				localMAC = net.HardwareAddr{0x02, 0x00, 0x5e, 0x10, 0x00, 0x01}
			}
			reply := tap.BuildARPReplyFrame(localMAC, senderMAC, targetIP, senderIP)
			if _, err := n.TAP.Write(reply); err != nil {
				log.Debug("ARP reply write failed: %v", err)
			}
			return true
		}
	}

	// IPv6 NDP proxy handling
	if len(payload) >= 86 &&
		binary.BigEndian.Uint16(payload[12:14]) == 0x86DD &&
		payload[20] == 58 &&
		payload[54] == 135 {

		targetIPv6 := net.IP(payload[62:78])
		senderIPv6 := net.IP(payload[22:38])

		if peerMAC, peerID := n.lookupPeerMACByIPv6(targetIPv6); peerMAC != nil {
			reply := tap.BuildIPv6NeighborAdvertisementFrame(peerMAC, targetIPv6, senderIPv6)
			if len(reply) > 0 {
				if _, err := n.TAP.Write(reply); err != nil {
					log.Debug("NDP NA reply for peer %s write failed: %v", targetIPv6, err)
				}
			}
			n.MACTable.Learn(peerMAC, peerID)
			return true
		}

		// NDP proxy for advertised subnets (IPv6)
		if peerMAC := n.lookupPeerMACByAdvertisedSubnet(targetIPv6); peerMAC != nil {
			reply := tap.BuildIPv6NeighborAdvertisementFrame(peerMAC, targetIPv6, senderIPv6)
			if len(reply) > 0 {
				if _, err := n.TAP.Write(reply); err != nil {
					log.Debug("NDP NA reply for advertised subnet IPv6 %s write failed: %v", targetIPv6, err)
				}
			}
			log.Debug("NDP proxy: %s resolved via advertised subnet peer MAC %s", targetIPv6, peerMAC.String())
			return true
		}

		if targetIPv6.Equal(n.localV6IP) ||
			(n.virtualWebUIV6IP != nil && targetIPv6.Equal(n.virtualWebUIV6IP)) {
			naFrame := tap.BuildIPv6NeighborAdvertisementFrame(n.localMAC, targetIPv6, senderIPv6)
			if len(naFrame) > 0 {
				if _, err := n.TAP.Write(naFrame); err != nil {
					log.Debug("NDP NA reply (local) write failed: %v", err)
				}
			}
			return true
		}
	}

	if n.Interceptor != nil && n.Interceptor.MatchAndHandle(payload, n.TAP) {
		return true
	}

	if n.isLocalWebUIVirtualPacket(payload) {
		log.Debug("TAP frame involves local WebUI virtual IP/MAC, dropping from P2P overlay dispatch")
		return true
	}

	dstMAC, srcMAC, errExtract := vswitch.ExtractEthernetMACs(payload)
	if errExtract {
		log.Debug("TAP frame MAC extraction failed (len=%d) from %s", readN, n.TAP.Name())
		return true
	}
	if log.IsDebug() {
		log.Debug("TAP read: len=%d %s", readN, describeEthernetFrame(payload))
	}

	n.MACTable.Learn(srcMAC, n.Host.ID())
	if len(payload) >= 14 {
		n.Collector.RecordFrame(payload)
	}
	n.IPTracker.ExtractAndRecord(payload, true)

	if targetPeer, found := n.MACTable.Lookup(dstMAC); found && targetPeer != n.Host.ID() {
		// Unicast: obfuscate and dispatch
		routes := n.getCachedRoutes()
		route, hasRoute := routes[targetPeer]

		seqID := n.Packer.NextSeqID()
		totalLen, perr := n.Packer.Pack(seqID, payload, outBuf)
		if perr != nil {
			log.Debug("Frame pack error: %v", perr)
			return true
		}
		packedCopy := make([]byte, totalLen)
		copy(packedCopy, outBuf[:totalLen])
		n.Collector.RecordPacketDir(payload, true)
		log.Debug("Tx Pack: seq=%d origLen=%d packedLen=%d mode=%s dst=%s", seqID, readN, totalLen, n.Packer.Mode, targetPeer.String())

		if hasRoute && !route.IsDirect && route.NextHop != "" && route.NextHop != targetPeer {
			log.Debug("Tx overlay relay: seq=%d len=%d dst=%s via nextHop=%s (totalRTT=%dms vs directRTT=%dms)",
				seqID, readN, targetPeer.String(), route.NextHop.String(), route.TotalRTTMs, route.DirectRTTMs)
			if relayBuf, err := routing.PackRelayFrame(targetPeer, n.Host.ID(), routing.MaxRelayTTL, packedCopy); err == nil {
				fallbackCopy := make([]byte, len(packedCopy))
				copy(fallbackCopy, packedCopy)
				n.dispatchNonblocking(dispatchTask{
					kind:      2,
					target:    targetPeer,
					relayHop:  route.NextHop,
					data:      fallbackCopy,
					relayData: relayBuf,
					origLen:   readN,
				})
			}
		} else {
			n.dispatchNonblocking(dispatchTask{
				kind:    0,
				target:  targetPeer,
				data:    packedCopy,
				origLen: readN,
			})
		}
	} else {
		// Broadcast or Unknown Unicast: obfuscate and flood
		seqID := n.Packer.NextSeqID()
		totalLen, perr := n.Packer.Pack(seqID, payload, outBuf)
		if perr != nil {
			log.Debug("Frame pack error: %v", perr)
			return true
		}
		packedCopy := make([]byte, totalLen)
		copy(packedCopy, outBuf[:totalLen])
		n.Collector.RecordPacketDir(payload, true)
		log.Debug("Tx Pack broadcast: seq=%d origLen=%d packedLen=%d mode=%s", seqID, readN, totalLen, n.Packer.Mode)
		n.dispatchNonblocking(dispatchTask{
			kind:    1,
			data:    packedCopy,
			origLen: readN,
		})
	}
	return true
}

// dispatchNonblocking sends a task to the worker pool without blocking.
// If the channel is full, the frame is dropped and droppedCount is incremented.
func (n *Node) dispatchNonblocking(task dispatchTask) {
	select {
	case n.dispatchCh <- task:
		// delivered
	default:
		dropped := atomic.AddUint64(&n.dispatchDropCount, 1)
		if dropped == 1 || dropped%10 == 0 {
			log.Warn("Dispatch channel full: dropped %d frames total (P2P send backpressure, %d active workers)",
				dropped, 4 /* dispatchWorkers */)
		}
	}
}

// dispatchWorker consumes tasks from the bounded dispatch channel and sends
// them to the appropriate P2P stream.  A fixed pool of these replaces the
// previous unbounded go-func-per-frame pattern that caused 75% ICMP loss
// under load.
// batchTasksKey groups dispatch tasks by (kind, target) for batched transmission.
type batchTasksKey struct {
	kind   uint8
	target peer.ID // empty for broadcast
}

func (n *Node) dispatchWorker(id int) {
	defer n.wg.Done()
	for {
		select {
		case <-n.ctx.Done():
			return
		case task := <-n.dispatchCh:
			// Batch drain: collect up to 32 pending tasks grouped by target.
			batches := make(map[batchTasksKey][]dispatchTask)
			batches[batchTasksKey{kind: task.kind, target: task.target}] = []dispatchTask{task}

			drainLoop:
			for i := 0; i < 31; i++ {
				select {
				case t := <-n.dispatchCh:
					key := batchTasksKey{kind: t.kind, target: t.target}
					batches[key] = append(batches[key], t)
				default:
					break drainLoop
				}
			}

			for key, tasks := range batches {
				switch key.kind {
				case 0: // unicast — async to avoid blocking worker on slow stream writes
					batch := make([][]byte, 0, len(tasks))
					origLens := make([]int, 0, len(tasks))
					for _, t := range tasks {
						batch = append(batch, t.data)
						origLens = append(origLens, t.origLen)
					}
					target := key.target
					if len(batch) == 1 {
						data := batch[0]
						origLen := origLens[0]
						go func() {
							if err := n.Dispatcher.SendToPeer(n.ctx, target, data); err != nil {
								log.Debug("Tx unicast send error to peer %s: %v", target.String(), err)
								n.triggerThrottledReconnect(target)
							} else {
								n.Collector.RecordSent(origLen)
							}
						}()
					} else {
						go func() {
							if err := n.Dispatcher.SendBatchToPeer(n.ctx, target, batch); err != nil {
								log.Debug("Tx batched unicast send error to peer %s (n=%d): %v",
									target.String(), len(batch), err)
								n.triggerThrottledReconnect(target)
							} else {
								for _, ol := range origLens {
									n.Collector.RecordSent(ol)
								}
							}
						}()
					}
			case 1: // broadcast — async to avoid blocking worker on wg.Wait()
				// Broadcast fans out one L2 frame to N peers; count TX once per task.
				if len(tasks) == 1 {
					data := tasks[0].data
					origLen := tasks[0].origLen
					go func() {
						n.Dispatcher.BroadcastToAllPeers(n.ctx, data)
						n.Collector.RecordSent(origLen)
					}()
				} else {
					batch := make([][]byte, 0, len(tasks))
					origLens := make([]int, 0, len(tasks))
					for _, t := range tasks {
						batch = append(batch, t.data)
						origLens = append(origLens, t.origLen)
					}
					go func() {
						n.Dispatcher.BroadcastBatchToAllPeers(n.ctx, batch)
						for _, ol := range origLens {
							n.Collector.RecordSent(ol)
						}
					}()
				}
			case 2: // relay — persistent pool per relayHop (eliminates per-frame stream open)
				for _, t := range tasks {
					t := t
					n.relayPool.Submit(t.relayHop, t.relayData,
						// onSent: track stats at origin
						func() { n.Collector.RecordSent(t.origLen) },
						// onFail: fallback to direct unicast
						func() {
							if derr := n.Dispatcher.SendToPeer(n.ctx, t.target, t.data); derr == nil {
								n.Collector.RecordSent(t.origLen)
							}
						},
					)
				}
				}
			}
		}
	}
}

func (n *Node) macCleanLoop() {
	defer n.wg.Done()
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-n.ctx.Done():
			return
		case <-ticker.C:
			n.MACTable.CleanStale(300 * time.Second)
			n.Router.CleanStaleNodes(60 * time.Second)
			n.invalidateRouteCache()
			n.updateWebCollectorState()
		}
	}
}

// getCachedRoutes returns the current routing table, reusing a cached copy
// when available (<2s stale).  This avoids redundant per-frame Dijkstra
// computations in tapReadLoop when topology changes are infrequent.
func (n *Node) getCachedRoutes() map[peer.ID]routing.RouteInfo {
	n.cachedRoutesMu.RLock()
	if time.Since(n.cachedRoutesAt) < 2*time.Second && n.cachedRoutes != nil {
		defer n.cachedRoutesMu.RUnlock()
		return n.cachedRoutes
	}
	n.cachedRoutesMu.RUnlock()

	n.cachedRoutesMu.Lock()
	defer n.cachedRoutesMu.Unlock()
	// Double-check: another goroutine may have populated the cache between the RUnlock and Lock.
	if time.Since(n.cachedRoutesAt) < 2*time.Second && n.cachedRoutes != nil {
		return n.cachedRoutes
	}
	n.cachedRoutes = n.Router.ComputeRoutes()
	n.cachedRoutesAt = time.Now()
	return n.cachedRoutes
}

// invalidateRouteCache forces the next getCachedRoutes call to recompute.
// Called periodically from macCleanLoop to pick up topology changes.
func (n *Node) invalidateRouteCache() {
	n.cachedRoutesMu.Lock()
	n.cachedRoutesAt = time.Time{}
	n.cachedRoutesMu.Unlock()
}

func (n *Node) updateWebCollectorState() {
	nodeName := n.Config.NodeName
	if nodeName == "" || nodeName == "auto" {
		if hostName, err := os.Hostname(); err == nil && hostName != "" {
			nodeName = hostName
		} else {
			nodeName = "p2ptap-node"
		}
	}
	n.Collector.SetNodeInfo(nodeName, n.Host.ID().String(), n.Config.TapIP, n.Config.TapIPv6, n.Config.TransportStrategy)

	// Build map of bootstrap and static peer IDs for quick role classification
	bootstrapMap := make(map[peer.ID]bool)
	for _, bStr := range n.Config.BootstrapPeers {
		if ma, err := multiaddr.NewMultiaddr(bStr); err == nil {
			if info, err := peer.AddrInfoFromP2pAddr(ma); err == nil {
				bootstrapMap[info.ID] = true
			}
		}
	}

	staticMap := make(map[peer.ID]bool)
	for _, sStr := range n.Config.StaticPeers {
		if ma, err := multiaddr.NewMultiaddr(sStr); err == nil {
			if info, err := peer.AddrInfoFromP2pAddr(ma); err == nil {
				staticMap[info.ID] = true
			}
		}
	}

	// Sync active peers and MAC table to web collector
	peersDTO := make([]web.PeerInfoDTO, 0)
	allActivePeers := n.getAllPeersForMetaSync()
	for _, pID := range allActivePeers {
		conns := n.Host.Network().ConnsToPeer(pID)
		addr := "unknown"
		transport := "P2P"
		hasDirectConn := false
		hasRelayConn := false
		isRelayedPeer := false

		if len(conns) > 0 {
			// Iterate ALL connections to detect mixed direct+relay scenarios.
			// A peer could have a direct TCP connection AND a relay fallback simultaneously.
			for _, c := range conns {
				a := c.RemoteMultiaddr().String()
				if strings.Contains(a, "/p2p-circuit") {
					hasRelayConn = true
					if addr == "unknown" {
						addr = a
					}
				} else {
					hasDirectConn = true
					addr = a // prefer direct address for display
					// Detect transport protocol from the direct connection
					if strings.Contains(a, "/quic") {
						transport = "QUIC"
					} else if strings.Contains(a, "/webrtc") {
						transport = "WebRTC"
					} else if strings.Contains(a, "/tcp") {
						transport = "TCP"
					}
				}
			}

			if hasRelayConn && !hasDirectConn {
				// All connections are through circuit relay — peer is relayed.
				isRelayedPeer = true
				transport = "Circuit Relay"
			} else if hasRelayConn && hasDirectConn {
				// Mixed — prefer direct, notate relay availability.
				transport = transport + "+Relay"
			}
			// hasDirectConn && !hasRelayConn → normal direct peer (isRelayedPeer=false)
		} else {
			// Zero transport connections — peer only reachable through overlay routing.
			isRelayedPeer = true
			transport = "Overlay Relay"
			routes := n.getCachedRoutes()
			if route, ok := routes[pID]; ok && route.NextHop != "" {
				addr = fmt.Sprintf("Overlay Relay via %s", route.NextHop.String()[:12])
			} else {
				addr = "Overlay Relay (Multi-Hop)"
			}
			log.Debug("Peer %s has zero transport connections; using overlay relay routing", pID.String())
		}

		role := "Peer"
		if bootstrapMap[pID] {
			role = "Bootstrap"
		} else if staticMap[pID] {
			role = "Static"
		} else if isRelayedPeer {
			role = "Relayed Peer"
		}

		nodeName := ""
		tapIP := ""
		tapIPv6 := ""
		osArch := ""
		version := ""
		uptimeStr := ""
		reachability := "Direct P2P Link"
		if isRelayedPeer {
			if len(conns) > 0 {
				reachability = "Circuit Relay v2"
			} else {
				reachability = "Overlay Relay"
			}
		}

		isExitNode := false
		exitNAT := false
		var peerTxSpd, peerRxSpd, peerTotalTx, peerTotalRx uint64
		if val, ok := n.peerMeta.Load(pID); ok {
			meta := val.(PeerMeta)
			nodeName = meta.NodeName
			tapIP = meta.TapIP
			tapIPv6 = meta.TapIPv6
			osArch = meta.OSArch
			version = meta.Version
			if reachability == "" && meta.Reachability != "" {
				reachability = meta.Reachability
			}
			isExitNode = meta.IsExitNode
			exitNAT = meta.ExitNAT
			if time.Since(meta.LastSync) < 45*time.Second {
				peerTxSpd = meta.TxSpeed
				peerRxSpd = meta.RxSpeed
			} else {
				peerTxSpd = 0
				peerRxSpd = 0
			}
			peerTotalTx = meta.TotalTx
			peerTotalRx = meta.TotalRx
			if meta.UptimeSec > 0 {
				dur := time.Duration(meta.UptimeSec) * time.Second
				if dur < time.Hour {
					uptimeStr = fmt.Sprintf("%dm", int(dur.Minutes()))
				} else {
					uptimeStr = fmt.Sprintf("%dh%dm", int(dur.Hours()), int(dur.Minutes())%60)
				}
			}
		}

		rttMs := n.getPeerLatency(pID)
		if rttMs > 0 {
			n.Router.UpdateDirectLink(pID, rttMs)
		}

		geoLoc := "🌐 Public Peer"
		if strings.Contains(addr, "127.0.0.1") || strings.Contains(addr, "::1") {
			geoLoc = "🏠 Local Loopback"
		} else if strings.Contains(addr, "10.") || strings.Contains(addr, "192.168.") || strings.Contains(addr, "172.16.") {
			geoLoc = "🏠 Local Mesh"
		} else if strings.Contains(addr, "/p2p-circuit") {
			geoLoc = "🔀 Relay Server"
		}

		jitterMs := float64(rttMs) * 0.08
		if jitterMs < 0.1 && rttMs > 0 {
			jitterMs = 0.5
		}

		var earliestOpen time.Time
		for _, c := range n.Host.Network().ConnsToPeer(pID) {
			st := c.Stat()
			if earliestOpen.IsZero() || st.Opened.Before(earliestOpen) {
				earliestOpen = st.Opened
			}
		}

		connSinceStr := "-"
		connAtStr := "-"
		if !earliestOpen.IsZero() {
			connAtStr = earliestOpen.Format("15:04:05")
			dur := time.Since(earliestOpen)
			if dur < time.Minute {
				connSinceStr = fmt.Sprintf("%ds ago", int(dur.Seconds()))
			} else if dur < time.Hour {
				connSinceStr = fmt.Sprintf("%dm %ds", int(dur.Minutes()), int(dur.Seconds())%60)
			} else {
				connSinceStr = fmt.Sprintf("%dh %dm", int(dur.Hours()), int(dur.Minutes())%60)
			}
		}

		lastSeenStr := "Just now"
		if val, ok := n.peerMeta.Load(pID); ok {
			meta := val.(PeerMeta)
			if !meta.LastSync.IsZero() {
				secAgo := int(time.Since(meta.LastSync).Seconds())
				if secAgo > 1 {
					if secAgo < 60 {
						lastSeenStr = fmt.Sprintf("%ds ago", secAgo)
					} else {
						lastSeenStr = fmt.Sprintf("%dm ago", secAgo/60)
					}
				}
			}
		}

		addrMap := make(map[string]bool)
		allAddrs := make([]string, 0)
		if addr != "" && addr != "unknown" {
			addrMap[addr] = true
			allAddrs = append(allAddrs, addr)
		}
		for _, a := range n.Host.Peerstore().Addrs(pID) {
			s := a.String()
			if !addrMap[s] {
				addrMap[s] = true
				allAddrs = append(allAddrs, s)
			}
		}

		peersDTO = append(peersDTO, web.PeerInfoDTO{
			PeerID:          pID.String(),
			NodeName:        nodeName,
			Role:            role,
			IsRelayed:       isRelayedPeer,
			IsExitNode:      isExitNode,
			ExitNAT:         exitNAT,
			TxSpeed:         peerTxSpd,
			RxSpeed:         peerRxSpd,
			TotalTx:         peerTotalTx,
			TotalRx:         peerTotalRx,
			TapIP:           tapIP,
			TapIPv6:         tapIPv6,
			OSArch:          osArch,
			Version:         version,
			Uptime:          uptimeStr,
			ConnectedAt:     connAtStr,
			ConnectedSince:  connSinceStr,
			LastSeen:        lastSeenStr,
			Reachability:    reachability,
			Addr:            addr,
			AllAddrs:        allAddrs,
			Transport:       transport,
			RTTMs:           rttMs,
			JitterMs:        float64(int(jitterMs*10)) / 10.0,
			LossRatePercent: 0.0,
			GeoLocation:     geoLoc,
		})
	}

	// Build MAC & ARP Table DTOs
	macDTO := make([]web.MACInfoDTO, 0)
	arpDTO := make([]web.ARPInfoDTO, 0)
	seenIP := make(map[string]bool)
	now := time.Now()

	// 1. Process peerMeta first (Highest Priority: official synced metadata from peer's config.json)
	n.peerMeta.Range(func(key, value interface{}) bool {
		pID := key.(peer.ID)
		meta := value.(PeerMeta)
		macStr := meta.TapMAC
		if macStr == "" {
			for mStr, entry := range n.MACTable.GetAllEntries() {
				if entry.PeerID == pID {
					macStr = mStr
					break
				}
			}
		}

		if meta.TapIP != "" {
			cleanV4 := strings.Split(meta.TapIP, "/")[0]
			if !seenIP[cleanV4] {
				seenIP[cleanV4] = true
				arpDTO = append(arpDTO, web.ARPInfoDTO{
					IP:       cleanV4,
					MAC:      macStr,
					PeerID:   pID.String(),
					NodeName: meta.NodeName,
					Type:     "Dynamic (ARP)",
					LastSeen: "Just now",
				})
			}
		}

		if meta.TapIPv6 != "" {
			cleanV6 := strings.Split(meta.TapIPv6, "/")[0]
			if !seenIP[cleanV6] {
				seenIP[cleanV6] = true
				arpDTO = append(arpDTO, web.ARPInfoDTO{
					IP:       cleanV6,
					MAC:      macStr,
					PeerID:   pID.String(),
					NodeName: meta.NodeName,
					Type:     "Dynamic (NDP)",
					LastSeen: "Just now",
				})
			}
		}
		return true
	})

	// 2. Process local node entries (local IP & MAC)
	for _, entry := range n.buildLocalARPEntries(nodeName) {
		if !seenIP[entry.IP] {
			seenIP[entry.IP] = true
			arpDTO = append(arpDTO, entry)
		}
	}

	// 3. Process remaining MACTable entries (dynamically learned MAC entries)
	for macStr, entry := range n.MACTable.GetAllEntries() {
		ago := now.Sub(entry.LastSeen).Truncate(time.Second).String() + " ago"
		macDTO = append(macDTO, web.MACInfoDTO{
			MAC:      macStr,
			PeerID:   entry.PeerID.String(),
			LastSeen: ago,
		})

		nodeName := ""
		ip := entry.IP
		tapIPv6 := ""
		if val, ok := n.peerMeta.Load(entry.PeerID); ok {
			meta := val.(PeerMeta)
			if nodeName == "" {
				nodeName = meta.NodeName
			}
			if ip == "" {
				ip = meta.TapIP
			}
			tapIPv6 = meta.TapIPv6
		}

		if ip != "" {
			cleanV4 := strings.Split(ip, "/")[0]
			if !seenIP[cleanV4] {
				seenIP[cleanV4] = true
				arpDTO = append(arpDTO, web.ARPInfoDTO{
					IP:       cleanV4,
					MAC:      macStr,
					PeerID:   entry.PeerID.String(),
					NodeName: nodeName,
					Type:     "Dynamic (ARP)",
					LastSeen: ago,
				})
			}
		}

		if tapIPv6 != "" {
			cleanV6 := strings.Split(tapIPv6, "/")[0]
			if !seenIP[cleanV6] {
				seenIP[cleanV6] = true
				arpDTO = append(arpDTO, web.ARPInfoDTO{
					IP:       cleanV6,
					MAC:      macStr,
					PeerID:   entry.PeerID.String(),
					NodeName: nodeName,
					Type:     "Dynamic (NDP)",
					LastSeen: ago,
				})
			}
		}
	}

	listenAddrsStrs := make([]string, 0)
	for _, a := range n.Host.Addrs() {
		listenAddrsStrs = append(listenAddrsStrs, fmt.Sprintf("%s/p2p/%s", a, n.Host.ID().String()))
	}
	n.Collector.ListenAddrs = listenAddrsStrs

	natStatus := "🟢 Public (Directly Reachable)"
	if len(n.Host.Network().Peers()) == 0 && len(n.Config.BootstrapPeers) > 0 {
		natStatus = "🟡 Symmetric NAT / Relay Mode"
	}
	n.Collector.NATStatus = natStatus

	n.Collector.DispatchDrops = atomic.LoadUint64(&n.dispatchDropCount)
	n.Collector.ActivePeers = peersDTO
	n.Collector.MACTable = macDTO
	n.Collector.ARPTable = arpDTO
	n.Collector.IPTable = n.IPTracker.GetDTOs(&n.peerMeta, n.Collector.NodeName, n.Config.TapIP, n.Config.TapIPv6, n.Host.ID().String())

	// Ensure all connected peers are present in the Router link-state graph
	for _, pID := range n.Host.Network().Peers() {
		rttMs := n.getPeerLatency(pID)
		if rttMs <= 0 {
			rttMs = 10
		}
		n.Router.UpdateDirectLink(pID, rttMs)
	}

	n.Collector.RoutesTable = n.Router.GetRouteInfoDTOs(func(pID peer.ID) (string, string, string) {
		if val, ok := n.peerMeta.Load(pID); ok {
			meta := val.(PeerMeta)
			return meta.NodeName, meta.TapIP, meta.TapIPv6
		}
		return "", "", ""
	})

	// Build SubnetRoutes DTOs
	subnetDTOs := make([]web.SubnetRouteDTO, 0)
	n.peerMeta.Range(func(key, value interface{}) bool {
		pID := key.(peer.ID)
		meta := value.(PeerMeta)
		for _, sub := range meta.AdvertisedSubnets {
			status := "Pending Authorization"
			if n.Config.AcceptAdvertisedSubnets {
				for _, allowed := range n.Config.AllowedSubnetPeers {
					if allowed == "*" || allowed == pID.String() {
						status = "Active (Authorized)"
						break
					}
				}
			}
			subnetDTOs = append(subnetDTOs, web.SubnetRouteDTO{
				SubnetCIDR:  sub,
				PeerID:      pID.String(),
				NodeName:    meta.NodeName,
				GatewayIP:   meta.TapIP,
				GatewayIPv6: meta.TapIPv6,
				Status:      status,
			})
		}
		return true
	})
	n.Collector.SubnetRoutes = subnetDTOs

	// Build MeshMatrix DTOs
	matrixDTOs := make([]web.MeshMatrixCellDTO, 0)
	routesMap := n.getCachedRoutes()
	for destPeer, r := range routesMap {
		destName := destPeer.String()
		if val, ok := n.peerMeta.Load(destPeer); ok {
			if metaName := val.(PeerMeta).NodeName; metaName != "" {
				destName = metaName
			}
		}
		matrixDTOs = append(matrixDTOs, web.MeshMatrixCellDTO{
			SrcPeerID: n.Host.ID().String(),
			SrcName:   n.Collector.NodeName,
			DstPeerID: destPeer.String(),
			DstName:   destName,
			RTTMs:     r.TotalRTTMs,
			Hops:      len(r.Path),
			IsDirect:  r.IsDirect,
		})
	}
	n.Collector.MeshMatrix = matrixDTOs

	log.Debug("Web collector updated: %d active peers, %d MACs, %d ARP entries, %d IP entries, %d routes, %d subnets", len(peersDTO), len(macDTO), len(arpDTO), len(n.Collector.IPTable), len(n.Collector.RoutesTable), len(subnetDTOs))
}

// TestMultiaddrLatency probes every known multiaddr for the given peer by
// performing a raw transport-level dial to each address.  It measures per-address
// RTT, supports concurrent probing with a timeout (3s per address, 2 retries),
// and returns results sorted from fastest to slowest.
//
// relay/circuit addresses are marked as reachable (the relay path is already
// established) but receive RTT=0 since per-transport dialing does not apply.
//
// Note: we use net.DialTimeout on the underlying transport address extracted
// via manet.DialArgs, so the measurement reflects TCP/UDP handshake time at
// the OS level — this is independent of libp2p stream/connection state and
// does not create persistent libp2p connections.
func (n *Node) TestMultiaddrLatency(targetStr string) []web.MultiaddrTestResultEntry {
	var pID peer.ID
	var candidateAddrs []string

	decodedPID, err := peer.Decode(targetStr)
	if err == nil {
		pID = decodedPID
	} else if n.Collector != nil {
		for _, p := range n.Collector.ActivePeers {
			if p.PeerID == targetStr || p.TapIP == targetStr || p.TapIPv6 == targetStr || strings.EqualFold(p.NodeName, targetStr) {
				if parsed, err := peer.Decode(p.PeerID); err == nil {
					pID = parsed
					candidateAddrs = p.AllAddrs
					break
				}
			}
		}
	}

	if pID == "" {
		return nil
	}

	peerstoreAddrs := n.Host.Peerstore().Addrs(pID)

	// Collect all unique multiaddrs: peerstore + current active connection + candidates.
	seen := make(map[string]bool)
	uniqueAddrs := make([]multiaddr.Multiaddr, 0)

	for _, a := range peerstoreAddrs {
		s := a.String()
		if !seen[s] {
			seen[s] = true
			uniqueAddrs = append(uniqueAddrs, a)
		}
	}

	for _, addStr := range candidateAddrs {
		if !seen[addStr] {
			if ma, err := multiaddr.NewMultiaddr(addStr); err == nil {
				seen[addStr] = true
				uniqueAddrs = append(uniqueAddrs, ma)
			}
		}
	}

	// Determine which address is currently in active use.
	activeAddr := ""
	for _, c := range n.Host.Network().ConnsToPeer(pID) {
		a := c.RemoteMultiaddr().String()
		if a != "" {
			activeAddr = a
			break
		}
	}
	// Ensure the active address is represented even if the peerstore is stale.
	if activeAddr != "" {
		if ma, err := multiaddr.NewMultiaddr(activeAddr); err == nil && !seen[activeAddr] {
			uniqueAddrs = append(uniqueAddrs, ma)
		}
	}

	if len(uniqueAddrs) == 0 {
		return nil
	}

	type probeResult struct {
		addr      string
		reachable bool
		rttMs     int64
		err       string
		isActive  bool
	}
	results := make([]probeResult, len(uniqueAddrs))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8) // max 8 concurrent probes

	for i, ma := range uniqueAddrs {
		idx := i
		addr := ma
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			addrStr := addr.String()
			isActive := (addrStr == activeAddr)

			if isActive {
				if echoRes := n.ProbePeerEcho(pID.String()); echoRes != nil && echoRes.Success {
					results[idx] = probeResult{addr: addrStr, reachable: true, rttMs: int64(echoRes.RTTMs), isActive: isActive}
					return
				}
			}

			// Relay/circuit addresses — the relay connection is already established
			// by the libp2p host; we cannot meaningfully dial a specific relay path.
			if strings.Contains(addrStr, "/p2p-circuit") {
				relayRTT := n.getPeerLatency(pID)
				results[idx] = probeResult{addr: addrStr, reachable: true, rttMs: relayRTT, err: "", isActive: isActive}
				return
			}

			// Strip any trailing /p2p/… component so manet can parse the transport part.
			transportMA := addr
			if _, err := addr.ValueForProtocol(multiaddr.P_P2P); err == nil {
				if dec, derr := multiaddr.NewMultiaddr(strings.TrimSuffix(addrStr, "/p2p/"+pID.String())); derr == nil {
					transportMA = dec
					if trimmed2, derr2 := multiaddr.NewMultiaddr(strings.SplitN(addrStr, "/p2p/", 2)[0]); derr2 == nil {
						transportMA = trimmed2
					}
				}
			}

			netType, dialAddr, err := manet.DialArgs(transportMA)
			if err != nil {
				// Fallback: strip exotic transport suffixes (quic-v1, webrtc-direct, webtransport, certhash, etc.)
				// to extract pure IP+Port multiaddr for underlying socket probing.
				if cleanMA, cleanErr := extractCleanTransportMA(transportMA); cleanErr == nil {
					netType, dialAddr, err = manet.DialArgs(cleanMA)
				}
			}
			if err != nil {
				if isActive {
					results[idx] = probeResult{addr: addrStr, reachable: true, rttMs: n.getPeerLatency(pID), err: "", isActive: isActive}
				} else {
					results[idx] = probeResult{addr: addrStr, reachable: false, err: "unsupported transport: " + err.Error(), isActive: isActive}
				}
				return
			}

			// Probe with timeout + retry.
			timeout := 3 * time.Second
			maxAttempts := 2

			for attempt := 0; attempt < maxAttempts; attempt++ {
				start := time.Now()
				conn, dialErr := net.DialTimeout(netType, dialAddr, timeout)
				elapsed := time.Since(start)

				if dialErr == nil {
					conn.Close()
					rtt := elapsed.Milliseconds()
					if rtt == 0 && isActive {
						rtt = n.getPeerLatency(pID)
					}
					results[idx] = probeResult{addr: addrStr, reachable: true, rttMs: rtt, isActive: isActive}
					return
				}

				if attempt < maxAttempts-1 {
					time.Sleep(200 * time.Millisecond) // backoff between retries
				} else {
					if isActive {
						// For active UDP (QUIC/WebRTC) connections where raw TCP dial fails, mark reachable using active stream RTT.
						results[idx] = probeResult{addr: addrStr, reachable: true, rttMs: n.getPeerLatency(pID), isActive: isActive}
					} else {
						results[idx] = probeResult{addr: addrStr, reachable: false, rttMs: 0, err: "unreachable: " + dialErr.Error(), isActive: isActive}
					}
				}
			}
		}()
	}
	wg.Wait()

	// Sort: reachable first (sorted by RTT ascending), then unreachable.
	dto := make([]web.MultiaddrTestResultEntry, len(results))
	for i, r := range results {
		dto[i] = web.MultiaddrTestResultEntry{
			Addr:      r.addr,
			Reachable: r.reachable,
			RTTMs:     r.rttMs,
			Error:     r.err,
			IsActive:  r.isActive,
		}
	}
	// Stable sort: active first, then reachable sorted by RTT, then unreachable.
	sortMultiaddrResults(dto)
	return dto
}

func sortMultiaddrResults(results []web.MultiaddrTestResultEntry) {
	// Simple insertion-sort: active > reachable(lowest RTT first) > unreachable.
	for i := 1; i < len(results); i++ {
		j := i
		for j > 0 && lessAddrEntry(results[j], results[j-1]) {
			results[j], results[j-1] = results[j-1], results[j]
			j--
		}
	}
}

func lessAddrEntry(a, b web.MultiaddrTestResultEntry) bool {
	if a.IsActive != b.IsActive {
		return a.IsActive
	}
	if a.Reachable != b.Reachable {
		return a.Reachable
	}
	return a.RTTMs < b.RTTMs
}

func (n *Node) Close() error {
	log.Info("Shutting down node...")
	if n.Gateway != nil {
		_ = n.Gateway.ClearExitNode()
	}
	n.cancel()
	if n.WebSrv != nil {
		_ = n.WebSrv.Close()
	}
	if n.TAP != nil {
		_ = n.TAP.Close()
	}
	_ = n.Host.Close()
	n.relayPool.shutdown()
	n.wg.Wait()
	log.Info("Node stopped")
	return nil
}

func (n *Node) discoveryLoop() {
	defer n.wg.Done()

	// Hash the PSK using SHA256 to generate a secure rendezvous string
	hash := sha256.Sum256([]byte(n.Config.PSK))
	rendezvousString := "p2ptap-" + hex.EncodeToString(hash[:])
	log.Debug("Generated secure rendezvous string for DHT discovery")

	// Initialize routing discovery
	routingDiscovery := drouting.NewRoutingDiscovery(n.DHT)

	// Advertise the hashed string as the rendezvous point
	util.Advertise(n.ctx, routingDiscovery, rendezvousString)

	// Helper for single discovery round
	runFind := func() {
		peerChan, err := routingDiscovery.FindPeers(n.ctx, rendezvousString)
		if err != nil {
			log.Debug("Error finding peers in DHT: %v", err)
			return
		}
		for p := range peerChan {
			if p.ID == n.Host.ID() || len(p.Addrs) == 0 {
				continue
			}

			// Feed newly discovered addresses to Peerstore for DCUtR hole punching
			n.Host.Peerstore().AddAddrs(p.ID, p.Addrs, 10*time.Minute)

			// Check if already connected; if not, initiate CONCURRENT connection with parallel race
			if n.Host.Network().Connectedness(p.ID) != network.Connected {
				log.Debug("DHT discovered new peer %s with addrs %v, connecting...", p.ID.String(), p.Addrs)
				go func(pi peer.AddrInfo) {
					if err := n.dialInParallel(n.ctx, pi, "discovered"); err != nil {
						log.Debug("All connection methods to discovered peer %s failed: %v", pi.ID.String(), err)
					}
				}(p)
			}
		}
	}

	// Initial fast discovery burst on startup (1s, 4s, 10s)
	burstIntervals := []time.Duration{1 * time.Second, 4 * time.Second, 10 * time.Second}
	for _, delay := range burstIntervals {
		select {
		case <-n.ctx.Done():
			return
		case <-time.After(delay):
			runFind()
		}
	}

	// Regular background discovery loop (every 20 seconds)
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-n.ctx.Done():
			return
		case <-ticker.C:
			runFind()
		}
	}
}

func (n *Node) isBootstrapPeer(pID peer.ID) bool {
	for _, bStr := range n.Config.BootstrapPeers {
		ma, err := multiaddr.NewMultiaddr(bStr)
		if err != nil {
			continue
		}
		info, err := peer.AddrInfoFromP2pAddr(ma)
		if err != nil {
			continue
		}
		if info.ID == pID {
			return true
		}
	}
	return false
}

func (n *Node) getPeerLatency(pID peer.ID) int64 {
	ewma := n.Host.Peerstore().LatencyEWMA(pID)
	if ewma > 0 {
		return ewma.Milliseconds()
	}
	return 10
}

func (n *Node) SynthesizeRelayCircuitAddrs(targetPeer peer.ID) []multiaddr.Multiaddr {
	type relayEntry struct {
		addr    multiaddr.Multiaddr
		latency time.Duration // 0 means unknown
	}

	var entries []relayEntry
	circuitComp, err := multiaddr.NewMultiaddr(fmt.Sprintf("/p2p-circuit/p2p/%s", targetPeer.String()))
	if err != nil {
		return nil
	}

	n.relayLatencyMu.RLock()
	defer n.relayLatencyMu.RUnlock()

	for _, bStr := range n.Config.BootstrapPeers {
		bMa, err := multiaddr.NewMultiaddr(bStr)
		if err != nil {
			continue
		}
		bInfo, err := peer.AddrInfoFromP2pAddr(bMa)
		if err != nil {
			continue
		}

		if n.Host.Network().Connectedness(bInfo.ID) == network.Connected {
			bootP2pComp, cerr := multiaddr.NewMultiaddr(fmt.Sprintf("/p2p/%s", bInfo.ID.String()))
			if cerr != nil {
				continue
			}
			bootAddrs := n.Host.Peerstore().Addrs(bInfo.ID)
			if len(bootAddrs) == 0 {
				bootAddrs = bInfo.Addrs
			}
			bootLatency := n.relayLatency[bInfo.ID] // cached RTT for this relay
			for _, a := range bootAddrs {
				if manet.IsIPLoopback(a) {
					continue
				}
				fullRelayAddr := a.Encapsulate(bootP2pComp).Encapsulate(circuitComp)
				entries = append(entries, relayEntry{addr: fullRelayAddr, latency: bootLatency})
			}
		}
	}

	// Sort: prefer lower-latency relay paths; unknown latency at end
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].latency == 0 && entries[j].latency == 0 {
			return false
		}
		if entries[i].latency == 0 {
			return false
		}
		if entries[j].latency == 0 {
			return true
		}
		return entries[i].latency < entries[j].latency
	})

	result := make([]multiaddr.Multiaddr, len(entries))
	for i, e := range entries {
		result[i] = e.addr
	}
	return result
}

// recordRelayLatency records the RTT to a relay bootstrap peer for path quality tracking.
func (n *Node) recordRelayLatency(relayID peer.ID, rtt time.Duration) {
	n.relayLatencyMu.Lock()
	if n.relayLatency == nil {
		n.relayLatency = make(map[peer.ID]time.Duration)
	}
	if existing, ok := n.relayLatency[relayID]; ok {
		// EWMA smoothing: 70% existing + 30% new
		n.relayLatency[relayID] = (existing*7 + rtt*3) / 10
	} else {
		n.relayLatency[relayID] = rtt
	}
	n.relayLatencyMu.Unlock()
}

func GetHostAddrs(h host.Host) []string {
	addrs := make([]string, 0)
	for _, a := range h.Addrs() {
		addrs = append(addrs, fmt.Sprintf("%s/p2p/%s", a.String(), h.ID().String()))
	}
	return addrs
}

func PrintBanner(n *Node) {
	log.Info("=========================================================")
	log.Info("             P2P TAP VPN (go-libp2p) Started             ")
	log.Info("=========================================================")
	log.Info(" Node Name     : %s", n.Collector.NodeName)
	log.Info(" Local Peer ID : %s", n.Host.ID())
	log.Info(" TAP Interface : %s (IPv4: %s | IPv6: %s)", n.TAP.Name(), n.Config.TapIP, n.Config.TapIPv6)
	log.Info(" P2P Strategy  : %s (Obfuscation: %s)", n.Config.TransportStrategy, n.Config.Obfuscation.Mode)
	log.Info(" Log Level     : %s", n.Config.LogLevel)
	if n.Config.WebUI.Enable {
		webIP := n.Config.WebUI.ListenIP
		if webIP == "0.0.0.0" || webIP == "" || webIP == "auto" {
			if tapIPv4, _, err := net.ParseCIDR(n.Config.TapIP); err == nil && tapIPv4 != nil {
				log.Info(" Web UI        : http://%s:%d (or http://127.0.0.1:%d)", tapIPv4.String(), n.Config.WebUI.Port, n.Config.WebUI.Port)
			} else {
				log.Info(" Web UI        : http://127.0.0.1:%d", n.Config.WebUI.Port)
			}
		} else {
			log.Info(" Web UI        : http://%s:%d", webIP, n.Config.WebUI.Port)
		}
	}
	log.Info(" Listen Addrs  :")
	for _, a := range n.Host.Addrs() {
		log.Info("   - %s/p2p/%s", a, n.Host.ID())
	}
	log.Info("=========================================================")
}

func loadOrGenerateNodeKey(keyPath string) (crypto.PrivKey, error) {
	if _, err := os.Stat(keyPath); err == nil {
		keyBytes, err := os.ReadFile(keyPath)
		if err != nil {
			return nil, err
		}
		return crypto.UnmarshalPrivateKey(keyBytes)
	}

	// Generate new Ed25519 keypair
	priv, _, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		return nil, err
	}

	keyBytes, err := crypto.MarshalPrivateKey(priv)
	if err != nil {
		return nil, err
	}

	_ = os.MkdirAll(filepath.Dir(keyPath), 0755)
	if err := os.WriteFile(keyPath, keyBytes, 0600); err != nil {
		log.Warn("Failed to save key file to %s: %v", keyPath, err)
	} else {
		log.Info("Generated new persistent identity key: %s", keyPath)
	}

	return priv, nil
}

func containsSub(s, substr string) bool {
	return strings.Contains(s, substr)
}

const (
	LSAProtocolID          protocol.ID = "/p2ptap/linkstate/1.0.0"
	OverlayRelayProtocolID protocol.ID = "/p2ptap/relay/1.0.0"
)

func (n *Node) lsaLoop() {
	defer n.wg.Done()
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	var seq uint64 = 1
	for {
		select {
		case <-n.ctx.Done():
			return
		case <-ticker.C:
			seq++
			n.broadcastLSA(seq)
		}
	}
}

func (n *Node) broadcastLSA(seq uint64) {
	lsa := n.Router.BuildLSA(seq)
	data, err := json.Marshal(lsa)
	if err != nil {
		return
	}

	for _, pID := range n.Host.Network().Peers() {
		if pID == n.Host.ID() {
			continue
		}
		target := pID
		go func(p peer.ID) {
			s, err := n.Host.NewStream(network.WithNoDial(n.ctx, "existing conn only"), p, LSAProtocolID)
			if err != nil {
				s, err = n.Host.NewStream(n.ctx, p, LSAProtocolID)
			}
			if err == nil {
				defer s.Close()
				_ = s.SetWriteDeadline(time.Now().Add(3 * time.Second))
				_, _ = s.Write(data)
			}
		}(target)
	}
}

func (n *Node) handleLSAStream(s network.Stream) {
	defer s.Close()
	data, err := io.ReadAll(io.LimitReader(s, 65536))
	if err != nil || len(data) == 0 {
		return
	}

	var lsa routing.LinkStatePayload
	if err := json.Unmarshal(data, &lsa); err != nil {
		return
	}

	changed := n.Router.ProcessLSA(&lsa)
	if changed && lsa.TTL > 1 {
		lsa.TTL--
		forwardData, err := json.Marshal(lsa)
		if err == nil {
			senderID := s.Conn().RemotePeer()
			for _, pID := range n.Host.Network().Peers() {
				if pID == n.Host.ID() || pID == senderID {
					continue
				}
				target := pID
				go func(p peer.ID) {
					fwStream, err := n.Host.NewStream(n.ctx, p, LSAProtocolID)
					if err == nil {
						defer fwStream.Close()
						_ = fwStream.SetWriteDeadline(time.Now().Add(3 * time.Second))
						_, _ = fwStream.Write(forwardData)
					}
				}(target)
			}
		}
	}
}

func (n *Node) handleRelayStream(s network.Stream) {
	defer s.Close()
	remotePeer := s.Conn().RemotePeer()

	// Loop read: handle multiple relay frames on the same stream (consistent with handleStream)
	buf := make([]byte, obfuscate.MaxFrameSize)
	for {
		readN, err := ReadFrame(s, buf)
		if err != nil || readN == 0 {
			break
		}
		data := buf[:readN]

		finalDst, srcPeer, ttl, innerPayload, err := routing.UnpackRelayFrame(data)
		if err != nil {
			log.Debug("Relay stream unpack error from %s: %v", remotePeer.String(), err)
			continue
		}

		if finalDst == n.Host.ID() {
			// Destination reached: unpack the obfuscated frame back to raw Ethernet for TAP delivery.
			seqID, unpacked, uerr := obfuscate.Unpack(innerPayload)
			var tapPayload []byte
			if uerr == nil {
				tapPayload = unpacked
				log.Debug("Relay Unpack: seq=%d payloadLen=%d innerLen=%d ttl=%d from=%s",
					seqID, len(unpacked), len(innerPayload), ttl, remotePeer.String())
			} else {
				tapPayload = innerPayload
				log.Debug("Relay Unpack: err=%v, using raw inner payload len=%d ttl=%d from=%s",
					uerr, len(innerPayload), ttl, remotePeer.String())
			}

			// Per-peer dedup (consistent with handleStream)
			n.dedupPeersMu.RLock()
			peerDedup, ok := n.dedupPeers[remotePeer]
			n.dedupPeersMu.RUnlock()
			if !ok {
				n.dedupPeersMu.Lock()
				peerDedup = n.dedupPeers[remotePeer]
				if peerDedup == nil {
					peerDedup = obfuscate.NewDeduplicator()
					n.dedupPeers[remotePeer] = peerDedup
				}
				n.dedupPeersMu.Unlock()
			}
			if uerr == nil && peerDedup.IsDuplicate(seqID) {
				n.Collector.RecordDedup()
				log.Debug("Duplicate relayed frame seq=%d from peer %s", seqID, remotePeer.String())
				continue
			}

			// ACL check
			if n.Config.ACL.Enable && !MatchACL(&n.Config.ACL, tapPayload, remotePeer.String(), false) {
				log.Debug("🛡️ ACL blocked relayed frame from peer %s", remotePeer.String())
				continue
			}

			// Learn source MAC — use sourcePeer from relay header so replies
			// are correctly routed back through the relay path (not sent directly
			// to the relay forwarder, which would drop them).
			if dstMAC, srcMAC, ok := vswitch.ExtractEthernetMACs(tapPayload); ok {
				if srcPeer != "" {
					n.MACTable.Learn(srcMAC, srcPeer)
				} else {
					// Legacy v1 frame: fall back to relay forwarder.
					n.MACTable.Learn(srcMAC, remotePeer)
				}
				log.Debug("Rx relayed frame: len=%d src=%s dst=%s from_peer=%s",
					len(tapPayload), net.HardwareAddr(srcMAC[:]).String(), net.HardwareAddr(dstMAC[:]).String(), remotePeer.String())
			}

			// Content-based broadcast dedup
			if dstMAC, _, ok := vswitch.ExtractEthernetMACs(tapPayload); ok && isBroadcastOrMulticastMAC(dstMAC) {
				contentHash := fnvHash64(tapPayload)
				if n.bcastDedup.isDuplicate(contentHash) {
					n.Collector.RecordDedup()
					continue
				}
			}

			// Write packet to local TAP device
			if n.TAP != nil {
				_, _ = n.TAP.Write(tapPayload)
				n.Collector.RecordRecv(len(tapPayload))
				n.Collector.RecordPacketDir(tapPayload, false)
				n.IPTracker.ExtractAndRecord(tapPayload, false)
				if len(tapPayload) >= 14 {
					ethType := binary.BigEndian.Uint16(tapPayload[12:14])
					n.Collector.RecordProtocol(ethType)
				}
			}
			continue
		}

		// Destination is another peer: forward frame if TTL > 1
		if ttl > 1 {
			routes := n.getCachedRoutes()
			nextHop := finalDst
			if route, ok := routes[finalDst]; ok && route.NextHop != "" {
				nextHop = route.NextHop
			}

			repacked, err := routing.PackRelayFrame(finalDst, srcPeer, ttl-1, innerPayload)
			if err == nil {
				// Use persistent relay pool instead of per-frame NewStream.
				// onSent=nil: forwarding does not double-count RecordSent (origin already counted).
				// onFail: silently drop; source will retransmit.
				n.relayPool.Submit(nextHop, repacked,
					nil, // onSent — no double-counting
					func() {
						log.Debug("Relay forward to %s via %s permanently failed",
							finalDst.String(), nextHop.String())
					},
				)
			}
		}
	}
}

// handleHealthCheck responds to connectivity probe streams.
// It simply accepts the stream and lets it close, confirming stream-level reachability.
func (n *Node) handleHealthCheck(s network.Stream) {
	// Accept and immediately close — the caller measures RTT from NewStream latency.
	s.Close()
}

// EchoProtocolID is a dedicated stream protocol for real end-to-end P2P echo testing.
const EchoProtocolID protocol.ID = "/p2ptap/echo/1.0.0"

// handleEcho responds to P2P echo probe streams by echoing back the exact payload bytes.
// Uses io.Copy for full-duplex streaming echo — supports any payload size (4B ping,
// 32B probe, or arbitrary future payloads). The client must call CloseWrite() after
// sending its payload so that io.Copy's Read side receives EOF and returns cleanly.
func (n *Node) handleEcho(s network.Stream) {
	defer s.Close()
	// Use a generous deadline to avoid hanging on broken streams.
	_ = s.SetDeadline(time.Now().Add(10 * time.Second))
	// Full-duplex echo: read everything the client sends, write it back immediately.
	// Returns when client half-closes write side (CloseWrite) or deadline expires.
	_, _ = io.Copy(s, s)
}

// ProbePeerEcho executes a real end-to-end P2P echo test over a dedicated libp2p stream.
// Sends random payload, measures round-trip time, and verifies payload byte integrity.
func (n *Node) ProbePeerEcho(targetStr string) *web.PeerEchoResultDTO {
	res := &web.PeerEchoResultDTO{
		PeerID:    targetStr,
		Timestamp: time.Now(),
	}

	var pid peer.ID
	var targetPeerInfo *web.PeerInfoDTO

	// Resolve target (PeerID, TAP IP, or Node Name)
	decodedPID, err := peer.Decode(targetStr)
	if err == nil {
		pid = decodedPID
	} else if n.Collector != nil {
		for _, p := range n.Collector.ActivePeers {
			if p.PeerID == targetStr || p.TapIP == targetStr || p.TapIPv6 == targetStr || strings.EqualFold(p.NodeName, targetStr) {
				if parsed, err := peer.Decode(p.PeerID); err == nil {
					pid = parsed
					targetPeerInfo = &p
					break
				}
			}
		}
	}

	if pid == "" {
		res.Error = fmt.Sprintf("cannot resolve target '%s' to a connected peer ID", targetStr)
		return res
	}

	if targetPeerInfo != nil {
		res.NodeName = targetPeerInfo.NodeName
		res.PeerID = targetPeerInfo.PeerID
	}

	// Generate 32 bytes of random test payload
	sentPayload := make([]byte, 32)
	_, _ = rand.Read(sentPayload)
	res.BytesSent = len(sentPayload)

	ctx, cancel := context.WithTimeout(n.ctx, 5*time.Second)
	defer cancel()

	start := time.Now()
	streamCtx := network.WithAllowLimitedConn(ctx, "echo-probe")
	s, err := n.Host.NewStream(streamCtx, pid, EchoProtocolID)
	if err != nil {
		res.Error = fmt.Sprintf("failed to open echo stream to %s: %v", pid.String(), err)
		return res
	}
	defer s.Close()

	if s.Conn() != nil {
		remoteAddr := s.Conn().RemoteMultiaddr().String()
		res.TransportAddr = remoteAddr
		res.IsRelayed = strings.Contains(remoteAddr, "/p2p-circuit")
	}

	_ = s.SetDeadline(time.Now().Add(4 * time.Second))

	// Send echo payload
	if _, err := s.Write(sentPayload); err != nil {
		res.Error = fmt.Sprintf("echo write failed: %v", err)
		return res
	}
	// Signal half-close: tell server we're done writing so its io.Copy returns cleanly
	_ = s.CloseWrite()

	// Read echo payload back
	recvBuf := make([]byte, 1024)
	readN, err := io.ReadAtLeast(s, recvBuf, len(sentPayload))
	rttDuration := time.Since(start)

	res.RTTMs = float64(rttDuration.Microseconds()) / 1000.0 // high precision in ms
	res.BytesRecv = readN

	if err != nil && err != io.EOF {
		res.Error = fmt.Sprintf("echo read error: %v", err)
		return res
	}

	if readN == len(sentPayload) && bytes.Equal(sentPayload, recvBuf[:readN]) {
		res.PayloadMatched = true
		res.Success = true
		res.Error = ""
	} else {
		res.Error = fmt.Sprintf("payload mismatch: sent %d bytes, received %d bytes", len(sentPayload), readN)
	}

	return res
}

// ProbePeerEchoAddr executes a targeted P2P stream echo test over a specific multiaddr path.
func (n *Node) ProbePeerEchoAddr(targetStr string, targetAddrStr string) *web.PeerEchoResultDTO {
	if targetAddrStr == "" {
		return n.ProbePeerEcho(targetStr)
	}

	res := &web.PeerEchoResultDTO{
		PeerID:    targetStr,
		Timestamp: time.Now(),
	}

	var pid peer.ID
	decodedPID, err := peer.Decode(targetStr)
	if err == nil {
		pid = decodedPID
	} else if n.Collector != nil {
		for _, p := range n.Collector.ActivePeers {
			if p.PeerID == targetStr || p.TapIP == targetStr || p.TapIPv6 == targetStr || strings.EqualFold(p.NodeName, targetStr) {
				if parsed, err := peer.Decode(p.PeerID); err == nil {
					pid = parsed
					res.NodeName = p.NodeName
					res.PeerID = p.PeerID
					break
				}
			}
		}
	}

	if pid == "" {
		res.Error = fmt.Sprintf("cannot resolve target '%s'", targetStr)
		return res
	}

	targetMA, err := multiaddr.NewMultiaddr(targetAddrStr)
	if err != nil {
		res.Error = fmt.Sprintf("invalid multiaddr '%s': %v", targetAddrStr, err)
		return res
	}

	// Aggressive: Clear dial backoff, remove stale addrs, and feed active targetMultiaddr to Peerstore (2 Hours TTL)
	n.clearSwarmBackoff(pid)
	n.Host.Peerstore().ClearAddrs(pid)
	n.Host.Peerstore().AddAddr(pid, targetMA, 2*time.Hour)

	ctx, cancel := context.WithTimeout(n.ctx, 5*time.Second)
	defer cancel()

	// Dial explicit target multiaddr
	_ = n.Host.Connect(ctx, peer.AddrInfo{ID: pid, Addrs: []multiaddr.Multiaddr{targetMA}})

	streamCtx := network.WithAllowLimitedConn(ctx, "echo-probe")
	s, err := n.Host.NewStream(streamCtx, pid, EchoProtocolID)
	if err != nil {
		res.Error = fmt.Sprintf("failed to open echo stream to %s via %s: %v", pid.String(), targetAddrStr, err)
		return res
	}
	defer s.Close()

	actualAddr := targetAddrStr
	if s.Conn() != nil {
		actualAddr = s.Conn().RemoteMultiaddr().String()
	}
	res.TransportAddr = actualAddr
	res.IsRelayed = strings.Contains(actualAddr, "/p2p-circuit")

	sentPayload := make([]byte, 32)
	_, _ = rand.Read(sentPayload)
	res.BytesSent = len(sentPayload)

	_ = s.SetDeadline(time.Now().Add(4 * time.Second))
	start := time.Now()
	if _, err := s.Write(sentPayload); err != nil {
		res.Error = fmt.Sprintf("echo write error: %v", err)
		return res
	}
	// Signal half-close: tell server we're done writing so its io.Copy returns cleanly
	_ = s.CloseWrite()

	recvBuf := make([]byte, 1024)
	readN, err := io.ReadAtLeast(s, recvBuf, len(sentPayload))
	elapsed := time.Since(start)

	res.RTTMs = float64(elapsed.Microseconds()) / 1000.0
	res.BytesRecv = readN

	if err != nil && err != io.EOF {
		res.Error = fmt.Sprintf("echo read error: %v", err)
		return res
	}

	if readN == len(sentPayload) && bytes.Equal(sentPayload, recvBuf[:readN]) {
		res.PayloadMatched = true
		res.Success = true
		res.Error = ""

		// Aggressive Promotion: record latency in libp2p Peerstore and update router path
		n.Host.Peerstore().RecordLatency(pid, elapsed)
		if res.RTTMs > 0 {
			n.Router.UpdateDirectLink(pid, int64(res.RTTMs))
		}
	} else {
		res.Error = fmt.Sprintf("payload mismatch: sent %d, got %d", len(sentPayload), readN)
	}

	return res
}

func computeKeyFingerprint(keyPath string) string {
	if data, err := os.ReadFile(keyPath); err == nil {
		h := sha256.Sum256(data)
		return hex.EncodeToString(h[:8])
	}
	return "dynamic-key"
}

// IsVirtualIP returns true if webUIIP is in the same subnet as tapIP, but NOT equal to tapIP itself (Category 2).
func IsVirtualIP(webUIIPStr, tapIPStr string) bool {
	if webUIIPStr == "" || webUIIPStr == "0.0.0.0" || webUIIPStr == "127.0.0.1" || webUIIPStr == "auto" {
		return false // Category 1: Non-virtual
	}

	cleanWebUI := strings.Split(webUIIPStr, "/")[0]
	webIP := net.ParseIP(cleanWebUI)
	if webIP == nil {
		return false
	}

	cleanTap, tapSubnet, err := net.ParseCIDR(tapIPStr)
	if err != nil {
		cleanTap = net.ParseIP(strings.Split(tapIPStr, "/")[0])
	}

	// Category 3: Same IP as tap_ip (Non-virtual)
	if cleanTap != nil && webIP.Equal(cleanTap) {
		return false
	}

	// Category 2: Different IP within TAP subnet OR dedicated Virtual IP
	if tapSubnet != nil && tapSubnet.Contains(webIP) {
		return true
	}

	return true
}

func isTapMultiaddr(a multiaddr.Multiaddr, tapIPv4, tapIPv6, webUIPv4, webUIPv6 string) bool {
	if ip4Str, err := a.ValueForProtocol(multiaddr.P_IP4); err == nil && ip4Str != "" {
		if tapIPv4 != "" {
			cleanTapIPv4, _, _ := strings.Cut(tapIPv4, "/")
			if ip4Str == cleanTapIPv4 {
				return true
			}
		}
		if webUIPv4 != "" && webUIPv4 != "0.0.0.0" && webUIPv4 != "127.0.0.1" && webUIPv4 != "auto" {
			cleanWebUIPv4, _, _ := strings.Cut(webUIPv4, "/")
			if ip4Str == cleanWebUIPv4 {
				return true
			}
		}
	}
	if ip6Str, err := a.ValueForProtocol(multiaddr.P_IP6); err == nil && ip6Str != "" {
		if tapIPv6 != "" {
			cleanTapIPv6, _, _ := strings.Cut(tapIPv6, "/")
			if ip6Str == cleanTapIPv6 {
				return true
			}
		}
		if webUIPv6 != "" && webUIPv6 != "::" && webUIPv6 != "auto" {
			cleanWebUIPv6, _, _ := strings.Cut(webUIPv6, "/")
			if ip6Str == cleanWebUIPv6 {
				return true
			}
		}
	}
	return false
}

func (n *Node) isLocalWebUIVirtualPacket(payload []byte) bool {
	if len(payload) < 14 {
		return false
	}

	// Check if source or destination MAC is the interceptor's virtual MAC
	if bytes.Equal(payload[0:6], web.InterceptorMAC) || bytes.Equal(payload[6:12], web.InterceptorMAC) {
		return true
	}

	ethType := binary.BigEndian.Uint16(payload[12:14])

	// Check for IPv4 packets involving the virtual WebUI IP
	if n.virtualWebUIV4IPUint32 > 0 && ethType == 0x0800 && len(payload) >= 34 {
		dstIPUint32 := binary.BigEndian.Uint32(payload[30:34])
		if dstIPUint32 == n.virtualWebUIV4IPUint32 {
			return true
		}
		srcIPUint32 := binary.BigEndian.Uint32(payload[26:30])
		if srcIPUint32 == n.virtualWebUIV4IPUint32 {
			return true
		}
	}

	// Check for ARP packets involving the virtual WebUI IP
	if n.virtualWebUIV4IPUint32 > 0 && ethType == 0x0806 && len(payload) >= 42 {
		targetIPUint32 := binary.BigEndian.Uint32(payload[38:42])
		if targetIPUint32 == n.virtualWebUIV4IPUint32 {
			return true
		}
		senderIPUint32 := binary.BigEndian.Uint32(payload[28:32])
		if senderIPUint32 == n.virtualWebUIV4IPUint32 {
			return true
		}
	}

	// Check for IPv6 packets involving the virtual WebUI IP
	if n.virtualWebUIV6IP != nil && ethType == 0x86DD && len(payload) >= 54 {
		if bytes.Equal(payload[38:54], n.virtualWebUIV6IP) { // dstIP
			return true
		}
		if bytes.Equal(payload[22:38], n.virtualWebUIV6IP) { // srcIP
			return true
		}
	}

	return false
}

// lookupPeerMACByIPv4 searches peerMeta for a peer whose TapIP matches the given
// IPv4 address and returns its TapMAC.  Returns nil when no matching peer is found
// or when the MAC cannot be parsed.
func (n *Node) lookupPeerMACByIPv4(ip net.IP) (net.HardwareAddr, peer.ID) {
	target := ip.To4()
	if target == nil {
		return nil, ""
	}
	targetStr := target.String()
	var foundMAC net.HardwareAddr
	var foundPeerID peer.ID
	n.peerMeta.Range(func(key, value any) bool {
		pID, _ := key.(peer.ID)
		meta := value.(PeerMeta)
		if meta.TapIP == "" || meta.TapMAC == "" {
			return true
		}
		cleanIP := strings.Split(meta.TapIP, "/")[0]
		if cleanIP == targetStr {
			if hw, err := net.ParseMAC(meta.TapMAC); err == nil {
				foundMAC = hw
				foundPeerID = pID
				return false // stop iteration
			}
		}
		return true
	})
	return foundMAC, foundPeerID
}

// lookupPeerMACByAdvertisedSubnet searches peerMeta for a peer whose
// AdvertisedSubnets contain the given IP, and returns its TapMAC.
// This enables ARP proxy for remote LAN subnets (e.g. 192.168.101.0/24
// advertised by peer with TapIP 10.0.0.2).
func (n *Node) lookupPeerMACByAdvertisedSubnet(ip net.IP) net.HardwareAddr {
	if ip == nil {
		return nil
	}
	var found net.HardwareAddr
	n.peerMeta.Range(func(key, value any) bool {
		meta := value.(PeerMeta)
		if meta.TapMAC == "" || len(meta.AdvertisedSubnets) == 0 {
			return true
		}
		for _, sub := range meta.AdvertisedSubnets {
			if sub == "" {
				continue
			}
			_, ipNet, err := net.ParseCIDR(sub)
			if err != nil {
				continue
			}
			if ipNet.Contains(ip) {
				if hw, err := net.ParseMAC(meta.TapMAC); err == nil {
					found = hw
					return false // stop iteration
				}
			}
		}
		return true
	})
	return found
}

// lookupPeerMACByIPv6 searches peerMeta for a peer whose TapIPv6 matches the given
// IPv6 address and returns its TapMAC.  Returns nil when no matching peer is found
// or when the MAC cannot be parsed.
func (n *Node) lookupPeerMACByIPv6(ip net.IP) (net.HardwareAddr, peer.ID) {
	target := ip.To16()
	if target == nil {
		return nil, ""
	}
	targetStr := target.String()
	var foundMAC net.HardwareAddr
	var foundPeerID peer.ID
	n.peerMeta.Range(func(key, value any) bool {
		pID, _ := key.(peer.ID)
		meta := value.(PeerMeta)
		if meta.TapIPv6 == "" || meta.TapMAC == "" {
			return true
		}
		cleanIP := strings.Split(meta.TapIPv6, "/")[0]
		if cleanIP == targetStr {
			if hw, err := net.ParseMAC(meta.TapMAC); err == nil {
				foundMAC = hw
				foundPeerID = pID
				return false // stop iteration
			}
		}
		return true
	})
	return foundMAC, foundPeerID
}

// extractCleanTransportMA extracts pure IP+Port transport components from exotic multiaddrs
func extractCleanTransportMA(ma multiaddr.Multiaddr) (multiaddr.Multiaddr, error) {
	var components []multiaddr.Component
	multiaddr.ForEach(ma, func(c multiaddr.Component) bool {
		code := c.Protocol().Code
		if code == multiaddr.P_IP4 || code == multiaddr.P_IP6 || code == multiaddr.P_TCP || code == multiaddr.P_UDP {
			components = append(components, c)
			if code == multiaddr.P_TCP || code == multiaddr.P_UDP {
				return false // stop after base transport port
			}
		}
		return true
	})
	if len(components) < 2 {
		return nil, fmt.Errorf("insufficient transport components in %s", ma.String())
	}
	var res multiaddr.Multiaddr
	for _, c := range components {
		if res == nil {
			res = c.Multiaddr()
		} else {
			res = res.Encapsulate(c.Multiaddr())
		}
	}
	return res, nil
}
