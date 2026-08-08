package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"p2ptap/pkg/meta"

	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/relay"
	"github.com/libp2p/go-libp2p"
	"github.com/multiformats/go-multiaddr"

	"p2ptap/pkg/version"
)

const (
	authProtocolID protocol.ID = "/p2ptap/auth/1.0.0"
	echoProtocolID protocol.ID = "/p2ptap/echo/1.0.0"
)

// pskACLFilter implements relay.ACLFilter to restrict relay usage to authenticated peers
type pskACLFilter struct {
	mu              sync.RWMutex
	authenticatedPeers map[peer.ID]time.Time // peer -> auth timestamp
	pskEnabled      bool
}

func newPSKACLFilter(pskEnabled bool) *pskACLFilter {
	return &pskACLFilter{
		authenticatedPeers: make(map[peer.ID]time.Time),
		pskEnabled:         pskEnabled,
	}
}

func (f *pskACLFilter) AddAuthenticated(p peer.ID) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.authenticatedPeers[p] = time.Now()
	fmt.Printf("[ACL] Peer %s authenticated for relay access\n", p.String())
}

func (f *pskACLFilter) RemoveAuthenticated(p peer.ID) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.authenticatedPeers, p)
}

func (f *pskACLFilter) IsAuthenticated(p peer.ID) bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	_, ok := f.authenticatedPeers[p]
	return ok
}

// AllowReserve decides whether a peer can make a relay reservation
func (f *pskACLFilter) AllowReserve(p peer.ID, a multiaddr.Multiaddr) bool {
	if !f.pskEnabled {
		fmt.Printf("[ACL Debug] Relay Reserve ALLOWED (open mode) for peer %s\n", p.String())
		return true
	}
	authed := f.IsAuthenticated(p)
	if authed {
		fmt.Printf("[ACL Debug] Relay Reserve ALLOWED for authenticated peer %s (addr: %s)\n", p.String(), a.String())
	} else {
		fmt.Printf("[ACL Debug] Relay Reserve DENIED for unauthenticated peer %s (addr: %s)\n", p.String(), a.String())
	}
	return authed
}

// AllowConnect decides whether a peer can connect through the relay to a destination
func (f *pskACLFilter) AllowConnect(src peer.ID, srcAddr multiaddr.Multiaddr, dest peer.ID) bool {
	if !f.pskEnabled {
		fmt.Printf("[ACL Debug] Relay Connect ALLOWED (open mode): src=%s -> dest=%s\n", src.String(), dest.String())
		return true
	}
	srcOK := f.IsAuthenticated(src)
	if !srcOK {
		fmt.Printf("[ACL Debug] Relay Connect DENIED: src=%s is NOT authenticated (dest=%s)\n", src.String(), dest.String())
	} else {
		fmt.Printf("[ACL Debug] Relay Connect ALLOWED: src=%s -> dest=%s\n", src.String(), dest.String())
	}
	return srcOK
}

func main() {
	if exePath, err := os.Executable(); err == nil {
		_ = os.Chdir(filepath.Dir(exePath))
	}
	port := flag.Int("port", 4001, "Port to listen on for UDP/TCP transports")
	keyPath := flag.String("key", "boot.key", "Path to private key file")
	psk := flag.String("psk", "", "Pre-shared key for relay authentication (hex string, must match p2ptap client PSK)")
	nodeName := flag.String("name", "Bootstrap-Relay", "Node identifier name for WebUI display")
	showVersion := flag.Bool("version", false, "Display version information and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(version.Full())
		return
	}

	// Load or generate persistent Identity Keypair
	privKey, err := loadOrGenerateKey(*keyPath)
	if err != nil {
		fmt.Printf("Error with identity key: %v\n", err)
		os.Exit(1)
	}

	pskEnabled := *psk != ""
	if pskEnabled {
		fmt.Println("[+] PSK authentication enabled — only authenticated peers can use relay")
	} else {
		fmt.Println("[!] WARNING: No PSK set — relay is OPEN to all peers. Use --psk to restrict access.")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	listenAddrs := []string{
		fmt.Sprintf("/ip4/0.0.0.0/udp/%d/quic-v1", *port),
		fmt.Sprintf("/ip6/::/udp/%d/quic-v1", *port),
		fmt.Sprintf("/ip4/0.0.0.0/udp/%d/webrtc-direct", *port+1),
		fmt.Sprintf("/ip6/::/udp/%d/webrtc-direct", *port+1),
		fmt.Sprintf("/ip4/0.0.0.0/udp/%d/webtransport", *port+2),
		fmt.Sprintf("/ip6/::/udp/%d/webtransport", *port+2),
		fmt.Sprintf("/ip4/0.0.0.0/tcp/%d", *port),
		fmt.Sprintf("/ip6/::/tcp/%d", *port),
	}

	var mAddrs []multiaddr.Multiaddr
	for _, aStr := range listenAddrs {
		ma, err := multiaddr.NewMultiaddr(aStr)
		if err != nil {
			fmt.Printf("Warning: Invalid multiaddr %q skipped: %v\n", aStr, err)
			continue
		}
		mAddrs = append(mAddrs, ma)
	}

	// Build Host with Public Server Options for NAT Traversal
	h, err := libp2p.New(
		libp2p.Identity(privKey),
		libp2p.ListenAddrs(mAddrs...),
		libp2p.NATPortMap(),
		libp2p.EnableNATService(),
		libp2p.EnableRelay(),
		libp2p.EnableHolePunching(),
		libp2p.ForceReachabilityPublic(),
	)
	if err != nil {
		fmt.Printf("Error starting bootstrap host: %v\n", err)
		os.Exit(1)
	}

	// 1. Enable Kademlia DHT in Server Mode
	kdht, err := dht.New(ctx, h, dht.Mode(dht.ModeServer))
	if err != nil {
		fmt.Printf("Error starting DHT server: %v\n", err)
	} else {
		_ = kdht.Bootstrap(ctx)
	}

	// 2. Setup PSK ACL filter for relay
	aclFilter := newPSKACLFilter(pskEnabled)

	// 3. Enable Circuit Relay v2 with ACL and resource limits
	relayRes := relay.DefaultResources()
	relayRes.ReservationTTL = 1 * time.Hour
	relayRes.MaxReservations = 256
	relayRes.MaxCircuits = 64
	relayRes.MaxReservationsPerPeer = 8
	relayRes.MaxReservationsPerIP = 16
	relayRes.Limit = &relay.RelayLimit{
		Duration: 5 * time.Minute,
		Data:     1 << 29, // 512 MiB per relay connection (↑ from 128MiB for better throughput)
	}

	_, err = relay.New(h,
		relay.WithACL(aclFilter),
		relay.WithResources(relayRes),
	)
	if err != nil {
		fmt.Printf("Warning: Circuit Relay v2 init error: %v\n", err)
	} else {
		fmt.Println("[+] Circuit Relay v2 enabled with ACL and resource limits")
	}

	// 4. Register PSK authentication stream handler
	if pskEnabled {
		pskHash := computePSKHash(*psk)
		h.SetStreamHandler(authProtocolID, func(s network.Stream) {
			handleAuthStream(s, pskHash, aclFilter)
		})
		fmt.Printf("[+] PSK auth handler registered (protocol: %s)\n", authProtocolID)
	}

	// 5. Register Metadata stream handler for WebUI Node Name exchange
	startTime := time.Now()
	h.SetStreamHandler(meta.MetaProtocolID, func(s network.Stream) {
		defer s.Close()
		// Read incoming metadata request payload (if any)
		_, _ = io.ReadAll(io.LimitReader(s, 4096))

		// Respond with Bootstrap Node's metadata
		payload := meta.NodeMetaPayload{
			NodeName:     *nodeName,
			TapIP:        "",
			TapIPv6:      "",
			OS:           runtime.GOOS,
			Arch:         runtime.GOARCH,
			Version:      version.Version,
			UptimeSec:    int64(time.Since(startTime).Seconds()),
			Reachability: "Public Server",
		}
		data, _ := json.Marshal(payload)
		_, _ = s.Write(data)
	})
	fmt.Printf("[+] Metadata handler registered (Node Name: '%s', protocol: %s)\n", *nodeName, meta.MetaProtocolID)

	// 6. Register Echo stream handler for liveness ping-pong probes
	h.SetStreamHandler(echoProtocolID, func(s network.Stream) {
		defer s.Close()
		_ = s.SetDeadline(time.Now().Add(10 * time.Second))
		_, _ = io.Copy(s, s)
	})
	fmt.Printf("[+] Echo ping-pong handler registered (protocol: %s)\n", echoProtocolID)

	// 6. Log peer connection/disconnection events
	h.Network().Notify(&network.NotifyBundle{
		ConnectedF: func(n network.Network, conn network.Conn) {
			fmt.Printf("[Peer] Connected: %s via %s\n", conn.RemotePeer().String(), conn.RemoteMultiaddr().String())
		},
		DisconnectedF: func(n network.Network, conn network.Conn) {
			peerID := conn.RemotePeer()
			fmt.Printf("[Peer] Disconnected: %s\n", peerID.String())
			aclFilter.RemoveAuthenticated(peerID)
		},
	})

	printBootstrapBanner(h, *nodeName, *port, pskEnabled)

	// Wait for OS shutdown signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	fmt.Println("\nShutting down bootstrap server...")
	_ = h.Close()
	fmt.Println("Shutdown complete.")
}

// computePSKHash derives a 32-byte authentication token from PSK using SHA-256
func computePSKHash(psk string) [32]byte {
	// Double hash: SHA-256("p2ptap-relay-auth:" + PSK)
	return sha256.Sum256([]byte("p2ptap-relay-auth:" + psk))
}

// handleAuthStream handles incoming PSK authentication requests
func handleAuthStream(s network.Stream, expectedHash [32]byte, acl *pskACLFilter) {
	defer s.Close()

	remotePeer := s.Conn().RemotePeer()
	fmt.Printf("[Auth Debug] Incoming PSK auth request from peer %s via %s\n", remotePeer.String(), s.Conn().RemoteMultiaddr().String())

	// Read 32-byte auth token from peer
	var token [32]byte
	if _, err := io.ReadFull(s, token[:]); err != nil {
		fmt.Printf("[Auth] FAILED: peer %s sent incomplete auth data (err: %v)\n", remotePeer.String(), err)
		_, _ = s.Write([]byte{0x00}) // Auth failed response
		return
	}

	// Verify token
	if token != expectedHash {
		fmt.Printf("[Auth] FAILED: peer %s provided incorrect PSK\n", remotePeer.String())
		_, _ = s.Write([]byte{0x00}) // Auth failed response
		return
	}

	// Authentication succeeded
	acl.AddAuthenticated(remotePeer)
	_, _ = s.Write([]byte{0x01}) // Auth success response
	fmt.Printf("[Auth] SUCCESS: peer %s authenticated for relay\n", remotePeer.String())
}

func loadOrGenerateKey(keyPath string) (crypto.PrivKey, error) {
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
		fmt.Printf("Warning: Failed to save key file to %s: %v\n", keyPath, err)
	} else {
		fmt.Printf("[+] Generated new persistent identity key: %s\n", keyPath)
	}

	return priv, nil
}

func printBootstrapBanner(h host.Host, name string, port int, pskEnabled bool) {
	fmt.Println("=========================================================")
	fmt.Println("         p2ptap Standalone Bootstrap Server              ")
	fmt.Println("=========================================================")
	fmt.Printf(" Node Name        : %s\n", name)
	fmt.Printf(" Bootstrap Peer ID : %s\n", h.ID())
	fmt.Println(" Features          : DHT Server, Circuit Relay v2,")
	fmt.Println("                     AutoNAT, Hole Punching")
	if pskEnabled {
		fmt.Println(" Relay Access      : PSK authenticated peers only")
	} else {
		fmt.Println(" Relay Access      : OPEN (no PSK — use --psk to restrict)")
	}
	relayLimits := []string{
		"MaxReservations=256", "MaxCircuits=64",
		"MaxPerPeer=8", "MaxPerIP=16",
		"ConnDuration=5m", "ConnData=512MiB",
	}
	fmt.Printf(" Relay Limits      : %s\n", strings.Join(relayLimits, ", "))
	fmt.Println(" Copy-paste any of the following Multiaddrs into your")
	fmt.Println(" p2ptap 'bootstrap_peers' configuration list:")
	fmt.Println("---------------------------------------------------------")
	for _, a := range h.Addrs() {
		fmt.Printf("   \"%s/p2p/%s\",\n", a.String(), h.ID())
	}
	fmt.Println("=========================================================")
}
