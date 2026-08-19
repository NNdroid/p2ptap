//go:build android

// Package P2PTap exposes the p2ptap P2P node to Android apps as an AAR produced
// by `gomobile bind`. It is the only package bound into the AAR; gomobile
// compiles the entire Go dependency tree (libp2p, crypto, the node core, etc.)
// into the AAR's native libraries under the P2PTap JNI class.
//
// Lifecycle (from the Kotlin/Java side):
//
//	val fd = vpnInterface.fileDescriptor.detachFd()   // from VpnService.Builder
//	P2PTap.setProtector(protector)                   // implements VpnService.protect(fd)
//	P2PTap.start(configJson, fd)                     // runs the node; non-blocking
//	// ... VPN runs ...
//	val running = P2PTap.isRunning()                 // check status
//	P2PTap.stop()                                    // tear down
//
// Android only supports a TUN (layer-3) device, so the node runs over a
// tun<->tap conversion layer (see p2ptap/pkg/tap + p2ptap/pkg/tuntap). The Exit
// Node server is intentionally NOT supported on Android (no host routing/NAT
// machinery on a TUN-only client) and is rejected at Start.
package P2PTap

/*
#include <dlfcn.h>
#include <stdint.h>

enum android_fdsan_error_level {
	ANDROID_FDSAN_ERROR_LEVEL_DISABLED = 0,
	ANDROID_FDSAN_ERROR_LEVEL_WARN_ONCE = 1,
	ANDROID_FDSAN_ERROR_LEVEL_WARN_ALWAYS = 2,
	ANDROID_FDSAN_ERROR_LEVEL_FATAL = 3,
};

static void disable_fdsan_abort() {
	void* lib = dlopen("libc.so", RTLD_NOW);
	if (lib) {
		void (*set_level)(enum android_fdsan_error_level) = (void (*)(enum android_fdsan_error_level))dlsym(lib, "android_fdsan_set_error_level");
		if (set_level) {
			set_level(ANDROID_FDSAN_ERROR_LEVEL_WARN_ONCE);
		}
		dlclose(lib);
	}
}
*/
import "C"

import (
	"context"
	crand "crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	basichost "github.com/libp2p/go-libp2p/p2p/host/basic"
	ma "github.com/multiformats/go-multiaddr"
	"p2ptap/pkg/config"
	"p2ptap/pkg/logger"
	"p2ptap/pkg/node"
	"p2ptap/pkg/observer"
	"p2ptap/pkg/routing"
	"p2ptap/pkg/tap"
	"p2ptap/pkg/version"
	"p2ptap/pkg/web"
)

var (
	interfaceProviderMu sync.RWMutex
	interfaceProvider   InterfaceProvider
)

// InterfaceProvider supplies local network interface IP addresses from Android Java runtime.
type InterfaceProvider interface {
	GetInterfaceAddresses() string // returns JSON array of IP strings e.g. ["192.168.1.100", "2408:..."]
}

// SetInterfaceProvider registers the Android Java network interface provider.
func SetInterfaceProvider(p InterfaceProvider) {
	interfaceProviderMu.Lock()
	defer interfaceProviderMu.Unlock()
	interfaceProvider = p
}

func init() {
	// Android 10+ (API 29+) fdsan aborts when Go runtime or Chromium WebView closes fds owned across JNI.
	// Downgrade error level to WARN_ONCE to prevent process crash.
	C.disable_fdsan_abort()

	// Android lacks /etc/resolv.conf. Configure a robust DNS resolver using standard DNS
	// servers (Alibaba 223.5.5.5, Google 8.8.8.8, Cloudflare 1.1.1.1) protected from the VPN tunnel.
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: 4 * time.Second,
				Control: node.GetSocketControlHook(""),
			}
			host, _, _ := net.SplitHostPort(address)
			if host == "127.0.0.1" || host == "localhost" || host == "" {
				address = "223.5.5.5:53"
			}
			conn, err := d.DialContext(ctx, "udp", address)
			if err != nil {
				conn, err = d.DialContext(ctx, "udp", "8.8.8.8:53")
			}
			if err != nil {
				conn, err = d.DialContext(ctx, "udp", "1.1.1.1:53")
			}
			return conn, err
		},
	}

	// Connect libp2p basic host address manager to Android Java NetworkInterface provider
	basichost.CustomInterfaceAddrsProvider = func() ([]ma.Multiaddr, error) {
		interfaceProviderMu.RLock()
		p := interfaceProvider
		interfaceProviderMu.RUnlock()

		if p == nil {
			return nil, errors.New("no interface provider registered")
		}

		jsonStr := p.GetInterfaceAddresses()
		if jsonStr == "" || jsonStr == "[]" {
			return nil, errors.New("empty interface list")
		}

		var ips []string
		if err := json.Unmarshal([]byte(jsonStr), &ips); err != nil {
			return nil, err
		}

		var result []ma.Multiaddr
		for _, ipStr := range ips {
			ip := net.ParseIP(strings.TrimSpace(ipStr))
			if ip == nil || ip.IsLoopback() {
				continue
			}
			var m ma.Multiaddr
			var err error
			if ip4 := ip.To4(); ip4 != nil {
				m, err = ma.NewMultiaddr(fmt.Sprintf("/ip4/%s", ip4.String()))
			} else if ip16 := ip.To16(); ip16 != nil {
				m, err = ma.NewMultiaddr(fmt.Sprintf("/ip6/%s", ip16.String()))
			}
			if err == nil && m != nil {
				result = append(result, m)
			}
		}

		if len(result) == 0 {
			return nil, errors.New("no valid IP addresses parsed")
		}
		return result, nil
	}
}

// Protector is implemented by the Android app to protect a socket file
// descriptor from being routed back through the VPN tunnel. gomobile generates
// a matching Java interface that the app implements and passes to SetProtector.
type Protector interface {
	// Protect marks the given socket fd as excluded from the VPN routing so
	// that traffic on it leaves via the underlying cellular/Wi-Fi interface.
	Protect(fd int32) bool
}

// StateListener is implemented by the Android app to receive high-frequency
// real-time metrics and state transitions directly over JNI with zero HTTP overhead.
type StateListener interface {
	// OnStateChange is invoked immediately when the node transitions state
	// (e.g. "STARTING", "RUNNING", "STOPPING", "IDLE", "ERROR").
	OnStateChange(state string, message string)

	// OnMetricsUpdate is pushed every second with live peer counts and throughput metrics.
	OnMetricsUpdate(peerCount int32, directPeers int32, relayPeers int32, txSpeed int64, rxSpeed int64, totalTx int64, totalRx int64)
}

var (
	mu              sync.Mutex
	instance        *node.Node
	activeCollector *web.StatsCollector
	log             = logger.New("Android")
	stateListenerMu sync.RWMutex
	stateListener   StateListener
	metricsCancel   context.CancelFunc
)

// SetStateListener registers the real-time event & metrics callback.
func SetStateListener(l StateListener) {
	stateListenerMu.Lock()
	defer stateListenerMu.Unlock()
	stateListener = l
}

// SetProtector registers the Android VpnService socket protector. It MUST be
// called before Start, otherwise P2P sockets may loop into the tunnel.
func SetProtector(p Protector) {
	node.SetAndroidProtectFunc(func(fd int) bool {
		if p == nil {
			return false
		}
		return p.Protect(int32(fd))
	})
}

// Start launches the P2P TAP node over the provided Android TUN file descriptor.
//
// cfgJSON is the node configuration in JSON (same schema as config.json). The
// Exit Node server (exit_node.enable=true) is rejected because it is not
// supported on Android. tunFd is the detached file descriptor obtained from
// android.os.ParcelFileDescriptor.detachFd(). Start returns immediately; the
// node runs in background goroutines until Stop is called.
func Start(cfgJSON string, tunFd int) error {
	mu.Lock()
	defer mu.Unlock()

	if instance != nil {
		log.Warn("android: node already running, stopping previous instance before starting new one")
		old := instance
		instance = nil
		activeCollector = nil
		if metricsCancel != nil {
			metricsCancel()
			metricsCancel = nil
		}
		_ = old.Close()
	}

	cfg := config.DefaultConfig()
	if cfgJSON != "" {
		if err := json.Unmarshal([]byte(cfgJSON), cfg); err != nil {
			return fmt.Errorf("android: invalid config JSON: %w", err)
		}
	}

	// Exit Node server is not supported on Android (TUN-only client, no host
	// routing/NAT). Reject it explicitly rather than silently doing nothing.
	if cfg.ExitNode.Enable {
		return errors.New("android: exit node server is not supported on this build")
	}

	if cfg.MTU <= 0 {
		cfg.MTU = 1500
	}
	if cfg.TapMAC == "" {
		cfg.TapMAC = config.GenerateRandomMAC()
	}

	dev, err := tap.CreateTunTAPDevice(tunFd, cfg.TapName, cfg.TapMAC, cfg.MTU)
	if err != nil {
		return fmt.Errorf("android: create TUN device: %w", err)
	}

	collector := web.NewStatsCollector()
	n, err := node.NewNodeWithTAP(cfg, dev, collector)
	if err != nil {
		_ = dev.Close()
		return fmt.Errorf("android: create node: %w", err)
	}

	if n.Gateway != nil {
		collector.Gateway = n.Gateway
	}

	n.MakeInterceptor = func(virtualIP, virtualIPv6 string, port int, c observer.Collector, cfg *config.Config, cfgPath string) observer.FrameFilter {
		return web.NewTAPInterceptor(virtualIP, virtualIPv6, port, collector, cfg, cfgPath)
	}
	n.StartWebServer = func(c observer.Collector, bindIP, bindIPv6 string, port int, cfg *config.Config, cfgPath string, socketProtectHook func(network, address string, c syscall.RawConn) error) (observer.WebServer, error) {
		srv, err := web.StartServer(collector, bindIP, bindIPv6, port, cfg, cfgPath, socketProtectHook)
		if err != nil {
			return nil, err
		}
		srv.SetTopologyProvider(func() any { return n.GetTopology() })
		srv.SetHostProvider(func() host.Host { return n.Host })
		srv.SetRouterProvider(func() *routing.Router { return n.Router })
		return srv, nil
	}

	if cfg.WebUI.Enable {
		if err := n.SetupWebUI(); err != nil {
			log.Warn("android: WebUI setup failed: %v", err)
		} else {
			log.Info("android: WebUI started successfully on %s:%d", cfg.WebUI.ListenIP, cfg.WebUI.Port)
		}
	}

	instance = n
	activeCollector = collector
	n.Start()

	if cfgJSON != "" {
		var rawMap map[string]any
		if err := json.Unmarshal([]byte(cfgJSON), &rawMap); err == nil {
			if exitPeer, ok := rawMap["exit_node_peer"].(string); ok && strings.TrimSpace(exitPeer) != "" {
				if err := setExitNodeLocked(n, exitPeer, "", ""); err != nil {
					log.Warn("android: failed to initialize exit node %s: %v", exitPeer, err)
				} else {
					log.Info("android: exit node initialized to %s", exitPeer)
				}
			}
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	metricsCancel = cancel

	stateListenerMu.RLock()
	sl := stateListener
	stateListenerMu.RUnlock()
	if sl != nil {
		sl.OnStateChange("RUNNING", "Node started successfully")
	}

	go metricsLoop(ctx, n, collector)

	return nil
}

func metricsLoop(ctx context.Context, n *node.Node, collector *web.StatsCollector) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			stateListenerMu.RLock()
			sl := stateListener
			stateListenerMu.RUnlock()
			if sl == nil {
				continue
			}

			n.UpdateWebCollectorState()

			resp := collector.GetResponse()
			totTx := int64(resp.PacketStats.BytesSent)
			totRx := int64(resp.PacketStats.BytesRecv)
			txSpd := int64(resp.Speed.TxBytesPerSec)
			rxSpd := int64(resp.Speed.RxBytesPerSec)

			var directCount, relayCount int32
			for _, p := range resp.ActivePeers {
				if p.ConnState == "relay_ok" {
					relayCount++
				} else if p.ConnState == "ok" {
					directCount++
				}
			}
			totalPeers := int32(len(resp.ActivePeers))

			sl.OnMetricsUpdate(totalPeers, directCount, relayCount, txSpd, rxSpd, totTx, totRx)
		}
	}
}

// Stop shuts down the running node and releases the TUN fd. It is safe to call
// when no node is running.
func Stop() error {
	mu.Lock()
	n := instance
	instance = nil
	activeCollector = nil
	if metricsCancel != nil {
		metricsCancel()
		metricsCancel = nil
	}
	mu.Unlock()

	if n == nil {
		return nil
	}

	stateListenerMu.RLock()
	sl := stateListener
	stateListenerMu.RUnlock()
	if sl != nil {
		sl.OnStateChange("IDLE", "Node stopped")
	}

	return n.Close()
}

// IsRunning reports whether the P2P TAP node is currently active.
func IsRunning() bool {
	mu.Lock()
	defer mu.Unlock()
	return instance != nil
}

// SetLogLevel adjusts the global log verbosity. level is one of
// "debug"|"info"|"warn"|"error" (case-insensitive); unknown values default to
// "info".
func SetLogLevel(level string) error {
	logger.SetGlobalLevel(logger.ParseLevel(level))
	return nil
}

// GetPeerID returns the libp2p Peer ID of the running node, or empty if not running.
func GetPeerID() string {
	mu.Lock()
	defer mu.Unlock()
	if instance != nil && instance.Host != nil {
		return instance.Host.ID().String()
	}
	return ""
}

// GetMultiaddrs returns all listening multiaddrs of the running node separated by newlines,
// including the /p2p/<peerID> suffix. Returns empty string if node is not running.
func GetMultiaddrs() string {
	mu.Lock()
	defer mu.Unlock()
	if instance != nil && instance.Host != nil {
		pid := instance.Host.ID().String()
		var addrs []string
		for _, a := range instance.Host.Addrs() {
			addrs = append(addrs, fmt.Sprintf("%s/p2p/%s", a.String(), pid))
		}
		return strings.Join(addrs, "\n")
	}
	return ""
}

// GetStatsJSON returns a JSON string containing the full StatsResponse
// including active peers, traffic, packet counters, and security status.
func GetStatsJSON() string {
	mu.Lock()
	defer mu.Unlock()
	if instance != nil {
		instance.UpdateWebCollectorState()
	}
	if activeCollector != nil {
		resp := activeCollector.GetResponse()
		data, err := json.Marshal(resp)
		if err == nil {
			return string(data)
		}
	}
	return "{}"
}

// GetPeerIDFromKey loads or generates the persistent identity key from keyPath
// and returns its canonical libp2p Peer ID string, even before the node is started.
func GetPeerIDFromKey(keyPath string) string {
	if keyPath == "" {
		return ""
	}
	if _, err := os.Stat(keyPath); err == nil {
		data, err := os.ReadFile(keyPath)
		if err == nil && len(data) > 0 {
			priv, err := crypto.UnmarshalPrivateKey(data)
			if err == nil {
				pid, err := peer.IDFromPrivateKey(priv)
				if err == nil {
					return pid.String()
				}
			}
		}
	}
	// Key does not exist yet: generate a new persistent Ed25519 identity key
	priv, _, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	if err != nil {
		return ""
	}
	data, err := crypto.MarshalPrivateKey(priv)
	if err != nil {
		return ""
	}
	_ = os.MkdirAll(filepath.Dir(keyPath), 0700)
	if err := os.WriteFile(keyPath, data, 0600); err != nil {
		return ""
	}
	pid, err := peer.IDFromPrivateKey(priv)
	if err != nil {
		return ""
	}
	return pid.String()
}

// Version returns the build version string (injected at build time).
func Version() string {
	if version.Version != "" {
		return version.Version
	}
	return "dev"
}

// OnNetworkChanged informs the Go engine that Android network connectivity has changed
// (e.g. Wi-Fi <-> Cellular handoff or reconnection). It triggers immediate interface
// re-probing, listener reconciliation, and peer/relay fast reconnection.
func OnNetworkChanged() {
	mu.Lock()
	n := instance
	mu.Unlock()

	if n != nil {
		n.TriggerRoam()
	}
}

// ExportIdentityKeyBase64 reads the private key at keyPath and returns it as a Base64 string.
func ExportIdentityKeyBase64(keyPath string) (string, error) {
	if keyPath == "" {
		return "", errors.New("keyPath cannot be empty")
	}
	data, err := os.ReadFile(keyPath)
	if err != nil {
		return "", fmt.Errorf("read key file: %w", err)
	}
	// Validate key structure before export
	if _, err := crypto.UnmarshalPrivateKey(data); err != nil {
		return "", fmt.Errorf("invalid private key data: %w", err)
	}
	return base64.StdEncoding.EncodeToString(data), nil
}

// ImportIdentityKeyBase64 writes a Base64-encoded private key to keyPath after verifying
// its validity, and returns the canonical libp2p Peer ID string.
func ImportIdentityKeyBase64(keyPath string, b64Key string) (string, error) {
	if keyPath == "" {
		return "", errors.New("keyPath cannot be empty")
	}
	if b64Key == "" {
		return "", errors.New("base64Key cannot be empty")
	}
	data, err := base64.StdEncoding.DecodeString(b64Key)
	if err != nil {
		return "", fmt.Errorf("base64 decode error: %w", err)
	}
	priv, err := crypto.UnmarshalPrivateKey(data)
	if err != nil {
		return "", fmt.Errorf("invalid libp2p private key: %w", err)
	}
	pid, err := peer.IDFromPrivateKey(priv)
	if err != nil {
		return "", fmt.Errorf("derive peer id: %w", err)
	}

	_ = os.MkdirAll(filepath.Dir(keyPath), 0755)
	if err := os.WriteFile(keyPath, data, 0600); err != nil {
		return "", fmt.Errorf("write key file: %w", err)
	}
	return pid.String(), nil
}

// GenerateNewIdentityKey generates a fresh Ed25519 node private key, saves it to keyPath,
// and returns the newly generated libp2p Peer ID string.
func GenerateNewIdentityKey(keyPath string) (string, error) {
	if keyPath == "" {
		return "", errors.New("keyPath cannot be empty")
	}
	priv, _, err := crypto.GenerateEd25519Key(crand.Reader)
	if err != nil {
		return "", fmt.Errorf("generate ed25519 key: %w", err)
	}
	data, err := crypto.MarshalPrivateKey(priv)
	if err != nil {
		return "", fmt.Errorf("marshal private key: %w", err)
	}
	pid, err := peer.IDFromPrivateKey(priv)
	if err != nil {
		return "", fmt.Errorf("derive peer id: %w", err)
	}
	_ = os.MkdirAll(filepath.Dir(keyPath), 0755)
	if err := os.WriteFile(keyPath, data, 0600); err != nil {
		return "", fmt.Errorf("write key file: %w", err)
	}
	return pid.String(), nil
}

// P2PTap provides an object-oriented receiver wrapper matching the class name.
type P2PTap struct{}

// NewP2PTap creates a new P2PTap instance wrapper.
func NewP2PTap() *P2PTap {
	return &P2PTap{}
}

func (a *P2PTap) SetProtector(p Protector) {
	SetProtector(p)
}

func (a *P2PTap) SetStateListener(l StateListener) {
	SetStateListener(l)
}

func (a *P2PTap) Start(cfgJSON string, tunFd int) error {
	return Start(cfgJSON, tunFd)
}

func (a *P2PTap) Stop() error {
	return Stop()
}

func (a *P2PTap) IsRunning() bool {
	return IsRunning()
}

func (a *P2PTap) SetLogLevel(level string) error {
	return SetLogLevel(level)
}

func (a *P2PTap) GetPeerID() string {
	return GetPeerID()
}

func (a *P2PTap) GetMultiaddrs() string {
	return GetMultiaddrs()
}

func (a *P2PTap) GetStatsJSON() string {
	return GetStatsJSON()
}

func (a *P2PTap) GetPeerIDFromKey(keyPath string) string {
	return GetPeerIDFromKey(keyPath)
}

func (a *P2PTap) ExportIdentityKeyBase64(keyPath string) (string, error) {
	return ExportIdentityKeyBase64(keyPath)
}

func (a *P2PTap) ImportIdentityKeyBase64(keyPath string, b64Key string) (string, error) {
	return ImportIdentityKeyBase64(keyPath, b64Key)
}

func (a *P2PTap) GenerateNewIdentityKey(keyPath string) (string, error) {
	return GenerateNewIdentityKey(keyPath)
}

// SetExitNode sets the designated peer ID and optional virtual TAP IP as the active exit gateway.
func SetExitNode(peerID, tapIPv4, tapIPv6 string) error {
	mu.Lock()
	n := instance
	mu.Unlock()
	return setExitNodeLocked(n, peerID, tapIPv4, tapIPv6)
}

func setExitNodeLocked(n *node.Node, peerID, tapIPv4, tapIPv6 string) error {
	if n != nil && n.Gateway != nil {
		target := strings.TrimSpace(peerID)
		if target == "" {
			return n.Gateway.ClearExitNode()
		}
		if ip := net.ParseIP(target); ip != nil {
			if ip.To4() != nil {
				return n.Gateway.SetExitNode("", target, "", nil)
			}
			return n.Gateway.SetExitNode("", "", target, nil)
		}
		// If peerID is given and bare IPs are empty, automatically resolve from peer metadata
		if tapIPv4 == "" && tapIPv6 == "" {
			if pid, err := peer.Decode(target); err == nil {
				if metaVal, ok := n.GetPeerMeta(pid); ok {
					if metaVal.TapIP != "" {
						tapIPv4 = strings.Split(metaVal.TapIP, "/")[0]
					}
					if metaVal.TapIPv6 != "" {
						tapIPv6 = strings.Split(metaVal.TapIPv6, "/")[0]
					}
				}
			}
		}
		return n.Gateway.SetExitNode(target, tapIPv4, tapIPv6, nil)
	}
	return nil
}

// UpdateTunFd hot-swaps the underlying Android TUN file descriptor safely without tearing down the P2P engine.
func UpdateTunFd(newTunFd int) error {
	mu.Lock()
	n := instance
	mu.Unlock()
	if n == nil || n.TAP == nil {
		return errors.New("android: node not running")
	}
	if updater, ok := n.TAP.(interface{ UpdateFd(int) error }); ok {
		return updater.UpdateFd(newTunFd)
	}
	return errors.New("android: TAP device does not support UpdateFd")
}

// ClearExitNode clears the active exit node gateway.
func ClearExitNode() error {
	mu.Lock()
	n := instance
	mu.Unlock()
	if n != nil && n.Gateway != nil {
		return n.Gateway.ClearExitNode()
	}
	return nil
}

// GetActiveExitNode returns the Peer ID of the currently active exit node gateway.
func GetActiveExitNode() string {
	mu.Lock()
	n := instance
	mu.Unlock()
	if n != nil && n.Gateway != nil {
		return n.Gateway.ActiveExitPeerID()
	}
	return ""
}

func (a *P2PTap) SetExitNode(peerID, tapIPv4, tapIPv6 string) error {
	return SetExitNode(peerID, tapIPv4, tapIPv6)
}

func (a *P2PTap) UpdateTunFd(newTunFd int) error {
	return UpdateTunFd(newTunFd)
}

func (a *P2PTap) ClearExitNode() error {
	return ClearExitNode()
}

func (a *P2PTap) GetActiveExitNode() string {
	return GetActiveExitNode()
}

func (a *P2PTap) Version() string {
	return Version()
}

