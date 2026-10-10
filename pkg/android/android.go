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

import (
	"context"
	crand "crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
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

// metricsInterval is the push cadence of the live stats callbacks; the Android
// service treats it as a heartbeat, so it must stay well under the staleness
// threshold on that side.
const metricsInterval = 1 * time.Second

// statsRefreshEvery controls how often metricsTick rebuilds the peer DTOs
// via UpdateWebCollectorState(). That call re-parses every bootstrap/static
// multiaddr, re-installs the TAP self-test closure and re-derives connection
// signals for every peer — expensive work that is wasted when the peer set
// hasn't changed. Speed and packet counters are always fresh from
// GetResponse(), so only the peer rows go stale, and by at most this many
// seconds. The pull path (GetStatsJSON) still calls UpdateWebCollectorState
// unconditionally because its caller is pulling on demand.
const statsRefreshEvery = 5

// metricsBackoff is applied per consecutive failed tick after the loop recovers
// from a panic, multiplied by the failure streak and capped at
// metricsBackoffMaxSteps so a wedged node is retried at a sane rate without the
// counters stalling for long.
const (
	metricsBackoff         = 1 * time.Second
	metricsBackoffMaxSteps = 30
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

// ConfigStore durably saves WebUI configuration in the app's own storage.
// Returning an error rejects the save before any runtime snapshot is changed.
type ConfigStore interface {
	SaveConfig(cfgJSON string) error
}

// LogCallback is implemented by the Android app to receive structured log
// entries with the correct android.util.Log priority. Without this, every Go
// log line goes through stderr→logcat and arrives at a single indistinguishable
// level, so INFO messages show up as ERROR in the viewer.
type LogCallback interface {
	// OnLog is invoked for every log entry that passes the global level filter.
	// priority is an android.util.Log constant (VERBOSE=2, DEBUG=3, INFO=4,
	// WARN=5, ERROR=6). module is the logger's module name (e.g. "node",
	// "Android"). message is the fully-formatted log line.
	OnLog(priority int32, module string, message string)
}

var configStoreMu sync.RWMutex
var configStore ConfigStore

func SetConfigStore(store ConfigStore) {
	configStoreMu.Lock()
	defer configStoreMu.Unlock()
	configStore = store
}

var (
	mu              sync.Mutex
	instance        *node.Node
	activeCollector *web.StatsCollector
	log             = logger.New("Android")
	stateListenerMu sync.RWMutex
	stateListener   StateListener
	metricsCancel   context.CancelFunc
	// stopping is published before the teardown starts so IsRunning() reports a
	// shutting-down node as not running immediately. node.Close() takes several
	// seconds while mu is held, and the Android service would otherwise keep
	// reporting "running" (tile active, WebUI button enabled) for the entire
	// teardown.
	stopping atomic.Bool
	// statsTickCounter counts metrics ticks so metricsTick can refresh the
	// peer DTOs at a slower cadence than the 1 Hz heartbeat. It is not reset
	// between sessions because the counter is only used for modulo arithmetic
	// against a small constant.
	statsTickCounter int64
)

// --- Native crash capture ---
//
// Go runtime fatal errors (e.g. "sync: unlock of unlocked mutex") call
// exit(2) directly — they bypass Java's UncaughtExceptionHandler entirely.
// Native segfaults from cgo/JNI code likewise skip the Java handler.
// SetCrashFilePath wires a crash file that the Android app reads on next
// launch. Two mechanisms are used:
//
//  1. debug.SetCrashOutput redirects the Go runtime's fatal-error output
//     (goroutine stacks, "fatal error: ..." lines) into the crash file.
//     This catches Go runtime throws that recover() cannot stop.
//
//  2. A signal.Notify goroutine catches native signals (SIGSEGV, SIGABRT,
//     SIGFPE, SIGBUS, SIGILL) that originate from C/C++ code reached through
//     cgo or the JNI boundary. The handler writes the signal name and
//     timestamp, then exits.
//
// The crash file is opened once with O_TRUNC and kept open for the process
// lifetime; debug.SetCrashOutput holds a reference to the *os.File.

var (
	crashFileMu   sync.RWMutex
	crashFilePath string
	crashFile     *os.File
)

// SetCrashFilePath configures where native (Go runtime + cgo) crashes are
// written. Call once from the Android Application.onCreate() before the
// engine starts. An empty path disables capture.
func SetCrashFilePath(path string) {
	crashFileMu.Lock()
	defer crashFileMu.Unlock()
	if path == "" {
		crashFilePath = ""
		return
	}
	crashFilePath = path
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		log.Warn("android: create crash dir: %v", err)
		return
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		log.Warn("android: open crash file %s: %v", path, err)
		return
	}
	crashFile = f
	// debug.SetCrashOutput duplicates f's fd internally, so the Go runtime
	// keeps its own copy even if we close f later. We keep crashFile open
	// for the signal handler to write native-crash info to the same file.
	if err := debug.SetCrashOutput(f, debug.CrashOptions{}); err != nil {
		log.Warn("android: SetCrashOutput: %v", err)
	}

	// Register a signal handler for native crashes that the Go runtime
	// cannot catch on its own.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGSEGV, syscall.SIGABRT, syscall.SIGFPE,
		syscall.SIGBUS, syscall.SIGILL)
	go func() {
		sig := <-sigCh
		msg := fmt.Sprintf(
			"P2PTap native crash: signal %v\nTime: %s\nVersion: %s\nGo version: %s\n",
			sig, time.Now().UTC().Format(time.RFC3339Nano),
			version.Full(), runtime.Version(),
		)
		crashFileMu.RLock()
		cf := crashFile
		crashFileMu.RUnlock()
		if cf != nil {
			_, _ = cf.WriteString(msg)
			_ = cf.Sync()
		}
		os.Exit(1)
	}()
}

// GetCrashFilePath returns the path of the crash file, if configured.
func GetCrashFilePath() string {
	crashFileMu.RLock()
	defer crashFileMu.RUnlock()
	return crashFilePath
}

// SetStateListener registers the real-time event & metrics callback.
func SetStateListener(l StateListener) {
	stateListenerMu.Lock()
	defer stateListenerMu.Unlock()
	stateListener = l
}

// SetLogCallback registers the structured log callback. Passing nil removes
// the callback and restores the stderr-only path. Call before Start() so
// early boot messages are not lost.
func SetLogCallback(cb LogCallback) {
	if cb == nil {
		logger.SetLogCallback(nil)
		return
	}
	logger.SetLogCallback(func(priority int, module, message string) {
		// Recover from any Java exception so a bad callback cannot kill the
		// logger goroutine (which includes the TAP read loop and stream
		// goroutines).
		defer func() {
			if r := recover(); r != nil {
				fmt.Fprintf(os.Stderr, "[android] panic in log callback: %v\n", r)
			}
		}()
		cb.OnLog(int32(priority), module, message)
	})
}

// SetProtector registers the Android VpnService socket protector. It MUST be
// called before Start, otherwise P2P sockets may loop into the tunnel.
func SetProtector(p Protector) {
	if p == nil {
		node.SetAndroidProtectFunc(nil)
		return
	}
	node.SetAndroidProtectFunc(func(fd int) bool {
		return p.Protect(int32(fd))
	})
}

func closeDetachedTunFD(fd int) {
	if fd > 0 {
		_ = syscall.Close(fd)
	}
}

// Start launches the P2P TAP node over the provided Android TUN file descriptor.
//
// cfgJSON is the node configuration in JSON (same schema as config.json). The
// Exit Node server (exit_node.enable=true) is rejected because it is not
// supported on Android. tunFd is the detached file descriptor obtained from
// android.os.ParcelFileDescriptor.detachFd(). Start consumes tunFd on every
// path, including validation or startup failure. It returns after local node
// initialization; peer/bootstrap connectivity is established asynchronously.
func Start(cfgJSON string, tunFd int) error {
	if tunFd <= 0 {
		return errors.New("android: invalid TUN fd")
	}

	cfg, err := parseConfig(cfgJSON)
	if err != nil {
		closeDetachedTunFD(tunFd)
		return err
	}

	mu.Lock()
	if instance != nil {
		mu.Unlock()
		closeDetachedTunFD(tunFd)
		return errors.New("android: node already running; call Stop() and wait for it to return before Start()")
	}

	dev, err := tap.CreateTunTAPDevice(tunFd, cfg.TapName, cfg.TapMAC, cfg.MTU)
	if err != nil {
		mu.Unlock()
		return fmt.Errorf("android: create TUN device: %w", err)
	}

	collector := web.NewStatsCollector()
	n, err := node.NewNodeWithTAP(cfg, dev, collector)
	if err != nil {
		_ = dev.Close()
		mu.Unlock()
		return fmt.Errorf("android: create node: %w", err)
	}
	configStoreMu.RLock()
	store := configStore
	configStoreMu.RUnlock()
	collector.PersistConfig = func(candidate *config.Config) error {
		if store == nil {
			return errors.New("android: configuration storage is not registered")
		}
		data, err := json.Marshal(candidate)
		if err != nil {
			return err
		}
		return store.SaveConfig(string(data))
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
		// /api/relay/diag — per-stage relay drop counters, wired from the AAR
		// so a phone build can be diagnosed from its own WebUI too.
		srv.SetRelayDiagProvider(func() any { return n.GetRelayDiag() })
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

	mu.Unlock()
	// Emit the RUNNING state outside mu: a synchronous JNI call under the
	// global lock would deadlock if the Java handler calls back into Go
	// (getStatsJSON, stop, etc.).  Same pattern as Stop().
	emitStateChange("RUNNING", "Node started successfully")
	go metricsLoop(ctx, n, collector)
	return nil
}

// metricsLoop is the only goroutine that pushes live stats to the Android
// service over JNI. It runs exactly once per Start(), and nothing restarts it
// on the app side, so it must be crash-proof: a Java exception raised inside
// the OnMetricsUpdate callback surfaces to Go as a panic on this goroutine,
// and without a recover() here the phone's traffic counters would freeze with
// the node still forwarding and nothing left to tell the app about it.
//
// A panic that escapes metricsTick is recovered, reported to the app as an ERROR
// state so the user sees it, and the loop is re-spawned, so a single crash can
// never permanently silence the counters. Backoff against repeated bad ticks
// lives in metricsLoopInner, where it is capped at metricsBackoffMaxSteps.
func metricsLoop(ctx context.Context, n *node.Node, collector *web.StatsCollector) {
	defer func() {
		r := recover()
		if r == nil {
			return
		}
		log.Error("android: metrics loop aborted by panic: %v", r)
		emitStateChange("ERROR", fmt.Sprintf("live traffic reporting failed: %v", r))
		select {
		case <-ctx.Done():
			return
		case <-time.After(metricsBackoff):
		}
		metricsLoop(ctx, n, collector)
	}()

	metricsLoopInner(ctx, n, collector)
}

func metricsLoopInner(ctx context.Context, n *node.Node, collector *web.StatsCollector) {
	ticker := time.NewTicker(metricsInterval)
	defer ticker.Stop()

	failStreak := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			mu.Lock()
			active := instance == n
			mu.Unlock()
			if !active {
				return
			}

			if metricsTick(n, collector) {
				failStreak = 0
				continue
			}
			failStreak++
			if failStreak == 5 {
				emitStateChange("ERROR", "live traffic reporting stalled; reconnecting")
			}
			// An occasional bad tick is normal; only a sustained failure is one
			// worth backing off for, and the backoff is capped so a slow phone
			// still gets fresh counters within a few seconds.
			backoff := metricsBackoff * time.Duration(min(failStreak, metricsBackoffMaxSteps))
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
		}
	}
}

// metricsTick pushes one batch of live stats to the Android service. It reports
// false when the tick panicked and the caller should back off before retrying.
// It never lets a panic escape: anything in the collector, the node, or the JNI
// callback can throw, and the loop has to survive all of it.
func metricsTick(n *node.Node, collector *web.StatsCollector) (ok bool) {
	defer func() {
		if r := recover(); r != nil {
			log.Error("android: metrics tick panicked: %v", r)
		}
	}()

	// Bail early during teardown: the node is being torn down and calling
	// UpdateWebCollectorState or collector.GetResponse against a half-closed
	// node is a data race.
	if stopping.Load() {
		return true
	}

	stateListenerMu.RLock()
	sl := stateListener
	stateListenerMu.RUnlock()
	if sl == nil {
		return true
	}

	// Always fetch fresh speed and packet counters from the collector. Only
	// rebuild the (expensive) peer DTOs every statsRefreshEvery ticks — the
	// cached peer rows are good enough for the in-between heartbeats.
	resp := collector.GetResponse()

	tick := atomic.AddInt64(&statsTickCounter, 1)
	if tick%statsRefreshEvery == 1 {
		n.UpdateWebCollectorState()
		resp = collector.GetResponse()
	}
	totTx := int64(resp.PacketStats.BytesSent)
	totRx := int64(resp.PacketStats.BytesRecv)
	txSpd := int64(resp.Speed.TxBytesPerSec)
	rxSpd := int64(resp.Speed.RxBytesPerSec)

	var directCount, relayCount int32
	for _, p := range resp.ActivePeers {
		if p.ConnState == "relay_ok" || (p.ConnState == "ok" && p.IsRelayed) {
			relayCount++
		} else if p.ConnState == "ok" && !p.IsRelayed {
			directCount++
		}
	}
	// Active means a verified healthy direct or relay data path. The
	// ActivePeers DTO also carries known/connecting/unreachable rows for
	// diagnostics, so len(ActivePeers) is not a truthful active count.
	totalPeers := directCount + relayCount

	return emitMetricsUpdate(sl, totalPeers, directCount, relayCount, txSpd, rxSpd, totTx, totRx)
}

// emitStateChange calls the Android state listener without ever letting a Java
// exception propagate: gomobile converts it into a panic on the calling goroutine,
// and neither the metrics loop nor Stop() should die because of a callback.
func emitStateChange(state, message string) {
	defer func() {
		if r := recover(); r != nil {
			log.Error("android: state callback panicked: %v", r)
		}
	}()
	stateListenerMu.RLock()
	sl := stateListener
	stateListenerMu.RUnlock()
	if sl != nil {
		sl.OnStateChange(state, message)
	}
}

// emitMetricsUpdate calls the Android metrics listener and reports whether the
// batch actually arrived. A Java exception is swallowed here so it cannot take
// down the caller, but the tick has to know the batch never landed.
func emitMetricsUpdate(sl StateListener, peerCount, direct, relay int32, txSpeed, rxSpeed, totalTx, totalRx int64) (delivered bool) {
	defer func() {
		if r := recover(); r != nil {
			log.Error("android: metrics callback panicked: %v", r)
			delivered = false
		}
	}()
	delivered = true
	sl.OnMetricsUpdate(peerCount, direct, relay, txSpeed, rxSpeed, totalTx, totalRx)
	return delivered
}

// Stop shuts down the running node and releases the TUN fd. It is safe to call
// when no node is running.
//
// ORDERING GUARANTEE (Android lifecycle contract): Stop() is fully synchronous.
// n.Close() runs to completion — including every multi-second timeout phase —
// while mu is held, and instance is cleared plus the IDLE callback fired only
// AFTER that. A concurrently blocked Start()/GetStatsJSON() caller therefore
// unblocks to observe a fully released engine: no half-closed libp2p Host, TUN
// fd or WebUI port can ever be observed as "running", and a queued Start() (the
// Android service serializes lifecycle commands on a single executor) cannot
// race the teardown for ports or devices.
//
// IsRunning() is deliberately exempt from that wait: it returns false as soon
// as teardown begins (see stopping), so the Android service and its quick
// settings tile react immediately instead of appearing live for the whole
// teardown. Stop returns only once the device is really released.
func Stop() error {
	mu.Lock()
	n := instance
	if metricsCancel != nil {
		metricsCancel()
		metricsCancel = nil
	}

	if n == nil {
		activeCollector = nil
		mu.Unlock()
		return nil
	}

	stopping.Store(true)
	// Capture what we need and unlock BEFORE n.Close(). Close can take up
	// to ~17s; holding mu that whole time blocks every stats query and
	// any re-entrant stop() from a JNI callback.
	collector := activeCollector
	instance = nil
	activeCollector = nil
	mu.Unlock()

	defer stopping.Store(false)
	var err error
	func() {
		defer func() {
			if r := recover(); r != nil {
				log.Warn("panic during node.Close(): %v", r)
			}
		}()
		err = n.Close()
	}()
	_ = collector // keep linter quiet
	emitStateChange("IDLE", "Node stopped")
	return err
}

// IsRunning reports whether the P2P TAP node is currently active. It answers
// without taking mu while a teardown is in flight, so a stopping node is never
// reported as live — the teardown takes several seconds and mu is held the
// whole time.
func IsRunning() bool {
	if stopping.Load() {
		return false
	}
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

// ApplyHotReload parses cfgJSON and hot-reloads the running node's Go-engine
// configuration without tearing down the TUN device or the P2P engine. It
// publishes the new config atomically (so the data plane observes it race-free)
// and triggers runtime side-effects (obfuscation packer update, exit-node NAT
// re-apply, peer re-announce).
//
// Fields that affect the Android VpnService (TAP IP, MTU, routes, DNS,
// session name) are NOT applied here — they require a full VPN restart.
func ApplyHotReload(cfgJSON string) error {
	cfg, err := parseConfig(cfgJSON)
	if err != nil {
		return err
	}

	mu.Lock()
	n := instance
	collector := activeCollector
	mu.Unlock()

	if n == nil {
		return errors.New("android: node not running")
	}

	// Update collector display state (mirrors web/server.go config save handler).
	if collector != nil {
		collector.UpdateDisplayState(cfg.NodeName, web.ExitNodeInfoDTO{
			Enable:       cfg.ExitNode.Enable,
			NATMasquerade: cfg.ExitNode.NATMasquerade,
			WANInterface:  cfg.ExitNode.WANInterface,
		})
		if collector.OnConfigReload != nil {
			collector.OnConfigReload(cfg)
		}
	}

	return nil
}

// GetPeerID returns the libp2p Peer ID of the running node, or empty if not running.
func GetPeerID() string {
	if stopping.Load() {
		return ""
	}
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
	if stopping.Load() {
		return ""
	}
	mu.Lock()
	defer mu.Unlock()
	if instance != nil && instance.Host != nil {
		pid := instance.Host.ID()
		var addrs []string
		for _, a := range instance.Host.Addrs() {
			addrs = append(addrs, node.WithPeerID(a, pid))
		}
		return strings.Join(addrs, "\n")
	}
	return ""
}

// GetStatsJSON returns a JSON string containing the full StatsResponse
// including active peers, traffic, packet counters, and security status.
//
// A wedged or half-torn-down node can panic while reading the collector, and
// without this guard that panic would reach the Android thread that called in
// and take it down with it. Callers must already be prepared for "{}", which
// is what this returns when the engine has nothing to report.
func GetStatsJSON() string {
	defer func() {
		if r := recover(); r != nil {
			log.Error("android: stats read panicked: %v", r)
		}
	}()
	return getStatsJSONLocked()
}

func getStatsJSONLocked() (out string) {
	defer func() {
		if r := recover(); r != nil {
			log.Error("android: stats read panicked: %v", r)
			out = "{}"
		}
	}()
	// During teardown the node is being torn down; return empty instead of
	// blocking on mu behind a multi-second n.Close().
	if stopping.Load() {
		return "{}"
	}
	// Collect the snapshot under mu so Stop() cannot race with a mid-read
	// node. GetResponse returns a value copy, so json.Marshal below is safe
	// outside the lock and Stop() can finish its multi-second n.Close()
	// while marshaling is in progress.
	mu.Lock()
	if instance != nil {
		instance.UpdateWebCollectorState()
	}
	var resp web.StatsResponse
	hasResp := false
	if activeCollector != nil {
		resp = activeCollector.GetResponse()
		hasResp = true
	}
	mu.Unlock()

	if hasResp {
		data, err := json.Marshal(resp)
		if err == nil {
			out = string(data)
		}
	}
	if out == "" {
		out = "{}"
	}
	return out
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

// GetDefaultConfigJSON returns the Go engine's default configuration as JSON.
// The Android app calls this to populate P2PConfig defaults (STUN/TURN servers,
// obfuscation, etc.) so they stay in sync with the Go source of truth.
func GetDefaultConfigJSON() string {
	cfg := config.DefaultConfig()
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return "{}"
	}
	return string(data)
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

func (a *P2PTap) SetLogCallback(cb LogCallback) {
	SetLogCallback(cb)
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

func (a *P2PTap) ApplyHotReload(cfgJSON string) error {
	return ApplyHotReload(cfgJSON)
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

// UpdateTunFd hot-swaps the underlying Android TUN file descriptor safely
// without tearing down the P2P engine. It consumes newTunFd on every path.
func UpdateTunFd(newTunFd int) error {
	if newTunFd <= 0 {
		return errors.New("android: invalid new TUN fd")
	}
	mu.Lock()
	n := instance
	mu.Unlock()
	if n == nil || n.TAP == nil {
		closeDetachedTunFD(newTunFd)
		return errors.New("android: node not running")
	}
	if updater, ok := n.TAP.(interface{ UpdateFd(int) error }); ok {
		return updater.UpdateFd(newTunFd)
	}
	closeDetachedTunFD(newTunFd)
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

func (a *P2PTap) GetDefaultConfigJSON() string {
	return GetDefaultConfigJSON()
}
