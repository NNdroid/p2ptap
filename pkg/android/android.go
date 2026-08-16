//go:build android

// Package android exposes the p2ptap P2P node to Android apps as an AAR produced
// by `gomobile bind`. It is the only package bound into the AAR; gomobile
// compiles the entire Go dependency tree (libp2p, crypto, the node core, etc.)
// into the AAR's native libraries.
//
// Lifecycle (from the Kotlin/Java side):
//
//	val fd = vpnInterface.fileDescriptor.detachFd()   // from VpnService.Builder
//	Android.SetProtector(protector)                  // implements VpnService.protect(fd)
//	Android.Start(configJson, fd)                   // runs the node; non-blocking
//	// ... VPN runs ...
//	Android.Stop()                                  // tear down
//
// Android only supports a TUN (layer-3) device, so the node runs over a
// tun<->tap conversion layer (see p2ptap/pkg/tap + p2ptap/pkg/tuntap). The Exit
// Node server is intentionally NOT supported on Android (no host routing/NAT
// machinery on a TUN-only client) and is rejected at Start.
package android

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"p2ptap/pkg/config"
	"p2ptap/pkg/logger"
	"p2ptap/pkg/node"
	"p2ptap/pkg/tap"
	"p2ptap/pkg/version"
)

// Protector is implemented by the Android app to protect a socket file
// descriptor from being routed back through the VPN tunnel. gomobile generates
// a matching Java interface that the app implements and passes to SetProtector.
type Protector interface {
	// Protect marks the given socket fd as excluded from the VPN routing so
	// that traffic on it leaves via the underlying cellular/Wi-Fi interface.
	Protect(fd int32) bool
}

var (
	mu       sync.Mutex
	instance *node.Node
)

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
		return errors.New("android: node already running; call Stop() first")
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

	n, err := node.NewNodeWithTAP(cfg, dev, nil)
	if err != nil {
		_ = dev.Close()
		return fmt.Errorf("android: create node: %w", err)
	}

	instance = n
	n.Start()
	return nil
}

// Stop shuts down the running node and releases the TUN fd. It is safe to call
// when no node is running.
func Stop() error {
	mu.Lock()
	defer mu.Unlock()

	if instance == nil {
		return nil
	}
	err := instance.Close()
	instance = nil
	return err
}

// SetLogLevel adjusts the global log verbosity. level is one of
// "debug"|"info"|"warn"|"error" (case-insensitive); unknown values default to
// "info".
func SetLogLevel(level string) error {
	logger.SetGlobalLevel(logger.ParseLevel(level))
	return nil
}

// Version returns the build version string (injected at build time).
func Version() string {
	if version.Version != "" {
		return version.Version
	}
	return "dev"
}
