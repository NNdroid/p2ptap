//go:build linux && !android
// +build linux,!android

package node

import (
	"context"
	"time"

	"github.com/vishvananda/netlink"
)

// newLinuxNetMonOrNil returns a Linux netlink-backed monitor. It is always
// non-nil on Linux; the !linux stub returns nil so NewNetMon falls back to the
// portable poller.
func newLinuxNetMonOrNil(tapName string) NetMon {
	return &linuxNetMon{tapName: tapName}
}

type linuxNetMon struct {
	tapName string
}

// Watch subscribes to netlink link + address updates, which are delivered
// promptly by the kernel (no polling lag). A 300ms throttle plus the node-level
// debounce collapses reassociation storms into a single reconcile.
func (m *linuxNetMon) Watch(ctx context.Context, onEvent func()) error {
	linkCh := make(chan netlink.LinkUpdate, 16)
	addrCh := make(chan netlink.AddrUpdate, 16)
	done := make(chan struct{})
	defer close(done)

	if err := netlink.LinkSubscribe(linkCh, done); err != nil {
		return err
	}
	if err := netlink.AddrSubscribe(addrCh, done); err != nil {
		return err
	}

	var last time.Time
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-linkCh:
		case <-addrCh:
		}
		now := time.Now()
		if now.Sub(last) < 300*time.Millisecond {
			continue
		}
		last = now
		onEvent()
	}
}

func (m *linuxNetMon) Close() error { return nil }
