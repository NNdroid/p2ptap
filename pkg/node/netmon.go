package node

import (
	"context"
	"sort"
	"time"
)

// NetMon watches the OS for changes to the set of eligible physical network
// interfaces (link up/down, address add/remove) and invokes onEvent when that
// set changes, so the node can re-bind its listeners to the current NICs.
type NetMon interface {
	// Watch begins monitoring. onEvent is invoked (on NetMon's own goroutine)
	// whenever the eligible NIC set or its addresses change. Watch blocks until
	// ctx is cancelled, then returns.
	Watch(ctx context.Context, onEvent func()) error
	// Close releases monitor resources. The bundled implementations are
	// ctx-driven, so Close is a no-op beyond the ctx cancellation done by the
	// caller.
	Close() error
}

// NewNetMon returns the platform-appropriate NetMon. tapName is excluded from
// change detection so TAP device churn does not trigger a reconcile.
func NewNetMon(tapName string) NetMon {
	if m := newLinuxNetMonOrNil(tapName); m != nil {
		return m
	}
	if m := newWindowsNetMonOrNil(tapName); m != nil {
		return m
	}
	return newPollNetMon(tapName)
}

// nicSignature returns a sorted, stable signature of the currently eligible
// physical NIC IPs. A change means a NIC came up/down or an address was
// added/removed — exactly the events we want to reconcile on.
func nicSignature() []string {
	ips, err := physicalNICIPs()
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	sort.Strings(out)
	return out
}

func signaturesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// pollNetMon is the portable fallback used on every non-Linux platform. It
// polls the eligible NIC set on an interval and fires onEvent when the
// signature changes. It reuses physicalNICIPs(), so TAP/loopback/overlay
// interfaces are naturally excluded.
type pollNetMon struct {
	tapName  string
	interval time.Duration
}

func newPollNetMon(tapName string) *pollNetMon {
	return &pollNetMon{tapName: tapName, interval: 2 * time.Second}
}

func (m *pollNetMon) Watch(ctx context.Context, onEvent func()) error {
	last := nicSignature()
	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
		cur := nicSignature()
		if !signaturesEqual(last, cur) {
			last = cur
			onEvent()
		}
	}
}

func (m *pollNetMon) Close() error { return nil }
