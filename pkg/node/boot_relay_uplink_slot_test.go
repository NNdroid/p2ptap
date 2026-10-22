package node

import (
	"testing"

	"github.com/libp2p/go-libp2p/core/test"
)

// TestBootRelayUplinkSlotLifecycle pins the bootRelayStarted guard that keeps
// exactly one uplink loop per boot. A second spawn is refused while the first
// holds the slot, a stale generation cannot retire a newcomer's slot, and
// retiring the slot lets a later reconnect start a fresh loop. That last part
// is what openBootRelayUplink's sustained-absence abort depends on: without a
// way to hand the slot back, a boot that leaves the mesh permanently would be
// stuck with a dead entry and never regain relay-over-backbone.
func TestBootRelayUplinkSlotLifecycle(t *testing.T) {
	boot := test.RandPeerIDFatal(t)
	n := newTopoTestNode(t, boot, test.RandPeerIDFatal(t))

	slot := func() (uint64, bool) {
		n.bootRelayMu.Lock()
		defer n.bootRelayMu.Unlock()
		g, ok := n.bootRelayStarted[boot]
		return g, ok
	}

	if !n.maybeSpawnBootRelayUplink(boot) {
		t.Fatalf("first spawn must start the uplink loop")
	}
	gen, ok := slot()
	if !ok {
		t.Fatalf("spawn did not record a slot for the boot")
	}
	if n.maybeSpawnBootRelayUplink(boot) {
		t.Fatalf("second spawn for the same boot must be refused while the slot is held")
	}

	// A loop that has since been superseded must not clear the newcomer's slot:
	// the abort path of a stale goroutine racing a fresh reconnect is the case
	// the generation check exists for.
	n.forgetBootRelayStarted(boot, gen+1)
	if _, ok := slot(); !ok {
		t.Fatalf("forget with a stale generation removed the current slot")
	}

	n.forgetBootRelayStarted(boot, gen)
	if _, ok := slot(); ok {
		t.Fatalf("forget with the owning generation did not retire the slot")
	}
	if !n.maybeSpawnBootRelayUplink(boot) {
		t.Fatalf("a freed slot must let a later reconnect start a fresh uplink loop")
	}
}
