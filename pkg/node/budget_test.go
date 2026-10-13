package node

import (
	"sync/atomic"
	"testing"

	"p2ptap/pkg/config"
	"p2ptap/pkg/obfuscate"
)

// TestMSSAndFragFitTheFrameBudget pins the invariant that made the old
// hardcoded "40" wrong: the exit-node MSS clamp and the fragmentation chunk
// size are both payloads of an obfuscate frame, so adding their own headers to
// the shared datagram budget must still leave them inside it. Exceeding the
// budget means the transport fragments a frame the node believes is already
// datagram-sized — the MSS clamp in particular then does not clamp at all.
func TestMSSAndFragFitTheFrameBudget(t *testing.T) {
	// MTUs below ~700 leave no room once the 512-byte floors on both values are
	// applied, so they are not asserted here: a 576-byte tunnel is pathological
	// and the floors exist so such a configuration still yields usable numbers.
	for _, mtu := range []int{0, 700, 900, 1200, 1500} {
		// MTU 0 means "unset"; both consumers fall back to 1500 internally.
		effMTU := mtu
		if effMTU <= 0 {
			effMTU = 1500
		}
		budget := obfuscate.MaxFrameForPathMTU(effMTU)
		if budget <= 0 {
			t.Fatalf("no budget for MTU %d", mtu)
		}

		// Inner IP + inner TCP + MSS is the frame payload, so the frame header
		// must still fit in the budget around it. The AEAD tag is NOT added here:
		// the budget is a pre-seal frame cap and already deducts it.
		mss := computeExitMSS(mtu, "none")
		if inner := mss + 40 + 20 + obfuscate.HeaderLen; inner > budget {
			t.Fatalf("MTU %d: MSS %d needs a %d-byte frame, budget is %d", mtu, mss, inner, budget)
		}

		// A re-obfuscated fragment is frame header + frag header + chunk.
		n := &Node{Config: config.DefaultConfig()}
		if mtu > 0 {
			n.Config.MTU = mtu
		}
		n.SetConfig(n.Config)
		chunk := n.maxFragPayload()
		if frame := chunk + fragHeaderLen + obfuscate.HeaderLen; frame > budget {
			t.Fatalf("MTU %d: frag chunk %d needs a %d-byte frame, budget is %d",
				mtu, chunk, frame, budget)
		}
		if mss > chunk {
			t.Fatalf("MTU %d: MSS %d exceeds the frag chunk %d, so a clamped TCP segment "+
				"would still be fragmented", mtu, mss, chunk)
		}
	}
}

// TestLoadNodeConfig covers the shared slot the WebRTC transport factory reads
// before this Node exists.
func TestLoadNodeConfig(t *testing.T) {
	fallback := config.DefaultConfig()
	slot := new(atomic.Pointer[config.Config])

	if got := loadNodeConfig(slot, fallback); got != fallback {
		t.Fatalf("empty slot fell through to %p, want the fallback %p", got, fallback)
	}

	reloaded := config.DefaultConfig()
	reloaded.NodeName = "reloaded"
	slot.Store(reloaded)
	if got := loadNodeConfig(slot, fallback); got != reloaded {
		t.Fatalf("slot returned %q, want the reloaded snapshot", got.NodeName)
	}
}

// TestSetConfigWithoutSlotAllocatesOne keeps the test convenience alive: a Node
// built with a bare &Node{} must still be hot-reloadable.
func TestSetConfigWithoutSlotAllocatesOne(t *testing.T) {
	n := &Node{}
	cfg := config.DefaultConfig()
	cfg.NodeName = "bare"
	n.SetConfig(cfg)
	if got := n.CurrentConfig(); got != cfg {
		t.Fatalf("CurrentConfig = %q, want the published snapshot", got.NodeName)
	}
	if got := n.config().NodeName; got != "bare" {
		t.Fatalf("config().NodeName = %q, want %q", got, "bare")
	}
}
