package obfuscate

import (
	"testing"

	"p2ptap/pkg/config"
)

// TestMaxFrameForPathMTU pins the single shared datagram budget. Every layer
// that must fit one transport datagram (padding, fragmentation, MSS clamping)
// derives its number from this, so the values here are the contract.
func TestMaxFrameForPathMTU(t *testing.T) {
	budget := MaxFrameForPathMTU(1500)
	want := PathMTU - OuterEncapsulation - AEADTagSize
	if budget != want {
		t.Fatalf("MaxFrameForPathMTU(1500) = %d, want %d (PathMTU %d - outer %d - AEAD %d)",
			budget, want, PathMTU, OuterEncapsulation, AEADTagSize)
	}
	// A larger link MTU must not enlarge the budget: the conservative path MTU
	// is the ceiling, not the link MTU.
	if got := MaxFrameForPathMTU(9000); got != budget {
		t.Fatalf("MaxFrameForPathMTU(9000) = %d, want the %d cap", got, budget)
	}
	// A small tunnel MTU is honoured down to the floor.
	if got := MaxFrameForPathMTU(700); got != 700-OuterEncapsulation-AEADTagSize {
		t.Fatalf("MaxFrameForPathMTU(700) = %d, want %d", got, 700-OuterEncapsulation-AEADTagSize)
	}
	if got := MaxFrameForPathMTU(300); got != MinFrameSize {
		t.Fatalf("MaxFrameForPathMTU(300) = %d, want the %d floor", got, MinFrameSize)
	}
	// Unknown MTU means "no budget", never a bogus constraint.
	if got := MaxFrameForPathMTU(0); got != 0 {
		t.Fatalf("MaxFrameForPathMTU(0) = %d, want 0", got)
	}
	if got := MaxFrameForPathMTU(-5); got != 0 {
		t.Fatalf("MaxFrameForPathMTU(-5) = %d, want 0", got)
	}

	// End to end: the budget must actually fit the path MTU once the AEAD tag and
	// the outer encapsulation are added back.
	if wire := budget + AEADTagSize + OuterEncapsulation; wire > PathMTU {
		t.Fatalf("budget %d does not fit PathMTU %d: %d + tag %d + outer %d = %d",
			budget, PathMTU, budget, AEADTagSize, OuterEncapsulation, wire)
	}

	// MaxPayloadForPathMTU is the frame cap minus the frame header — the AEAD tag
	// must not be deducted a second time.
	if got := MaxPayloadForPathMTU(1500); got != budget-HeaderLen {
		t.Fatalf("MaxPayloadForPathMTU(1500) = %d, want %d", got, budget-HeaderLen)
	}
	if got := MaxPayloadForPathMTU(0); got != 0 {
		t.Fatalf("MaxPayloadForPathMTU(0) = %d, want 0", got)
	}
}

func newBudgetPacker(t *testing.T, cfg *config.ObfuscationConfig, mtu int) *FramePacker {
	t.Helper()
	fp := NewFramePackerFull(cfg)
	fp.SetFrameBudget(mtu)
	return fp
}

// TestPackHonoursFrameBudget is the regression test for padding inflating a
// frame past what one transport datagram can carry: the default fixed_size of
// 1500 sits well above the ~1103-byte budget, so every small frame used to be
// padded all the way to 1500.
func TestPackHonoursFrameBudget(t *testing.T) {
	budget := MaxFrameForPathMTU(1500)
	if budget <= 0 {
		t.Fatal("budget unexpectedly empty")
	}

	payload := make([]byte, 60)
	cases := []struct {
		name string
		cfg  *config.ObfuscationConfig
	}{
		{"fixed over budget", &config.ObfuscationConfig{Enable: true, Mode: "fixed", FixedSize: 1500}},
		{"fixed at budget", &config.ObfuscationConfig{Enable: true, Mode: "fixed", FixedSize: budget}},
		{"dynamic over budget", &config.ObfuscationConfig{Enable: true, Mode: "dynamic", MinSize: 512, MaxSize: 1500}},
		{"random over budget", &config.ObfuscationConfig{Enable: true, Mode: "random", MinSize: 512, FixedSize: 1500}},
		{"block", &config.ObfuscationConfig{Enable: true, Mode: "block", BlockSize: 256}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fp := newBudgetPacker(t, tc.cfg, 1500)
			out := make([]byte, MaxSealedFrameSize)
			n, err := fp.Pack(1, payload, out)
			if err != nil {
				t.Fatalf("Pack(%d bytes) error: %v", len(payload), err)
			}
			if n > budget {
				t.Fatalf("packed frame is %d bytes, exceeds the %d-byte datagram budget", n, budget)
			}
			if want := HeaderLen + len(payload); n < want {
				t.Fatalf("packed frame is %d bytes, below the %d-byte bare overhead", n, want)
			}
			// MaxPackedLen is the buffer-sizing contract for Pack: it must never
			// be below what Pack actually writes.
			if bound := fp.MaxPackedLen(len(payload)); bound < n {
				t.Fatalf("MaxPackedLen = %d but Pack wrote %d", bound, n)
			}
		})
	}
}

// TestPackNoBudgetIsUnchanged confirms the cap is opt-in: a packer that was
// never told its MTU keeps the historic behaviour.
func TestPackNoBudgetIsUnchanged(t *testing.T) {
	fp := NewFramePackerFull(&config.ObfuscationConfig{Enable: true, Mode: "fixed", FixedSize: 1500})
	payload := make([]byte, 60)
	out := make([]byte, MaxSealedFrameSize)
	n, err := fp.Pack(1, payload, out)
	if err != nil {
		t.Fatalf("Pack error: %v", err)
	}
	if n != 1500 {
		t.Fatalf("packed frame = %d, want the uncapped 1500", n)
	}
}

// TestLargePayloadExceedingBudgetIsLeftAlone ensures the cap never shrinks a
// payload that is already bigger than the budget: shrinking would only create
// more fragments, not fewer.
func TestLargePayloadExceedingBudgetIsLeftAlone(t *testing.T) {
	fp := newBudgetPacker(t,
		&config.ObfuscationConfig{Enable: true, Mode: "fixed", FixedSize: 1500}, 1500)
	payload := make([]byte, MaxFrameSize-HeaderLen-1)
	out := make([]byte, MaxSealedFrameSize)
	n, err := fp.Pack(1, payload, out)
	if err != nil {
		t.Fatalf("Pack error: %v", err)
	}
	if want := HeaderLen + len(payload); n != want {
		t.Fatalf("packed frame = %d, want the bare overhead %d (a payload above the budget must not be shrunk)",
			n, want)
	}
}

// TestSetFrameBudgetAppliesToDefaults pins the "default frame size IS the
// budget" rule: with no explicit sizes, the packer pads to the budget instead
// of the historic 1500. Explicit sizes are never rewritten.
func TestSetFrameBudgetAppliesToDefaults(t *testing.T) {
	budget := MaxFrameForPathMTU(1500)

	fp := newBudgetPacker(t, &config.ObfuscationConfig{Enable: true, Mode: "fixed"}, 1500)
	if fp.FixedSize != budget {
		t.Fatalf("default FixedSize = %d, want the %d-byte budget", fp.FixedSize, budget)
	}
	if fp.MaxSize != budget {
		t.Fatalf("default MaxSize = %d, want the %d-byte budget", fp.MaxSize, budget)
	}
	if fp.MinSize != MinFrameSize {
		t.Fatalf("default MinSize = %d, want %d", fp.MinSize, MinFrameSize)
	}

	explicit := newBudgetPacker(t,
		&config.ObfuscationConfig{Enable: true, Mode: "fixed", FixedSize: 1500, MaxSize: 1500}, 1500)
	if explicit.FixedSize != 1500 || explicit.MaxSize != 1500 {
		t.Fatalf("explicit sizes were rewritten: FixedSize=%d MaxSize=%d", explicit.FixedSize, explicit.MaxSize)
	}

	// An unknown MTU leaves the historic defaults in place.
	none := newBudgetPacker(t, &config.ObfuscationConfig{Enable: true, Mode: "fixed"}, 0)
	if none.FixedSize != 1500 {
		t.Fatalf("FixedSize with unknown MTU = %d, want 1500", none.FixedSize)
	}
}

// TestSetFrameBudgetHotReload checks the budget can move at runtime, which is
// what an MTU-only hot reload relies on.
func TestSetFrameBudgetHotReload(t *testing.T) {
	fp := newBudgetPacker(t,
		&config.ObfuscationConfig{Enable: true, Mode: "dynamic", MinSize: 512, MaxSize: 1500}, 1500)
	big := MaxFrameForPathMTU(1500)
	payload := make([]byte, 60)
	out := make([]byte, MaxSealedFrameSize)

	for i := 0; i < 200; i++ {
		n, err := fp.Pack(uint64(i), payload, out)
		if err != nil {
			t.Fatalf("Pack error: %v", err)
		}
		if n > big {
			t.Fatalf("packed frame = %d, exceeds the original %d-byte budget", n, big)
		}
	}

	fp.SetFrameBudget(700)
	small := MaxFrameForPathMTU(700)
	if small >= big {
		t.Fatalf("shrinking the MTU did not shrink the budget: %d >= %d", small, big)
	}
	for i := 0; i < 200; i++ {
		n, err := fp.Pack(uint64(1000+i), payload, out)
		if err != nil {
			t.Fatalf("Pack error: %v", err)
		}
		if n > small {
			t.Fatalf("packed frame = %d, exceeds the reloaded %d-byte budget", n, small)
		}
	}
}
