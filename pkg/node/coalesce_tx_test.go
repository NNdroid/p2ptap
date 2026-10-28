package node

import (
	"bytes"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"

	"p2ptap/pkg/config"
	"p2ptap/pkg/obfuscate"
)

// coalesceHarness is a minimal Node whose coalescer dispatches into a buffered
// dispatchCh (Router=nil ⇒ direct path), so the test can inspect exactly what
// would go on the wire.
type coalesceHarness struct {
	t     *testing.T
	n     *Node
	c     *txCoalescer
	peer  peer.ID
	dst   []byte
	flush func(peer.ID)
}

func newCoalesceHarness(t *testing.T, rule string) *coalesceHarness {
	t.Helper()
	cfg := &config.ObfuscationConfig{Enable: true, PaddingRules: rule}
	n := &Node{
		Packer:     obfuscate.NewFramePackerFull(cfg),
		Collector:  noopCollector{},
		Gateway:    &GatewayManager{},
		dispatchCh: make(chan dispatchTask, 64),
	}
	n.Packer.SetSourceIdentity("coalesce-test")
	c := newTxCoalescer(n)
	return &coalesceHarness{
		t:    t,
		n:    n,
		c:    c,
		peer: peer.ID("coalesce-target"),
		dst:  bytes.Repeat([]byte{0xaa}, 6),
	}
}

func (h *coalesceHarness) pending() int {
	h.c.mu.Lock()
	defer h.c.mu.Unlock()
	if e := h.c.buf[h.peer]; e != nil {
		return len(e.subFrames)
	}
	return 0
}

func (h *coalesceHarness) pendingBytes() int {
	h.c.mu.Lock()
	defer h.c.mu.Unlock()
	if e := h.c.buf[h.peer]; e != nil {
		return e.totalBytes
	}
	return 0
}

// drain dispatches the next queued task and returns (packedFrame, origLen).
func (h *coalesceHarness) drain() ([]byte, int) {
	h.t.Helper()
	select {
	case task := <-h.n.dispatchCh:
		if task.owned {
			releaseFrameBuf(task.data)
		}
		return task.data, task.origLen
	case <-time.After(2 * time.Second):
		h.t.Fatal("timed out waiting for a dispatched task")
		return nil, 0
	}
}

// TestCoalesceBuffersSmallFrames verifies a short unicast frame below the band
// target is buffered rather than dispatched immediately (so a later frame can
// merge into the same logical frame and avoid padding).
func TestCoalesceBuffersSmallFrames(t *testing.T) {
	h := newCoalesceHarness(t, "0 -> 400-600")
	payload := bytes.Repeat([]byte{0x01}, 100)

	if ok := h.c.maybeBuffer(h.peer, h.dst, payload); !ok {
		t.Fatal("maybeBuffer returned false for a coalescable frame")
	}
	if h.pending() != 1 || h.pendingBytes() != 100 {
		t.Fatalf("buffered = %d frames/%d bytes, want 1/100", h.pending(), h.pendingBytes())
	}
	// Nothing dispatched yet.
	select {
	case task := <-h.n.dispatchCh:
		t.Fatalf("frame dispatched before reaching the band target: %+v", task)
	default:
	}
}

// TestCoalesceFlushesUnpaddedAtBandTarget verifies that once the accumulated
// bytes reach the current band's target_min the buffer flushes WITHOUT padding:
// the batch payload is 4×100+envelope = 414 bytes, which is ≥ 400, so Pack
// leaves it natural and the on-wire frame is exactly HeaderLen+414.
func TestCoalesceFlushesUnpaddedAtBandTarget(t *testing.T) {
	h := newCoalesceHarness(t, "0 -> 400-600")
	payload := bytes.Repeat([]byte{0x01}, 100)

	for i := 0; i < 4; i++ {
		if ok := h.c.maybeBuffer(h.peer, h.dst, payload); !ok {
			t.Fatalf("maybeBuffer(%d) returned false", i)
		}
	}
	// The 4th frame (400 bytes accumulated) must have flushed the batch.
	if h.pending() != 0 {
		t.Fatalf("buffer not flushed: %d frames pending", h.pending())
	}
	frame, _ := h.drain()
	// Batch payload = 6 + 4*(2+100) = 414 >= band target 400 ⇒ unpadded.
	want := obfuscate.HeaderLen + 414
	if len(frame) != want {
		t.Fatalf("flushed frame = %d bytes, want %d (unpadded batch)", len(frame), want)
	}
	_, payloadGot, err := obfuscate.Unpack(frame)
	if err != nil {
		t.Fatalf("Unpack: %v", err)
	}
	subs, ok := obfuscate.SplitBatchPayload(payloadGot)
	if !ok || len(subs) != 4 {
		t.Fatalf("payload is not a 4-frame batch: ok=%v len=%d", ok, len(subs))
	}
	for i := range subs {
		if !bytes.Equal(subs[i], payload) {
			t.Fatalf("sub-frame %d mismatch", i)
		}
	}
}

// TestCoalesceTimerFlushPads verifies that a genuinely short buffer flushed by
// the timer (data insufficient) IS padded to the band target: a single 100-byte
// frame becomes a 400-600 byte frame, and the receiver still recovers the real
// 100-byte payload from the PayloadLen header field.
func TestCoalesceTimerFlushPads(t *testing.T) {
	h := newCoalesceHarness(t, "0 -> 400-600")
	payload := bytes.Repeat([]byte{0x01}, 100)

	if ok := h.c.maybeBuffer(h.peer, h.dst, payload); !ok {
		t.Fatal("maybeBuffer returned false")
	}
	// Force a timer-style flush of the short buffer.
	h.c.flush(h.peer)
	frame, _ := h.drain()
	padded := len(frame) - obfuscate.HeaderLen
	if padded < 400 || padded > 600 {
		t.Fatalf("timer-flushed frame payload = %d bytes, want in [400,600]", padded)
	}
	_, payloadGot, err := obfuscate.Unpack(frame)
	if err != nil {
		t.Fatalf("Unpack: %v", err)
	}
	// Unpack truncates to the real payload length (the 100-byte sub-frame), so
	// the receiver never sees padding as data.
	if !bytes.Equal(payloadGot, payload) {
		t.Fatalf("unpacked payload = %d bytes, want the %d-byte original (padding stripped)", len(payloadGot), len(payload))
	}
}

// TestCoalesceOffBypasses verifies that coalescing off (or padding disabled)
// makes maybeBuffer decline the frame so it goes out through the normal path.
func TestCoalesceOffBypasses(t *testing.T) {
	h := newCoalesceHarness(t, "0 -> 400-600\ncoalesce off")
	payload := bytes.Repeat([]byte{0x01}, 100)
	if ok := h.c.maybeBuffer(h.peer, h.dst, payload); ok {
		t.Fatal("maybeBuffer consumed a frame with coalesce off")
	}

	// Padding disabled entirely: also bypass.
	h2 := newCoalesceHarness(t, "0 -> 400-600")
	h2.n.Packer.UpdateConfig(&config.ObfuscationConfig{Enable: false, PaddingRules: "0 -> 400-600"})
	if ok := h2.c.maybeBuffer(h2.peer, h2.dst, payload); ok {
		t.Fatal("maybeBuffer consumed a frame with padding disabled")
	}
}

// TestCoalesceExitNodeBypasses verifies exit-node egress is never held back.
func TestCoalesceExitNodeBypasses(t *testing.T) {
	h := newCoalesceHarness(t, "0 -> 400-600")
	h.n.Gateway.activeExitPID = h.peer
	payload := bytes.Repeat([]byte{0x01}, 100)
	if ok := h.c.maybeBuffer(h.peer, h.dst, payload); ok {
		t.Fatal("maybeBuffer consumed exit-node egress")
	}
}

// TestCoalesceFlushAllDrainsOnShutdown verifies run() drains the buffer on
// context cancellation so no frame is lost at shutdown.
func TestCoalesceFlushAllDrainsOnShutdown(t *testing.T) {
	h := newCoalesceHarness(t, "0 -> 400-600")
	payload := bytes.Repeat([]byte{0x01}, 100)
	if ok := h.c.maybeBuffer(h.peer, h.dst, payload); !ok {
		t.Fatal("maybeBuffer returned false")
	}
	// Simulate the flusher goroutine's shutdown drain.
	h.c.flushAll()
	frame, _ := h.drain()
	if _, _, err := obfuscate.Unpack(frame); err != nil {
		t.Fatalf("Unpack of drained frame: %v", err)
	}
}
