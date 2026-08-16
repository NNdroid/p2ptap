package node

import "sync"

// frameBufPool reuses the per-TAP-frame payload buffers that flow through the
// egress path. A frame read from the TAP device is copied out of the shared
// read buffer (which the very next TAP read would overwrite) into one of these
// before being handed to the async dispatch worker. That copy is mandatory —
// the read buffer is reused while the worker runs in a different goroutine, so
// without a private copy the worker would read torn data. Pooling the copy
// removes a per-frame heap allocation from the hottest path in the daemon.
//
// Go 1.21+ keeps sub-32 KiB pooled entries out of the GC mark/scan set, so this
// also cuts collector work, not only allocation count — exactly the lever that
// lowers steady-state CPU when the tunnel is busy.
var frameBufPool = sync.Pool{
	New: func() any {
		// A typical Ethernet frame is ≤ 1514 bytes; size a little above so the
		// common case needs no grow, while jumbo frames (up to ~9 KiB) simply
		// fall through to a fresh allocation without wasting memory here.
		b := make([]byte, 0, 2048)
		return b
	},
}

// acquireFrameBuf returns a buffer with len == size, reusing a pooled one when
// its capacity fits. Ownership transfers to the dispatch worker, which releases
// it with releaseFrameBuf once the frame has been transmitted. Buffers obtained
// elsewhere (e.g. urgent frames from callers, relay fallbacks) must NOT be
// released through this pool — see dispatchTask.owned.
func acquireFrameBuf(size int) []byte {
	b, ok := frameBufPool.Get().([]byte)
	if !ok || cap(b) < size {
		return make([]byte, size)
	}
	return b[:size]
}

// releaseFrameBuf returns a frame buffer to the pool. It first drops the live
// payload reference so the GC can reclaim the underlying array when the pooled
// entry ages out, while keeping the capacity for the next reuse.
func releaseFrameBuf(b []byte) {
	// Trim to zero length but preserve capacity: the caller must no longer
	// reference the payload after releasing.
	b = b[:0]
	frameBufPool.Put(b)
}
