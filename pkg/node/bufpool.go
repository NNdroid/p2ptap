package node

import (
	"sync"
)

// frameBufPool reuses standard-sized (MTU 1500) TAP frame buffers.
var frameBufPool = sync.Pool{
	New: func() any {
		return new([2048]byte)
	},
}

// jumboFrameBufPool reuses Jumbo (MTU 9000) frame buffers.
var jumboFrameBufPool = sync.Pool{
	New: func() any {
		return new([9216]byte)
	},
}

// cipherBufPool reuses working slices for SealTo/OpenTo zero-allocation encryption/decryption.
var cipherBufPool = sync.Pool{
	New: func() any {
		return new([2080]byte)
	},
}

// sealedBufPool reuses full-sized wire frame buffers up to MaxSealedFrameSize.
var sealedBufPool = sync.Pool{
	New: func() any {
		return new([65552]byte)
	},
}

// acquireFrameBuf returns a buffer with len == size, reusing a pooled one when
// its capacity fits. Ownership transfers to the dispatch worker, which releases
// it with releaseFrameBuf once the frame has been transmitted.
func acquireFrameBuf(size int) []byte {
	if size <= 2048 {
		return frameBufPool.Get().(*[2048]byte)[:size]
	} else if size <= 9216 {
		return jumboFrameBufPool.Get().(*[9216]byte)[:size]
	}
	return make([]byte, size)
}

// Store array pointers: putting a slice into an interface allocates a boxed
// slice header on every release. Exact capacities also exclude oversized
// foreign buffers from the bounded size classes. Ownership must have ended.
func releaseFrameBuf(b []byte) {
	if cap(b) == 9216 {
		jumboFrameBufPool.Put((*[9216]byte)(b[:9216]))
	} else if cap(b) == 2048 {
		frameBufPool.Put((*[2048]byte)(b[:2048]))
	}
}

// AcquireCipherBuf retrieves a reusable buffer for zero-alloc AEAD SealTo/OpenTo.
func AcquireCipherBuf(size int) []byte {
	if size <= 2080 {
		return cipherBufPool.Get().(*[2080]byte)[:size]
	}
	return make([]byte, size)
}

// ReleaseCipherBuf returns a cipher working buffer to the pool.
func ReleaseCipherBuf(b []byte) {
	if cap(b) == 2080 {
		cipherBufPool.Put((*[2080]byte)(b[:2080]))
	}
}

// AcquireSealedBuf retrieves a wire frame buffer for full-frame packing.
func AcquireSealedBuf(size int) []byte {
	if size <= 65552 {
		return sealedBufPool.Get().(*[65552]byte)[:size]
	}
	return make([]byte, size)
}

// ReleaseSealedBuf returns a sealed wire buffer to the pool.
func ReleaseSealedBuf(b []byte) {
	if cap(b) == 65552 {
		sealedBufPool.Put((*[65552]byte)(b[:65552]))
	}
}
