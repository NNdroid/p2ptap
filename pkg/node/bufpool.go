package node

import (
	"sync"
)

// frameBufPool reuses standard-sized (MTU 1500) TAP frame buffers.
var frameBufPool = sync.Pool{
	New: func() any {
		return make([]byte, 0, 2048)
	},
}

// jumboFrameBufPool reuses Jumbo (MTU 9000) frame buffers.
var jumboFrameBufPool = sync.Pool{
	New: func() any {
		return make([]byte, 0, 9216)
	},
}

// cipherBufPool reuses working slices for SealTo/OpenTo zero-allocation encryption/decryption.
var cipherBufPool = sync.Pool{
	New: func() any {
		return make([]byte, 0, 2048+32)
	},
}

// sealedBufPool reuses full-sized wire frame buffers up to MaxSealedFrameSize.
var sealedBufPool = sync.Pool{
	New: func() any {
		return make([]byte, 0, 65552)
	},
}

// acquireFrameBuf returns a buffer with len == size, reusing a pooled one when
// its capacity fits. Ownership transfers to the dispatch worker, which releases
// it with releaseFrameBuf once the frame has been transmitted.
func acquireFrameBuf(size int) []byte {
	if size <= 2048 {
		if b, ok := frameBufPool.Get().([]byte); ok && cap(b) >= size {
			return b[:size]
		}
	} else if size <= 9216 {
		if b, ok := jumboFrameBufPool.Get().([]byte); ok && cap(b) >= size {
			return b[:size]
		}
	}
	return make([]byte, size)
}

// releaseFrameBuf returns a frame buffer to the appropriate pool.
func releaseFrameBuf(b []byte) {
	if cap(b) >= 9216 {
		jumboFrameBufPool.Put(b[:0])
	} else if cap(b) >= 2048 {
		frameBufPool.Put(b[:0])
	}
}

// AcquireCipherBuf retrieves a reusable buffer for zero-alloc AEAD SealTo/OpenTo.
func AcquireCipherBuf(size int) []byte {
	if size <= 2080 {
		if b, ok := cipherBufPool.Get().([]byte); ok && cap(b) >= size {
			return b[:size]
		}
	}
	return make([]byte, size)
}

// ReleaseCipherBuf returns a cipher working buffer to the pool.
func ReleaseCipherBuf(b []byte) {
	if cap(b) >= 2080 {
		cipherBufPool.Put(b[:0])
	}
}

// AcquireSealedBuf retrieves a wire frame buffer for full-frame packing.
func AcquireSealedBuf(size int) []byte {
	if size <= 65552 {
		if b, ok := sealedBufPool.Get().([]byte); ok && cap(b) >= size {
			return b[:size]
		}
	}
	return make([]byte, size)
}

// ReleaseSealedBuf returns a sealed wire buffer to the pool.
func ReleaseSealedBuf(b []byte) {
	if cap(b) >= 65552 {
		sealedBufPool.Put(b[:0])
	}
}
