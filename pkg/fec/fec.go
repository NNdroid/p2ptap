// Package fec implements systematic Reed-Solomon erasure coding over GF(2^8)
// for the small shard counts the tunnel fragmentation layer needs.
//
// The code is systematic: the first k shards are the data itself, so a receiver
// that loses nothing never pays for decoding, and the parity shards are pure
// overhead that only gets read when something is missing.
//
// The generator matrix is the systematic Reed-Solomon construction: start from
// the full n×k Vandermonde matrix F (row j is [1, b_j, b_j^2, ...] with distinct
// non-zero bases b_j), then right-multiply by the inverse of its top k×k block:
//
//	G = F · F_top^-1
//
// The top k rows of G are therefore the identity (systematic: shard i IS data
// shard i), and G is MDS because F is MDS and right-multiplication by an
// invertible matrix preserves that property. So ANY k of the k+r rows are
// linearly independent and any k surviving shards reconstruct all the data —
// which is exactly what the tunnel needs when the failed paths are not known in
// advance. (Simply stacking an identity on a raw Vandermonde block, the obvious
// shortcut, is NOT MDS once r > 1: rows 2,4,5,6,7,8,9,10 of an 8+4 block are
// singular, and the decoder would report unrecoverable data that was in fact
// recoverable.)
package fec

import (
	"errors"
	"sync"
)

var (
	// ErrTooManyShards is returned when k+r exceeds the field's 255 usable
	// non-zero elements, which is the hard ceiling of GF(2^8) coding.
	ErrTooManyShards = errors.New("fec: too many shards for GF(256)")
	// ErrInvalidLayout is returned for mismatched shard lengths or counts.
	ErrInvalidLayout = errors.New("fec: invalid layout")
	// ErrNotEnoughShards is returned by Reconstruct when fewer than k shards
	// survived; the data is then mathematically unrecoverable.
	ErrNotEnoughShards = errors.New("fec: not enough shards to reconstruct")
	// ErrSingular is returned if the surviving rows cannot be inverted. It
	// cannot happen with the MDS construction above and would indicate a
	// corrupt matrix, so it is surfaced instead of silently producing garbage.
	ErrSingular = errors.New("fec: singular matrix")
)

// GF(2^8) arithmetic with the AES/Rijndael primitive polynomial 0x11d.
var (
	gfExp [512]byte // anti-log table, doubled so +log never needs a modulo
	gfLog [256]byte // log table (log[0] is unused; callers must special-case 0)
)

func init() {
	x := 1
	for i := 0; i < 255; i++ {
		gfExp[i] = byte(x)
		gfLog[byte(x)] = byte(i)
		x <<= 1
		if x&0x100 != 0 {
			x ^= 0x11d
		}
	}
	// Extend so a plain index add (max 254+254) stays in bounds.
	for i := 255; i < len(gfExp); i++ {
		gfExp[i] = gfExp[i-255]
	}
}

// gfMul multiplies two field elements.
func gfMul(a, b byte) byte {
	if a == 0 || b == 0 {
		return 0
	}
	return gfExp[int(gfLog[a])+int(gfLog[b])]
}

// gfInv returns the multiplicative inverse of a non-zero element.
func gfInv(a byte) byte {
	return gfExp[255-int(gfLog[a])]
}

// gfPow returns b^e.
func gfPow(b byte, e int) byte {
	if e == 0 {
		return 1
	}
	if b == 0 {
		return 0
	}
	return gfExp[(int(gfLog[b])*e)%255]
}

// MaxShards is the largest total shard count GF(2^8) supports.
const MaxShards = 255

// generator codecs are tiny (k ≤ 8 for the tunnel's stripe size) and depend only
// on (k, r), so they are built once and shared. The matrices are read-only after
// publication.
var (
	codecMu    sync.RWMutex
	codecCache = map[codecKey][][]byte{}
)

type codecKey struct{ k, r int }

// generatorMatrix returns G = F · F_top^-1 (see the package comment).
func generatorMatrix(k, r int) ([][]byte, error) {
	if k <= 0 || r < 0 || k+r > MaxShards {
		return nil, ErrTooManyShards
	}
	key := codecKey{k: k, r: r}
	codecMu.RLock()
	g, ok := codecCache[key]
	codecMu.RUnlock()
	if ok {
		return g, nil
	}

	n := k + r
	// Full Vandermonde: row j uses the base j+1, all distinct and non-zero.
	f := make([][]byte, n)
	for j := 0; j < n; j++ {
		row := make([]byte, k)
		for i := 0; i < k; i++ {
			row[i] = gfPow(byte(j+1), i)
		}
		f[j] = row
	}
	top := make([][]byte, k)
	for i := 0; i < k; i++ {
		top[i] = append([]byte(nil), f[i]...)
	}
	inv, err := invert(top)
	if err != nil {
		return nil, err
	}
	out := make([][]byte, n)
	for j := 0; j < n; j++ {
		row := make([]byte, k)
		for i := 0; i < k; i++ {
			var s byte
			for t := 0; t < k; t++ {
				s ^= gfMul(f[j][t], inv[t][i])
			}
			row[i] = s
		}
		out[j] = row
	}

	codecMu.Lock()
	if cached, exists := codecCache[key]; exists {
		out = cached
	} else {
		codecCache[key] = out
	}
	codecMu.Unlock()
	return out, nil
}

// Encode returns r parity shards for data. Every data shard must have the same
// length; the parity shards have that same length.
func Encode(data [][]byte, r int) ([][]byte, error) {
	k := len(data)
	g, err := generatorMatrix(k, r)
	if err != nil {
		return nil, err
	}
	size := len(data[0])
	for _, d := range data {
		if len(d) != size {
			return nil, ErrInvalidLayout
		}
	}
	out := make([][]byte, r)
	for j := 0; j < r; j++ {
		row := g[k+j]
		shard := make([]byte, size)
		for i := 0; i < k; i++ {
			c := row[i]
			if c == 0 {
				continue
			}
			src := data[i]
			for p := 0; p < size; p++ {
				shard[p] ^= gfMul(c, src[p])
			}
		}
		out[j] = shard
	}
	return out, nil
}

// Reconstruct fills in every nil entry of parts, which must hold exactly k+r
// shards laid out as k data shards followed by r parity shards. At least k
// entries must be non-nil. All shards must be the same length.
//
// Missing data shards are recovered from any k survivors; missing parity shards
// are then re-encoded from the complete data set, so on return parts is fully
// populated. Present shards are never modified; recovered shards are freshly
// allocated so the caller keeps ownership of whatever it passed in.
func Reconstruct(parts [][]byte, k, r int) error {
	if k <= 0 || r < 0 || k+r > MaxShards || len(parts) != k+r {
		return ErrInvalidLayout
	}
	g, err := generatorMatrix(k, r)
	if err != nil {
		return err
	}
	available := make([]int, 0, k+r)
	size := 0
	for i, p := range parts {
		if p == nil {
			continue
		}
		if size == 0 {
			size = len(p)
		} else if len(p) != size {
			return ErrInvalidLayout
		}
		available = append(available, i)
	}
	if len(available) < k {
		return ErrNotEnoughShards
	}
	if len(available) == k+r {
		return nil // nothing missing
	}
	// Any k of the available rows form an invertible matrix; keep a stable
	// prefix so the result is deterministic.
	rows := available[:k]

	// Every case handled below needs the data shards complete. When they all
	// arrived, only parity is missing and the inversion is skipped entirely.
	needDecode := false
	for t := 0; t < k; t++ {
		if parts[t] == nil {
			needDecode = true
			break
		}
	}
	if needDecode {
		m := make([][]byte, k)
		for i, idx := range rows {
			m[i] = append([]byte(nil), g[idx]...)
		}
		inv, err := invert(m)
		if err != nil {
			return err
		}
		for t := 0; t < k; t++ {
			if parts[t] != nil {
				continue
			}
			out := make([]byte, size)
			for ri, idx := range rows {
				c := inv[t][ri]
				if c == 0 {
					continue
				}
				src := parts[idx]
				for p := 0; p < len(src); p++ {
					out[p] ^= gfMul(c, src[p])
				}
			}
			parts[t] = out
		}
	}
	// Re-encode any parity shards that were lost, now that the data is complete.
	for t := k; t < k+r; t++ {
		if parts[t] != nil {
			continue
		}
		row := g[t]
		out := make([]byte, size)
		for i := 0; i < k; i++ {
			c := row[i]
			if c == 0 {
				continue
			}
			src := parts[i]
			for p := 0; p < len(src); p++ {
				out[p] ^= gfMul(c, src[p])
			}
		}
		parts[t] = out
	}
	return nil
}

// invert returns the inverse of the square matrix a (Gauss-Jordan elimination
// over GF(2^8)). a is consumed.
func invert(a [][]byte) ([][]byte, error) {
	n := len(a)
	inv := make([][]byte, n)
	for i := 0; i < n; i++ {
		if len(a[i]) != n {
			return nil, ErrInvalidLayout
		}
		inv[i] = make([]byte, n)
		inv[i][i] = 1
	}
	for col := 0; col < n; col++ {
		pivot := -1
		for r := col; r < n; r++ {
			if a[r][col] != 0 {
				pivot = r
				break
			}
		}
		if pivot < 0 {
			return nil, ErrSingular
		}
		a[col], a[pivot] = a[pivot], a[col]
		inv[col], inv[pivot] = inv[pivot], inv[col]

		f := gfInv(a[col][col])
		if f != 1 {
			for c := 0; c < n; c++ {
				a[col][c] = gfMul(a[col][c], f)
				inv[col][c] = gfMul(inv[col][c], f)
			}
		}
		for r := 0; r < n; r++ {
			if r == col {
				continue
			}
			coef := a[r][col]
			if coef == 0 {
				continue
			}
			for c := 0; c < n; c++ {
				a[r][c] ^= gfMul(coef, a[col][c])
				inv[r][c] ^= gfMul(coef, inv[col][c])
			}
		}
	}
	return inv, nil
}
