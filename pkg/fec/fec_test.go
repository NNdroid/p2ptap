package fec

import (
	"bytes"
	"fmt"
	"math/rand/v2"
	"testing"
)

// buildShards splits payload into k equal-length data shards, zero-padding the
// last one, exactly like the fragmentation layer does.
func buildShards(payload []byte, k int) [][]byte {
	size := (len(payload) + k - 1) / k
	out := make([][]byte, k)
	for i := 0; i < k; i++ {
		s := make([]byte, size)
		start := i * size
		if start < len(payload) {
			copy(s, payload[start:])
		}
		out[i] = s
	}
	return out
}

func randPayload(n int) []byte {
	p := make([]byte, n)
	for i := range p {
		p[i] = byte(rand.Uint32())
	}
	return p
}

// TestEncodeReconstructAllLossPatterns exhaustively drops every combination of
// up to r shards and requires the original payload back byte for byte. This is
// the core MDS guarantee: it does not matter WHICH paths failed.
func TestEncodeReconstructAllLossPatterns(t *testing.T) {
	for _, tc := range []struct {
		name string
		k, r int
		size int
	}{
		{"k1_r1", 1, 1, 64},
		{"k2_r1", 2, 1, 100},
		{"k3_r1", 3, 1, 255},
		{"k4_r1", 4, 1, 1000},
		{"k4_r2", 4, 2, 300},
		{"k8_r2", 8, 2, 4096},
		{"k8_r4", 8, 4, 777},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload := randPayload(tc.size)
			data := buildShards(payload, tc.k)
			parity, err := Encode(data, tc.r)
			if err != nil {
				t.Fatalf("Encode: %v", err)
			}
			if len(parity) != tc.r {
				t.Fatalf("parity count = %d, want %d", len(parity), tc.r)
			}
			n := tc.k + tc.r

			// Every subset of size 0..r is dropped.
			for drop := 0; drop <= tc.r; drop++ {
				combos := combinations(n, drop)
				for _, dropped := range combos {
					parts := make([][]byte, n)
					copy(parts, data)
					copy(parts[tc.k:], parity)
					for _, d := range dropped {
						parts[d] = nil
					}
					if err := Reconstruct(parts, tc.k, tc.r); err != nil {
						t.Fatalf("Reconstruct drop=%v: %v", dropped, err)
					}
					var got []byte
					for i := 0; i < tc.k; i++ {
						got = append(got, parts[i]...)
					}
					// Reconstructed data equals the original k data shards.
					var want []byte
					for _, d := range data {
						want = append(want, d...)
					}
					if !bytes.Equal(got, want) {
						t.Fatalf("drop=%v: reconstructed data mismatch", dropped)
					}
				}
			}
		})
	}
}

// TestReconstructTooManyLosses pins the boundary: r+1 losses must be reported as
// unrecoverable instead of silently producing corrupt data.
func TestReconstructTooManyLosses(t *testing.T) {
	k, r := 4, 1
	data := buildShards(randPayload(400), k)
	parity, err := Encode(data, r)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	parts := make([][]byte, k+r)
	copy(parts, data)
	copy(parts[k:], parity)
	parts[0] = nil
	parts[1] = nil
	if err := Reconstruct(parts, k, r); err != ErrNotEnoughShards {
		t.Fatalf("err = %v, want ErrNotEnoughShards", err)
	}
}

func TestEncodeRejectsBadLayout(t *testing.T) {
	if _, err := Encode([][]byte{{1, 2}, {3}}, 1); err != ErrInvalidLayout {
		t.Fatalf("ragged shards: err = %v, want ErrInvalidLayout", err)
	}
	if _, err := Encode(nil, 1); err != ErrTooManyShards {
		t.Fatalf("no data shards: err = %v, want ErrTooManyShards", err)
	}
	if _, err := Encode([][]byte{{1}}, 255); err != ErrTooManyShards {
		t.Fatalf("k+r>255: err = %v, want ErrTooManyShards", err)
	}
	if err := Reconstruct(make([][]byte, 3), 2, 2); err != ErrInvalidLayout {
		t.Fatalf("wrong part count: err = %v, want ErrInvalidLayout", err)
	}
	if err := Reconstruct([][]byte{{1}, {1, 2}, nil}, 2, 1); err != ErrInvalidLayout {
		t.Fatalf("ragged available shards: err = %v, want ErrInvalidLayout", err)
	}
}

// TestNoLossIsFree verifies Reconstruct is a no-op when everything arrived: the
// caller must not be handed new buffers or pay decode cost on the happy path.
func TestNoLossIsFree(t *testing.T) {
	k, r := 4, 2
	data := buildShards(randPayload(500), k)
	parity, err := Encode(data, r)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	parts := make([][]byte, k+r)
	copy(parts, data)
	copy(parts[k:], parity)
	before := make([][]byte, len(parts))
	copy(before, parts)
	if err := Reconstruct(parts, k, r); err != nil {
		t.Fatalf("Reconstruct: %v", err)
	}
	for i := range parts {
		if &parts[i][0] != &before[i][0] {
			t.Fatalf("shard %d was reallocated on the no-loss path", i)
		}
	}
}

// TestSingleByteShards exercises the degenerate size the padding logic can
// produce for tiny payloads.
func TestSingleByteShards(t *testing.T) {
	data := [][]byte{{0x00}, {0xff}, {0x2a}}
	parity, err := Encode(data, 1)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if len(parity[0]) != 1 {
		t.Fatalf("parity length = %d, want 1", len(parity[0]))
	}
	// Losing any single 1-byte shard must still recover it.
	for lost := 0; lost < 4; lost++ {
		parts := [][]byte{data[0], data[1], data[2], parity[0]}
		want := parts[lost][0]
		parts[lost] = nil
		if err := Reconstruct(parts, 3, 1); err != nil {
			t.Fatalf("Reconstruct losing %d: %v", lost, err)
		}
		if got := parts[lost]; got == nil || len(got) != 1 || got[0] != want {
			t.Fatalf("shard %d = %v, want %#x", lost, got, want)
		}
	}
}

func combinations(n, k int) [][]int {
	var out [][]int
	var rec func(start int, cur []int)
	rec = func(start int, cur []int) {
		if len(cur) == k {
			cp := make([]int, k)
			copy(cp, cur)
			out = append(out, cp)
			return
		}
		for i := start; i < n; i++ {
			rec(i+1, append(cur, i))
		}
	}
	rec(0, nil)
	if out == nil {
		return [][]int{{}}
	}
	return out
}

func BenchmarkEncodeK4(b *testing.B) {
	data := buildShards(make([]byte, 4*16384), 4)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := Encode(data, 1); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkReconstructK4OneLost(b *testing.B) {
	k, r := 4, 1
	data := buildShards(make([]byte, 4*16384), k)
	parity, _ := Encode(data, r)
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		parts := make([][]byte, k+r)
		copy(parts, data)
		copy(parts[k:], parity)
		parts[1] = nil
		if err := Reconstruct(parts, k, r); err != nil {
			b.Fatal(fmt.Sprint(err))
		}
	}
}
