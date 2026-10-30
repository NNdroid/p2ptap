package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/test"

	"p2ptap/pkg/routing"
)

// rawByteStream models a libp2p stream at the BYTE level: every Write appends to
// one shared buffer, exactly like the wire. It deliberately yields after each
// append so a writer that does not hold a lock across its whole frame is almost
// guaranteed to be interleaved by another goroutine instead of passing by luck.
//
// fakeStream (mesh_test.go) cannot catch this class of bug: it folds each Write
// into its own slice under a mutex, so it stays well-formed no matter how the
// caller interleaves. Only a byte-level model exposes a torn length prefix.
type rawByteStream struct {
	network.Stream
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *rawByteStream) Write(p []byte) (int, error) {
	s.mu.Lock()
	n, err := s.buf.Write(p)
	s.mu.Unlock()
	// Widen the interleaving window: without it a two-write frame can finish
	// before the competing goroutine is scheduled at all.
	runtime.Gosched()
	return n, err
}

func (s *rawByteStream) SetWriteDeadline(time.Time) error { return nil }

func (s *rawByteStream) bytes() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]byte, s.buf.Len())
	copy(out, s.buf.Bytes())
	return out
}

// TestRelayRouterSerializesConcurrentWrites is the regression test for torn
// frames on a shared boot-relay stream.
//
// route() runs on one goroutine per attached client uplink and per backbone
// boot, so when several peers send to the SAME destination they all write into
// that destination's single stream. libp2p streams are not safe for concurrent
// Write: without a per-stream lock the 4-byte length prefix of one frame lands
// inside another frame's body, the destination's readFrame reads a garbage
// length, errors out, and the uplink is torn down and reopened. Under parallel
// TCP flows (i.e. any real page load) that turned a connected relay into an
// unusable tunnel, which reads as "hard to connect, pages barely load".
func TestRelayRouterSerializesConcurrentWrites(t *testing.T) {
	rr, acl := newTestRelayRouter(t)
	const netID = "test-net"

	dst := test.RandPeerIDFatal(t)
	acl.AddAuthenticated(dst, netID)
	stream := &rawByteStream{}
	rr.registerClient(dst, stream)

	const senders = 8
	const perSender = 24

	// Build every frame up front: packTestFrame calls t.Fatalf, which must only
	// run on the test goroutine.
	type job struct {
		frame []byte
		from  peer.ID
	}
	jobs := make([]job, 0, senders*perSender)
	for s := 0; s < senders; s++ {
		origin := test.RandPeerIDFatal(t)
		for i := 0; i < perSender; i++ {
			// Unique, large payloads: a torn frame cannot re-parse by accident.
			p := make([]byte, 220)
			copy(p, fmt.Sprintf("s%02d-i%03d|", s, i))
			for j := len(p) - 1; j >= 16; j-- {
				p[j] = byte('a' + (s+i)%26)
			}
			jobs = append(jobs, job{
				frame: packTestFrame(t, netID, routing.BootRelayKindData, "", dst, dst, 2, p),
				from:  origin,
			})
		}
	}

	var wg sync.WaitGroup
	for _, j := range jobs {
		wg.Add(1)
		go func(frame []byte, from peer.ID) {
			defer wg.Done()
			// fromPeer only has to be a member; the delivery decision is made on
			// finalDst, which is the shared client stream every sender targets.
			rr.route(frame, false, from)
		}(j.frame, j.from)
	}
	wg.Wait()

	raw := stream.bytes()
	var got int
	for off := 0; off+4 <= len(raw); {
		n := int(binary.BigEndian.Uint32(raw[off : off+4]))
		prefixAt := off
		off += 4
		if n <= 0 || off+n > len(raw) {
			t.Fatalf("torn frame at offset %d: length prefix %d with %d bytes left "+
				"(%d frames parsed OK before it) — concurrent writes were not serialized",
				prefixAt, n, len(raw)-off, got)
		}
		body := raw[off : off+n]
		off += n
		// Every delivered frame must still unpack as a boot-relay frame whose
		// destination is the shared client.
		_, _, _, fd, _, _, payload, err := routing.UnpackBootRelayFrame(body)
		if err != nil {
			t.Fatalf("frame %d failed to unpack: %v — the byte stream was corrupted", got, err)
		}
		if fd != dst {
			t.Fatalf("frame %d addressed to %s, want %s", got, fd, dst)
		}
		if len(payload) != 220 || payload[3] != '-' {
			t.Fatalf("frame %d payload is corrupted (len=%d)", got, len(payload))
		}
		got++
	}
	if want := senders * perSender; got != want {
		t.Fatalf("delivered %d frames, want %d (a mismatch means frames were lost or merged)", got, want)
	}
}
