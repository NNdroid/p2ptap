package tap

import (
	"net"
	"testing"
	"time"
)

// The Android TUN reader (tun_android.go Read) arms its park deadline once per
// Read call rather than once per packet, because re-arming cost 56ns of runtime
// timer work on a path whose real work is a single read syscall. That is only
// safe while a deadline survives successful reads — otherwise a deadline that
// expired during a busy stretch would stop the reader parking forever and the
// read loop would spin. These tests pin the two properties that guarantee it,
// using a real netpoller-backed fd (an os.Pipe is not pollable on Windows, so
// it cannot model the TUN fd here).

// connPair returns a connected TCP pair on loopback.
func connPair(tb testing.TB) (net.Conn, net.Conn) {
	tb.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	type accepted struct {
		c   net.Conn
		err error
	}
	ch := make(chan accepted, 1)
	go func() {
		c, aerr := ln.Accept()
		ch <- accepted{c, aerr}
	}()

	w, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		tb.Fatalf("dial: %v", err)
	}
	res := <-ch
	if res.err != nil {
		_ = w.Close()
		tb.Fatalf("accept: %v", res.err)
	}
	tb.Cleanup(func() { _ = w.Close(); _ = res.c.Close() })
	return res.c, w
}

// TestParkDeadlineSurvivesSuccessfulReads pins the first half of the contract
// the single arm depends on: a deadline set before a successful read still
// fires on the next read that has to block. Without this, a read that parks
// after some successful ones would never wake, and the closed/fd-swap checks
// below it would become unreachable.
func TestParkDeadlineSurvivesSuccessfulReads(t *testing.T) {
	r, w := connPair(t)
	buf := make([]byte, 64)

	if _, err := w.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	const park = 120 * time.Millisecond
	_ = r.SetReadDeadline(time.Now().Add(park))

	// Read #1 succeeds immediately; the deadline is deliberately NOT re-armed.
	if _, err := r.Read(buf); err != nil {
		t.Fatalf("first read should succeed: %v", err)
	}

	// Nothing left to read, so this read has to block. The stale deadline must
	// still wake it, and promptly — not at some far-future time.
	start := time.Now()
	_, err := r.Read(buf)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected the park deadline to fire on the blocking read")
	}
	if elapsed > 2*park {
		t.Fatalf("park deadline fired after %v, want ~%v", elapsed, park)
	}
}

// TestExpiredParkDeadlineFailsFast pins the second half, and it is the reason
// the timeout branch MUST re-arm: once a deadline has expired it wins even over
// data that is already waiting, so every subsequent read fails until the
// deadline is pushed forward again. Read therefore cannot simply arm once for
// the device's lifetime — it arms per call and re-arms on timeout.
func TestExpiredParkDeadlineFailsFast(t *testing.T) {
	r, w := connPair(t)
	buf := make([]byte, 64)

	// Expire the deadline first, then make data available.
	_ = r.SetReadDeadline(time.Now().Add(-time.Second))
	if _, err := w.Write([]byte("abc")); err != nil {
		t.Fatal(err)
	}
	// Give the bytes time to become readable on the socket.
	time.Sleep(20 * time.Millisecond)

	start := time.Now()
	n, err := r.Read(buf)
	if err == nil {
		t.Fatalf("read with an expired deadline returned %d bytes; the design assumes it fails so the caller re-arms", n)
	}
	if elapsed := time.Since(start); elapsed > 200*time.Millisecond {
		t.Fatalf("expired deadline should fail fast, took %v", elapsed)
	}

	// Re-arming must restore normal operation — this is exactly what Read does
	// on the timeout branch.
	_ = r.SetReadDeadline(time.Now().Add(time.Second))
	if n, err := r.Read(buf); err != nil {
		t.Fatalf("read after re-arming should succeed: %v", err)
	} else if n != 3 {
		t.Fatalf("read %d bytes after re-arm, want 3", n)
	}
}
