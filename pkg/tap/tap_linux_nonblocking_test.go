//go:build linux && !android
// +build linux,!android

package tap

import (
	"errors"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func newNonblockingPipeTAP(t *testing.T) (*LinuxTAPDevice, int) {
	t.Helper()
	fds := make([]int, 2)
	if err := unix.Pipe2(fds, unix.O_NONBLOCK|unix.O_CLOEXEC); err != nil {
		t.Fatalf("pipe2: %v", err)
	}
	file := os.NewFile(uintptr(fds[0]), "p2ptap-linux-read-test")
	if file == nil {
		_ = unix.Close(fds[0])
		_ = unix.Close(fds[1])
		t.Fatal("os.NewFile returned nil")
	}
	dev := &LinuxTAPDevice{file: file, eventFd: -1}
	t.Cleanup(func() {
		_ = file.Close()
		_ = unix.Close(fds[1])
	})
	return dev, fds[1]
}

func TestLinuxTAPReadConsumesReadyData(t *testing.T) {
	dev, writeFD := newNonblockingPipeTAP(t)
	want := []byte("ready-frame")
	if _, err := unix.Write(writeFD, want); err != nil {
		t.Fatalf("write pipe: %v", err)
	}

	buf := make([]byte, 64)
	n, err := dev.Read(buf)
	if err != nil {
		t.Fatalf("Read returned error: %v", err)
	}
	if got := string(buf[:n]); got != string(want) {
		t.Fatalf("Read payload = %q, want %q", got, want)
	}
}

func TestLinuxTAPReadReturnsImmediatelyOnEAGAIN(t *testing.T) {
	dev, _ := newNonblockingPipeTAP(t)
	buf := make([]byte, 64)

	start := time.Now()
	n, err := dev.Read(buf)
	elapsed := time.Since(start)

	if n != 0 {
		t.Fatalf("Read bytes = %d, want 0", n)
	}
	if !errors.Is(err, ErrReadTimeout) {
		t.Fatalf("Read error = %v, want ErrReadTimeout", err)
	}
	// The previous implementation entered poll(..., 50ms) after EAGAIN. Keep
	// enough scheduler slack for CI while still catching that regression.
	if elapsed >= 40*time.Millisecond {
		t.Fatalf("empty nonblocking Read took %v; epoll drain must not wait for the old 50ms poll timeout", elapsed)
	}
}

func BenchmarkLinuxTAPReadEmpty(b *testing.B) {
	dev, _ := newNonblockingPipeTAP(&testing.T{})
	buf := make([]byte, 64)
	b.ReportAllocs()
	for b.Loop() {
		_, _ = dev.Read(buf)
	}
}
