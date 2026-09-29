//go:build linux && !android
// +build linux,!android

package tap

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

const (
	batchBenchFrames = 256
	batchBenchSize   = 128
)

func newDatagramBenchTAP(tb testing.TB) (*LinuxTAPDevice, int) {
	tb.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		tb.Fatalf("socketpair: %v", err)
	}
	file := os.NewFile(uintptr(fds[0]), "p2ptap-linux-batch-bench")
	if file == nil {
		_ = unix.Close(fds[0])
		_ = unix.Close(fds[1])
		tb.Fatal("os.NewFile returned nil")
	}
	efd, err := unix.Eventfd(0, unix.EFD_NONBLOCK|unix.EFD_CLOEXEC)
	if err != nil {
		_ = file.Close()
		_ = unix.Close(fds[1])
		tb.Fatalf("eventfd: %v", err)
	}
	dev := &LinuxTAPDevice{name: "batch-bench", file: file, eventFd: efd}
	tb.Cleanup(func() {
		_ = dev.Close()
		_ = unix.Close(fds[1])
	})
	return dev, fds[1]
}

func fillDatagramBurst(tb testing.TB, fd int, frame []byte, count int) {
	tb.Helper()
	for i := 0; i < count; i++ {
		for {
			_, err := unix.Write(fd, frame)
			if err == nil {
				break
			}
			if errors.Is(err, unix.EINTR) {
				continue
			}
			tb.Fatalf("fill burst frame %d/%d: %v", i+1, count, err)
		}
	}
}

// BenchmarkLinuxEpollDrainBatch quantifies the only part of tapReadLoopEpoll
// changed by the batch limit: how many epoll wake/drain cycles are required to
// consume the same burst of frame-preserving, non-blocking reads. The AF_UNIX
// datagram socket preserves one-write/one-read frame boundaries like a TAP fd
// while avoiding root/CAP_NET_ADMIN requirements on CI runners.
func BenchmarkLinuxEpollDrainBatch(b *testing.B) {
	frame := make([]byte, batchBenchSize)
	for i := range frame {
		frame[i] = byte(i)
	}

	for _, batchSize := range []int{16, 32, 64, 128, 256} {
		batchSize := batchSize
		b.Run(fmt.Sprintf("batch_%d", batchSize), func(b *testing.B) {
			dev, writeFD := newDatagramBenchTAP(b)
			poller, err := NewEpollPoller(dev)
			if err != nil {
				b.Fatalf("NewEpollPoller: %v", err)
			}
			defer poller.Close()

			buf := make([]byte, 2048)
			ctx := context.Background()
			var wakeups uint64
			b.ReportAllocs()
			b.ResetTimer()

			for b.Loop() {
				b.StopTimer()
				fillDatagramBurst(b, writeFD, frame, batchBenchFrames)
				b.StartTimer()

				remaining := batchBenchFrames
				for remaining > 0 {
					if err := poller.Wait(ctx); err != nil {
						b.Fatalf("epoll wait: %v", err)
					}
					wakeups++
					for drained := 0; drained < batchSize; drained++ {
						n, err := dev.Read(buf)
						if err != nil {
							if errors.Is(err, ErrReadTimeout) {
								break
							}
							b.Fatalf("read: %v", err)
						}
						if n != batchBenchSize {
							b.Fatalf("read len=%d want=%d", n, batchBenchSize)
						}
						remaining--
						if remaining == 0 {
							break
						}
					}
				}
			}

			b.ReportMetric(float64(batchBenchFrames), "frames/op")
			if b.N > 0 {
				b.ReportMetric(float64(wakeups)/float64(b.N), "epoll-wakeups/op")
			}
		})
	}
}
