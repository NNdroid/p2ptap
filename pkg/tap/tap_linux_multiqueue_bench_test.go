//go:build linux && !android
// +build linux,!android

package tap

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	realTAPBenchEnv             = "P2PTAP_REAL_TAP_BENCH"
	realTAPBenchFrames          = 20000
	realTAPBenchSenders         = 4
	realTAPBenchDrainIdle       = 75 * time.Millisecond
	realTAPBenchMaxOutstanding  = 64
	realTAPBenchThrottleEvery   = 8
	realTAPBenchThrottleTimeout = 5 * time.Millisecond
)

type realTAPMQReader struct {
	frames atomic.Uint64
	bytes  atomic.Uint64
}

func openRealTAPMultiQueue(tb testing.TB, name string, queues int, subnetOctet int) ([]*os.File, net.IP) {
	tb.Helper()
	if os.Getenv(realTAPBenchEnv) != "1" {
		tb.Skipf("set %s=1 and run as root to enable real /dev/net/tun benchmark", realTAPBenchEnv)
	}
	if os.Geteuid() != 0 {
		tb.Skip("real multi-queue TAP benchmark requires root/CAP_NET_ADMIN")
	}

	files := make([]*os.File, 0, queues)
	cleanupFiles := func() {
		for i := len(files) - 1; i >= 0; i-- {
			_ = files[i].Close()
		}
	}

	for idx := 0; idx < queues; idx++ {
		file, err := os.OpenFile("/dev/net/tun", os.O_RDWR|unix.O_NONBLOCK, 0)
		if err != nil {
			cleanupFiles()
			tb.Fatalf("open /dev/net/tun queue %d: %v", idx, err)
		}
		var req ifreq
		copy(req.name[:], []byte(name))
		req.flags = unix.IFF_TAP | unix.IFF_NO_PI | unix.IFF_MULTI_QUEUE
		_, _, errno := unix.Syscall(
			unix.SYS_IOCTL,
			file.Fd(),
			uintptr(unix.TUNSETIFF),
			uintptr(unsafe.Pointer(&req)),
		)
		if errno != 0 {
			_ = file.Close()
			cleanupFiles()
			tb.Fatalf("TUNSETIFF queue %d: %v", idx, errno)
		}
		files = append(files, file)
	}

	link, err := netlink.LinkByName(name)
	if err != nil {
		cleanupFiles()
		tb.Fatalf("LinkByName(%s): %v", name, err)
	}
	if err := netlink.LinkSetMTU(link, 1500); err != nil {
		cleanupFiles()
		tb.Fatalf("LinkSetMTU: %v", err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		cleanupFiles()
		tb.Fatalf("LinkSetUp: %v", err)
	}

	localCIDR := fmt.Sprintf("198.18.%d.1/24", subnetOctet)
	addr, err := netlink.ParseAddr(localCIDR)
	if err != nil {
		cleanupFiles()
		tb.Fatalf("ParseAddr(%s): %v", localCIDR, err)
	}
	if err := netlink.AddrReplace(link, addr); err != nil {
		cleanupFiles()
		tb.Fatalf("AddrReplace(%s): %v", localCIDR, err)
	}

	targetIP := net.ParseIP(fmt.Sprintf("198.18.%d.2", subnetOctet)).To4()
	neighbor := &netlink.Neigh{
		LinkIndex:    link.Attrs().Index,
		Family:       unix.AF_INET,
		State:        netlink.NUD_PERMANENT,
		IP:           targetIP,
		HardwareAddr: net.HardwareAddr{0x02, 0x00, 0x00, byte(subnetOctet), 0x00, 0x02},
	}
	if err := netlink.NeighSet(neighbor); err != nil {
		cleanupFiles()
		tb.Fatalf("NeighSet: %v", err)
	}

	tb.Cleanup(cleanupFiles)
	return files, targetIP
}

func runRealTAPQueueReader(ctx context.Context, file *os.File, stats *realTAPMQReader, wg *sync.WaitGroup) {
	defer wg.Done()
	epfd, err := unix.EpollCreate1(unix.EPOLL_CLOEXEC)
	if err != nil {
		return
	}
	defer unix.Close(epfd)
	fd := int(file.Fd())
	if err := unix.EpollCtl(epfd, unix.EPOLL_CTL_ADD, fd, &unix.EpollEvent{Events: unix.EPOLLIN, Fd: int32(fd)}); err != nil {
		return
	}

	events := make([]unix.EpollEvent, 4)
	buf := make([]byte, 2048)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		n, err := unix.EpollWait(epfd, events, 25)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return
		}
		if n == 0 {
			continue
		}
		for {
			rn, rerr := unix.Read(fd, buf)
			if rerr != nil {
				if errors.Is(rerr, unix.EINTR) {
					continue
				}
				if errors.Is(rerr, unix.EAGAIN) || errors.Is(rerr, unix.EWOULDBLOCK) {
					break
				}
				return
			}
			if rn > 0 {
				stats.frames.Add(1)
				stats.bytes.Add(uint64(rn))
			}
		}
	}
}

func sumRealTAPReaders(readers []realTAPMQReader) (uint64, uint64) {
	var frames, bytes uint64
	for i := range readers {
		frames += readers[i].frames.Load()
		bytes += readers[i].bytes.Load()
	}
	return frames, bytes
}

func benchRealTAPMultiQueueBurst(b *testing.B, queues, payloadSize, subnetOctet int) {
	name := fmt.Sprintf("p2pmq%d%d", queues, payloadSize/100)
	files, targetIP := openRealTAPMultiQueue(b, name, queues, subnetOctet)

	ctx, cancel := context.WithCancel(context.Background())
	readers := make([]realTAPMQReader, len(files))
	var readerWG sync.WaitGroup
	for i := range files {
		readerWG.Add(1)
		go runRealTAPQueueReader(ctx, files[i], &readers[i], &readerWG)
	}
	defer func() {
		cancel()
		readerWG.Wait()
	}()

	payload := make([]byte, payloadSize)
	for i := range payload {
		payload[i] = byte(i)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for iter := 0; iter < b.N; iter++ {
		beforeFrames, beforeBytes := sumRealTAPReaders(readers)
		beforeQueueFrames := make([]uint64, len(readers))
		for i := range readers {
			beforeQueueFrames[i] = readers[i].frames.Load()
		}
		start := make(chan struct{})
		var sendWG sync.WaitGroup
		var sent atomic.Uint64
		var sendErr atomic.Value

		for sender := 0; sender < realTAPBenchSenders; sender++ {
			sender := sender
			sendWG.Add(1)
			go func() {
				defer sendWG.Done()
				dst := &net.UDPAddr{IP: targetIP, Port: 40000 + sender}
				conn, err := net.DialUDP("udp4", nil, dst)
				if err != nil {
					sendErr.Store(err)
					return
				}
				defer conn.Close()
				<-start
				localSent := 0
				for seq := sender; seq < realTAPBenchFrames; seq += realTAPBenchSenders {
					if _, err := conn.Write(payload); err != nil {
						sendErr.Store(err)
						return
					}
					sent.Add(1)
					localSent++
					if localSent%realTAPBenchThrottleEvery != 0 {
						continue
					}
					waitStarted := time.Now()
					for {
						curFrames, _ := sumRealTAPReaders(readers)
						delivered := curFrames - beforeFrames
						curSent := sent.Load()
						if curSent <= delivered+realTAPBenchMaxOutstanding {
							break
						}
						if time.Since(waitStarted) >= realTAPBenchThrottleTimeout {
							break
						}
						runtime.Gosched()
					}
				}
			}()
		}

		started := time.Now()
		close(start)
		sendWG.Wait()
		if v := sendErr.Load(); v != nil {
			b.Fatalf("UDP generator failed: %v", v)
		}

		lastFrames := uint64(0)
		idleSince := time.Now()
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			curFrames, _ := sumRealTAPReaders(readers)
			curFrames -= beforeFrames
			if curFrames >= sent.Load() {
				break
			}
			if curFrames != lastFrames {
				lastFrames = curFrames
				idleSince = time.Now()
			} else if time.Since(idleSince) >= realTAPBenchDrainIdle {
				break
			}
			time.Sleep(1 * time.Millisecond)
		}

		elapsed := time.Since(started)
		afterFrames, afterBytes := sumRealTAPReaders(readers)
		delivered := afterFrames - beforeFrames
		deliveredBytes := afterBytes - beforeBytes
		if delivered == 0 {
			b.Fatal("real TAP benchmark delivered zero frames")
		}
		b.ReportMetric(float64(delivered)/elapsed.Seconds(), "frames/s")
		b.ReportMetric(float64(deliveredBytes)/elapsed.Seconds()/1e6, "MB/s")
		b.ReportMetric(100*float64(delivered)/float64(sent.Load()), "%delivered")
		for qi := range readers {
			qFrames := readers[qi].frames.Load() - beforeQueueFrames[qi]
			b.ReportMetric(100*float64(qFrames)/float64(delivered), fmt.Sprintf("q%d%%", qi))
		}
	}
	b.StopTimer()
}

// BenchmarkLinuxRealTAPMultiQueue uses a real IFF_MULTI_QUEUE /dev/net/tun
// device and kernel-generated UDP traffic. It is intentionally opt-in because
// it needs root/CAP_NET_ADMIN; Stage2 CI runs it under sudo. Two payload sizes
// cover PPS-heavy and bandwidth-heavy regimes, while 1/2/4 queues reveal
// whether extra queue fds actually improve Linux TAP scaling on the runner.
func BenchmarkLinuxRealTAPMultiQueue(b *testing.B) {
	for _, payloadSize := range []int{128, 1200} {
		payloadSize := payloadSize
		b.Run(fmt.Sprintf("payload_%d", payloadSize), func(b *testing.B) {
			for _, queues := range []int{1, 2, 4} {
				queues := queues
				b.Run(fmt.Sprintf("queues_%d", queues), func(b *testing.B) {
					subnetOctet := 40 + payloadSize/100 + queues
					benchRealTAPMultiQueueBurst(b, queues, payloadSize, subnetOctet)
				})
			}
		})
	}
}
