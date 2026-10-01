//go:build linux && !android
// +build linux,!android

package tap

import (
	"encoding/binary"
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
	mqBenchDuration     = 2 * time.Second
	mqBenchFlows        = 32
	mqBenchDrainSize    = 128
	mqBenchWarmupTarget = 2000
	mqBenchWarmupTimeout = 2 * time.Second
)

var mqBenchSeq atomic.Uint32

func newRealMultiQueueTAP(tb testing.TB, queues int) (string, []*os.File, net.IP, net.IP, func()) {
	tb.Helper()
	id := mqBenchSeq.Add(1)
	// Never reuse the same interface name or connected route inside one benchmark
	// process. TAP destruction and route teardown are asynchronous enough that a
	// back-to-back recreation can otherwise attach to stale multiqueue state and
	// make repeated samples alternate between healthy throughput and no delivery.
	name := fmt.Sprintf("p2mq%03x%03x", os.Getpid()&0xfff, id&0xfff)
	octet := byte(16 + (id % 200))
	srcIP := net.IPv4(10, 252, octet, 1).To4()
	dstIP := net.IPv4(10, 252, octet, 2).To4()

	files := make([]*os.File, 0, queues)
	flags := uint16(unix.IFF_TAP | unix.IFF_NO_PI | unix.IFF_MULTI_QUEUE)

	for i := 0; i < queues; i++ {
		f, err := os.OpenFile("/dev/net/tun", os.O_RDWR|unix.O_NONBLOCK, 0)
		if err != nil {
			for _, q := range files {
				_ = q.Close()
			}
			tb.Fatalf("open /dev/net/tun queue %d: %v", i, err)
		}
		var req ifreq
		copy(req.name[:], name)
		req.flags = flags
		_, _, errno := unix.Syscall(unix.SYS_IOCTL, f.Fd(), uintptr(unix.TUNSETIFF), uintptr(unsafe.Pointer(&req)))
		if errno != 0 {
			_ = f.Close()
			for _, q := range files {
				_ = q.Close()
			}
			tb.Fatalf("TUNSETIFF queue %d: %v", i, errno)
		}
		files = append(files, f)
	}

	var closeOnce sync.Once
	cleanup := func() {
		closeOnce.Do(func() {
			for _, f := range files {
				_ = f.Close()
			}
		})
	}
	tb.Cleanup(cleanup)

	link, err := netlink.LinkByName(name)
	if err != nil {
		cleanup()
		tb.Fatalf("LinkByName(%s): %v", name, err)
	}
	if err := netlink.LinkSetMTU(link, 1500); err != nil {
		cleanup()
		tb.Fatalf("LinkSetMTU: %v", err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		cleanup()
		tb.Fatalf("LinkSetUp: %v", err)
	}

	addr, err := netlink.ParseAddr(srcIP.String() + "/24")
	if err != nil {
		cleanup()
		tb.Fatalf("ParseAddr: %v", err)
	}
	if err := netlink.AddrReplace(link, addr); err != nil {
		cleanup()
		tb.Fatalf("AddrReplace: %v", err)
	}
	if err := netlink.NeighSet(&netlink.Neigh{
		LinkIndex:    link.Attrs().Index,
		IP:           dstIP,
		HardwareAddr: net.HardwareAddr{0x02, 0, 0, 0, 0, 2},
		State:        netlink.NUD_PERMANENT,
	}); err != nil {
		cleanup()
		tb.Fatalf("NeighSet: %v", err)
	}
	return name, files, srcIP, dstIP, cleanup
}

func runMQBenchReader(f *os.File, dstIP net.IP, stop <-chan struct{}, ready chan<- error, packets, bytesRead *atomic.Uint64, wg *sync.WaitGroup) {
	defer wg.Done()
	fd := int(f.Fd())
	epfd, err := unix.EpollCreate1(unix.EPOLL_CLOEXEC)
	if err != nil {
		ready <- err
		return
	}
	defer unix.Close(epfd)
	if err := unix.EpollCtl(epfd, unix.EPOLL_CTL_ADD, fd, &unix.EpollEvent{Events: unix.EPOLLIN, Fd: int32(fd)}); err != nil {
		ready <- err
		return
	}
	ready <- nil

	buf := make([]byte, 2048)
	var events [1]unix.EpollEvent
	for {
		select {
		case <-stop:
			return
		default:
		}
		n, err := unix.EpollWait(epfd, events[:], 20)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return
		}
		if n == 0 {
			continue
		}
		for drained := 0; drained < mqBenchDrainSize; drained++ {
			nn, err := unix.Read(fd, buf)
			if err != nil {
				if errors.Is(err, unix.EINTR) {
					continue
				}
				if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
					break
				}
				return
			}
			// Ignore kernel control traffic; count only the benchmark's IPv4 UDP
			// frames addressed to this iteration's unique destination address.
			if nn < 42 || binary.BigEndian.Uint16(buf[12:14]) != 0x0800 || buf[23] != 17 || !net.IP(buf[30:34]).Equal(dstIP) {
				continue
			}
			packets.Add(1)
			bytesRead.Add(uint64(nn))
		}
	}
}

func runMQBenchSenders(tb testing.TB, srcIP, dstIP net.IP, payloadSize int, stop <-chan struct{}, sent, writeErrors *atomic.Uint64, wg *sync.WaitGroup) {
	tb.Helper()
	dst := &net.UDPAddr{IP: dstIP, Port: 49000}
	payload := make([]byte, payloadSize)
	for i := range payload {
		payload[i] = byte(i)
	}

	for flow := 0; flow < mqBenchFlows; flow++ {
		conn, err := net.DialUDP("udp4", &net.UDPAddr{IP: srcIP, Port: 0}, dst)
		if err != nil {
			tb.Fatalf("DialUDP flow %d: %v", flow, err)
		}
		wg.Add(1)
		go func(c *net.UDPConn) {
			defer wg.Done()
			defer c.Close()
			for {
				select {
				case <-stop:
					return
				default:
				}
				if _, err := c.Write(payload); err != nil {
					writeErrors.Add(1)
					return
				}
				sent.Add(1)
			}
		}(conn)
	}
}

func mqBenchReceived(counts []atomic.Uint64) uint64 {
	var total uint64
	for i := range counts {
		total += counts[i].Load()
	}
	return total
}

func waitMQBenchWarmup(counts []atomic.Uint64, writeErrors *atomic.Uint64) bool {
	deadline := time.Now().Add(mqBenchWarmupTimeout)
	for time.Now().Before(deadline) {
		if writeErrors.Load() != 0 {
			return false
		}
		if mqBenchReceived(counts) >= mqBenchWarmupTarget {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return false
}

// BenchmarkLinuxContinuousTAPMultiQueue measures the real kernel IFF_MULTI_QUEUE
// receive path. It intentionally runs only when invoked with CAP_NET_ADMIN
// (the stage2 workflow uses sudo). Multiple UDP flows give the kernel stable
// per-flow hashes so queue distribution and scaling are representative of a
// multi-flow VPN workload rather than a synthetic userspace socketpair.
func BenchmarkLinuxContinuousTAPMultiQueue(b *testing.B) {
	if os.Geteuid() != 0 {
		b.Skip("real TAP multiqueue benchmark requires root/CAP_NET_ADMIN")
	}
	b.ReportMetric(float64(runtime.NumCPU()), "logical-cpus")

	for _, payloadSize := range []int{64, 1200} {
		payloadSize := payloadSize
		b.Run(fmt.Sprintf("payload_%d", payloadSize), func(b *testing.B) {
			for _, queueCount := range []int{1, 2, 4, 8} {
				queueCount := queueCount
				b.Run(fmt.Sprintf("queues_%d", queueCount), func(b *testing.B) {
					for range b.N {
						b.StopTimer()
						_, queues, srcIP, dstIP, cleanup := newRealMultiQueueTAP(b, queueCount)
						stopReaders := make(chan struct{})
						ready := make(chan error, queueCount)
						var readerWG sync.WaitGroup
						packetCounts := make([]atomic.Uint64, queueCount)
						byteCounts := make([]atomic.Uint64, queueCount)
						for i, q := range queues {
							readerWG.Add(1)
							go runMQBenchReader(q, dstIP, stopReaders, ready, &packetCounts[i], &byteCounts[i], &readerWG)
						}
						for i := 0; i < queueCount; i++ {
							if err := <-ready; err != nil {
								close(stopReaders)
								readerWG.Wait()
								cleanup()
								b.Fatalf("reader setup: %v", err)
							}
						}

						// Warm the exact same kernel route/TAP transmit path before taking
						// a sample. Hosted VMs occasionally need a short period after
						// link/address setup before the first frames reach the TAP queues;
						// accepting that startup interval as throughput produced false zero
						// samples. Require observed delivery, then stop the warm-up senders,
						// drain, reset counters and start a clean timed sender set.
						warmStop := make(chan struct{})
						var warmWG sync.WaitGroup
						var warmSent, warmWriteErrors atomic.Uint64
						runMQBenchSenders(b, srcIP, dstIP, payloadSize, warmStop, &warmSent, &warmWriteErrors, &warmWG)
						if !waitMQBenchWarmup(packetCounts, &warmWriteErrors) {
							close(warmStop)
							warmWG.Wait()
							close(stopReaders)
							readerWG.Wait()
							cleanup()
							b.Fatalf("TAP warm-up failed: queues=%d sent=%d received=%d write_errors=%d",
								queueCount, warmSent.Load(), mqBenchReceived(packetCounts), warmWriteErrors.Load())
						}
						close(warmStop)
						warmWG.Wait()
						time.Sleep(25 * time.Millisecond)
						for i := range packetCounts {
							packetCounts[i].Store(0)
							byteCounts[i].Store(0)
						}

						stopSenders := make(chan struct{})
						var senderWG sync.WaitGroup
						var sent, writeErrors atomic.Uint64
						runMQBenchSenders(b, srcIP, dstIP, payloadSize, stopSenders, &sent, &writeErrors, &senderWG)
						b.StartTimer()
						start := time.Now()
						time.Sleep(mqBenchDuration)
						elapsed := time.Since(start)
						b.StopTimer()

						close(stopSenders)
						senderWG.Wait()
						// Let readers consume frames already queued by the kernel before
						// stopping them; this is outside the timed generation interval.
						time.Sleep(75 * time.Millisecond)
						close(stopReaders)
						readerWG.Wait()

						var received, bytesTotal, maxQueue uint64
						active := 0
						for i := range packetCounts {
							p := packetCounts[i].Load()
							received += p
							bytesTotal += byteCounts[i].Load()
							if p > 0 {
								active++
							}
							if p > maxQueue {
								maxQueue = p
							}
						}
						cleanup()
						secs := elapsed.Seconds()
						b.ReportMetric(float64(received)/secs, "packets/s")
						b.ReportMetric(float64(bytesTotal)/secs/1e6, "MB/s")
						b.ReportMetric(float64(active), "active-queues")
						b.ReportMetric(float64(sent.Load()), "sent")
						b.ReportMetric(float64(received), "received")
						b.ReportMetric(float64(writeErrors.Load()), "write-errors")
						if received > 0 && sent.Load() > 0 {
							b.ReportMetric(100*float64(maxQueue)/float64(received), "max-queue-share-%")
							b.ReportMetric(100*float64(received)/float64(sent.Load()), "received/sent-%")
						}
					}
				})
			}
		})
	}
}
