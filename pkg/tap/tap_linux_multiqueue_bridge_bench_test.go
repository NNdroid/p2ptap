//go:build linux && !android
// +build linux,!android

package tap

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	bridgeBenchFrames        = 40000
	bridgeBenchFlows         = 16
	bridgeBenchSourceQueues  = 4
	bridgeBenchWindow        = 512
	bridgeBenchThrottleEvery = 32
	bridgeBenchPortBase      = 44000
)

type bridgeBenchStats struct {
	frames atomic.Uint64
	bytes  atomic.Uint64
}

func openBridgeBenchTAP(tb testing.TB, name string, queues int, multi bool) ([]*os.File, netlink.Link) {
	tb.Helper()
	if os.Getenv(realTAPBenchEnv) != "1" {
		tb.Skipf("set %s=1 and run as root to enable real /dev/net/tun benchmark", realTAPBenchEnv)
	}
	files := make([]*os.File, 0, queues)
	for idx := 0; idx < queues; idx++ {
		file, err := os.OpenFile("/dev/net/tun", os.O_RDWR|unix.O_NONBLOCK, 0)
		if err != nil {
			tb.Fatalf("open %s queue %d: %v", name, idx, err)
		}
		var req ifreq
		copy(req.name[:], []byte(name))
		req.flags = unix.IFF_TAP | unix.IFF_NO_PI
		if multi {
			req.flags |= unix.IFF_MULTI_QUEUE
		}
		_, _, errno := unix.Syscall(unix.SYS_IOCTL, file.Fd(), uintptr(unix.TUNSETIFF), uintptr(unsafe.Pointer(&req)))
		if errno != 0 {
			_ = file.Close()
			tb.Fatalf("TUNSETIFF %s queue %d: %v", name, idx, errno)
		}
		files = append(files, file)
	}
	link, err := netlink.LinkByName(name)
	if err != nil {
		tb.Fatalf("LinkByName(%s): %v", name, err)
	}
	if err := netlink.LinkSetMTU(link, 1500); err != nil {
		tb.Fatalf("LinkSetMTU(%s): %v", name, err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		tb.Fatalf("LinkSetUp(%s): %v", name, err)
	}
	return files, link
}

func setupBridgeBench(tb testing.TB, suffix string, dstQueues int) ([]*os.File, []*os.File) {
	tb.Helper()
	srcName := "p2psrc" + suffix
	dstName := "p2pdst" + suffix
	brName := "p2pbr" + suffix

	srcFiles, srcLink := openBridgeBenchTAP(tb, srcName, bridgeBenchSourceQueues, true)
	dstFiles, dstLink := openBridgeBenchTAP(tb, dstName, dstQueues, dstQueues > 1)

	attrs := netlink.NewLinkAttrs()
	attrs.Name = brName
	bridge := &netlink.Bridge{LinkAttrs: attrs}
	if err := netlink.LinkAdd(bridge); err != nil {
		tb.Fatalf("LinkAdd bridge %s: %v", brName, err)
	}
	brLink, err := netlink.LinkByName(brName)
	if err != nil {
		tb.Fatalf("LinkByName bridge %s: %v", brName, err)
	}
	if err := netlink.LinkSetUp(brLink); err != nil {
		tb.Fatalf("LinkSetUp bridge %s: %v", brName, err)
	}
	if err := netlink.LinkSetMaster(srcLink, brLink); err != nil {
		tb.Fatalf("attach %s to %s: %v", srcName, brName, err)
	}
	if err := netlink.LinkSetMaster(dstLink, brLink); err != nil {
		tb.Fatalf("attach %s to %s: %v", dstName, brName, err)
	}

	// The source side is a generator. Make its writes blocking so generator
	// backpressure is explicit instead of turning EAGAIN into artificial loss.
	for _, file := range srcFiles {
		if err := unix.SetNonblock(int(file.Fd()), false); err != nil {
			tb.Fatalf("set source TAP blocking: %v", err)
		}
	}

	tb.Cleanup(func() {
		_ = netlink.LinkDel(brLink)
		for _, file := range dstFiles {
			_ = file.Close()
		}
		for _, file := range srcFiles {
			_ = file.Close()
		}
	})

	// Bridge ports are STP-free by default, but give the kernel a short turn to
	// publish the forwarding state before the warmup begins.
	time.Sleep(20 * time.Millisecond)
	return srcFiles, dstFiles
}

func buildBridgeBenchFrame(payloadSize, flow int) []byte {
	frame := make([]byte, 14+20+8+payloadSize)
	for i := 0; i < 6; i++ {
		frame[i] = 0xff // broadcast: bridge must flood from source TAP to dest TAP
	}
	copy(frame[6:12], []byte{0x02, 0x10, 0x20, 0x30, 0x40, byte(flow)})
	frame[12], frame[13] = 0x08, 0x00
	ip := frame[14:34]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(20+8+payloadSize))
	ip[8] = 64
	ip[9] = unix.IPPROTO_UDP
	copy(ip[12:16], []byte{10, 254, 0, 1})
	copy(ip[16:20], []byte{10, 254, 0, 2})
	udp := frame[34:42]
	binary.BigEndian.PutUint16(udp[0:2], uint16(43000+flow))
	binary.BigEndian.PutUint16(udp[2:4], uint16(bridgeBenchPortBase+flow))
	binary.BigEndian.PutUint16(udp[4:6], uint16(8+payloadSize))
	for i := 42; i < len(frame); i++ {
		frame[i] = byte(i + flow)
	}
	return frame
}

func isBridgeBenchFrame(frame []byte) bool {
	if len(frame) < 42 || frame[12] != 0x08 || frame[13] != 0x00 {
		return false
	}
	ip := frame[14:]
	if ip[0]>>4 != 4 || ip[9] != unix.IPPROTO_UDP || ip[16] != 10 || ip[17] != 254 || ip[18] != 0 || ip[19] != 2 {
		return false
	}
	ihl := int(ip[0]&0x0f) * 4
	if ihl < 20 || len(ip) < ihl+8 {
		return false
	}
	port := int(binary.BigEndian.Uint16(ip[ihl+2 : ihl+4]))
	return port >= bridgeBenchPortBase && port < bridgeBenchPortBase+bridgeBenchFlows
}

func runBridgeBenchReader(ctx context.Context, fd int, stats *bridgeBenchStats, ready *sync.WaitGroup, wg *sync.WaitGroup) {
	defer wg.Done()
	epfd, err := unix.EpollCreate1(unix.EPOLL_CLOEXEC)
	if err != nil {
		ready.Done()
		return
	}
	defer unix.Close(epfd)
	if err := unix.EpollCtl(epfd, unix.EPOLL_CTL_ADD, fd, &unix.EpollEvent{Events: unix.EPOLLIN, Fd: int32(fd)}); err != nil {
		ready.Done()
		return
	}
	ready.Done()
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
			if rn > 0 && isBridgeBenchFrame(buf[:rn]) {
				stats.frames.Add(1)
				stats.bytes.Add(uint64(rn))
			}
		}
	}
}

func sumBridgeBenchStats(stats []bridgeBenchStats) (uint64, uint64) {
	var frames, bytes uint64
	for i := range stats {
		frames += stats[i].frames.Load()
		bytes += stats[i].bytes.Load()
	}
	return frames, bytes
}

func waitBridgeBench(stats []bridgeBenchStats, base, want uint64, timeout time.Duration) uint64 {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		frames, _ := sumBridgeBenchStats(stats)
		if frames >= base+want {
			return frames - base
		}
		time.Sleep(100 * time.Microsecond)
	}
	frames, _ := sumBridgeBenchStats(stats)
	return frames - base
}

func writeBridgeBenchFrame(fd int, frame []byte) error {
	for {
		n, err := unix.Write(fd, frame)
		if err == nil {
			if n != len(frame) {
				return fmt.Errorf("short TAP write: %d/%d", n, len(frame))
			}
			return nil
		}
		if errors.Is(err, unix.EINTR) {
			continue
		}
		return err
	}
}

func benchLinuxTAPBridgeMultiQueue(b *testing.B, dstQueues, payloadSize int) {
	suffix := fmt.Sprintf("%d%d", dstQueues, payloadSize/100)
	srcFiles, dstFiles := setupBridgeBench(b, suffix, dstQueues)
	frames := make([][]byte, bridgeBenchFlows)
	for flow := range frames {
		frames[flow] = buildBridgeBenchFrame(payloadSize, flow)
	}

	ctx, cancel := context.WithCancel(context.Background())
	stats := make([]bridgeBenchStats, len(dstFiles))
	var readyWG, readerWG sync.WaitGroup
	readyWG.Add(len(dstFiles))
	readerWG.Add(len(dstFiles))
	for i := range dstFiles {
		go runBridgeBenchReader(ctx, int(dstFiles[i].Fd()), &stats[i], &readyWG, &readerWG)
	}
	readyWG.Wait()
	defer func() {
		cancel()
		readerWG.Wait()
	}()

	// Verify the bridge path before measuring it.
	warmBase, _ := sumBridgeBenchStats(stats)
	const warmFrames = 128
	for i := 0; i < warmFrames; i++ {
		fd := int(srcFiles[i%len(srcFiles)].Fd())
		if err := writeBridgeBenchFrame(fd, frames[i%len(frames)]); err != nil {
			b.Fatalf("bridge warmup write: %v", err)
		}
	}
	warmDelivered := waitBridgeBench(stats, warmBase, warmFrames, 500*time.Millisecond)
	if warmDelivered != warmFrames {
		b.Fatalf("bridge warmup delivered %d/%d benchmark frames", warmDelivered, warmFrames)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for iter := 0; iter < b.N; iter++ {
		beforeFrames, beforeBytes := sumBridgeBenchStats(stats)
		beforeQueues := make([]uint64, len(stats))
		for i := range stats {
			beforeQueues[i] = stats[i].frames.Load()
		}
		start := make(chan struct{})
		var sent atomic.Uint64
		var sendErr atomic.Value
		var sendWG sync.WaitGroup
		for writer := 0; writer < len(srcFiles); writer++ {
			writer := writer
			sendWG.Add(1)
			go func() {
				defer sendWG.Done()
				<-start
				localSent := 0
				for seq := writer; seq < bridgeBenchFrames; seq += len(srcFiles) {
					if err := writeBridgeBenchFrame(int(srcFiles[writer].Fd()), frames[seq%len(frames)]); err != nil {
						sendErr.Store(err)
						return
					}
					sent.Add(1)
					localSent++
					if localSent%bridgeBenchThrottleEvery != 0 {
						continue
					}
					deadline := time.Now().Add(2 * time.Millisecond)
					for time.Now().Before(deadline) {
						delivered, _ := sumBridgeBenchStats(stats)
						delivered -= beforeFrames
						if sent.Load() <= delivered+bridgeBenchWindow {
							break
						}
						time.Sleep(10 * time.Microsecond)
					}
				}
			}()
		}

		started := time.Now()
		close(start)
		sendWG.Wait()
		if v := sendErr.Load(); v != nil {
			b.Fatalf("bridge generator failed: %v", v)
		}
		_ = waitBridgeBench(stats, beforeFrames, sent.Load(), 750*time.Millisecond)
		elapsed := time.Since(started)
		afterFrames, afterBytes := sumBridgeBenchStats(stats)
		delivered := afterFrames - beforeFrames
		deliveredBytes := afterBytes - beforeBytes
		deliveredPct := 100 * float64(delivered) / float64(sent.Load())
		if deliveredPct < 99.0 {
			b.Fatalf("bridge benchmark delivery too low: %.3f%% (%d/%d)", deliveredPct, delivered, sent.Load())
		}
		b.ReportMetric(float64(delivered)/elapsed.Seconds(), "frames/s")
		b.ReportMetric(float64(deliveredBytes)/elapsed.Seconds()/1e6, "MB/s")
		b.ReportMetric(deliveredPct, "%delivered")
		for qi := range stats {
			qFrames := stats[qi].frames.Load() - beforeQueues[qi]
			b.ReportMetric(100*float64(qFrames)/float64(delivered), fmt.Sprintf("q%d%%", qi))
		}
	}
	b.StopTimer()
}

func BenchmarkLinuxTAPBridgeMultiQueue(b *testing.B) {
	for _, payloadSize := range []int{128, 1200} {
		payloadSize := payloadSize
		b.Run(fmt.Sprintf("payload_%d", payloadSize), func(b *testing.B) {
			for _, queues := range []int{1, 2, 4} {
				queues := queues
				b.Run(fmt.Sprintf("queues_%d", queues), func(b *testing.B) {
					benchLinuxTAPBridgeMultiQueue(b, queues, payloadSize)
				})
			}
		})
	}
}
