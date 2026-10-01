//go:build linux && !android
// +build linux,!android

package tap

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	realTAPStableFrames          = 20000
	realTAPStableSenders         = 16
	realTAPStableWarmupPerSender = 4
	realTAPStableWindow          = 128
	realTAPStableThrottleEvery   = 16
	realTAPStablePortBase        = 42000
)

func isStableBenchUDPFrame(frame []byte, target [4]byte) bool {
	if len(frame) < 14+20+8 || frame[12] != 0x08 || frame[13] != 0x00 {
		return false
	}
	ip := frame[14:]
	if ip[0]>>4 != 4 || ip[9] != unix.IPPROTO_UDP {
		return false
	}
	ihl := int(ip[0]&0x0f) * 4
	if ihl < 20 || len(ip) < ihl+8 {
		return false
	}
	if ip[16] != target[0] || ip[17] != target[1] || ip[18] != target[2] || ip[19] != target[3] {
		return false
	}
	udp := ip[ihl:]
	port := int(binary.BigEndian.Uint16(udp[2:4]))
	return port >= realTAPStablePortBase && port < realTAPStablePortBase+realTAPStableSenders
}

func runReadyRealTAPQueueReader(ctx context.Context, fileFD int, target [4]byte, stats *realTAPMQReader, ready *sync.WaitGroup, wg *sync.WaitGroup) {
	defer wg.Done()
	epfd, err := unix.EpollCreate1(unix.EPOLL_CLOEXEC)
	if err != nil {
		ready.Done()
		return
	}
	defer unix.Close(epfd)
	if err := unix.EpollCtl(epfd, unix.EPOLL_CTL_ADD, fileFD, &unix.EpollEvent{Events: unix.EPOLLIN, Fd: int32(fileFD)}); err != nil {
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
			rn, rerr := unix.Read(fileFD, buf)
			if rerr != nil {
				if errors.Is(rerr, unix.EINTR) {
					continue
				}
				if errors.Is(rerr, unix.EAGAIN) || errors.Is(rerr, unix.EWOULDBLOCK) {
					break
				}
				return
			}
			if rn > 0 && isStableBenchUDPFrame(buf[:rn], target) {
				stats.frames.Add(1)
				stats.bytes.Add(uint64(rn))
			}
		}
	}
}

func waitForRealTAPFrames(readers []realTAPMQReader, base, want uint64, timeout time.Duration) uint64 {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		frames, _ := sumRealTAPReaders(readers)
		if frames >= base+want {
			return frames - base
		}
		time.Sleep(250 * time.Microsecond)
	}
	frames, _ := sumRealTAPReaders(readers)
	if frames < base {
		return 0
	}
	return frames - base
}

func ensureStableBenchRoute(b *testing.B, name string, targetIP net.IP) net.IP {
	b.Helper()
	link, err := netlink.LinkByName(name)
	if err != nil {
		b.Fatalf("LinkByName(%s): %v", name, err)
	}
	mask := net.CIDRMask(24, 32)
	dst := &net.IPNet{IP: targetIP.Mask(mask), Mask: mask}
	if err := netlink.RouteReplace(&netlink.Route{LinkIndex: link.Attrs().Index, Dst: dst, Scope: netlink.SCOPE_LINK}); err != nil {
		b.Fatalf("RouteReplace(%s via %s): %v", dst, name, err)
	}
	routes, err := netlink.RouteGet(targetIP)
	if err != nil {
		b.Fatalf("RouteGet(%s): %v", targetIP, err)
	}
	found := false
	for _, route := range routes {
		if route.LinkIndex == link.Attrs().Index {
			found = true
			break
		}
	}
	if !found {
		b.Fatalf("target %s is not routed through %s (link index %d): %+v", targetIP, name, link.Attrs().Index, routes)
	}
	localIP := append(net.IP(nil), targetIP.To4()...)
	localIP[3] = 1
	return localIP
}

func benchRealTAPMultiQueueStable(b *testing.B, queues, payloadSize, subnetOctet int) {
	name := fmt.Sprintf("p2pst%d%d", queues, payloadSize/100)
	files, targetIP := openRealTAPMultiQueue(b, name, queues, subnetOctet)
	localIP := ensureStableBenchRoute(b, name, targetIP)
	target4 := targetIP.To4()
	var target [4]byte
	copy(target[:], target4)

	ctx, cancel := context.WithCancel(context.Background())
	readers := make([]realTAPMQReader, len(files))
	var readyWG sync.WaitGroup
	var readerWG sync.WaitGroup
	readyWG.Add(len(files))
	readerWG.Add(len(files))
	for i := range files {
		go runReadyRealTAPQueueReader(ctx, int(files[i].Fd()), target, &readers[i], &readyWG, &readerWG)
	}
	readyWG.Wait()
	defer func() {
		cancel()
		readerWG.Wait()
	}()

	payload := make([]byte, payloadSize)
	for i := range payload {
		payload[i] = byte(i)
	}

	conns := make([]*net.UDPConn, realTAPStableSenders)
	for sender := 0; sender < realTAPStableSenders; sender++ {
		local := &net.UDPAddr{IP: localIP}
		dst := &net.UDPAddr{IP: targetIP, Port: realTAPStablePortBase + sender}
		conn, err := net.DialUDP("udp4", local, dst)
		if err != nil {
			b.Fatalf("DialUDP sender %d: %v", sender, err)
		}
		conns[sender] = conn
		defer conn.Close()
	}

	// Warm every flow only after all queue readers have registered with epoll.
	warmBase, _ := sumRealTAPReaders(readers)
	for sender := range conns {
		for i := 0; i < realTAPStableWarmupPerSender; i++ {
			if _, err := conns[sender].Write(payload); err != nil {
				b.Fatalf("warmup sender %d: %v", sender, err)
			}
		}
	}
	warmWant := uint64(realTAPStableSenders * realTAPStableWarmupPerSender)
	warmDelivered := waitForRealTAPFrames(readers, warmBase, warmWant, 500*time.Millisecond)
	if warmDelivered < warmWant*95/100 {
		b.Fatalf("warmup benchmark UDP unstable: delivered=%d want=%d route=%s->%s dev=%s", warmDelivered, warmWant, localIP, targetIP, name)
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
		for sender := range conns {
			sender := sender
			sendWG.Add(1)
			go func() {
				defer sendWG.Done()
				<-start
				localSent := 0
				for seq := sender; seq < realTAPStableFrames; seq += realTAPStableSenders {
					if _, err := conns[sender].Write(payload); err != nil {
						sendErr.Store(err)
						return
					}
					sent.Add(1)
					localSent++
					if localSent%realTAPStableThrottleEvery != 0 {
						continue
					}
					deadline := time.Now().Add(2 * time.Millisecond)
					for time.Now().Before(deadline) {
						curFrames, _ := sumRealTAPReaders(readers)
						delivered := curFrames - beforeFrames
						if sent.Load() <= delivered+realTAPStableWindow {
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
			b.Fatalf("UDP generator failed: %v", v)
		}
		_ = waitForRealTAPFrames(readers, beforeFrames, sent.Load(), 750*time.Millisecond)
		elapsed := time.Since(started)
		afterFrames, afterBytes := sumRealTAPReaders(readers)
		delivered := afterFrames - beforeFrames
		deliveredBytes := afterBytes - beforeBytes
		if delivered == 0 {
			b.Fatal("stable real TAP benchmark delivered zero matching UDP frames")
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

func BenchmarkLinuxRealTAPMultiQueueStable(b *testing.B) {
	for _, payloadSize := range []int{128, 1200} {
		payloadSize := payloadSize
		b.Run(fmt.Sprintf("payload_%d", payloadSize), func(b *testing.B) {
			for _, queues := range []int{1, 2, 4} {
				queues := queues
				b.Run(fmt.Sprintf("queues_%d", queues), func(b *testing.B) {
					subnetOctet := 70 + payloadSize/100 + queues
					benchRealTAPMultiQueueStable(b, queues, payloadSize, subnetOctet)
				})
			}
		})
	}
}
