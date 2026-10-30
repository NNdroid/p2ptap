package node

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"p2ptap/pkg/config"
	"p2ptap/pkg/packet"
	"p2ptap/pkg/tap"
)

// buildOversizedIPv4Frame builds a complete Ethernet frame carrying one
// unfragmented IPv4 packet with payloadLen payload bytes (so the IP packet is
// 20+payloadLen bytes). The header checksum is valid.
func buildOversizedIPv4Frame(payloadLen int) []byte {
	totalLen := 20 + payloadLen
	frame := make([]byte, packet.EthernetHeaderLen+totalLen)
	copy(frame[0:6], net.HardwareAddr{0x02, 0, 0, 0, 0, 1})
	copy(frame[6:12], net.HardwareAddr{0x02, 0, 0, 0, 0, 2})
	binary.BigEndian.PutUint16(frame[12:14], packet.EtherTypeIPv4)
	ip := frame[packet.EthernetHeaderLen:]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(ip[4:6], 0x1234)
	ip[8] = 64
	ip[9] = 17
	copy(ip[12:16], net.IPv4(10, 0, 0, 1).To4())
	copy(ip[16:20], net.IPv4(10, 0, 0, 2).To4())
	for i := 0; i < payloadLen; i++ {
		ip[20+i] = byte(i*11 + 7)
	}
	binary.BigEndian.PutUint16(ip[10:12], packet.IPChecksum(ip[:20]))
	return frame
}

// readMemFrame reads a single frame from a MemTAP device with a timeout. It uses
// one reader goroutine per call because MemTAP forbids concurrent readers. ok is
// false if nothing arrived within the timeout. The result is delivered on a
// channel, so the caller never observes the goroutine's buffer mid-write.
func readMemFrame(t *testing.T, dev *tap.MemTAP, timeout time.Duration) (f []byte, ok bool) {
	t.Helper()
	ch := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 65535)
		rn, err := dev.Read(buf)
		if err != nil {
			ch <- nil
			return
		}
		f := make([]byte, rn)
		copy(f, buf[:rn])
		ch <- f
	}()
	select {
	case f := <-ch:
		return f, true
	case <-time.After(timeout):
		return nil, false
	}
}

// readMemFrames reads exactly n frames from a MemTAP device, one at a time.
func readMemFrames(t *testing.T, dev *tap.MemTAP, n int) [][]byte {
	t.Helper()
	frames := make([][]byte, 0, n)
	for i := 0; i < n; i++ {
		f, ok := readMemFrame(t, dev, 2*time.Second)
		if !ok {
			t.Fatalf("timed out reading frame %d/%d (got %d so far)", i+1, n, len(frames))
		}
		frames = append(frames, f)
	}
	return frames
}

// TestTapWriteRefragmentsOversizedIPv4 is the receiver-side MTU-asymmetry
// regression: a sender with MTU 1500 delivers a 1500-byte IP packet to a TAP
// with MTU 1400. Previously tapWrite dropped it (silent blackhole); now it is
// re-fragmented and delivered.
func TestTapWriteRefragmentsOversizedIPv4(t *testing.T) {
	a, b := tap.NewMemTAPPair("rfrag-a", "rfrag-b")
	n := &Node{TAP: a, Config: &config.Config{MTU: 1400}}

	frame := buildOversizedIPv4Frame(1480) // 1500-byte IP, 1514-byte frame
	wrote, err := n.tapWrite(frame)
	if err != nil {
		t.Fatalf("tapWrite: %v", err)
	}
	if wrote != len(frame) {
		t.Fatalf("tapWrite reported %d bytes, want %d (logical frame)", wrote, len(frame))
	}

	frags := readMemFrames(t, b, 2)
	if len(frags) != 2 {
		t.Fatalf("expected 2 fragments, got %d", len(frags))
	}
	// Each fragment must fit the device (<= MTU+14).
	for i, f := range frags {
		if len(f) > 1400+packet.EthernetHeaderLen {
			t.Fatalf("fragment %d is %d bytes > MTU+14", i, len(f))
		}
	}
	// Reassemble and verify byte-exact payload preservation + ID + offsets.
	var payload bytes.Buffer
	var lastOffset int
	var id uint16
	for i, f := range frags {
		if packet.EtherType(f) != packet.EtherTypeIPv4 {
			t.Fatalf("fragment %d wrong ethertype", i)
		}
		ip := f[packet.EthernetHeaderLen:]
		ihl := int(ip[0]&0x0f) * 4
		totalLen := int(binary.BigEndian.Uint16(ip[2:4]))
		fo := binary.BigEndian.Uint16(ip[6:8])
		if i == 0 {
			id = binary.BigEndian.Uint16(ip[4:6])
		} else if binary.BigEndian.Uint16(ip[4:6]) != id {
			t.Fatalf("fragment %d ID mismatch", i)
		}
		if i == 0 && fo&0x4000 != 0 {
			t.Fatalf("fragment 0 still has DF set")
		}
		if i == len(frags)-1 && fo&0x2000 != 0 {
			t.Fatalf("last fragment has MF set")
		}
		if i < len(frags)-1 && fo&0x2000 == 0 {
			t.Fatalf("non-last fragment %d lacks MF", i)
		}
		off := int(fo&0x1fff) * 8
		if i > 0 && off <= lastOffset {
			t.Fatalf("fragment %d offset %d not increasing", i, off)
		}
		lastOffset = off
		payload.Write(ip[ihl:totalLen])
	}
	want := frame[packet.EthernetHeaderLen+20:]
	if !bytes.Equal(payload.Bytes(), want) {
		t.Fatalf("reassembled payload mismatch: got %d bytes, want %d", payload.Len(), len(want))
	}
}

// TestTapWriteRefragmentsOversizedIPv6 covers the IPv6 branch (Fragment header
// insertion + identification).
func TestTapWriteRefragmentsOversizedIPv6(t *testing.T) {
	a, b := tap.NewMemTAPPair("rfrag6-a", "rfrag6-b")
	n := &Node{TAP: a, Config: &config.Config{MTU: 1400}}

	payloadLen := 1480
	total := 40 + payloadLen
	frame := make([]byte, packet.EthernetHeaderLen+total)
	copy(frame[0:6], net.HardwareAddr{0x02, 0, 0, 0, 0, 1})
	copy(frame[6:12], net.HardwareAddr{0x02, 0, 0, 0, 0, 2})
	binary.BigEndian.PutUint16(frame[12:14], packet.EtherTypeIPv6)
	ip := frame[packet.EthernetHeaderLen:]
	ip[0] = 0x60
	binary.BigEndian.PutUint16(ip[4:6], uint16(payloadLen))
	ip[6] = 17 // UDP
	ip[7] = 64
	copy(ip[8:24], net.ParseIP("2001:db8::1").To16())
	copy(ip[24:40], net.ParseIP("2001:db8::2").To16())
	for i := 0; i < payloadLen; i++ {
		ip[40+i] = byte(i*3 + 9)
	}

	wrote, err := n.tapWrite(frame)
	if err != nil {
		t.Fatalf("tapWrite: %v", err)
	}
	if wrote != len(frame) {
		t.Fatalf("tapWrite reported %d bytes, want %d", wrote, len(frame))
	}

	frags := readMemFrames(t, b, 2)
	if len(frags) != 2 {
		t.Fatalf("expected 2 fragments, got %d", len(frags))
	}
	var payload bytes.Buffer
	var fragID uint32
	for i, f := range frags {
		if packet.EtherType(f) != packet.EtherTypeIPv6 {
			t.Fatalf("fragment %d wrong ethertype", i)
		}
		ip := f[packet.EthernetHeaderLen:]
		if ip[6] != 44 {
			t.Fatalf("fragment %d next header %d != 44", i, ip[6])
		}
		if ip[40] != 17 {
			t.Fatalf("fragment %d frag next header %d != 17", i, ip[40])
		}
		if i == 0 {
			fragID = binary.BigEndian.Uint32(ip[44:48])
		} else if binary.BigEndian.Uint32(ip[44:48]) != fragID {
			t.Fatalf("fragment %d identification mismatch", i)
		}
		offM := binary.BigEndian.Uint16(ip[42:44])
		if i == len(frags)-1 && offM&1 != 0 {
			t.Fatalf("last IPv6 fragment has M set")
		}
		pLen := int(binary.BigEndian.Uint16(ip[4:6]))
		payload.Write(ip[48 : 48+pLen-8])
	}
	want := frame[packet.EthernetHeaderLen+40:]
	if !bytes.Equal(payload.Bytes(), want) {
		t.Fatalf("IPv6 reassembled payload mismatch: got %d bytes, want %d", payload.Len(), len(want))
	}
}

// TestPrepareTapWriteJobRefragmentsOversized is the receive-path regression:
// the reorder gate pools frames with prepareTapWriteJob, which used to reject
// oversized frames outright (dropping them before tapWrite could re-fragment).
// Now it pools them, and enqueueTapWritePrepared re-fragments at write time.
func TestPrepareTapWriteJobRefragmentsOversized(t *testing.T) {
	a, b := tap.NewMemTAPPair("rfragp-a", "rfragp-b")
	n := &Node{TAP: a, Config: &config.Config{MTU: 1400}}

	frame := buildOversizedIPv4Frame(1480)
	job, err := n.prepareTapWriteJob(frame, false, "", "")
	if err != nil {
		t.Fatalf("prepareTapWriteJob must accept an oversized frame, got: %v", err)
	}
	n.enqueueTapWritePrepared(job) // no tapWriteLoop running => synchronous fallback

	frags := readMemFrames(t, b, 2)
	if len(frags) != 2 {
		t.Fatalf("expected 2 fragments, got %d", len(frags))
	}
	var payload bytes.Buffer
	for i, f := range frags {
		if len(f) > 1400+packet.EthernetHeaderLen {
			t.Fatalf("fragment %d is %d bytes > MTU+14", i, len(f))
		}
		ip := f[packet.EthernetHeaderLen:]
		ihl := int(ip[0]&0x0f) * 4
		totalLen := int(binary.BigEndian.Uint16(ip[2:4]))
		payload.Write(ip[ihl:totalLen])
	}
	want := frame[packet.EthernetHeaderLen+20:]
	if !bytes.Equal(payload.Bytes(), want) {
		t.Fatalf("reassembled payload mismatch via pooled path: got %d bytes, want %d", payload.Len(), len(want))
	}
}

// TestTapWriteDropsNonRefragmentableOversized: an oversized frame that is
// already an IP fragment cannot be re-fragmented and must still fail (the
// previous drop behaviour) rather than corrupting the stream.
func TestTapWriteDropsNonRefragmentableOversized(t *testing.T) {
	a, b := tap.NewMemTAPPair("rfragd-a", "rfragd-b")
	n := &Node{TAP: a, Config: &config.Config{MTU: 1400}}

	frame := buildOversizedIPv4Frame(1480)
	ip := frame[packet.EthernetHeaderLen:]
	binary.BigEndian.PutUint16(ip[6:8], 0x2000) // MF set => already a fragment
	binary.BigEndian.PutUint16(ip[10:12], 0)    // zero before recomputing
	binary.BigEndian.PutUint16(ip[10:12], packet.IPChecksum(ip[:20]))

	wrote, err := n.tapWrite(frame)
	if err == nil {
		t.Fatalf("expected an error for a non-refragmentable oversized frame, got nil (wrote=%d)", wrote)
	}
	if wrote != 0 {
		t.Fatalf("wrote %d bytes on failure", wrote)
	}
	// Nothing must have been written to the device: a timed read must time out.
	if f, ok := readMemFrame(t, b, 150*time.Millisecond); ok {
		t.Fatalf("expected no frames written, got %d bytes", len(f))
	}
}
