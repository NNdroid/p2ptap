package packet

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
)

// buildIPv4Frame builds a complete Ethernet frame carrying one unfragmented IPv4
// packet: ethHeader (dst+src MAC, EtherTypeIPv4), a 20-byte IP header with the
// given total length / DF / ID, and a payload of exactly totalLen-20 bytes.
// The header checksum is set correctly so IPChecksum validation can run.
func buildIPv4Frame(payloadLen int, id uint16, df bool) []byte {
	totalLen := 20 + payloadLen
	frame := make([]byte, EthernetHeaderLen+totalLen)
	copy(frame[0:6], net.HardwareAddr{0x02, 0, 0, 0, 0, 1})  // dst
	copy(frame[6:12], net.HardwareAddr{0x02, 0, 0, 0, 0, 2}) // src
	binary.BigEndian.PutUint16(frame[12:14], EtherTypeIPv4)
	ip := frame[EthernetHeaderLen:]
	ip[0] = 0x45 // version 4, IHL 5
	binary.BigEndian.PutUint16(ip[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(ip[4:6], id)
	ip[8] = 64 // TTL
	ip[9] = 17 // UDP
	copy(ip[12:16], net.IPv4(10, 0, 0, 1).To4())
	copy(ip[16:20], net.IPv4(10, 0, 0, 2).To4())
	if df {
		binary.BigEndian.PutUint16(ip[6:8], 0x4000)
	}
	// Fill payload with a deterministic pattern so byte preservation is checkable.
	for i := 0; i < payloadLen; i++ {
		ip[20+i] = byte(i*7 + 3)
	}
	binary.BigEndian.PutUint16(ip[10:12], IPChecksum(ip[:20]))
	return frame
}

// reassembleIPv4 recombines fragments (sorted by offset) into the original IP
// datagram and verifies each fragment's invariants. Returns the reconstructed
// IP payload (after the first fragment's header) and the ID.
func reassembleIPv4(t *testing.T, frames [][]byte) ([]byte, uint16) {
	t.Helper()
	if len(frames) == 0 {
		t.Fatal("no fragments")
	}
	type frag struct {
		off   int
		mf    bool
		ip    []byte
		chunk []byte
	}
	var fl []frag
	var id uint16
	for i, f := range frames {
		if len(f) < EthernetHeaderLen+20 {
			t.Fatalf("fragment %d too short", i)
		}
		if EtherType(f) != EtherTypeIPv4 {
			t.Fatalf("fragment %d wrong ethertype", i)
		}
		ip := f[EthernetHeaderLen:]
		if ip[0]>>4 != 4 {
			t.Fatalf("fragment %d not IPv4", i)
		}
		ihl := int(ip[0]&0x0f) * 4
		totalLen := int(binary.BigEndian.Uint16(ip[2:4]))
		if totalLen < ihl || totalLen > len(ip) {
			t.Fatalf("fragment %d bad totalLen %d (len %d)", i, totalLen, len(ip))
		}
		ck := binary.BigEndian.Uint16(ip[10:12])
		binary.BigEndian.PutUint16(ip[10:12], 0)
		if ck != IPChecksum(ip[:ihl]) {
			t.Fatalf("fragment %d bad header checksum %#04x", i, ck)
		}
		binary.BigEndian.PutUint16(ip[10:12], ck)
		fo := binary.BigEndian.Uint16(ip[6:8])
		if fo&0x4000 != 0 {
			t.Fatalf("fragment %d DF still set", i)
		}
		mf := fo&0x2000 != 0
		off := int(fo&0x1fff) * 8
		if i == 0 && id == 0 {
			id = binary.BigEndian.Uint16(ip[4:6])
		} else if got := binary.BigEndian.Uint16(ip[4:6]); got != id {
			t.Fatalf("fragment %d ID %d != %d", i, got, id)
		}
		fl = append(fl, frag{off: off, mf: mf, ip: ip, chunk: ip[ihl:totalLen]})
	}
	// Last fragment must not have MF; all others must.
	for i := range fl {
		if i == len(fl)-1 && fl[i].mf {
			t.Fatalf("last fragment has MF set")
		}
		if i < len(fl)-1 && !fl[i].mf {
			t.Fatalf("non-last fragment %d lacks MF", i)
		}
	}
	// Offsets must be strictly increasing by multiples of 8.
	for i := 1; i < len(fl); i++ {
		if fl[i].off <= fl[i-1].off {
			t.Fatalf("fragment %d offset %d not increasing", i, fl[i].off)
		}
		if fl[i].off%8 != 0 {
			t.Fatalf("fragment %d offset %d not multiple of 8", i, fl[i].off)
		}
	}
	// Reassemble: concatenate chunks in offset order.
	var buf bytes.Buffer
	for _, f := range fl {
		buf.Write(f.chunk)
	}
	return buf.Bytes(), id
}

func TestRefragmentIPv4(t *testing.T) {
	payloadLen := 3000 // 3000 > 1400-20, forces 3 fragments at MTU 1400
	frame := buildIPv4Frame(payloadLen, 0xabcd, true)
	frames := Refragment(frame, 1400, 0)
	if len(frames) == 0 {
		t.Fatal("expected fragments, got nil")
	}
	got, id := reassembleIPv4(t, frames)
	if id != 0xabcd {
		t.Fatalf("ID not preserved: got %#04x want 0xabcd", id)
	}
	// Reconstructed payload must match the original pattern exactly.
	want := frame[EthernetHeaderLen+20:]
	if !bytes.Equal(got, want) {
		t.Fatalf("reassembled payload mismatch: got %d bytes, want %d", len(got), len(want))
	}
	// Every fragment's IP length must be <= 1400.
	for i, f := range frames {
		ip := f[EthernetHeaderLen:]
		totalLen := int(binary.BigEndian.Uint16(ip[2:4]))
		if totalLen > 1400 {
			t.Fatalf("fragment %d IP length %d > 1400", i, totalLen)
		}
		if len(f) > 1400+EthernetHeaderLen {
			t.Fatalf("fragment %d frame length %d exceeds MTU+14", i, len(f))
		}
	}
}

func TestRefragmentIPv4AlreadyFits(t *testing.T) {
	frame := buildIPv4Frame(100, 1, false)
	if got := Refragment(frame, 1400, 0); got != nil {
		t.Fatalf("fits frame should not be re-fragmented, got %d frames", len(got))
	}
}

func TestRefragmentIPv4ExactBoundary(t *testing.T) {
	// Payload of exactly 1400-20 = 1380 bytes: one fragment, should not split.
	frame := buildIPv4Frame(1380, 2, false)
	if got := Refragment(frame, 1400, 0); got != nil {
		t.Fatalf("exact-fit frame should not be re-fragmented, got %d frames", len(got))
	}
	// One byte over -> splits into two.
	frame2 := buildIPv4Frame(1381, 2, false)
	got := Refragment(frame2, 1400, 0)
	if len(got) != 2 {
		t.Fatalf("one-byte-over frame should split into 2, got %d", len(got))
	}
}

func TestRefragmentIPv4AlreadyFragment(t *testing.T) {
	// Set MF (0x2000) and an offset: must be refused.
	frame := buildIPv4Frame(200, 3, false)
	ip := frame[EthernetHeaderLen:]
	binary.BigEndian.PutUint16(ip[6:8], 0x2000)
	binary.BigEndian.PutUint16(ip[10:12], IPChecksum(ip[:20]))
	if got := Refragment(frame, 1400, 0); got != nil {
		t.Fatalf("already-fragmented frame should be refused, got %d frames", len(got))
	}
}

func TestRefragmentNonIP(t *testing.T) {
	// ARP frame (28 bytes payload).
	frame := make([]byte, EthernetHeaderLen+28)
	copy(frame[0:6], net.HardwareAddr{1, 2, 3, 4, 5, 6})
	copy(frame[6:12], net.HardwareAddr{6, 5, 4, 3, 2, 1})
	binary.BigEndian.PutUint16(frame[12:14], EtherTypeARP)
	if got := Refragment(frame, 1400, 0); got != nil {
		t.Fatalf("ARP should not be re-fragmented, got %d frames", len(got))
	}
}

func TestRefragmentMalformed(t *testing.T) {
	if got := Refragment([]byte{1, 2, 3}, 1400, 0); got != nil {
		t.Fatalf("short frame should be refused")
	}
	frame := buildIPv4Frame(100, 4, false)
	frame[EthernetHeaderLen] = 0x4f // IHL 15 -> ihl=60 > len(ip)
	if got := Refragment(frame, 1400, 0); got != nil {
		t.Fatalf("bad IHL should be refused")
	}
	if got := Refragment(buildIPv4Frame(100, 5, false), 0, 0); got != nil {
		t.Fatalf("mtu<=0 should be refused")
	}
}

// buildIPv6Frame builds a complete Ethernet frame carrying one unfragmented IPv6
// packet with an upper-layer next header (default UDP=17) and payloadLen payload
// bytes after the 40-byte base header.
func buildIPv6Frame(payloadLen int, nextHdr byte, id uint32) []byte {
	total := 40 + payloadLen
	frame := make([]byte, EthernetHeaderLen+total)
	copy(frame[0:6], net.HardwareAddr{0x02, 0, 0, 0, 0, 1})
	copy(frame[6:12], net.HardwareAddr{0x02, 0, 0, 0, 0, 2})
	binary.BigEndian.PutUint16(frame[12:14], EtherTypeIPv6)
	ip := frame[EthernetHeaderLen:]
	ip[0] = 0x60 // version 6
	binary.BigEndian.PutUint16(ip[4:6], uint16(payloadLen))
	ip[6] = nextHdr
	ip[7] = 64
	copy(ip[8:24], net.ParseIP("2001:db8::1").To16())
	copy(ip[24:40], net.ParseIP("2001:db8::2").To16())
	for i := 0; i < payloadLen; i++ {
		ip[40+i] = byte(i*5 + 1)
	}
	_ = id
	return frame
}

func TestRefragmentIPv6(t *testing.T) {
	payloadLen := 3000
	frame := buildIPv6Frame(payloadLen, 17, 0)
	frames := Refragment(frame, 1400, 0xfeedbeef)
	if len(frames) == 0 {
		t.Fatal("expected IPv6 fragments, got nil")
	}
	// Verify invariants and reassemble.
	type frag struct {
		off   int
		m     bool
		chunk []byte
	}
	var fl []frag
	for i, f := range frames {
		if len(f) < EthernetHeaderLen+48 {
			t.Fatalf("fragment %d too short", i)
		}
		if EtherType(f) != EtherTypeIPv6 {
			t.Fatalf("fragment %d wrong ethertype", i)
		}
		ip := f[EthernetHeaderLen:]
		if ip[0]>>4 != 6 {
			t.Fatalf("fragment %d not IPv6", i)
		}
		if ip[6] != 44 {
			t.Fatalf("fragment %d next header %d != 44 (Fragment)", i, ip[6])
		}
		pLen := int(binary.BigEndian.Uint16(ip[4:6]))
		if pLen != 8+len(ip)-48 {
			t.Fatalf("fragment %d payload len %d != frag hdr+chunk", i, pLen)
		}
		if ip[40] != 17 {
			t.Fatalf("fragment %d frag-hdr next header %d != 17", i, ip[40])
		}
		if got := binary.BigEndian.Uint32(ip[44:48]); got != 0xfeedbeef {
			t.Fatalf("fragment %d identification %#08x != 0xfeedbeef", i, got)
		}
		if len(f) > 1400+EthernetHeaderLen {
			t.Fatalf("fragment %d frame length %d exceeds MTU+14", i, len(f))
		}
		offM := binary.BigEndian.Uint16(ip[42:44])
		m := offM&1 != 0
		off := int(offM>>3) * 8
		if off%8 != 0 {
			t.Fatalf("fragment %d offset %d not multiple of 8", i, off)
		}
		fl = append(fl, frag{off: off, m: m, chunk: ip[48:]})
	}
	for i := range fl {
		if i == len(fl)-1 && fl[i].m {
			t.Fatal("last IPv6 fragment has M set")
		}
		if i < len(fl)-1 && !fl[i].m {
			t.Fatalf("non-last IPv6 fragment %d lacks M", i)
		}
	}
	var buf bytes.Buffer
	for _, f := range fl {
		buf.Write(f.chunk)
	}
	want := frame[EthernetHeaderLen+40:]
	if !bytes.Equal(buf.Bytes(), want) {
		t.Fatalf("IPv6 reassembled payload mismatch: got %d bytes, want %d", buf.Len(), len(want))
	}
}

func TestRefragmentIPv6ExtensionHeader(t *testing.T) {
	// Hop-by-Hop (0) precedes payload -> ambiguous insertion, must be refused.
	frame := buildIPv6Frame(3000, 0, 0)
	if got := Refragment(frame, 1400, 1); got != nil {
		t.Fatalf("IPv6 with Hop-by-Hop should be refused, got %d frames", len(got))
	}
	// Already a fragment (next header 44) -> refused.
	frame2 := buildIPv6Frame(3000, 44, 0)
	if got := Refragment(frame2, 1400, 1); got != nil {
		t.Fatalf("IPv6 already-fragmented should be refused, got %d frames", len(got))
	}
}

func TestRefragmentIPv6Fits(t *testing.T) {
	frame := buildIPv6Frame(100, 17, 0)
	if got := Refragment(frame, 1400, 1); got != nil {
		t.Fatalf("fitting IPv6 frame should not be re-fragmented, got %d frames", len(got))
	}
}
