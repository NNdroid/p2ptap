package web

import (
	"encoding/binary"
	"testing"
)

// benchFrameTCP builds an IPv4/TCP frame of the given total length whose
// payload is filled with a non-trivial byte pattern, so hex-dumping and
// protocol parsing see realistic input rather than a run of zeroes.
func benchFrameTCP(totalLen int) []byte {
	const ethLen, ipLen, tcpLen = 14, 20, 20
	frame := make([]byte, totalLen)
	copy(frame[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	copy(frame[6:12], []byte{0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc})
	binary.BigEndian.PutUint16(frame[12:14], 0x0800)

	ip := frame[ethLen:]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(totalLen-ethLen))
	binary.BigEndian.PutUint16(ip[4:6], 0x1234)
	ip[8] = 64
	ip[9] = 6 // TCP
	copy(ip[12:16], []byte{10, 0, 0, 1})
	copy(ip[16:20], []byte{10, 0, 0, 2})

	tcp := ip[ipLen:]
	binary.BigEndian.PutUint16(tcp[0:2], 443)
	binary.BigEndian.PutUint16(tcp[2:4], 51234)
	binary.BigEndian.PutUint32(tcp[4:8], 0xdeadbeef)
	tcp[12] = 5 << 4 // data offset
	tcp[13] = 0x18   // PSH,ACK
	binary.BigEndian.PutUint16(tcp[14:16], 65535)
	for i := range tcp[tcpLen:] {
		tcp[tcpLen+i] = byte(i * 7)
	}
	return frame
}

// BenchmarkParseFrame measures the per-captured-frame cost of the capture ring:
// the work that runs for every frame admitted by sampleEvery/maxRatePerSec. It
// exists to keep that path honest — a captured frame is parsed and
// ring-appended on the datapath, so anything added here is paid at line rate.
// The full-payload base64 copy that this benchmark outlived cost ~1.9KB of
// garbage per 1400B frame for a field no consumer ever read.
func BenchmarkParseFrame(b *testing.B) {
	for _, c := range []struct {
		name string
		f    []byte
	}{
		{"64B", benchFrameTCP(64)},
		{"1400B", benchFrameTCP(1400)},
	} {
		b.Run(c.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				cf := parseFrame(uint64(i), DirRx, c.f, 64, nil)
				if cf.Hex == "" {
					b.Fatal("empty hex dump")
				}
			}
		})
	}
}
