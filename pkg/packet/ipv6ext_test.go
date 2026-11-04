package packet

import "testing"

func TestIPv6ExtHeaderLen(t *testing.T) {
	cases := []struct {
		name   string
		nh     byte
		hdr    []byte
		want   int
		wantOK bool
	}{
		// Hdr Ext Len = 0 -> 8 bytes (minimum options header).
		{"hopbyhop min", 0, []byte{58, 0, 0, 0, 0, 0, 0, 0}, 8, true},
		// Hdr Ext Len = 255 -> (255+1)*8 = 2048. The historical 4-bit mask
		// computed 8 here and misparsed every long options header.
		{"hopbyhop max", 0, []byte{58, 255, 0, 0, 0, 0, 0, 0}, 2048, true},
		{"routing", 43, []byte{58, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 24, true},
		{"destopts", 60, []byte{58, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 16, true},
		// Fragment is fixed-length; hdr[1] is reserved and ignored.
		{"fragment fixed", 44, []byte{58, 0, 0, 0, 0, 0, 0, 0}, 8, true},
		// AH: PayloadLen = 1 -> (1+2)*4 = 12 bytes (RFC 4302 minimum, no ICV).
		{"ah min", 51, []byte{58, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 12, true},
		// AH: PayloadLen = 0 was misparsed as 4 bytes by the old (x+1)*4 form;
		// the RFC formula gives 8.
		{"ah payloadlen0", 51, []byte{58, 0, 0, 0, 0, 0, 0, 0}, 8, true},
		{"ah max", 51, append([]byte{58, 255}, make([]byte, 1023)...), (255 + 2) * 4, true},
		// Not length-encoded extension headers.
		{"tcp is not ext", 6, []byte{0, 0}, 0, false},
		{"icmpv6 is not ext", 58, []byte{0, 0}, 0, false},
		{"esp is not ext", 50, []byte{0, 0}, 0, false},
		// Truncated below the length field.
		{"truncated", 0, []byte{58}, 0, false},
		{"empty", 0, nil, 0, false},
	}
	for _, tc := range cases {
		got, ok := IPv6ExtHeaderLen(tc.nh, tc.hdr)
		if ok != tc.wantOK || (ok && got != tc.want) {
			t.Errorf("%s: IPv6ExtHeaderLen(%d, %d bytes) = (%d, %v), want (%d, %v)",
				tc.name, tc.nh, len(tc.hdr), got, ok, tc.want, tc.wantOK)
		}
	}
}
