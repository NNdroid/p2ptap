package node

import (
	"bytes"
	"testing"

	"p2ptap/pkg/config"
	"p2ptap/pkg/obfuscate"
)

func TestTapPayloadLenFromPackedFrameExcludesFixedPadding(t *testing.T) {
	packer := obfuscate.NewFramePackerFull(&config.ObfuscationConfig{
		Enable:       true,
		PaddingRules: "0 -> 1500-1500",
	})
	packer.SetSourceIdentity("peer-speed-test")

	tests := []struct {
		name string
		size int
	}{
		{name: "tcp_ack_sized_frame", size: 54},
		{name: "full_ethernet_frame", size: 1514},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := bytes.Repeat([]byte{0x5a}, tt.size)
			out := make([]byte, packer.MaxPackedLen(len(payload)))
			n, err := packer.Pack(packer.NextSeqID(0), payload, out)
			if err != nil {
				t.Fatalf("Pack: %v", err)
			}
			if tt.size == 54 && n != obfuscate.HeaderLen+1500 {
				t.Fatalf("fixed padding precondition: packed ACK length = %d, want %d", n, obfuscate.HeaderLen+1500)
			}
			if got := tapPayloadLenFromPackedFrame(out[:n]); got != tt.size {
				t.Fatalf("TAP payload length = %d, want %d (packed=%d)", got, tt.size, n)
			}
		})
	}
}

func TestTapPayloadLenFromPackedFrameRejectsMalformedData(t *testing.T) {
	if got := tapPayloadLenFromPackedFrame([]byte("not a p2ptap frame")); got != 0 {
		t.Fatalf("malformed frame payload length = %d, want 0", got)
	}
}
