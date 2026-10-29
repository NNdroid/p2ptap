package node

import (
	"encoding/binary"
	"testing"

	"p2ptap/pkg/obfuscate"
)

// packedFrameForTest builds a minimal packed p2ptap frame whose payload is
// exactly payload, matching what Pack produces for the fields framePayloadStats
// reads (magic at [0:2], PayloadLen at [11:13]).
func packedFrameForTest(payload []byte) []byte {
	buf := make([]byte, obfuscate.HeaderLen+len(payload))
	binary.BigEndian.PutUint16(buf[0:2], obfuscate.FrameMagic)
	binary.BigEndian.PutUint16(buf[11:13], uint16(len(payload)))
	copy(buf[obfuscate.HeaderLen:], payload)
	return buf
}

func TestFramePayloadStatsSingle(t *testing.T) {
	payload := make([]byte, 100)
	stat := framePayloadStats(packedFrameForTest(payload))
	if stat.bytes != 100 || stat.frames != 1 {
		t.Fatalf("single frame: got %+v, want {100 1}", stat)
	}
}

func TestFramePayloadStatsBatch(t *testing.T) {
	subs := [][]byte{make([]byte, 20), make([]byte, 30), make([]byte, 40)}
	stat := framePayloadStats(packedFrameForTest(obfuscate.BuildBatchPayload(subs)))
	if stat.bytes != 90 || stat.frames != 3 {
		t.Fatalf("batch frame: got %+v, want {90 3}", stat)
	}
}

func TestFramePayloadStatsInvalid(t *testing.T) {
	// Non-p2ptap magic.
	if stat := framePayloadStats(make([]byte, 64)); stat.bytes != 0 || stat.frames != 0 {
		t.Fatalf("non-p2ptap: got %+v, want zero", stat)
	}
	// Header claims a payload longer than the buffer.
	bad := make([]byte, obfuscate.HeaderLen+10)
	binary.BigEndian.PutUint16(bad[0:2], obfuscate.FrameMagic)
	binary.BigEndian.PutUint16(bad[11:13], uint16(999))
	if stat := framePayloadStats(bad); stat.bytes != 0 || stat.frames != 0 {
		t.Fatalf("overlong payload: got %+v, want zero", stat)
	}
}
