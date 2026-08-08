package obfuscate

import (
	"bytes"
	"testing"
)

func TestFramePackAndUnpackModes(t *testing.T) {
	modes := []string{"fixed", "block", "random", "dynamic", "auto"}
	originalPayload := []byte("Hello P2P TAP VPN Packet Obfuscation Test Payload Data!")

	for _, mode := range modes {
		t.Run("Mode_"+mode, func(t *testing.T) {
			packer := NewFramePacker(true, mode, 512, 128)
			outBuf := make([]byte, 2048)

			seqID := packer.NextSeqID()
			totalLen, err := packer.Pack(seqID, originalPayload, outBuf)
			if err != nil {
				t.Fatalf("Pack failed in mode %s: %v", mode, err)
			}

			if mode == "fixed" && (totalLen < 512-64 || totalLen > 512+64) {
				t.Errorf("Fixed mode expected totalLen within [448, 576], got %d", totalLen)
			}

			if mode == "block" && totalLen < 64 {
				t.Errorf("Block mode expected totalLen >= 64, got %d", totalLen)
			}

			recvSeq, unpackedPayload, err := Unpack(outBuf[:totalLen])
			if err != nil {
				t.Fatalf("Unpack failed in mode %s: %v", mode, err)
			}

			if recvSeq != seqID {
				t.Errorf("SeqID mismatch: sent %d, got %d", seqID, recvSeq)
			}

			if !bytes.Equal(unpackedPayload, originalPayload) {
				t.Errorf("Payload corrupted in mode %s! Got %s", mode, string(unpackedPayload))
			}
		})
	}
}

func TestDeduplicator(t *testing.T) {
	dedup := NewDeduplicator()

	// Seq 1: new
	if dedup.IsDuplicate(1) {
		t.Error("Seq 1 should not be duplicate")
	}

	// Seq 1 again: duplicate
	if !dedup.IsDuplicate(1) {
		t.Error("Seq 1 should be detected as duplicate")
	}

	// Seq 2, 3, 4: new
	for i := uint64(2); i <= 4; i++ {
		if dedup.IsDuplicate(i) {
			t.Errorf("Seq %d should not be duplicate", i)
		}
	}

	// Repeat Seq 3: duplicate
	if !dedup.IsDuplicate(3) {
		t.Error("Seq 3 should be detected as duplicate")
	}

	// Out of order receive: Seq 6 then Seq 5
	if dedup.IsDuplicate(6) {
		t.Error("Seq 6 should not be duplicate")
	}
	if dedup.IsDuplicate(5) {
		t.Error("Seq 5 out of order should not be duplicate")
	}
	if !dedup.IsDuplicate(5) {
		t.Error("Seq 5 repeated should be duplicate")
	}
}

func TestCorruptedFrameUnpack(t *testing.T) {
	buf := []byte{0x00, 0x00, 0x00} // Too short
	_, _, err := Unpack(buf)
	if err == nil {
		t.Error("Expected error for short buffer, got nil")
	}

	badMagic := []byte{0x12, 0x34, 0, 0, 0, 0, 0, 0, 0, 1, 0, 5, 0, 0, 'a', 'b', 'c', 'd', 'e'}
	_, unpacked, err := Unpack(badMagic)
	if err != nil || !bytes.Equal(unpacked, badMagic) {
		t.Errorf("Expected raw payload fallback for bad magic, got err=%v unpacked=%v", err, unpacked)
	}
}
