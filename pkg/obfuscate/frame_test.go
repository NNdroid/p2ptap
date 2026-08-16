package obfuscate

import (
	"bytes"
	"testing"

	"p2ptap/pkg/config"
)

func TestFramePackAndUnpackModes(t *testing.T) {
	modes := []string{"fixed", "block", "random", "dynamic", "auto"}
	originalPayload := []byte("Hello P2P TAP VPN Packet Obfuscation Test Payload Data!")

	for _, mode := range modes {
		t.Run("Mode_"+mode, func(t *testing.T) {
			t.Logf("[pack] mode=%s payloadLen=%d", mode, len(originalPayload))
			packer := NewFramePackerFull(&config.ObfuscationConfig{Enable: true, Mode: mode, FixedSize: 512, BlockSize: 128})
			outBuf := make([]byte, 2048)

			seqID := packer.NextSeqID(0)
			totalLen, err := packer.Pack(seqID, originalPayload, outBuf)
			if err != nil {
				t.Fatalf("Pack failed in mode %s: %v", mode, err)
			}
			t.Logf("[pack] mode=%s seqID=%d totalLen=%d", mode, seqID, totalLen)

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
			t.Logf("[unpack] mode=%s recvSeq=%d payloadLen=%d", mode, recvSeq, len(unpackedPayload))

			if recvSeq != seqID {
				t.Errorf("SeqID mismatch: sent %d, got %d", seqID, recvSeq)
			}

			if !bytes.Equal(unpackedPayload, originalPayload) {
				t.Errorf("Payload corrupted in mode %s! Got %s", mode, string(unpackedPayload))
			}
			t.Logf("[ok] mode=%s round-trip verified", mode)
		})
	}
}

func TestDeduplicator(t *testing.T) {
	dedup := NewDeduplicator()
	// Build structured SeqIDs via a packer so the ver/srcHash/ts fields are set.
	p := NewFramePackerFull(&config.ObfuscationConfig{Enable: false, Mode: "fixed", FixedSize: 512, BlockSize: 128})
	p.SetSourceIdentity("peerA")
	var seqs []uint64
	for i := 0; i < 8; i++ {
		seqs = append(seqs, p.NextSeqID(0))
	}
	t.Logf("[dedup] built %d structured seqIDs (peerA) first=%d last=%d", len(seqs), seqs[0], seqs[7])

	// Seq 0: new
	if dedup.IsDuplicate(seqs[0]) {
		t.Error("Seq 0 should not be duplicate")
	} else {
		t.Logf("[dedup] seq0=%d accepted as new", seqs[0])
	}
	// Seq 0 again: duplicate
	if !dedup.IsDuplicate(seqs[0]) {
		t.Error("Seq 0 should be detected as duplicate")
	} else {
		t.Logf("[dedup] seq0=%d detected as duplicate on repeat", seqs[0])
	}
	// Seq 1,2,3: new
	for i := 1; i <= 3; i++ {
		if dedup.IsDuplicate(seqs[i]) {
			t.Errorf("Seq %d should not be duplicate", i)
		} else {
			t.Logf("[dedup] seq%d=%d accepted as new", i, seqs[i])
		}
	}
	// Repeat seq 2: duplicate
	if !dedup.IsDuplicate(seqs[2]) {
		t.Error("Seq 2 should be detected as duplicate")
	} else {
		t.Logf("[dedup] seq2=%d detected as duplicate on repeat", seqs[2])
	}
	// Out of order: seq 6 then seq 5
	if dedup.IsDuplicate(seqs[6]) {
		t.Error("Seq 6 should not be duplicate")
	} else {
		t.Logf("[dedup] seq6=%d accepted (out-of-order, fresh)", seqs[6])
	}
	if dedup.IsDuplicate(seqs[5]) {
		t.Error("Seq 5 out of order should not be duplicate")
	} else {
		t.Logf("[dedup] seq5=%d accepted (out-of-order, fresh)", seqs[5])
	}
	if !dedup.IsDuplicate(seqs[5]) {
		t.Error("Seq 5 repeated should be duplicate")
	} else {
		t.Logf("[dedup] seq5=%d detected as duplicate on repeat", seqs[5])
	}
}

func TestSeqIDStructure(t *testing.T) {
	p := NewFramePackerFull(&config.ObfuscationConfig{Enable: false, Mode: "fixed", FixedSize: 512, BlockSize: 128})
	p.SetSourceIdentity("nodeXYZ")
	seq := p.NextSeqID(0)
	t.Logf("[seqid] raw=%d structured=%v srcHash=%d counter=%d", seq, IsStructuredSeq(seq), SrcHashFromSeq(seq), CounterFromSeq(seq))
	if !IsStructuredSeq(seq) {
		t.Fatalf("expected structured seq, got %d", seq)
	}
	if SrcHashFromSeq(seq) != SeqSrcHash("nodeXYZ") {
		t.Errorf("srcHash mismatch: got %d want %d", SrcHashFromSeq(seq), SeqSrcHash("nodeXYZ"))
	}
	if CounterFromSeq(seq) != 1 {
		t.Errorf("counter should start at 1, got %d", CounterFromSeq(seq))
	}
}

func TestSyncFromAnchorsWindow(t *testing.T) {
	dedup := NewDeduplicator()
	p := NewFramePackerFull(&config.ObfuscationConfig{Enable: false, Mode: "fixed", FixedSize: 512, BlockSize: 128})
	p.SetSourceIdentity("peerB")
	// Simulate peer having already sent up to seq #5000.
	remote := make([]uint64, 5001)
	for i := range remote {
		remote[i] = p.NextSeqID(0)
	}
	t.Logf("[anchor] simulating peerB already at seq#%d", remote[5000])
	dedup.SyncFrom(remote[5000])
	// The anchor itself is marked seen.
	if !dedup.IsDuplicate(remote[5000]) {
		t.Error("anchor frame should be duplicate")
	} else {
		t.Logf("[anchor] anchor seq#%d marked seen", remote[5000])
	}
	// The very next frame is accepted (forward).
	if dedup.IsDuplicate(remote[5000] + 1) {
		t.Error("frame after anchor should be accepted")
	} else {
		t.Logf("[anchor] next seq#%d accepted (forward)", remote[5000]+1)
	}
	// A repeated frame is a duplicate (bit set).
	if !dedup.IsDuplicate(remote[5000] + 1) {
		t.Error("repeated frame after anchor should be duplicate")
	} else {
		t.Logf("[anchor] repeated seq#%d detected duplicate", remote[5000]+1)
	}
	// A fresh-timestamped out-of-order frame below the anchor is still
	// accepted (bit not yet set) — out-of-order multi-path delivery must not
	// be dropped. Cross-session stale replays are caught by the timestamp age
	// check instead.
	if dedup.IsDuplicate(remote[10]) {
		t.Error("fresh out-of-order frame below anchor should be accepted")
	} else {
		t.Logf("[anchor] out-of-order seq#%d below anchor accepted (fresh)", remote[10])
	}
}

func TestReplayDropByConnEpoch(t *testing.T) {
	dedup := NewDeduplicator()
	// Negotiate an epoch of 0xABC with this peer during SeqSync.
	dedup.SetConnEpoch(0xABC)
	t.Logf("[epoch] connection epoch set to 0x%X", 0xABC)

	// A frame carrying the matching epoch is processed normally.
	good := seqVer1<<seqVerShift | (SeqSrcHash("peerC") << seqSrcShift) | (uint64(0xABC) << seqEpochShift) | 1
	if dedup.IsDuplicate(good) {
		t.Error("matching-epoch frame should not be dropped")
	} else {
		t.Logf("[epoch] matching-epoch frame (0x%X) accepted", 0xABC)
	}

	// A frame captured from a *previous* session uses a stale epoch and must
	// be rejected (cross-session replay protection, no wall-clock dependency).
	stale := seqVer1<<seqVerShift | (SeqSrcHash("peerC") << seqSrcShift) | (uint64(0x123) << seqEpochShift) | 1
	if !dedup.IsDuplicate(stale) {
		t.Error("stale-epoch (cross-session) replay should be dropped")
	} else {
		t.Logf("[epoch] stale-epoch frame (0x%X) dropped as cross-session replay", 0x123)
	}
}

// TestDedupWindowSlidesAfterCounterWrap is a regression test for the out-of-order
// frame drops that caused "unstable TAP transmission" over multi-path (direct +
// relay) links.
//
// The source counter is 32-bit but the dedup bitmask is keyed on its low 16 bits,
// which wrap every 65536 frames. The OLD eviction (evictBehind) only fired on
// large forward jumps, so for normal sequential traffic it never ran: every
// low-16 counter bit stayed set forever, and any out-of-order frame (routine
// under multi-path delivery) was dropped as a "duplicate". The fixed evictRange
// slides the 16-bit window on EVERY forward move, so stale bits are cleared and
// legitimate out-of-order frames are kept.
func TestDedupWindowSlidesAfterCounterWrap(t *testing.T) {
	dedup := NewDeduplicator()
	dedup.SetConnEpoch(0) // deterministic: every frame carries epoch 0

	// mkSeq builds a structured seqID with the given low-32 counter (epoch 0).
	mkSeq := func(c uint64) uint64 {
		return (seqVer1 << seqVerShift) |
			(uint64(0xA1B2) << seqSrcShift) |
			(uint64(0) << seqEpochShift) |
			(c & seqCntMask)
	}

	// Feed a long monotonic stream well past the 65536 low-16 wrap.
	const total = 70000
	for c := uint64(1); c <= total; c++ {
		if dedup.IsDuplicate(mkSeq(c)) {
			t.Fatalf("frame c=%d dropped as duplicate on first sequential pass", c)
		}
	}

	// Replay an out-of-order frame whose low-16 counter (50000) was seen ~20000
	// frames "ago" in the 16-bit projection — outside the 16384 out-of-order
	// tolerance, so its bit must have been evicted by the sliding window. Before
	// the fix this was wrongly dropped as a "duplicate".
	if dedup.IsDuplicate(mkSeq(50000)) {
		t.Errorf("out-of-order frame c=50000 wrongly dropped as duplicate; dedup window is not sliding")
	}

	// An exact repeat of a *recent* in-window counter must still be detected.
	if !dedup.IsDuplicate(mkSeq(69999)) {
		t.Errorf("recent duplicate c=69999 should be detected as duplicate")
	}
}

func TestCorruptedFrameUnpack(t *testing.T) {
	buf := []byte{0x00, 0x00, 0x00} // Too short
	t.Logf("[corrupt] unpack short buffer len=%d", len(buf))
	_, _, err := Unpack(buf)
	if err == nil {
		t.Error("Expected error for short buffer, got nil")
	} else {
		t.Logf("[corrupt] short buffer rejected: %v", err)
	}

	badMagic := []byte{0x12, 0x34, 0, 0, 0, 0, 0, 0, 0, 1, 0, 5, 0, 0, 'a', 'b', 'c', 'd', 'e'}
	t.Logf("[corrupt] unpack bad-magic header %x", badMagic[:2])
	_, _, err = Unpack(badMagic)
	if err == nil {
		t.Error("Expected error for bad magic, got nil")
	} else {
		t.Logf("[corrupt] bad-magic rejected: %v", err)
	}
}

// TestEncryptDecryptRoundTrip verifies the full Pack -> EncryptPayloadRegion
// -> DecryptPayloadRegion -> Unpack cycle and, crucially, that UnpackWith
// (which historically derived the AEAD nonce differently from EncryptPayloadRegion
// and could never open a real frame) now agrees with the encryptor. A mismatch
// here would mean the two code paths disagree on the nonce — the exact bug this
// regression test guards against.
func TestEncryptDecryptRoundTrip(t *testing.T) {
	packer := NewFramePackerFull(&config.ObfuscationConfig{Enable: true, Mode: "fixed", FixedSize: 1500, BlockSize: 256})
	packer.SetSourceIdentity("nodeA")
	// Stamp the ObfType byte so the frame header agrees with the cipher we
	// encrypt with — mirroring what the live send path does via SetSendAlgo.
	// Without it UnpackWith would treat the frame as plaintext (ObfType=none)
	// and return the raw ciphertext.
	packer.SetSendAlgo(ObfAlgoChaCha20)

	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	cipher, err := NewObfCipher(ObfAlgoChaCha20, key)
	if err != nil {
		t.Fatalf("NewObfCipher: %v", err)
	}
	t.Logf("[rt] cipher=chacha20 keyFP=%s", KeyFingerprint(key))

	payload := []byte("secret TAP payload over the encrypted overlay!!")
	outBuf := make([]byte, 4096)
	seqID := packer.NextSeqID(0)
	n, err := packer.Pack(seqID, payload, outBuf)
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	packed := outBuf[:n]
	t.Logf("[rt] packed seqID=%d frameLen=%d", seqID, n)

	enc, err := EncryptPayloadRegion(packed, cipher)
	if err != nil {
		t.Fatalf("EncryptPayloadRegion: %v", err)
	}
	t.Logf("[rt] after EncryptPayloadRegion encLen=%d nonce=%s", len(enc), NonceHex(enc))
	dec, err := DecryptPayloadRegion(enc, cipher)
	if err != nil {
		t.Fatalf("DecryptPayloadRegion: %v", err)
	}
	t.Logf("[rt] after DecryptPayloadRegion decLen=%d", len(dec))
	_, got, err := Unpack(dec)
	if err != nil {
		t.Fatalf("Unpack after decrypt: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("round-trip payload mismatch: got %q want %q", got, payload)
	}
	t.Logf("[rt] Pack->Encrypt->Decrypt->Unpack OK payloadLen=%d", len(got))

	// UnpackWith must open the SAME encrypted frame with the same cipher.
	// This guards the regression where UnpackWith derived the AEAD nonce from
	// frame[2:14] (SeqID+ObfType+PayloadLen) while EncryptPayloadRegion used
	// frame[0:10]|frame[10]|frame[13] — the two never agreed, so UnpackWith
	// could never open a real encrypted frame. Both now share obfNonceFromHeader.
	_, got2, err := UnpackWith(enc, cipher)
	if err != nil {
		t.Fatalf("UnpackWith decrypt: %v", err)
	}
	if !bytes.Equal(got2, payload) {
		t.Fatalf("UnpackWith payload mismatch: got %q want %q", got2, payload)
	}
	t.Logf("[rt] UnpackWith agrees with EncryptPayloadRegion (nonce shared via obfNonceFromHeader) OK")
}
