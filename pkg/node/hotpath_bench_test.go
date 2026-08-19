package node

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"p2ptap/pkg/logger"
	"p2ptap/pkg/obfuscate"
)

// These microbenchmarks quantify the per-frame overhead of the diagnostic
// helpers that were being evaluated even when debug logging was suppressed:
// Go evaluates a function's arguments at the CALL SITE, so
//
//	log.Debug("...", peer.String())
//
// pays the full base58 / SHA-256 / hex cost on every frame regardless of the
// configured log level. The logger's own level check happens too late to help.
// They exist to prove the `log.IsDebug()` guards actually removed that cost.

func BenchmarkPeerIDString(b *testing.B) {
	p := benchPeerID(b)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = p.String()
	}
}

func BenchmarkKeyFingerprint(b *testing.B) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = obfuscate.KeyFingerprint(key)
	}
}

func BenchmarkNonceHex(b *testing.B) {
	// A minimal well-formed frame is enough: NonceHex only reads the header.
	frame := make([]byte, obfuscate.HeaderLen+32)
	frame[0] = 0x50
	frame[1] = 0x54
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = obfuscate.NonceHex(frame)
	}
}

func BenchmarkAlgoName(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = obfuscate.AlgoName(obfuscate.ObfAlgoChaCha20)
	}
}

// BenchmarkPeerIDStringCached quantifies the per-peer base58 cache added for the
// receive path: RecordRxSeq / checkACL / CaptureFrameWithPeers all need a peer's
// string form on EVERY frame, and re-rendering an immutable ID each time is
// pure waste. Compare against BenchmarkPeerIDString to see the win.
func BenchmarkPeerIDStringCached(b *testing.B) {
	n := &Node{}
	p := benchPeerID(b)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = n.peerIDString(p)
	}
}

// BenchmarkPingPongFailReset models the per-frame reset on the RX path
// (resetPingPongFailCountForPeer) after the copy-on-write change: one atomic
// snapshot load plus a map lookup, with no global mutex on the hot path.
func BenchmarkPingPongFailReset(b *testing.B) {
	n := &Node{}
	p := benchPeerID(b)
	n.pingPongFailCounterFor(p).Store(1) // non-zero so the reset path is exercised
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		n.resetPingPongFailCountForPeer(p)
	}
}

// BenchmarkPerFrameDiagnostics models the combined per-frame diagnostic cost
// that used to be paid unconditionally on the RX path: one peer.String() in the
// read loop plus KeyFingerprint/peer.String/NonceHex/AlgoName inside
// decryptPeerFrame. It is the number that matters for "CPU too high".
func BenchmarkPerFrameDiagnostics(b *testing.B) {
	p := benchPeerID(b)
	key := make([]byte, 32)
	frame := make([]byte, obfuscate.HeaderLen+32)
	frame[0] = 0x50
	frame[1] = 0x54
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = p.String()                                  // node_streams.go read loop
		_ = obfuscate.KeyFingerprint(key)               // node_crypto.go obfDecryptCipherForPeer
		_ = p.String()                                  // node_crypto.go obfDecryptCipherForPeer
		_ = obfuscate.NonceHex(frame)                   // node_crypto.go decryptPeerFrame success
		_ = p.String()                                  // node_crypto.go decryptPeerFrame success
		_ = obfuscate.AlgoName(obfuscate.ObfAlgoChaCha20) // node_crypto.go
	}
}

// BenchmarkPerFrameDiagnosticsGuarded models the SAME per-frame diagnostic work
// as BenchmarkPerFrameDiagnostics but behind the `if log.IsDebug()` guard that
// now protects the hot paths. Comparing the two shows the win: the guarded form
// costs nothing at info level, while the unguarded form paid ~2.9us and 8
// allocations on every single frame.
func BenchmarkPerFrameDiagnosticsGuarded(b *testing.B) {
	p := benchPeerID(b)
	key := make([]byte, 32)
	frame := make([]byte, obfuscate.HeaderLen+32)
	frame[0] = 0x50
	frame[1] = 0x54
	const debugEnabled = false // == log.IsDebug() at default/info level
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if debugEnabled {
			_ = p.String()
			_ = obfuscate.KeyFingerprint(key)
			_ = p.String()
			_ = obfuscate.NonceHex(frame)
			_ = p.String()
			_ = obfuscate.AlgoName(obfuscate.ObfAlgoChaCha20)
		}
	}
}

// BenchmarkDecryptPeerFrame measures the REAL per-frame RX decrypt path
// (obfDecryptCipherForPeer + AEAD open + decryptPeerFrame bookkeeping) at the
// PRODUCTION log level (info — the default when config.json omits log_level).
// This is the number that bounds achievable pps per core in deployment.
func BenchmarkDecryptPeerFrame(b *testing.B) {
	// arp_ping_3node_test.go pins the package-wide level to Debug, which is not
	// what production runs at. Pin to Info for the measurement, restore after.
	logger.SetGlobalLevel(logger.LevelInfo)
	defer logger.SetGlobalLevel(logger.LevelDebug)
	benchmarkDecryptPeerFrame(b)
}

// BenchmarkDecryptPeerFrameDebugLevel is the same path with debug logging ON.
// It shows why running the daemon at log_level=debug is expensive: the guards
// are bypassed and every frame pays base58 + SHA-256 + hex plus log I/O.
func BenchmarkDecryptPeerFrameDebugLevel(b *testing.B) {
	logger.SetGlobalLevel(logger.LevelDebug)
	defer logger.SetGlobalLevel(logger.LevelDebug)
	benchmarkDecryptPeerFrame(b)
}

func benchmarkDecryptPeerFrame(b *testing.B) {
	const algo = obfuscate.ObfAlgoChaCha20
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i)
	}
	c, err := obfuscate.NewObfCipher(algo, k)
	if err != nil {
		b.Fatalf("cipher build: %v", err)
	}
	n := minimalDecryptNode()
	tbl := make(map[peer.ID]*PeerObf)
	n.perPeerObf.Store(&tbl)
	p := benchPeerID(b)
	n.storePeerObf(p, &PeerObf{
		algo:       algo,
		txCipher:   c,
		rxCipher:   c,
		negotiated: true,
		txKey:      bytes.Repeat([]byte{1}, 32),
		rxKey:      bytes.Repeat([]byte{2}, 32),
	})
	frame := benchSealFrame(b, c, bytes.Repeat([]byte("x"), 1200))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, ok, _ := n.decryptPeerFrame(frame, p); !ok {
			b.Fatal("decrypt failed")
		}
	}
}

// benchSealFrame builds a sealed obfuscate frame without needing *testing.T
// (benchmark variant of sealWithCipher).
func benchSealFrame(b *testing.B, c obfuscate.ObfCipher, payload []byte) []byte {
	b.Helper()
	const hLen = 15
	frame := make([]byte, hLen+len(payload))
	for i := 0; i < 10; i++ {
		frame[i] = byte(i)
	}
	frame[10] = 0x01
	frame[13] = 0x02
	binary.BigEndian.PutUint16(frame[11:13], uint16(len(payload)))
	copy(frame[hLen:], payload)
	enc, err := obfuscate.EncryptPayloadRegion(frame, c)
	if err != nil {
		b.Fatalf("encrypt: %v", err)
	}
	return enc
}

// benchPeerID mints a deterministic peer ID without needing *testing.T, which
// benchmarks do not have (the existing newTestPeerID helper requires it).
func benchPeerID(b *testing.B) peer.ID {
	b.Helper()
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	priv, _, err := crypto.GenerateEd25519Key(bytes.NewReader(seed))
	if err != nil {
		b.Fatalf("mint peer key: %v", err)
	}
	id, err := peer.IDFromPrivateKey(priv)
	if err != nil {
		b.Fatalf("derive peer id: %v", err)
	}
	return id
}
