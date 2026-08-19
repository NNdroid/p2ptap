package obfuscate

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math/big"
	"sync"
	"sync/atomic"
	"time"

	"p2ptap/pkg/config"
	"p2ptap/pkg/logger"
)

var log = logger.New("Obfuscate")

// crc32Of is a tiny dependency-free CRC32 (IEEE) used only for the 20-bit
// source-hash field of structured SeqIDs. We avoid importing hash/crc32's
// table setup on the hot path by using the built-in.
func crc32Of(b []byte) uint32 {
	table := crc32IEEETable()
	var crc uint32 = 0xFFFFFFFF
	for _, ch := range b {
		crc = table[(crc^uint32(ch))&0xFF] ^ (crc >> 8)
	}
	return crc ^ 0xFFFFFFFF
}

var crc32TableOnce bool
var crc32TableMem [256]uint32

func crc32IEEETable() *[256]uint32 {
	if !crc32TableOnce {
		for i := 0; i < 256; i++ {
			crc := uint32(i)
			for j := 0; j < 8; j++ {
				if crc&1 == 1 {
					crc = (crc >> 1) ^ 0xEDB88320
				} else {
					crc >>= 1
				}
			}
			crc32TableMem[i] = crc
		}
		crc32TableOnce = true
	}
	return &crc32TableMem
}

const (
	FrameMagic uint16 = 0x5054 // "PT" (P2PTAP)
	// Header layout:
	//   Magic(2) | SeqID(8) | ObfType(1) | PayloadLen(2) | PaddingLen(2)
	// ObfType identifies the algorithm used to seal the payload (see crypto.go);
	// the key is derived per-peer via ECDH and is NEVER on the wire.
	HeaderLen         = 2 + 8 + 1 + 2 + 2 // = 15 bytes
	MaxFrameSize      = 65535
	MaxOutputSize     = MaxFrameSize
	WindowSizeBitmask = 1024

	// AEADTagSize is the authentication tag length of the per-peer ciphers
	// (ChaCha20Poly1305 and AES-256-GCM). EncryptPayloadRegion appends exactly
	// this many bytes to the payload, so a full-frame obfuscate frame reaches
	// MaxFrameSize + AEADTagSize on the wire.
	AEADTagSize = 16

	// MaxSealedFrameSize is the largest frame that can appear ON THE WIRE after
	// per-peer AEAD sealing. RX read buffers MUST size to this, otherwise a
	// sealed full-frame would exceed a MaxFrameSize buffer and ReadFrame would
	// reject it as "frame too large" (silently dropping valid peer traffic).
	MaxSealedFrameSize = MaxFrameSize + AEADTagSize
)

// --- Structured SeqID layout (v1) ---
//
// The 8-byte SeqID is structured so the receiver can (a) identify the
// originating node, (b) reject cross-session / replayed frames by a per-connection
// epoch negotiated at handshake time, and (c) keep a per-source dedup window.
//
// The receiver seeds its window and records the expected connEpoch via the
// SeqSync control protocol on connect (see pkg/node). Layout (MSB first):
//
//	[ ver:4 | srcHash:16 | connEpoch:12 | counter:32 ]
//
//	ver        : protocol version (1). Lets us evolve the layout later.
//	srcHash    : high 16 bits of crc32 of the sender's PeerID (enough to
//	             disambiguate nodes within a mesh; collisions only widen the
//	             shared window slightly, never causing false drops).
//	connEpoch  : a 12-bit random epoch negotiated for THIS connection (see
//	             SetConnEpoch). It changes on every reconnect/restart, so a
//	             frame captured in a previous session carries a stale epoch and
//	             is rejected at the dedup layer — no wall-clock dependency.
//	counter    : per-source monotonic counter (32 bits, never wraps within a
//	             connection's lifetime). The full 64-bit SeqID is embedded
//	             verbatim into the AEAD nonce (see EncryptPayloadRegion), so a
//	             32-bit counter makes that nonce effectively unique — fixing the
//	             historical 16-bit counter, which reused a nonce after 65536
//	             frames (catastrophic AEAD key/nonce reuse).
const (
	seqVerShift   = 60
	seqVerMask    = uint64(0xF) << seqVerShift
	seqSrcShift   = 44
	seqSrcMask    = uint64(0xFFFF) << seqSrcShift
	seqEpochShift = 32
	seqEpochMask  = uint64(0xFFF) << seqEpochShift
	seqCntMask    = uint64(0xFFFFFFFF)
	seqVer1       = uint64(1)
	SeqSrcHashLen = 16
)

// SeqSrcHash computes the 16-bit source hash for a peer ID string.
func SeqSrcHash(peerID string) uint64 {
	h := crc32Of([]byte(peerID))
	return uint64(h>>16) & 0xFFFF // keep high 16 bits
}

// SrcHashFromSeq extracts the 16-bit source hash field from a structured SeqID.
func SrcHashFromSeq(seqID uint64) uint64 {
	return (seqID & seqSrcMask) >> seqSrcShift
}

// ConnEpochFromSeq extracts the per-connection epoch field from a structured SeqID.
func ConnEpochFromSeq(seqID uint64) uint64 {
	return (seqID & seqEpochMask) >> seqEpochShift
}

// CounterFromSeq extracts the per-source counter field.
func CounterFromSeq(seqID uint64) uint64 {
	return seqID & seqCntMask
}

// IsStructuredSeq reports whether seqID uses the v1 structured layout.
func IsStructuredSeq(seqID uint64) bool {
	return (seqID&seqVerMask)>>seqVerShift == seqVer1
}

var (
	ErrInvalidMagic   = errors.New("invalid frame magic header")
	ErrBufferTooSmall = errors.New("buffer size too small for frame")
	ErrFrameCorrupted = errors.New("frame length mismatch or corrupted")
)

// FramePool manages byte buffers using sync.Pool for zero-allocation performance.
var FramePool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, MaxFrameSize)
		return &b
	},
}

// autoState tracks per-mode traffic statistics for the auto-detection engine.
type autoState struct {
	mu          sync.Mutex
	packetSizes []int // ring buffer of recent packet sizes
	packetIdx   int
	packetCount int
}

const autoRingSize = 64

func newAutoState() *autoState {
	return &autoState{packetSizes: make([]int, autoRingSize)}
}

func (a *autoState) recordSize(sz int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.packetSizes[a.packetIdx] = sz
	a.packetIdx = (a.packetIdx + 1) % autoRingSize
	if a.packetCount < autoRingSize {
		a.packetCount++
	}
}

// entropyScore returns 0..1 measuring size distribution uniformity.
func (a *autoState) entropyScore() float64 {
	a.mu.Lock()
	// copy for analysis
	count := a.packetCount
	if count < 8 {
		a.mu.Unlock()
		return 0
	}
	sizes := make([]int, count)
	for i := 0; i < count; i++ {
		sizes[i] = a.packetSizes[(a.packetIdx-count+i+autoRingSize)%autoRingSize]
	}
	a.mu.Unlock()

	seen := make(map[int]int)
	for _, sz := range sizes {
		seen[sz]++
	}
	var entropy float64
	n := float64(count)
	for _, cnt := range seen {
		p := float64(cnt) / n
		if p > 0 {
			entropy -= p * (p)
		}
	}
	if entropy > 1.0 {
		entropy = 1.0
	}
	return entropy
}

func (a *autoState) evaluate() string {
	entropy := a.entropyScore()
	a.mu.Lock()
	count := a.packetCount
	a.mu.Unlock()
	if count < 8 {
		return "dynamic"
	}
	if entropy > 0.7 {
		return "random"
	}
	if entropy < 0.3 {
		return "dynamic"
	}
	return "block"
}

// FramePacker pads frames for traffic obfuscation & DPI resistance.
type FramePacker struct {
	Enable    bool   `json:"enable"`
	Mode      string `json:"mode"`
	FixedSize int    `json:"fixed_size"`
	BlockSize int    `json:"block_size"`
	// Extended jitter & dynamic range
	JitterRange int `json:"jitter_range"`
	MinSize     int `json:"min_size"`
	MaxSize     int `json:"max_size"`

	// Auto-detection
	AutoDetectInterval int  `json:"auto_detect_interval"`
	AutoThresholdBytes int  `json:"auto_threshold_bytes"`
	AllowModeSwitch    bool `json:"allow_mode_switch"`

	seqCounter uint64 // per-source monotonic counter (low 32 bits of structured SeqID)
	srcHash    uint64 // 16-bit source hash for this node's PeerID
	auto       *autoState
	lastEval   time.Time
	totalBytes int64
	mu         sync.Mutex

	// algo is the ObfType byte stamped into outgoing frames so the receiver
	// knows which cipher to use. Per-peer encryption is applied at send time
	// (see Node.encryptForPeer), so the packer itself holds no cipher.
	algo byte
}

// NewFramePackerFull creates a FramePacker from full ObfuscationConfig.
func NewFramePackerFull(cfg *config.ObfuscationConfig) *FramePacker {
	if cfg == nil || !cfg.Enable {
		return &FramePacker{Enable: false}
	}
	fp := &FramePacker{
		Enable:             cfg.Enable,
		Mode:               cfg.Mode,
		FixedSize:          cfg.FixedSize,
		BlockSize:          cfg.BlockSize,
		JitterRange:        cfg.JitterRange,
		MinSize:            cfg.MinSize,
		MaxSize:            cfg.MaxSize,
		AutoDetectInterval: cfg.AutoDetectInterval,
		AutoThresholdBytes: cfg.AutoThresholdBytes,
		AllowModeSwitch:    cfg.AllowModeSwitch,
	}
	fp.applyDefaults()
	if fp.Mode == "auto" {
		fp.auto = newAutoState()
	}
	return fp
}

func (fp *FramePacker) applyDefaults() {
	if fp.Mode == "" {
		fp.Mode = "random"
	}
	if fp.BlockSize <= 0 {
		fp.BlockSize = 256
	}
	if fp.FixedSize <= 0 {
		fp.FixedSize = 1500
	}
	if fp.MinSize <= 0 {
		fp.MinSize = 512
	}
	if fp.MaxSize <= 0 {
		fp.MaxSize = 1500
	}
}

// SetSourceIdentity initialises the structured-SeqID source hash from this
// node's PeerID. Call once at startup, before any Pack().
func (fp *FramePacker) SetSourceIdentity(peerID string) {
	fp.srcHash = SeqSrcHash(peerID)
}

// CurrentCounter returns the RAW, unmasked monotonic frame counter (the value
// behind NextSeqID before it is folded into the 32-bit structured-SeqID field).
// It is monotonically increasing for the process lifetime. The node layer uses
// it as the GLOBAL safety-net anchor for proactive per-peer key rotation:
// because the AEAD nonce is derived from this 32-bit counter field (shared
// node-wide), a peer must rotate its key once the node has shipped ~2^32 frames
// total — even a quiet peer — so the counter can never wrap and reuse a (key,
// nonce) pair. The per-peer frame count (framesSinceRekey) is the additional,
// tighter trigger for chatty peers; both are bounded by obfRekeyFrameThreshold.
func (fp *FramePacker) CurrentCounter() uint64 {
	return atomic.LoadUint64(&fp.seqCounter)
}

// BumpCounter advances the process-wide monotonic frame counter by one and
// returns the new raw counter value. The node layer calls this ONCE per logical
// TAP frame (even when the frame is fanned out to many peers as a broadcast),
// then folds the SAME counter into each peer's structured SeqID via MakeSeqID
// together with THAT peer's own anti-replay epoch.
func (fp *FramePacker) BumpCounter() uint64 {
	return atomic.AddUint64(&fp.seqCounter, 1)
}

// MakeSeqID folds a raw counter and a peer-specific anti-replay epoch into a
// structured v1 SeqID. The epoch is PER-PEER (negotiated with each remote peer
// during its SeqSync handshake), NOT a single node-wide value — so rotating the
// epoch for one reconnecting peer never disturbs the dedup windows of any other
// peer. Layout: [ver:4 | srcHash:16 | connEpoch:12 | counter:32].
func (fp *FramePacker) MakeSeqID(counter, epoch uint64) uint64 {
	return seqVer1<<seqVerShift | (fp.srcHash << seqSrcShift) | ((epoch & 0xFFF) << seqEpochShift) | (counter & seqCntMask)
}

// NextSeqID returns the next structured SeqID (v1) for dedup tracking, folding in
// the given per-peer anti-replay epoch. It is the single-peer convenience form of
// BumpCounter+MakeSeqID (used for unicast frames, which address exactly one peer).
// Layout: [ver:4 | srcHash:16 | connEpoch:12 | counter:32].
func (fp *FramePacker) NextSeqID(epoch uint64) uint64 {
	return fp.MakeSeqID(fp.BumpCounter(), epoch)
}

// randomJitter returns [-jitter, +jitter].
func randomJitter(jitter int) int {
	if jitter <= 0 {
		return 0
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(jitter*2+1)))
	if err != nil {
		return 0
	}
	return int(n.Int64()) - jitter
}

// randomBetween returns [min, max].
func randomBetween(minVal, maxVal int) int {
	if minVal >= maxVal {
		return maxVal
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(maxVal-minVal+1)))
	if err != nil {
		return maxVal
	}
	return int(n.Int64()) + minVal
}

func fillRandom(buf []byte) {
	_, _ = rand.Read(buf)
}

// Pack pads the payload into outBuf.
// Returns total bytes written, or an error if outBuf is too small.
// The frame format for standard padding modes (fixed/block/random/dynamic/auto):
//
//	[Magic(2) | SeqID(8) | PayloadLen(2) | PaddingLen(2) | payload | random padding]
func (fp *FramePacker) Pack(seqID uint64, payload []byte, outBuf []byte) (int, error) {
	if !fp.Enable {
		// When obfuscation padding is disabled, we still write the standard 15-byte header with PaddingLen=0
		// so that Magic (0x5054), SeqID (dedup/anti-replay), ObfType (encryption), and PayloadLen are preserved.
		return fp.packStandard(seqID, payload, outBuf, "none")
	}

	mode := fp.Mode
	if mode == "auto" && fp.auto != nil {
		fp.auto.recordSize(len(payload))
		fp.totalBytes += int64(len(payload))
		if fp.AllowModeSwitch && fp.AutoDetectInterval > 0 {
			now := time.Now()
			if now.Sub(fp.lastEval) >= time.Duration(fp.AutoDetectInterval)*time.Second {
				newMode := fp.auto.evaluate()
				if newMode != fp.Mode {
					fp.Mode = newMode
					mode = newMode
				}
				fp.lastEval = now
			}
		}
		if fp.AllowModeSwitch {
			fp.mu.Lock()
			mode = fp.Mode
			fp.mu.Unlock()
		}
	}

	return fp.packStandard(seqID, payload, outBuf, mode)
}

// packStandard handles fixed/block/random/dynamic modes with Magic header.
func (fp *FramePacker) packStandard(seqID uint64, payload []byte, outBuf []byte, mode string) (int, error) {
	// Determine target total frame size
	var targetSize int
	switch mode {
	case "none":
		targetSize = HeaderLen + len(payload)
	case "fixed":
		targetSize = fp.FixedSize + randomJitter(fp.JitterRange)
	case "block":

		overhead := HeaderLen + len(payload)
		blocks := overhead / fp.BlockSize
		if overhead%fp.BlockSize != 0 {
			blocks++
		}
		targetSize = blocks*fp.BlockSize + randomJitter(fp.JitterRange)
	case "dynamic":
		overhead := HeaderLen + len(payload)
		// Scale padding proportionally to payload size, capped at 4× overhead.
		// This prevents extreme waste: an 86-byte ICMPv6 packet should not
		// balloon to 500-1500 bytes (6-17× overhead). Instead it would be
		// ~100-400 bytes, still providing traffic analysis resistance.
		idealTarget := overhead * 4
		if idealTarget < fp.MinSize {
			idealTarget = fp.MinSize
		}
		if idealTarget > fp.MaxSize {
			idealTarget = fp.MaxSize
		}
		targetSize = randomBetween(overhead, idealTarget)
	default: // "random" or auto
		targetSize = randomBetween(64, fp.FixedSize) + randomJitter(fp.JitterRange)
	}

	// The payload is written in the CLEAR here. Per-peer encryption is applied
	// later by the Node send path (encryptForPeer) using the negotiated
	// per-peer cipher, so a single Pack() result can be fanned out to many
	// peers, each encrypted with its own key. ObfType records the algorithm so
	// the receiver knows which cipher to use.
	sealed := payload

	overhead := HeaderLen + len(sealed)
	if targetSize < overhead {
		targetSize = overhead
	}
	if targetSize > MaxFrameSize {
		targetSize = MaxFrameSize
	}
	if len(outBuf) < targetSize {
		return 0, ErrBufferTooSmall
	}

	paddingLen := uint16(targetSize - HeaderLen - len(sealed))

	// Write header (v2 includes the ObfType byte at offset 10).
	binary.BigEndian.PutUint16(outBuf[0:2], uint16(FrameMagic))
	binary.BigEndian.PutUint64(outBuf[2:10], uint64(seqID))
	outBuf[10] = fp.algo
	binary.BigEndian.PutUint16(outBuf[11:13], uint16(len(sealed)))
	binary.BigEndian.PutUint16(outBuf[13:15], paddingLen)

	// Copy sealed payload
	copy(outBuf[HeaderLen:], sealed)

	// Fill padding with random bytes
	if paddingLen > 0 {
		fillRandom(outBuf[HeaderLen+len(sealed) : targetSize])
	}

	return targetSize, nil
}

// Unpack reverses Pack with a nil cipher (no decryption). Convenience wrapper
// around UnpackWith for callers that do not apply per-peer encryption.
func Unpack(frame []byte) (seqID uint64, payload []byte, err error) {
	return UnpackWith(frame, nil)
}

// UnpackWith reverses Pack. If cipher is non-nil it is used to open the
// encrypted payload; otherwise the ObfType header is ignored and the payload
// is returned verbatim (plaintext behaviour). All frames are v2 layout
// (15-byte header including the ObfType byte).
func UnpackWith(frame []byte, cipher ObfCipher) (seqID uint64, payload []byte, err error) {
	if len(frame) < HeaderLen {
		return 0, nil, ErrFrameCorrupted
	}

	magic := binary.BigEndian.Uint16(frame[0:2])
	if magic != uint16(FrameMagic) {
		log.Debug("UnpackWith: magic mismatch (got 0x%04x expected 0x%04x)", magic, uint16(FrameMagic))
		return 0, nil, ErrFrameCorrupted
	}

	obfType := frame[10]
	seqID = binary.BigEndian.Uint64(frame[2:10])
	pLen := int(binary.BigEndian.Uint16(frame[11:13])) // PayloadLen field (ObfType at [10])
	if HeaderLen+pLen > len(frame) {
		log.Debug("UnpackWith: payload length overflow, pLen=%d frameLen=%d", pLen, len(frame))
		return 0, nil, ErrFrameCorrupted
	}
	raw := frame[HeaderLen : HeaderLen+pLen]

	if cipher != nil && obfType != ObfAlgoNone {
		// Nonce = the same 12 bytes derived from the immutable header that
		// EncryptPayloadRegion used to Seal this frame (see obfNonceFromHeader).
		// Historically this used frame[2:14] (SeqID+ObfType+PayloadLen), which
		// disagreed with the encryptor and could never open a real frame.
		nonce := obfNonceFromHeader(frame)
		log.Debug("UnpackWith: DECRYPT branch seqID=%d obfType=%s algo=%s nonce=%s ctLen=%d",
			seqID, AlgoName(obfType), AlgoName(cipher.Algo()), NonceHex(frame), len(raw))
		opened, oerr := cipher.Open(nonce[:], raw)
		if oerr != nil {
			// AEAD authentication failed under the supplied key. We deliberately
			// do NOT log the raw stdlib "message authentication failed" string:
			// it would flood the log for every in-flight old-key frame during a
			// rotation (the caller retries staged fallback keys before giving
			// up). Keep a neutral, classified note with the nonce for tracing.
			log.Debug("UnpackWith: supplied rx key did NOT open frame seqID=%d algo=%s nonce=%s (AEAD auth failed)",
				seqID, AlgoName(cipher.Algo()), NonceHex(frame))
			return 0, nil, ErrFrameCorrupted
		}
		payload = opened
	} else {
		log.Debug("UnpackWith: PLAINTEXT branch seqID=%d obfType=%s (cipherPresent=%v) — payload returned as-is", seqID, AlgoName(obfType), cipher != nil)
		payload = raw
	}
	log.Debug("UnpackWith: done seqID=%d payloadLen=%d frameLen=%d", seqID, len(payload), len(frame))
	return seqID, payload, nil
}

// Algo returns the configured ObfType byte for this packer.
func (fp *FramePacker) Algo() byte {
	return fp.algo
}

// SetSendAlgo records the ObfType byte written into outgoing frames so the
// receiver knows which algorithm to use. It does NOT install a cipher; payload
// encryption is applied per-peer at send time via EncryptPayloadRegion.
func (fp *FramePacker) SetSendAlgo(algo byte) {
	fp.algo = algo
}

// headerLenOf returns the fixed header length of a v2 frame.
func headerLenOf(frame []byte) int {
	return HeaderLen
}

// obfNonceFromHeader derives the 12-byte AEAD nonce for a packed frame from its
// IMMUTABLE header bytes. Seal (EncryptPayloadRegion) and Open
// (DecryptPayloadRegion / UnpackWith) MUST all use exactly this derivation so
// the receiver can reconstruct the nonce from the on-wire header — the header
// is transmitted in cleartext, which is safe: AEAD nonces are public, they only
// need to be unique per (key).
//
// Layout (12 bytes): Magic(2) + SeqID(8) + ObfType(1) + PaddingLen-high(1).
//   - Magic + SeqID occupy frame[0:10] and uniquely identify the frame within a
//     (key, direction) — they are never rewritten, so both ends agree.
//   - ObfType at frame[10] is constant for the peer's negotiated algorithm.
//   - The high byte of PaddingLen (frame[13]) is immutable across Seal↔Open; the
//     PayloadLen field [11:13] is deliberately EXCLUDED because it is rewritten
//     with the ciphertext length between Seal and Open, which would otherwise
//     desynchronise a nonce that overlapped it.
//
// NOTE: previous code derived the nonce in three different, incompatible ways
// (EncryptPayloadRegion used frame[0:10]|frame[10]|frame[13]; UnpackWith used
// frame[2:14]). That inconsistency meant the UnpackWith decrypt path could never
// agree with the encryptor. This single helper is now the only source of truth.
func obfNonceFromHeader(frame []byte) [12]byte {
	var nonce [12]byte
	copy(nonce[0:10], frame[0:10])
	nonce[10] = frame[10]
	nonce[11] = frame[13]
	return nonce
}

// NonceHex returns a compact hex string of the AEAD nonce carried by a frame,
// for debug logging. AEAD nonces are PUBLIC (they only need to be unique per
// key), so this is safe to log and lets an operator correlate a TX Seal with the
// RX Open of the SAME frame — identical nonce strings across the two ends mean
// the receiver saw exactly the frame the sender sealed.
func NonceHex(frame []byte) string {
	n12 := obfNonceFromHeader(frame)
	return hex.EncodeToString(n12[:])
}

// EncryptPayloadRegion encrypts the payload portion of an already-Packed frame
// using the given cipher, returning a NEW frame slice whose PayloadLen field is
// updated to the ciphertext length (which includes the AEAD tag). The trailing
// padding is preserved. A nil cipher (or ObfAlgoNone) returns the input frame
// unchanged. seqID is read from the frame header to derive the nonce.
//
// Allocation note: AEAD Seal must allocate the ciphertext (it appends a tag),
// but we rebuild the frame with a single append chain instead of three separate
// copies — header (fixed) + ciphertext + trailing padding are assembled in one
// pass, which halves the copy work on the hot TX path.
func EncryptPayloadRegion(frame []byte, cipher ObfCipher) ([]byte, error) {
	if cipher == nil || cipher.Algo() == ObfAlgoNone {
		return frame, nil
	}
	hLen := headerLenOf(frame)
	if len(frame) < hLen {
		return nil, ErrFrameCorrupted
	}
	pLen := int(binary.BigEndian.Uint16(frame[11:13]))
	if hLen+pLen > len(frame) {
		return nil, ErrFrameCorrupted
	}
	// Nonce derived from the immutable header bytes; see obfNonceFromHeader.
	// This is the ONLY place the nonce is constructed for the TX path, and it
	// is shared verbatim by DecryptPayloadRegion and UnpackWith on the RX side.
	nonce := obfNonceFromHeader(frame)
	seqID := binary.BigEndian.Uint64(frame[2:10])
	ct := cipher.Seal(nonce[:], frame[hLen:hLen+pLen])
	log.Debug("ObfEncrypt: seqID=%d algo=%s nonce=%s ptLen=%d ctLen=%d",
		seqID, AlgoName(cipher.Algo()), NonceHex(frame), pLen, len(ct))

	// Reassemble: [header | ct | trailing padding].
	out := make([]byte, 0, hLen+len(ct)+(len(frame)-(hLen+pLen)))
	out = append(out, frame[:hLen]...)
	binary.BigEndian.PutUint16(out[11:13], uint16(len(ct)))
	out = append(out, ct...)
	out = append(out, frame[hLen+pLen:]...) // preserve trailing padding
	return out, nil
}

// DecryptPayloadRegion reverses EncryptPayloadRegion: it opens the encrypted
// payload and returns a new frame slice with PayloadLen restored to the
// plaintext length. Trailing padding is preserved (ignored by Unpack).
//
// Same single-append-chain assembly as EncryptPayloadRegion to minimise copies
// on the hot RX path.
func DecryptPayloadRegion(frame []byte, cipher ObfCipher) ([]byte, error) {
	if cipher == nil || cipher.Algo() == ObfAlgoNone {
		return frame, nil
	}
	hLen := headerLenOf(frame)
	if len(frame) < hLen {
		return nil, ErrFrameCorrupted
	}
	pLen := int(binary.BigEndian.Uint16(frame[11:13]))
	if hLen+pLen > len(frame) {
		return nil, ErrFrameCorrupted
	}
	// Nonce derived from immutable header bytes (see EncryptPayloadRegion).
	nonce := obfNonceFromHeader(frame)
	seqID := binary.BigEndian.Uint64(frame[2:10])
	pt, err := cipher.Open(nonce[:], frame[hLen:hLen+pLen])
	if err != nil {
		// AEAD authentication failed under the CURRENT rx key. This is EXPECTED
		// during a key rotation or when a straggler from a prior connection
		// arrives: the node RX path retries staged fallback keys (rxRing /
		// prevRxCipher) before declaring the frame garbage. We do NOT log the
		// raw stdlib "message authentication failed" string here — it would
		// flood the log for every in-flight old-key frame that the fallback then
		// successfully opens. The authoritative, classified failure line lives
		// in the node RX path after all fallback keys have been tried.
		log.Debug("ObfDecrypt: current rx key did NOT open frame seqID=%d algo=%s nonce=%s ctLen=%d (AEAD auth failed; caller retries fallback keys)",
			seqID, AlgoName(cipher.Algo()), NonceHex(frame), pLen)
		return nil, err
	}
	log.Debug("ObfDecrypt: OK seqID=%d algo=%s nonce=%s ctLen=%d ptLen=%d",
		seqID, AlgoName(cipher.Algo()), NonceHex(frame), pLen, len(pt))
	// Reassemble: [header | pt | trailing padding].
	out := make([]byte, 0, hLen+len(pt)+(len(frame)-(hLen+pLen)))
	out = append(out, frame[:hLen]...)
	binary.BigEndian.PutUint16(out[11:13], uint16(len(pt)))
	out = append(out, pt...)
	out = append(out, frame[hLen+pLen:]...)
	return out, nil
}

// UpdateConfig hot-reloads obfuscation settings from config.
func (fp *FramePacker) UpdateConfig(cfg *config.ObfuscationConfig) {
	if fp == nil {
		return
	}
	fp.mu.Lock()
	defer fp.mu.Unlock()
	fp.Enable = cfg.Enable
	fp.Mode = cfg.Mode
	fp.FixedSize = cfg.FixedSize
	fp.BlockSize = cfg.BlockSize
	fp.JitterRange = cfg.JitterRange
	fp.MinSize = cfg.MinSize
	fp.MaxSize = cfg.MaxSize
	fp.AutoDetectInterval = cfg.AutoDetectInterval
	fp.AutoThresholdBytes = cfg.AutoThresholdBytes
	fp.AllowModeSwitch = cfg.AllowModeSwitch
	fp.applyDefaults()
	if fp.Mode == "auto" && fp.auto == nil {
		fp.auto = newAutoState()
	}
}
