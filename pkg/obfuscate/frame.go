package obfuscate

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash/crc32"
	"math"
	randv2 "math/rand/v2"
	"sync"
	"sync/atomic"
	"time"

	"p2ptap/pkg/config"
	"p2ptap/pkg/logger"
)

var log = logger.New("Obfuscate")

// crc32Of wraps hash/crc32.ChecksumIEEE for the 16-bit source-hash field
// of structured SeqIDs. Called once at startup (SetSourceIdentity), never
// on the packet hot path.
func crc32Of(b []byte) uint32 {
	return crc32.ChecksumIEEE(b)
}

const (
	FrameMagic uint16 = 0x5054 // "PT" (P2PTAP)
	// Header layout:
	//   Magic(2) | SeqID(8) | ObfType(1) | PayloadLen(2) | PaddingLen(2)
	// ObfType identifies the algorithm used to seal the payload (see crypto.go);
	// the key is derived per-peer via ECDH and is NEVER on the wire.
	HeaderLen     = 2 + 8 + 1 + 2 + 2 // = 15 bytes
	MaxFrameSize  = 65535
	MaxOutputSize = MaxFrameSize

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

// --- Path-MTU frame budget ---
//
// Every obfuscate frame is carried inside the tunnel's transport datagrams, so
// its size is bounded by the path MTU, not just by the 65535-byte PayloadLen
// field. The budget is computed once here so that padding, fragmentation and
// MSS clamping all agree on the same number instead of each hardcoding a
// slightly different overhead: a frame that fits one datagram is fragmented by
// nobody, and one that fits none is fragmented by everybody.
const (
	// PathMTU is the conservative end-to-end datagram budget: 1200 bytes leaves
	// room under a 1500-byte link MTU for the outer encapsulation below. Lower
	// configured tunnel MTUs are honoured instead of clamped up.
	PathMTU = 1200

	// OuterIPHeader is the outer IP header. 40 bytes covers an IPv4 header with
	// options and is IPv6-safe (40 bytes exactly).
	OuterIPHeader = 40
	// OuterUDPHeader is the outer UDP header carrying the QUIC/WebRTC datagram.
	OuterUDPHeader = 8
	// OuterTransportHeader bounds the transport header inside the outer UDP
	// datagram: a QUIC long header is up to 33 bytes (a short header is only
	// 10), so 33 keeps the budget valid for both.
	OuterTransportHeader = 33

	// OuterEncapsulation is everything between the link MTU and the obfuscate
	// frame itself.
	OuterEncapsulation = OuterIPHeader + OuterUDPHeader + OuterTransportHeader

	// MinFrameSize is the floor for a padded frame: below it the padding adds
	// nothing but header overhead relative to the payload.
	MinFrameSize = 512
)

// MaxFrameForPathMTU returns the largest PRE-seal obfuscate frame — HeaderLen
// plus payload plus padding — that fits inside a single transport datagram of
// the given path MTU. The AEAD tag is deducted up front because sealing happens
// after packing, so the sealed frame is what actually goes on the wire.
//
// Returns 0 for a non-positive pathMTU, which callers must treat as "no budget
// constraint" (tests and legacy callers that do not know their MTU).
func MaxFrameForPathMTU(pathMTU int) int {
	if pathMTU <= 0 {
		return 0
	}
	if pathMTU > PathMTU {
		pathMTU = PathMTU
	}
	n := pathMTU - OuterEncapsulation - AEADTagSize
	if n < MinFrameSize {
		n = MinFrameSize
	}
	return n
}

// MaxPayloadForPathMTU is the largest obfuscate FRAME PAYLOAD — the frame size
// minus HeaderLen, so everything after the 15-byte header — that fits one
// transport datagram. Callers that wrap the payload in their own headers (a
// fragmentation header, an inner IP/TCP segment) subtract those from here.
//
// It exists to stop callers re-deriving the AEAD tag: it is already deducted by
// MaxFrameForPathMTU, and subtracting it a second time understates the budget.
func MaxPayloadForPathMTU(pathMTU int) int {
	n := MaxFrameForPathMTU(pathMTU)
	if n <= 0 {
		return 0
	}
	return n - HeaderLen
}

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

// entropyScore returns the normalized Shannon entropy of the size distribution
// in [0, 1]. Entropy measures how UNIFORMLY the observed packet sizes are spread:
//
//	≈0  -> nearly all packets are the same size (deterministic / "dynamic" traffic)
//	≈1  -> sizes are uniformly varied (high-entropy / "random" traffic)
//
// This is the discrimination signal the auto mode uses to switch padding.
//
// NOTE: this was historically computed as `-Σ p·p` (sum of squared probabilities),
// which is always in [-1, 0] — never > 0.7 and always < 0.3 — so evaluate()
// returned "dynamic" for EVERY traffic profile and the auto engine never
// switched modes. The correct measure is Shannon entropy -Σ p·log2(p); we
// normalize by log2(numDistinctSizes) so a fully uniform spread reads ~1.0.
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
	n := float64(count)
	var sum float64
	for _, cnt := range seen {
		p := float64(cnt) / n
		if p > 0 {
			sum -= p * math.Log2(p)
		}
	}
	// Normalize to [0,1]: max entropy for k distinct sizes is log2(k).
	if k := len(seen); k > 1 {
		if mx := math.Log2(float64(k)); mx > 0 {
			sum /= mx
		}
	}
	if sum < 0 {
		sum = 0
	}
	if sum > 1 {
		sum = 1
	}
	return sum
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
	AllowModeSwitch    bool `json:"allow_mode_switch"`

	seqCounter uint64 // per-source monotonic counter (low 32 bits of structured SeqID); accessed atomically
	srcHash    uint64 // 16-bit source hash for this node's PeerID
	auto       atomic.Pointer[autoState]
	// lastEvalUnixNano is the last auto-mode evaluation time as Unix nanos.
	// Kept as an int64 rather than time.Time because concurrent Pack() calls
	// from the dispatch workers write it, and there is no atomic time.Time.
	lastEvalUnixNano atomic.Int64
	mu               sync.Mutex

	// params is an immutable copy-on-write view of the padding configuration.
	// UpdateConfig and auto-mode transitions publish a new snapshot while the
	// packet hot path only performs an atomic pointer load. This removes the
	// previous global mutex acquisition from every Pack and MaxPackedLen call.
	params atomic.Pointer[packerParams]

	// algo is the ObfType byte stamped into outgoing frames so the receiver
	// knows which cipher to use. Per-peer encryption is applied at send time
	// (see Node.encryptForPeer), so the packer itself holds no cipher. It is
	// rewritten by SetSendAlgo from the config hot-reload goroutine while the
	// data path reads it every frame, hence the atomic.
	algo atomic.Uint32

	// frameBudget is the largest frame padding may grow a payload to, derived
	// from the tunnel MTU by SetFrameBudget. It is carried in packerParams so
	// the Pack hot path reads it from the same immutable snapshot as the mode.
	frameBudget int
	// sizeConfigured reports whether FixedSize/MaxSize came from configuration.
	// When false, applyDefaults owns them and re-derives them from frameBudget on
	// every SetFrameBudget — otherwise the very first applyDefaults (which runs
	// before the MTU is known) would pin them at the historic 1500 forever.
	sizeConfigured bool
}

// NewFramePackerFull creates a FramePacker from full ObfuscationConfig.
func NewFramePackerFull(cfg *config.ObfuscationConfig) *FramePacker {
	fp := &FramePacker{}
	if cfg == nil || !cfg.Enable {
		fp.Enable = false
		fp.applyDefaults()
		fp.publishParamsLocked()
		return fp
	}
	fp.Enable = cfg.Enable
	fp.Mode = cfg.Mode
	fp.FixedSize = cfg.FixedSize
	fp.BlockSize = cfg.BlockSize
	fp.JitterRange = cfg.JitterRange
	fp.MinSize = cfg.MinSize
	fp.MaxSize = cfg.MaxSize
	fp.AutoDetectInterval = cfg.AutoDetectInterval
	fp.AllowModeSwitch = cfg.AllowModeSwitch
	fp.sizeConfigured = cfg.FixedSize > 0 || cfg.MaxSize > 0
	fp.applyDefaults()
	if fp.Mode == "auto" {
		fp.auto.Store(newAutoState())
	}
	fp.publishParamsLocked()
	return fp
}

func (fp *FramePacker) applyDefaults() {
	if fp.Mode == "" {
		fp.Mode = "random"
	}
	if fp.BlockSize <= 0 {
		fp.BlockSize = 256
	}
	if fp.MinSize <= 0 {
		fp.MinSize = MinFrameSize
	}
	if !fp.sizeConfigured {
		// No configured sizes: the defaults are ours, so they follow the datagram
		// budget. Re-derived on every call so a later SetFrameBudget moves them.
		fp.FixedSize = fp.defaultFrameSize()
		fp.MaxSize = fp.defaultFrameSize()
		return
	}
	// Sizes were configured, so they are honoured as written; only a value that
	// was left unset (the two can be configured independently) gets the default.
	if fp.FixedSize <= 0 {
		fp.FixedSize = fp.defaultFrameSize()
	}
	if fp.MaxSize <= 0 {
		fp.MaxSize = fp.defaultFrameSize()
	}
}

// defaultFrameSize is the default padded frame size: the path-MTU budget when
// SetFrameBudget has been called, otherwise the historic 1500. Padding to 1500
// when the datagram budget is smaller only creates fragments, so the budget is
// the right default. Explicit configuration always wins.
func (fp *FramePacker) defaultFrameSize() int {
	if fp.frameBudget > 0 {
		return fp.frameBudget
	}
	return 1500
}

// SetFrameBudget constrains padding to frames that fit one transport datagram
// for a tunnel of the given path MTU (see MaxFrameForPathMTU). It also
// re-applies the size defaults, because the default fixed/max frame size IS the
// budget; explicitly configured sizes are never touched. Call it after
// NewFramePackerFull and after every UpdateConfig so a hot reload of the MTU is
// picked up. A non-positive pathMTU clears the budget entirely.
func (fp *FramePacker) SetFrameBudget(pathMTU int) {
	if fp == nil {
		return
	}
	fp.mu.Lock()
	defer fp.mu.Unlock()
	fp.frameBudget = MaxFrameForPathMTU(pathMTU)
	fp.applyDefaults()
	fp.publishParamsLocked()
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
// Upper-bound clamped: jitter*2+1 overflows signed int for jitter > math.MaxInt/2,
// causing randv2.IntN to panic with "invalid argument" and crash the node.
// The clamp at 1<<20 (1 MiB) is well above any realistic MTU or frame size.
func randomJitter(jitter int) int {
	if jitter <= 0 {
		return 0
	}
	if jitter > 1<<20 {
		jitter = 1 << 20
	}
	return randv2.IntN(jitter*2+1) - jitter
}

// randomBetween returns [min, max].
func randomBetween(minVal, maxVal int) int {
	if minVal >= maxVal {
		return maxVal
	}
	return randv2.IntN(maxVal-minVal+1) + minVal
}

// Each borrower exclusively owns the generator until Put. Seeding uses fresh
// process randomness, just like the previous per-word rand/v2 calls; no padding
// byte templates are cached or reused between packets.
var paddingRandomPool = sync.Pool{New: func() any {
	var seed [32]byte
	for i := 0; i < len(seed); i += 8 {
		binary.LittleEndian.PutUint64(seed[i:], randv2.Uint64())
	}
	return randv2.NewChaCha8(seed)
}}

func fillRandom(buf []byte) {
	// Keep short padding on the cheaper per-P runtime generator. For larger
	// regions, amortize generator lookup across the entire random byte stream.
	if len(buf) >= 256 {
		rng := paddingRandomPool.Get().(*randv2.ChaCha8)
		_, _ = rng.Read(buf)
		paddingRandomPool.Put(rng)
		return
	}
	for len(buf) >= 8 {
		binary.LittleEndian.PutUint64(buf[:8], randv2.Uint64())
		buf = buf[8:]
	}
	if len(buf) > 0 {
		v := randv2.Uint64()
		for i := range buf {
			buf[i] = byte(v)
			v >>= 8
		}
	}
}

// Pack pads the payload into outBuf.
// Returns total bytes written, or an error if outBuf is too small.
// The frame format for standard padding modes (fixed/block/random/dynamic/auto):
//
//	[Magic(2) | SeqID(8) | PayloadLen(2) | PaddingLen(2) | payload | random padding]
//
// packerParams is one immutable, internally consistent view of the padding
// parameters. Writers publish a complete copy after config changes; readers on
// the packet hot path load it without taking the global configuration mutex.
type packerParams struct {
	enable             bool
	mode               string
	fixedSize          int
	blockSize          int
	jitterRange        int
	minSize            int
	maxSize            int
	autoDetectInterval int
	allowModeSwitch    bool
	// frameBudget caps the padded target size (see MaxFrameForPathMTU). Zero
	// means "no cap", which is the state of a packer that was never told its
	// tunnel MTU — tests and legacy callers.
	frameBudget int
}

// paramsFromFieldsLocked snapshots the exported compatibility fields. The caller
// must either hold fp.mu or be in single-threaded construction before publication.
func (fp *FramePacker) paramsFromFieldsLocked() packerParams {
	return packerParams{
		enable:             fp.Enable,
		mode:               fp.Mode,
		fixedSize:          fp.FixedSize,
		blockSize:          fp.BlockSize,
		jitterRange:        fp.JitterRange,
		minSize:            fp.MinSize,
		maxSize:            fp.MaxSize,
		autoDetectInterval: fp.AutoDetectInterval,
		allowModeSwitch:    fp.AllowModeSwitch,
		frameBudget:        fp.frameBudget,
	}
}

func (fp *FramePacker) publishParamsLocked() {
	p := fp.paramsFromFieldsLocked()
	fp.params.Store(&p)
}

func (fp *FramePacker) snapshotParams() *packerParams {
	if p := fp.params.Load(); p != nil {
		return p
	}

	// Support zero-value / struct-literal FramePackers used by tests and legacy
	// callers. This slow path runs once; steady-state reads are atomic-only.
	fp.mu.Lock()
	defer fp.mu.Unlock()
	if p := fp.params.Load(); p != nil {
		return p
	}
	fp.applyDefaults()
	fp.publishParamsLocked()
	return fp.params.Load()
}

func (fp *FramePacker) Pack(seqID uint64, payload []byte, outBuf []byte) (int, error) {
	p := fp.snapshotParams()

	if !p.enable {
		// When obfuscation padding is disabled, we still write the standard 15-byte header with PaddingLen=0
		// so that Magic (0x5054), SeqID (dedup/anti-replay), ObfType (encryption), and PayloadLen are preserved.
		return fp.packStandard(seqID, payload, outBuf, "none", p)
	}

	mode := p.mode
	if auto := fp.auto.Load(); mode == "auto" && auto != nil {
		auto.recordSize(len(payload))
		if p.allowModeSwitch && p.autoDetectInterval > 0 {
			now := time.Now()
			if now.Sub(time.Unix(0, fp.lastEvalUnixNano.Load())) >= time.Duration(p.autoDetectInterval)*time.Second {
				newMode := auto.evaluate()
				if newMode != mode {
					// Preserve the historic auto-mode behaviour (the selected mode
					// becomes the new current mode) without overwriting a concurrent
					// explicit hot reload that already moved away from auto.
					fp.mu.Lock()
					if cur := fp.params.Load(); cur != nil && cur.mode == "auto" {
						fp.Mode = newMode
						fp.publishParamsLocked()
					}
					fp.mu.Unlock()
					mode = newMode
				}
				fp.lastEvalUnixNano.Store(now.UnixNano())
			}
		}
	}

	return fp.packStandard(seqID, payload, outBuf, mode, p)
}

// packStandard handles fixed/block/random/dynamic modes with Magic header.
//
// p carries the immutable parameter snapshot taken by Pack. Reading the exported
// fields directly here would race with UpdateConfig and could mix generations.
func (fp *FramePacker) packStandard(seqID uint64, payload []byte, outBuf []byte, mode string, p *packerParams) (int, error) {
	// Guard against uint16 underflow in paddingLen calculation below: if the
	// payload is larger than MaxFrameSize-HeaderLen, overhead exceeds
	// MaxFrameSize, targetSize gets clamped to MaxFrameSize (which is now
	// less than overhead), and uint16(targetSize-overhead) underflows.
	if len(payload) > MaxFrameSize-HeaderLen {
		return 0, ErrBufferTooSmall
	}
	overhead := HeaderLen + len(payload)
	var targetSize int
	switch mode {
	case "none":
		targetSize = overhead
	case "fixed":
		targetSize = p.fixedSize + randomJitter(p.jitterRange)
	case "block":
		blockSize := p.blockSize
		if blockSize <= 0 {
			blockSize = 256
		}
		blocks := overhead / blockSize
		if overhead%blockSize != 0 {
			blocks++
		}
		targetSize = blocks*blockSize + randomJitter(p.jitterRange)
	case "dynamic":
		// Fill to maxSize to minimize fragmentation: every frame occupies the
		// full MTU-sized obfuscation slot regardless of payload size. This
		// eliminates per-packet fragmentation on the wire (each obfuscated frame
		// fits in a single QUIC/UDP datagram) and makes all packets the same
		// size class, which is stronger for traffic analysis resistance.
		targetSize = randomBetween(overhead, p.maxSize)
	default: // "random" or auto
		low := p.minSize
		if low < overhead {
			low = overhead
		}
		targetSize = randomBetween(low, p.fixedSize) + randomJitter(p.jitterRange)
	}

	// clampFrameSize enforces the datagram budget on top of the size chosen
	// above. Padding is a traffic-shaping knob, not a correctness one, so a
	// configured fixed_size/max_size above the path-MTU budget used to inflate
	// every small frame well past what one transport datagram can carry — extra
	// fragments with no additional confidentiality or size-normalisation.
	targetSize = clampFrameSize(targetSize, len(payload), p.frameBudget)
	if len(outBuf) < targetSize {
		return 0, ErrBufferTooSmall
	}

	paddingLen := uint16(targetSize - overhead)

	// Write header (v2 includes the ObfType byte at offset 10).
	binary.BigEndian.PutUint16(outBuf[0:2], uint16(FrameMagic))
	binary.BigEndian.PutUint64(outBuf[2:10], uint64(seqID))
	outBuf[10] = byte(fp.algo.Load())
	binary.BigEndian.PutUint16(outBuf[11:13], uint16(len(payload)))
	binary.BigEndian.PutUint16(outBuf[13:15], paddingLen)

	// Copy payload. It is written in the CLEAR here — per-peer encryption is
	// applied later by the Node send path (encryptForPeer) using the negotiated
	// per-peer cipher, so a single Pack() result can be fanned out to many
	// peers, each encrypted with its own key. ObfType records the algorithm so
	// the receiver knows which cipher to use.
	copy(outBuf[HeaderLen:], payload)

	// Fill padding with random bytes
	if paddingLen > 0 {
		fillRandom(outBuf[HeaderLen+len(payload) : targetSize])
	}

	return targetSize, nil
}

// MaxPackedLen returns a strict UPPER BOUND on the byte count Pack will write
// for a payload of the given length under the CURRENT configuration. Callers can
// size their output buffer to exactly this value instead of over-allocating a
// fixed slack (e.g. +4096 bytes), eliminating per-frame heap waste on the relay
// hot path. It is guaranteed that Pack never needs more than MaxPackedLen
// returns; if it ever does, that is a bug in this bound and Pack will return
// ErrBufferTooSmall (it never truncates) — so the bound is safe by construction.
func (fp *FramePacker) MaxPackedLen(payloadLen int) int {
	p := fp.snapshotParams()
	mode := p.mode
	enable := p.enable
	fixed, block, jitter := p.fixedSize, p.blockSize, p.jitterRange
	minS, maxS := p.minSize, p.maxSize

	if !enable {
		mode = "none"
	}
	if block <= 0 {
		block = 256
	}

	// Auto can switch modes at runtime; cover the worst case across candidates
	// so we never under-allocate regardless of which mode it settles on.
	if mode == "auto" {
		b := overheadPlus(payloadLen)
		b = max(b, fixed+jitter)
		b = max(b, blockBound(payloadLen, block, jitter))
		b = max(b, dynamicBound(payloadLen, minS, maxS))
		return clampFrameSize(b, payloadLen, p.frameBudget)
	}

	switch mode {
	case "none":
		return clampFrameSize(overheadPlus(payloadLen), payloadLen, p.frameBudget)
	case "fixed":
		return clampFrameSize(fixed+jitter, payloadLen, p.frameBudget)
	case "block":
		return clampFrameSize(blockBound(payloadLen, block, jitter), payloadLen, p.frameBudget)
	case "dynamic":
		return clampFrameSize(dynamicBound(payloadLen, minS, maxS), payloadLen, p.frameBudget)
	default: // "random" or unrecognised
		return clampFrameSize(fixed+jitter, payloadLen, p.frameBudget)
	}
}

func overheadPlus(payloadLen int) int { return HeaderLen + payloadLen }

func blockBound(payloadLen, block, jitter int) int {
	overhead := HeaderLen + payloadLen
	blocks := overhead / block
	if overhead%block != 0 {
		blocks++
	}
	return blocks*block + jitter
}

// dynamicBound mirrors packStandard's "dynamic" branch: targetSize is
// randomBetween(overhead, maxSize), so the maximum is simply the larger of
// overhead and maxSize.
func dynamicBound(payloadLen, minS, maxS int) int {
	overhead := HeaderLen + payloadLen
	return max(overhead, maxS)
}

// clampFrameSize is the single place the final size guards live, shared by Pack
// and MaxPackedLen so the two can never disagree: never below the bare overhead
// for this payload, never above the datagram budget when one is set, never above
// MaxFrameSize.
func clampFrameSize(b, payloadLen, budget int) int {
	overhead := HeaderLen + payloadLen
	if b < overhead {
		b = overhead
	}
	if budget > 0 && b > budget {
		// A payload that already exceeds the budget is left alone: it is
		// fragmented by the transport either way, so shrinking it would only
		// create more fragments.
		b = max(budget, overhead)
	}
	if b > MaxFrameSize {
		b = MaxFrameSize
	}
	return b
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

	if cipher != nil {
		// Nonce = the same 12 bytes derived from the immutable header that
		// EncryptPayloadRegion used to Seal this frame (see obfNonceFromHeader).
		// Historically this used frame[2:14] (SeqID+ObfType+PayloadLen), which
		// disagreed with the encryptor and could never open a real frame.
		nonce := obfNonceFromHeader(frame)
		// PERF: per-frame path. NonceHex() is a hex encode plus an allocation
		// and Go evaluates it at the CALL SITE regardless of log level, so an
		// unguarded log.Debug() costs that on every frame even at info level.
		if log.IsDebug() {
			log.Debug("UnpackWith: DECRYPT branch seqID=%d obfType=%s algo=%s nonce=%s ctLen=%d",
				seqID, AlgoName(obfType), AlgoName(cipher.Algo()), NonceHex(frame), len(raw))
		}
		opened, oerr := cipher.OpenTo(make([]byte, 0, len(raw)), nonce[:], raw)
		if oerr != nil {
			// AEAD authentication failed under the supplied key. We deliberately
			// do NOT log the raw stdlib "message authentication failed" string:
			// it would flood the log for every in-flight old-key frame during a
			// rotation (the caller retries staged fallback keys before giving
			// up). Keep a neutral, classified note with the nonce for tracing.
			// PERF: per-frame during a key-divergence storm — keep guarded.
			if log.IsDebug() {
				log.Debug("UnpackWith: supplied rx key did NOT open frame seqID=%d algo=%s nonce=%s (AEAD auth failed)",
					seqID, AlgoName(cipher.Algo()), NonceHex(frame))
			}
			return 0, nil, ErrFrameCorrupted
		}
		payload = opened
	} else {
		if log.IsDebug() {
			log.Debug("UnpackWith: PLAINTEXT branch seqID=%d obfType=%s (cipherPresent=%v) — payload returned as-is", seqID, AlgoName(obfType), cipher != nil)
		}
		payload = raw
	}
	// PERF: this one fires on EVERY frame, which is why it must stay guarded:
	// the arguments are evaluated at the call site whatever the level is.
	if log.IsDebug() {
		log.Debug("UnpackWith: done seqID=%d payloadLen=%d frameLen=%d", seqID, len(payload), len(frame))
	}
	return seqID, payload, nil
}

// Algo returns the configured ObfType byte for this packer.
func (fp *FramePacker) Algo() byte {
	return byte(fp.algo.Load())
}

// SetSendAlgo records the ObfType byte written into outgoing frames so the
// receiver knows which algorithm to use. It does NOT install a cipher; payload
// encryption is applied per-peer at send time via EncryptPayloadRegion.
func (fp *FramePacker) SetSendAlgo(algo byte) {
	// Called from the hot-reload goroutine (applyHotReload) while the data path
	// stamps this byte into every outgoing frame — hence atomic, not a plain
	// assignment.
	fp.algo.Store(uint32(algo))
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
// Allocation note: AEAD SealTo appends directly into the pre-allocated output
// buffer, eliminating intermediate slice allocations on the hot TX path.
func EncryptPayloadRegion(frame []byte, cipher ObfCipher) ([]byte, error) {
	return EncryptPayloadRegionInto(nil, frame, cipher)
}

// EncryptPayloadRegionInto is EncryptPayloadRegion with an optional caller-owned
// destination. Supplying reusable capacity lets the fragmented TX path keep the
// outer AEAD frame in the same small-buffer pools as its plaintext envelope.
func EncryptPayloadRegionInto(dst, frame []byte, cipher ObfCipher) ([]byte, error) {
	if cipher == nil || cipher.Algo() == ObfAlgoNone {
		if dst == nil {
			return frame, nil
		}
		out := append(dst[:0], frame...)
		return out, nil
	}
	hLen := HeaderLen
	if len(frame) < hLen {
		return nil, ErrFrameCorrupted
	}
	pLen := int(binary.BigEndian.Uint16(frame[11:13]))
	if hLen+pLen > len(frame) {
		return nil, ErrFrameCorrupted
	}
	nonce := obfNonceFromHeader(frame)
	seqID := binary.BigEndian.Uint64(frame[2:10])

	// Assemble [header | ciphertext | trailing padding] directly into dst.
	// Reserve the complete frame once: growing first for the header, then for
	// ciphertext and finally for padding otherwise allocates and copies twice.
	if cap(dst) < len(frame)+cipher.Overhead() {
		dst = make([]byte, 0, len(frame)+cipher.Overhead())
	}
	out := append(dst[:0], frame[:hLen]...)
	out = cipher.SealTo(out, nonce[:], frame[hLen:hLen+pLen])
	ctLen := len(out) - hLen
	if ctLen > math.MaxUint16 {
		return nil, ErrFrameCorrupted
	}
	binary.BigEndian.PutUint16(out[11:13], uint16(ctLen))
	out = append(out, frame[hLen+pLen:]...)

	if log.IsDebug() {
		log.Debug("ObfEncrypt: seqID=%d algo=%s nonce=%s ptLen=%d ctLen=%d",
			seqID, AlgoName(cipher.Algo()), NonceHex(frame), pLen, ctLen)
	}
	return out, nil
}

// DecryptPayloadRegion reverses EncryptPayloadRegion: it opens the encrypted
// payload and returns a new frame slice with PayloadLen restored to the
// plaintext length. Trailing padding is preserved (ignored by Unpack).
//
// Same single-append-chain assembly with OpenTo to minimise copies on the hot RX path.
func DecryptPayloadRegion(frame []byte, cipher ObfCipher) ([]byte, error) {
	return DecryptPayloadRegionInto(nil, frame, cipher)
}

// DecryptPayloadRegionInto is DecryptPayloadRegion with a caller-supplied
// destination: the plaintext frame is appended into dst[:0] (dst may be nil,
// in which case the behaviour is identical to DecryptPayloadRegion). The
// returned slice may alias a GROWN dst — the caller on a per-frame hot path
// keeps it as the new scratch base (capacity is preserved) so steady-state
// frames cost zero allocations, and must not let it outlive the current frame
// processing iteration without copying (downstream stages may mutate it).
func DecryptPayloadRegionInto(dst, frame []byte, cipher ObfCipher) ([]byte, error) {
	if cipher == nil || cipher.Algo() == ObfAlgoNone {
		// Legacy behaviour returned the input frame itself; with a caller
		// scratch we must still not alias the caller's READ buffer (it is
		// reused by the next stream read), so copy into dst when it fits,
		// allocate only when the scratch is smaller than the frame.
		if cap(dst)-len(dst) >= len(frame) {
			out := dst[:len(frame)]
			copy(out, frame)
			return out, nil
		}
		out := make([]byte, len(frame))
		copy(out, frame)
		return out, nil
	}
	hLen := HeaderLen
	if len(frame) < hLen {
		return nil, ErrFrameCorrupted
	}
	pLen := int(binary.BigEndian.Uint16(frame[11:13]))
	if hLen+pLen > len(frame) {
		return nil, ErrFrameCorrupted
	}
	// Nonc derived from immutable header bytes (see EncryptPayloadRegion).
	nonce := obfNonceFromHeader(frame)
	seqID := binary.BigEndian.Uint64(frame[2:10])

	// Reassemble with a single append chain into the caller's buffer:
	// [header | pt | trailing padding].
	// The decrypted frame excludes the tag. Preserve reuse when the caller
	// supplies exactly enough space for plaintext, including maximum frames.
	capacity := max(hLen, len(frame)-cipher.Overhead())
	if cap(dst) < capacity {
		dst = make([]byte, 0, capacity)
	}
	out := append(dst[:0], frame[:hLen]...)
	var err error
	out, err = cipher.OpenTo(out, nonce[:], frame[hLen:hLen+pLen])
	if err != nil {
		// AEAD authentication failed under the CURRENT rx key. This is EXPECTED
		// during a key rotation or when a straggler from a prior connection
		// arrives: the node RX path retries staged fallback keys (rxRing /
		// prevRxCipher) before declaring the frame garbage. We do NOT log the
		// raw stdlib "message authentication failed" string here — it would
		// flood the log for every in-flight old-key frame that the fallback then
		// successfully opens. The authoritative, classified failure line lives
		// in the node RX path after all fallback keys have been tried.
		// PERF: hit on every frame whose AEAD open fails under the current key
		// (a key-divergence storm) — keep guarded.
		if log.IsDebug() {
			log.Debug("ObfDecrypt: current rx key did NOT open frame seqID=%d algo=%s nonce=%s ctLen=%d (AEAD auth failed; caller retries fallback keys)",
				seqID, AlgoName(cipher.Algo()), NonceHex(frame), pLen)
		}
		return nil, err
	}
	ptLen := len(out) - hLen
	binary.BigEndian.PutUint16(out[11:13], uint16(ptLen))
	out = append(out, frame[hLen+pLen:]...)

	// PERF: per-frame RX success path — keep guarded (see UnpackWith note).
	if log.IsDebug() {
		log.Debug("ObfDecrypt: OK seqID=%d algo=%s nonce=%s ctLen=%d ptLen=%d",
			seqID, AlgoName(cipher.Algo()), NonceHex(frame), pLen, ptLen)
	}
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
	fp.AllowModeSwitch = cfg.AllowModeSwitch
	fp.sizeConfigured = cfg.FixedSize > 0 || cfg.MaxSize > 0
	fp.applyDefaults()
	if fp.Mode == "auto" && fp.auto.Load() == nil {
		fp.auto.Store(newAutoState())
	}
	fp.publishParamsLocked()
}
