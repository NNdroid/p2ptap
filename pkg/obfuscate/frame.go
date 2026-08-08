package obfuscate

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"math/big"
	"sync"
	"sync/atomic"
	"time"

	"p2ptap/pkg/config"
	"p2ptap/pkg/logger"
)

var log = logger.New("Obfuscate")

const (
	FrameMagic       uint16 = 0x5054 // "PT" (P2PTAP)
	HeaderLen               = 2 + 8 + 2 + 2 // Magic(2) + SeqID(8) + PayloadLen(2) + PaddingLen(2) = 14 bytes
	MaxFrameSize            = 65535
	MaxOutputSize           = MaxFrameSize
	WindowSizeBitmask       = 1024
)

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

// GetBuffer fetches a buffer from pool.
func GetBuffer() *[]byte {
	return FramePool.Get().(*[]byte)
}

// PutBuffer returns a buffer to pool.
func PutBuffer(b *[]byte) {
	FramePool.Put(b)
}

// autoState tracks per-mode traffic statistics for the auto-detection engine.
type autoState struct {
	mu          sync.Mutex
	packetSizes []int   // ring buffer of recent packet sizes
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
	Enable           bool   `json:"enable"`
	Mode             string `json:"mode"`
	FixedSize        int    `json:"fixed_size"`
	BlockSize        int    `json:"block_size"`
	// Extended jitter & dynamic range
	JitterRange int `json:"jitter_range"`
	MinSize     int `json:"min_size"`
	MaxSize     int `json:"max_size"`

	// Auto-detection
	AutoDetectInterval int  `json:"auto_detect_interval"`
	AutoThresholdBytes int  `json:"auto_threshold_bytes"`
	AllowModeSwitch    bool `json:"allow_mode_switch"`

	seqCounter   uint64      // monotonically increasing sequence number
	auto         *autoState
	lastEval     time.Time
	totalBytes   int64
	mu           sync.Mutex
}

// NewFramePacker creates a FramePacker with the given parameters.
// Signature kept for backward compatibility.
func NewFramePacker(enable bool, mode string, fixedSize int, blockSize int) *FramePacker {
	fp := &FramePacker{
		Enable:             enable,
		Mode:               mode,
		FixedSize:          fixedSize,
		BlockSize:          blockSize,
		JitterRange:        64,
		MinSize:            512,
		MaxSize:            1500,
		AutoDetectInterval: 30,
		AutoThresholdBytes: 65536,
	}
	fp.applyDefaults()
	if fp.Mode == "auto" {
		fp.auto = newAutoState()
	}
	return fp
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

// NextSeqID returns the next monotonic sequence ID for dedup tracking.
func (fp *FramePacker) NextSeqID() uint64 {
	return atomic.AddUint64(&fp.seqCounter, 1)
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
//   [Magic(2) | SeqID(8) | PayloadLen(2) | PaddingLen(2) | payload | random padding]
func (fp *FramePacker) Pack(seqID uint64, payload []byte, outBuf []byte) (int, error) {
	if !fp.Enable {
		// No obfuscation: just length prefix
		if len(outBuf) < 2+len(payload) {
			return 0, ErrBufferTooSmall
		}
		binary.BigEndian.PutUint16(outBuf[0:2], uint16(len(payload)))
		copy(outBuf[2:], payload)
		return 2 + len(payload), nil
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

	overhead := HeaderLen + len(payload)
	if targetSize < overhead {
		targetSize = overhead
	}
	if targetSize > MaxFrameSize {
		targetSize = MaxFrameSize
	}
	if len(outBuf) < targetSize {
		return 0, ErrBufferTooSmall
	}

	paddingLen := uint16(targetSize - HeaderLen - len(payload))

	// Write header
	binary.BigEndian.PutUint16(outBuf[0:2], uint16(FrameMagic))
	binary.BigEndian.PutUint64(outBuf[2:10], uint64(seqID))
	binary.BigEndian.PutUint16(outBuf[10:12], uint16(len(payload)))
	binary.BigEndian.PutUint16(outBuf[12:14], paddingLen)

	// Copy payload
	copy(outBuf[HeaderLen:], payload)

	// Fill padding with random bytes
	if paddingLen > 0 {
		fillRandom(outBuf[HeaderLen+len(payload) : targetSize])
	}

	return targetSize, nil
}

// Unpack reverses Pack: returns the seqID and payload from a frame.
func Unpack(frame []byte) (seqID uint64, payload []byte, err error) {
	if len(frame) < HeaderLen {
		return 0, nil, ErrFrameCorrupted
	}

	magic := binary.BigEndian.Uint16(frame[0:2])
	if magic != uint16(FrameMagic) {
		// Not our frame — treat entire buffer as raw payload for backward compat
		log.Debug("Unpack: magic mismatch (got 0x%04x expected 0x%04x), treating as raw payload (len=%d)", magic, uint16(FrameMagic), len(frame))
		return 0, frame, nil
	}

	seqID = binary.BigEndian.Uint64(frame[2:10])
	pLen := int(binary.BigEndian.Uint16(frame[10:12]))
	if HeaderLen+pLen > len(frame) {
		log.Debug("Unpack: payload length overflow, headerLen=%d pLen=%d frameLen=%d", HeaderLen, pLen, len(frame))
		return 0, nil, ErrFrameCorrupted
	}
	log.Debug("Unpack: seqID=%d payloadLen=%d frameLen=%d", seqID, pLen, len(frame))
	return seqID, frame[HeaderLen : HeaderLen+pLen], nil
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
