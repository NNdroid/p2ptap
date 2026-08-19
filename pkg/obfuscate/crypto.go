// Package obfuscate provides lightweight per-frame obfuscation (padding/disguise)
// plus optional AEAD encryption negotiated per-peer via an ECDH(P256) handshake.
//
// Design goals:
//   - Symmetric: Pack/Unpack require identical mode/key on both ends.
//   - Per-peer crypto: a fresh ECDH key pair is generated at startup; the public
//     key is exchanged over the trusted SeqSync control channel. The derived
//     shared secret is never transmitted (forward secrecy, no static PSK).
//   - Low intrusion: the packer only stamps an ObfType byte; payload encryption
//     is applied per-peer at send time and removed at receive time.
package obfuscate

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// ObfAlgo identifies an obfuscation/encryption algorithm family.
// It is carried in the frame header (ObfType byte) so receivers know how to
// interpret the payload.
const (
	ObfAlgoNone     byte = 0 // plaintext (no encryption)
	ObfAlgoAESGCM   byte = 1
	ObfAlgoChaCha20 byte = 2
)

// DefaultAlgoPreference is the negotiation order under config "auto".
// Most peers prefer ChaCha20 (constant-time, no AES-NI dependency), then AES-GCM,
// then plaintext fallback for peers configured with encryption disabled.
var DefaultAlgoPreference = []byte{ObfAlgoChaCha20, ObfAlgoAESGCM, ObfAlgoNone}

// AlgoName returns a human-readable name for an algorithm byte.
func AlgoName(a byte) string {
	switch a {
	case ObfAlgoAESGCM:
		return "aes-gcm"
	case ObfAlgoChaCha20:
		return "chacha20"
	case ObfAlgoNone:
		return "none"
	}
	return fmt.Sprintf("unknown(0x%02x)", a)
}

// SelectAlgo picks the strongest algorithm both sides support.
// mine is this node's preference order; peer is the peer's advertised set.
// Returns ObfAlgoNone if there is no common algorithm (callers downgrade).
func SelectAlgo(mine, peer []byte) byte {
	for _, m := range mine {
		for _, p := range peer {
			if m == p {
				return m
			}
		}
	}
	return ObfAlgoNone
}

// ObfCipher seals/opens a frame payload. The same AEAD instance is reused for
// all frames to a given peer; uniqueness of the nonce is guaranteed by the
// structured SeqID (see frame.go), so no random nonce is needed.
type ObfCipher interface {
	Seal(seqID []byte, plaintext []byte) []byte
	Open(seqID []byte, ciphertext []byte) ([]byte, error)
	SealTo(dst, seqID, plaintext []byte) []byte
	OpenTo(dst, seqID, ciphertext []byte) ([]byte, error)
	Algo() byte
	Overhead() int
}

type noneCipher struct{}

func (noneCipher) Seal(seqID, p []byte) []byte                 { return p }
func (noneCipher) Open(seqID, c []byte) ([]byte, error)        { return c, nil }
func (noneCipher) SealTo(dst, seqID, p []byte) []byte          { return append(dst, p...) }
func (noneCipher) OpenTo(dst, seqID, c []byte) ([]byte, error) { return append(dst, c...), nil }
func (noneCipher) Algo() byte                                  { return ObfAlgoNone }
func (noneCipher) Overhead() int                               { return 0 }

type aeadCipher struct {
	algo byte
	aead cipher.AEAD
}

func (c *aeadCipher) Seal(seqID, plaintext []byte) []byte {
	return c.aead.Seal(nil, seqID, plaintext, nil)
}
func (c *aeadCipher) Open(seqID, ciphertext []byte) ([]byte, error) {
	return c.aead.Open(nil, seqID, ciphertext, nil)
}
func (c *aeadCipher) SealTo(dst, seqID, plaintext []byte) []byte {
	return c.aead.Seal(dst, seqID, plaintext, nil)
}
func (c *aeadCipher) OpenTo(dst, seqID, ciphertext []byte) ([]byte, error) {
	return c.aead.Open(dst, seqID, ciphertext, nil)
}
func (c *aeadCipher) Algo() byte    { return c.algo }
func (c *aeadCipher) Overhead() int { return c.aead.Overhead() }

// NewObfCipher constructs a cipher for the given algorithm from a 32-byte key.
// Returns nil (with no error) for ObfAlgoNone — callers treat nil as plaintext.
func NewObfCipher(algo byte, key []byte) (ObfCipher, error) {
	switch algo {
	case ObfAlgoNone:
		return noneCipher{}, nil
	case ObfAlgoAESGCM:
		blk, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		aead, err := cipher.NewGCM(blk)
		if err != nil {
			return nil, err
		}
		return &aeadCipher{algo: algo, aead: aead}, nil
	case ObfAlgoChaCha20:
		aead, err := chacha20poly1305.New(key)
		if err != nil {
			return nil, err
		}
		return &aeadCipher{algo: algo, aead: aead}, nil
	}
	return nil, fmt.Errorf("obfuscate: unsupported algorithm 0x%02x", algo)
}

// ObfKeyPair is an ephemeral ECDH(P256) key pair used only for per-peer key
// agreement. The public key is exchanged over the trusted SeqSync channel; the
// private key never leaves the process.
type ObfKeyPair struct {
	priv *ecdh.PrivateKey
}

// GenerateObfKeyPair creates a fresh P256 key pair.
func GenerateObfKeyPair() (*ObfKeyPair, error) {
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &ObfKeyPair{priv: priv}, nil
}

// PublicKeyBytes returns the raw X9.62 uncompressed public key (65 bytes).
func (k *ObfKeyPair) PublicKeyBytes() ([]byte, error) {
	return k.priv.PublicKey().Bytes(), nil
}

// Fingerprint returns a short, stable hex string derived from this node's public
// key. Two peers that completed the same ECDH exchange derive the same secret,
// but this fingerprint is local-identity scoped and useful for UI display.
func (k *ObfKeyPair) Fingerprint() string {
	sum := sha256.Sum256(k.priv.PublicKey().Bytes())
	return hex.EncodeToString(sum[:4])
}

// DeriveKeys performs ECDH against the peer's public key using the SUPPLIED
// private key, then expands the shared secret into TWO 32-byte symmetric keys
// (keyA, keyB) via HKDF-SHA256. The private key is passed by the caller so that
// callers may use a one-shot ephemeral key per handshake (perfect forward
// secrecy) instead of a long-lived node key — the caller simply discards the
// temporary private key after the handshake.
//
// The two keys let traffic in each direction use a distinct key. Both sides derive
// the same keyA/keyB from the identical shared secret, but assign them to
// directions by PeerID ordering (see negotiateObfWithPeer): the side with the
// smaller PeerID sends with keyA / receives with keyB, the other side the reverse.
// This guarantees the sender's encrypt key always equals the receiver's decrypt
// key, AND that A→B and B→A never share a (key, nonce) pair — closing the
// cross-direction AEAD nonce-reuse hole that a single shared key allowed.
// Returns (nil,nil,nil) if priv/peerPub is empty/invalid (caller falls back to
// plaintext). The raw ECDH shared secret is wiped from memory as soon as the two
// keys are derived, so key material does not linger.
func DeriveKeys(priv *ecdh.PrivateKey, peerPub []byte) (keyA, keyB []byte, err error) {
	if priv == nil || len(peerPub) == 0 {
		return nil, nil, nil
	}
	remote, err := ecdh.P256().NewPublicKey(peerPub)
	if err != nil {
		return nil, nil, fmt.Errorf("obfuscate: invalid peer public key: %w", err)
	}
	shared, err := priv.ECDH(remote)
	if err != nil {
		return nil, nil, fmt.Errorf("obfuscate: ECDH failed: %w", err)
	}
	// Wipe the raw shared secret immediately — it is only needed to seed HKDF,
	// and must not persist in memory alongside the derived keys.
	defer func() { for i := range shared { shared[i] = 0 } }()

	keyA = make([]byte, 32)
	keyB = make([]byte, 32)
	rA := hkdf.New(sha256.New, shared, nil, []byte("p2ptap-obf-key-a"))
	if _, err = io.ReadFull(rA, keyA); err != nil {
		return nil, nil, err
	}
	rB := hkdf.New(sha256.New, shared, nil, []byte("p2ptap-obf-key-b"))
	if _, err = io.ReadFull(rB, keyB); err != nil {
		return nil, nil, err
	}
	return keyA, keyB, nil
}

// DeriveSharedSecret performs ECDH using THIS key pair's private key (see
// DeriveKeys for the full key-derivation contract). Retained for the
// long-lived-key fallback path; the handshake now prefers per-handshake
// ephemeral keys via DeriveKeys for forward secrecy.
func (k *ObfKeyPair) DeriveSharedSecret(peerPub []byte) (keyA, keyB []byte, err error) {
	return DeriveKeys(k.priv, peerPub)
}

// Priv exposes the private key. It exists so callers performing per-handshake
// ephemeral ECDH can derive with a temporary key without holding the key pair
// long-term. Callers must not persist or transmit the result.
func (k *ObfKeyPair) Priv() *ecdh.PrivateKey { return k.priv }

// Zeroize discards the private key material. After calling this the key pair is
// no longer usable for ECDH; callers that rotate keys should drop the old pair.
func (k *ObfKeyPair) Zeroize() { k.priv = nil }

// IsZeroKey reports whether every byte of a derived key is zero. A valid ECDH
// shared secret (and therefore an HKDF-expanded key) is all-zero only with
// negligible probability; callers use this as a sanity guard to refuse
// encrypting with a degenerate, publicly-known key.
func IsZeroKey(key []byte) bool {
	for _, b := range key {
		if b != 0 {
			return false
		}
	}
	return len(key) > 0
}

// KeyFingerprint returns a short, stable, NON-REVERSIBLE fingerprint of a
// symmetric key — the first 8 hex chars of its SHA-256. It is safe to log: it
// reveals nothing about the key itself, yet lets an operator confirm that two
// endpoints derived the SAME key (identical fingerprint ⇒ identical key), which
// is the single most useful signal when debugging a "frames won't decrypt"
// mismatch between peers. Never log the raw key bytes; log this fingerprint.
func KeyFingerprint(key []byte) string {
	if len(key) == 0 {
		return "(none)"
	}
	sum := sha256.Sum256(key)
	return hex.EncodeToString(sum[:4])
}
