package routing

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"p2ptap/pkg/obfuscate"
)

// Domain separators for the three PSK derivatives. Keeping them named makes
// the hashes unmistakably distinct and prevents one call site from silently
// adopting the other's separator. Encoded to avoid appearing in binary strings.
var (
	pskDomainRelayAuth = obfuscate.D([]byte{0x38, 0x7a, 0x38, 0x3c, 0x29, 0x38, 0x65, 0x3a, 0x2d, 0x24, 0x29, 0x31, 0x65, 0x29, 0x3d, 0x3c, 0x20, 0x72})
	pskDomainNetworkID = obfuscate.D([]byte{0x38, 0x7a, 0x38, 0x3c, 0x29, 0x38, 0x65, 0x26, 0x2d, 0x3c, 0x72})
	pskDomainDiscovery = obfuscate.D([]byte{0x38, 0x7a, 0x38, 0x3c, 0x29, 0x38, 0x65, 0x2c, 0x21, 0x3b, 0x2b, 0x27, 0x72})
)

// PSKKeyBytes returns the canonical byte form of a configured PSK: the bytes
// every PSK-dependent derivation must be computed from.
//
// A hex string is lowercased first, because hex is case-insensitive and both
// cases denote the same key. Without this, a network whose operators typed
// "ABCD" in one config file and "abcd" in another derived different per-peer
// keys and different relay auth tokens, so the pair silently failed to form —
// and LuCI's validator has always admitted [0-9a-fA-F]+, so the mismatch was
// reachable straight from the UI.
//
// Deliberately NOT hex-decoded. The byte shape of the salt is part of the wire
// compatibility of an already-deployed PSK network: decoding 64 hex characters
// down to 32 bytes would change every derived key and break any mixed-version
// pair. Lowercasing changes nothing for the lowercase keys p2ptap's own
// generator emits (cmd/p2ptap genconf uses hex.EncodeToString), so existing
// deployments are byte-for-byte unaffected.
//
// Non-hex values pass through untouched: a plaintext passphrase is not an
// encoding of anything, and lowercasing it would collapse genuinely distinct
// secrets.
func PSKKeyBytes(psk string) []byte {
	if isHexEncoded(psk) {
		return []byte(strings.ToLower(psk))
	}
	return []byte(psk)
}

// isHexEncoded reports whether s is a non-empty, even-length string of hex
// digits, i.e. an unambiguous encoding of whole bytes.
func isHexEncoded(s string) bool {
	if s == "" || len(s)%2 == 1 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

// RelayAuthToken derives the 32-byte token a mesh node presents on the boot
// relay auth handshake (pkg/node/node_connect.go). The boot server computes the
// same value for every configured PSK, so both sides must route through here —
// an independent implementation on either side would silently break relay auth.
func RelayAuthToken(psk string) [32]byte {
	return pskHash(pskDomainRelayAuth, psk)
}

// RelayAuthChallengeLen is the challenge length for the PSK relay auth
// handshake. 32 bytes of crypto/rand is a 256-bit nonce, immune to replay and
// to offline dictionary attack on the HMAC response.
const RelayAuthChallengeLen = 32

// RelayAuthResponse derives the response to a fresh relay-auth challenge. The
// static RelayAuthToken never travels on the wire: only
// HMAC-SHA256(token, challenge) does, so a sniffed handshake leaks nothing
// about the token and cannot be replayed against another session. Both ends
// must call this (the boot with its configured PSK hash, the node with its
// derived token) so the derivation cannot drift.
func RelayAuthResponse(token [32]byte, challenge []byte) [32]byte {
	mac := hmac.New(sha256.New, token[:])
	mac.Write(challenge)
	var out [32]byte
	copy(out[:], mac.Sum(nil))
	return out
}

// NetworkIDFromPSK derives the opaque network ID for a PSK: the first 8 bytes
// of SHA-256(pskDomainNetworkID + canonical key bytes), hex-encoded (16 chars).
//
// It MUST stay byte-for-byte identical to the boot server's
// networkIDFromPSK — the boot delegates to this very function, so the node
// (which tags relay-over-backbone envelopes in-band) and the boot (which
// enforces PSK isolation) cannot drift. The plaintext PSK is never placed on
// the wire; only this derivative travels.
func NetworkIDFromPSK(psk string) string {
	sum := pskHash(pskDomainNetworkID, psk)
	return hex.EncodeToString(sum[:8])
}

// DiscoRendezvousKey derives the DHT discovery rendezvous key for a PSK: the
// full 32-byte SHA-256(pskDomainDiscovery + canonical key bytes), hex-encoded.
//
// The discovery layer must use a domain-separated, PSKKeyBytes-normalised hash
// — NOT raw sha256(PSK). Without this, a hex PSK "ABCD" would produce a
// different rendezvous key than "abcd" (the two halves of a mixed-case network
// would never find each other in the DHT), and the hash could collide with
// another protocol's raw-PSK hash.
func DiscoRendezvousKey(psk string) string {
	sum := pskHash(pskDomainDiscovery, psk)
	return hex.EncodeToString(sum[:])
}

// pskHash hashes a domain separator over the canonical PSK key bytes.
func pskHash(domain, psk string) [32]byte {
	buf := make([]byte, 0, len(domain)+len(psk))
	buf = append(buf, domain...)
	buf = append(buf, PSKKeyBytes(psk)...)
	return sha256.Sum256(buf)
}
