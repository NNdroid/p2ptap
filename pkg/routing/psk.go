package routing

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// Domain separators for the two PSK derivatives. Keeping them named makes the
// two hashes unmistakably distinct and prevents one call site from silently
// adopting the other's separator.
const (
	pskDomainRelayAuth = "p2ptap-relay-auth:"
	pskDomainNetworkID = "p2ptap-net:"
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

// pskHash hashes a domain separator over the canonical PSK key bytes.
func pskHash(domain, psk string) [32]byte {
	buf := make([]byte, 0, len(domain)+len(psk))
	buf = append(buf, domain...)
	buf = append(buf, PSKKeyBytes(psk)...)
	return sha256.Sum256(buf)
}
