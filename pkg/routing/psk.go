package routing

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"time"

	"p2ptap/pkg/obfuscate"
)

// Domain separators for the three PSK derivatives. Keeping them named makes
// the hashes unmistakably distinct and prevents one call site from silently
// adopting the other's separator. Encoded to avoid appearing in binary strings.
var (
	pskDomainRelayAuth = obfuscate.D([]byte{0x38, 0x7a, 0x38, 0x3c, 0x29, 0x38, 0x65, 0x3a, 0x2d, 0x24, 0x29, 0x31, 0x65, 0x29, 0x3d, 0x3c, 0x20, 0x72})
	pskDomainNetworkID = obfuscate.D([]byte{0x38, 0x7a, 0x38, 0x3c, 0x29, 0x38, 0x65, 0x26, 0x2d, 0x3c, 0x72})
	pskDomainDiscovery = obfuscate.D([]byte{0x38, 0x7a, 0x38, 0x3c, 0x29, 0x38, 0x65, 0x2c, 0x21, 0x3b, 0x2b, 0x27, 0x72})
	// pskDomainTicket salts the HKDF that derives the per-boot session-ticket
	// master key. It is domain-separated from the other derivatives so a ticket
	// MAC cannot be confused with a relay-auth token or a discovery key.
	pskDomainTicket = obfuscate.D([]byte{0x38, 0x7a, 0x38, 0x3c, 0x29, 0x38, 0x65, 0x34, 0x2d, 0x24, 0x29, 0x35, 0x65, 0x29, 0x3d, 0x3c, 0x20, 0x72})
)

// HKDF info strings. Each derivation is domain-separated twice: by its salt
// (pskDomain*) and by this fixed info label, so no two PSK derivatives can
// collide even if a caller reuses the wrong helper.
const (
	pskInfoRelayAuth = "p2ptap-relay-auth-v2"
	pskInfoTicket    = "p2ptap-relay-ticket-v2"
)

// relayAuthModes are the one-byte mode tags that lead every node-to-boot auth
// stream. The node always sends exactly one before the boot decides how to
// proceed, so the boot never has to probe for a mode and there is no
// read-timeout race.
const (
	RelayAuthModeFull   = 0x00 // no cached ticket: proceed with challenge-response
	RelayAuthModeTicket = 0x01 // cached session ticket: authenticate without a full round-trip
)

// RelayChallengeByte is the fixed first byte of every relay-auth challenge.
// The challenge is sent as [RelayChallengeByte][31B random] so the node can
// unambiguously distinguish a challenge (0x02) from a 0x00 failure or 0x01
// success response byte on the same stream.
const RelayChallengeByte = 0x02

// RelayTicketLen is the fixed on-wire length of a relay session ticket:
// 16B ticketID || 16B netID || 8B expiry || 16B HMAC.
const RelayTicketLen = 56

// RelayTicketTTL is how long a minted session ticket stays valid. It is short
// by design: a ticket is a bearer credential that is weaker than the long-lived
// PSK it was derived from, so the reuse window after a leak must be small.
// The node re-authenticates with the full challenge-response at most once per
// TTL, which is a negligible cost against the round-trip saved on every
// reconnect within the window.
const RelayTicketTTL = 10 * 60 // seconds

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

// RelayAuthToken derives the 32-byte authentication key a mesh node uses on the
// boot relay auth handshake (pkg/node/node_connect.go). The boot server computes
// the same value for every configured PSK, so both sides must route through here
// — an independent implementation on either side would silently break relay
// auth.
//
// It is derived with HKDF-SHA256 (salt = the domain separator, info =
// pskInfoRelayAuth) rather than a bare SHA-256, so the on-wire HMAC key is
// cryptographically independent of every other PSK derivative and of the raw
// key bytes. This is what keeps the PSK itself off the wire even under a
// captured challenge-response pair: the response is
// HMAC-SHA256(HKDF(psk), challenge), and neither the HMAC nor the HKDF output
// can be inverted to recover the PSK.
func RelayAuthToken(psk string) [32]byte {
	out, err := hkdf.Key(sha256.New, PSKKeyBytes(psk), []byte(pskDomainRelayAuth), pskInfoRelayAuth, 32)
	if err != nil {
		panic("routing: HKDF-SHA256 relay auth key expansion failed: " + err.Error())
	}
	var token [32]byte
	copy(token[:], out)
	return token
}

// RelayTicketMasterKey derives the per-PSK master key that authenticates relay
// session tickets (MintRelayTicket / VerifyRelayTicket). Like RelayAuthToken it
// is HKDF-derived and domain-separated, so a ticket MAC key cannot be confused
// with the auth key or any other derivative.
func RelayTicketMasterKey(psk string) [32]byte {
	out, err := hkdf.Key(sha256.New, PSKKeyBytes(psk), []byte(pskDomainTicket), pskInfoTicket, 32)
	if err != nil {
		panic("routing: HKDF-SHA256 ticket master key expansion failed: " + err.Error())
	}
	var key [32]byte
	copy(key[:], out)
	return key
}

// MintRelayTicket issues a bearer session ticket for a network. The ticket is
// opaque, contains no PSK material, and is authenticated with
// HMAC-SHA256(masterKey, ticketID || netID || expiry)[:16]; only the boot that
// derived masterKey can mint or verify it. The expiry is embedded (big-endian
// unix seconds) and bound into the MAC, so it cannot be extended without the
// key. now is the boot's wall clock.
func MintRelayTicket(masterKey [32]byte, netID string, now time.Time) []byte {
	ticket := make([]byte, RelayTicketLen)
	if _, err := rand.Read(ticket[0:16]); err != nil {
		panic("routing: crypto/rand ticket ID generation failed: " + err.Error())
	}
	copy(ticket[16:32], netID)
	binary.BigEndian.PutUint64(ticket[32:40], uint64(now.Add(RelayTicketTTL*time.Second).Unix()))
	mac := hmac.New(sha256.New, masterKey[:])
	mac.Write(ticket[0:40])
	copy(ticket[40:56], mac.Sum(nil)[:16])
	return ticket
}

// VerifyRelayTicket checks a ticket against one master key. It fails on wrong
// length, an expired expiry, or a MAC mismatch (constant-time). netID is not
// validated here — the caller reads it from the ticket and looks up the right
// master key first, then calls this.
func VerifyRelayTicket(masterKey [32]byte, ticket []byte, now time.Time) bool {
	if len(ticket) != RelayTicketLen {
		return false
	}
	expiry := int64(binary.BigEndian.Uint64(ticket[32:40]))
	if now.Unix() > expiry {
		return false
	}
	mac := hmac.New(sha256.New, masterKey[:])
	mac.Write(ticket[0:40])
	return subtle.ConstantTimeCompare(ticket[40:56], mac.Sum(nil)[:16]) == 1
}

// RelayTicketNetID extracts the network ID embedded in a ticket (the bytes the
// boot uses to select the master key for verification). Callers should treat an
// out-of-range ticket as invalid; only call with a full-length ticket.
func RelayTicketNetID(ticket []byte) string {
	if len(ticket) != RelayTicketLen {
		return ""
	}
	return string(ticket[16:32])
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
