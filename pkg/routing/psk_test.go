package routing

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

// productionPSK is the 64-hex-char key deployed on the production bootstrap
// server. Used as-is so a regression cannot be masked by editing the fixture.
const productionPSK = "2d5c54ee79fcd3855c23d521c413985e23ad5f31cf039737fd28d84f98683b39"

func TestPSKKeyBytesHexIsCaseInsensitive(t *testing.T) {
	got := PSKKeyBytes(strings.ToUpper(productionPSK))
	want := []byte(productionPSK)
	if string(got) != string(want) {
		t.Fatalf("uppercase hex must canonicalize to lowercase: got %q", got)
	}
	if string(PSKKeyBytes(productionPSK)) != string(PSKKeyBytes(strings.ToUpper(productionPSK))) {
		t.Fatal("case variants of the same key must produce identical bytes")
	}
	if got := PSKKeyBytes("A1B2c3D4"); string(got) != "a1b2c3d4" {
		t.Fatalf("mixed-case hex not lowercased: %q", got)
	}
}

// Hex is NOT decoded: the byte shape of the salt is part of the wire
// compatibility of a deployed PSK network, so 8 hex characters must stay 8
// bytes. Decoding would change every derived key for existing deployments.
func TestPSKKeyBytesDoesNotDecodeHex(t *testing.T) {
	got := PSKKeyBytes("deadbeef")
	if len(got) != 8 || string(got) != "deadbeef" {
		t.Fatalf("hex must stay as characters, got %q (len %d)", got, len(got))
	}
}

func TestPSKKeyBytesNonHexPassthrough(t *testing.T) {
	cases := map[string]string{
		"":                   "",
		"s3cret-passphrase1": "s3cret-passphrase1",
		// Not a valid hex encoding (odd length), so no lowercasing: this could be
		// a passphrase where case is meaningful.
		"AbC":           "AbC",
		"MyPassword123": "MyPassword123",
	}
	for in, want := range cases {
		if got := string(PSKKeyBytes(in)); got != want {
			t.Errorf("PSKKeyBytes(%q) = %q, want %q", in, got, want)
		}
	}
}

// Backward compatibility is the whole reason this canonicalization lowercases
// rather than hex-decoding: for every PSK that a deployed network could already
// be using (lowercase hex, or plaintext), the derived values must be
// byte-for-byte identical to the pre-existing formulas.
func TestPSKDerivationsAreBackwardCompatible(t *testing.T) {
		for _, psk := range []string{
			productionPSK,                      // 64 lowercase hex chars
			"deadbeefdeadbeef",                 // short lowercase hex
			"2024-01-15 12:00 UTC session key", // non-ASCII-adjacent prose
		} {
			// Legacy network ID: hex(SHA-256("p2ptap-net:" + PSK)[:8])
			sum := sha256.Sum256([]byte("p2ptap-net:" + psk))
			legacyNetID := hex.EncodeToString(sum[:8])
			if got := NetworkIDFromPSK(psk); got != legacyNetID {
				t.Errorf("NetworkIDFromPSK(%q) changed vs legacy formula", psk)
			}
		}
		// The relay-auth token is deliberately NOT legacy-compatible anymore:
		// it is HKDF-derived (see RelayAuthToken), so the old bare-SHA256 token
		// is never accepted and vice versa. Node and boot are upgraded together.
		if legacyToken := sha256.Sum256([]byte("p2ptap-relay-auth:" + productionPSK)); RelayAuthToken(productionPSK) == legacyToken {
			t.Fatal("RelayAuthToken must no longer derive the legacy bare-SHA256 token")
		}
}

// Uppercase hex is the one case that intentionally changes: those are exactly
// the deployments where two operators typed the same key differently and the
// network silently failed to form.
func TestPSKDerivationsCanonicalizeUppercase(t *testing.T) {
	upper := strings.ToUpper(productionPSK)
	if string(PSKKeyBytes(upper)) != string(PSKKeyBytes(productionPSK)) {
		t.Fatal("uppercase key must canonicalize to the lowercase key")
	}
	legacyToken := sha256.Sum256([]byte("p2ptap-relay-auth:" + upper))
	if got := RelayAuthToken(upper); got == legacyToken {
		t.Fatal("uppercase hex must no longer derive the legacy (case-sensitive) token")
	}
	if RelayAuthToken(upper) != RelayAuthToken(productionPSK) {
		t.Fatal("both cases of one key must authenticate identically")
	}
	if NetworkIDFromPSK(upper) != NetworkIDFromPSK(productionPSK) {
		t.Fatal("both cases of one key must map to one network ID")
	}
}

// Domain separation: the two PSK derivatives must stay distinct, otherwise the
// auth token could be mistaken for a network ID.
func TestPSKDomainsAreSeparated(t *testing.T) {
	auth := RelayAuthToken(productionPSK)
	netSum := sha256.Sum256(append([]byte("p2ptap-net:"), PSKKeyBytes(productionPSK)...))
	if auth == netSum {
		t.Fatal("relay auth domain and network ID domain must not collide")
	}
	if net := NetworkIDFromPSK(productionPSK); len(net) != 16 {
		t.Fatalf("network ID must be 16 hex chars, got %q", net)
	}
	if _, err := hex.DecodeString(NetworkIDFromPSK(productionPSK)); err != nil {
		t.Fatalf("network ID must be hex: %v", err)
	}
}

// --- relay session ticket ---------------------------------------------------

func TestRelayTicketMasterKeyDistinctFromAuthToken(t *testing.T) {
	// Domain separation: the ticket master key must never equal the relay-auth
	// token, or a ticket MAC key could be replayed as a handshake response.
	auth := RelayAuthToken(productionPSK)
	mk := RelayTicketMasterKey(productionPSK)
	if auth == mk {
		t.Fatal("relay-auth token and ticket master key must be domain-separated")
	}
	if RelayTicketMasterKey(strings.ToUpper(productionPSK)) != mk {
		t.Fatal("both cases of one key must derive one ticket master key")
	}
}

func TestRelayTicketRoundTrip(t *testing.T) {
	now := time.Now()
	mk := RelayTicketMasterKey(productionPSK)
	netID := NetworkIDFromPSK(productionPSK)

	ticket := MintRelayTicket(mk, netID, now)
	if len(ticket) != RelayTicketLen {
		t.Fatalf("ticket length = %d, want %d", len(ticket), RelayTicketLen)
	}
	if !VerifyRelayTicket(mk, ticket, now) {
		t.Fatal("freshly minted ticket must verify")
	}
	if got := RelayTicketNetID(ticket); got != netID {
		t.Fatalf("ticket netID = %q, want %q", got, netID)
	}
	// A ticket must still verify just inside its TTL.
	if !VerifyRelayTicket(mk, ticket, now.Add((RelayTicketTTL-1)*time.Second)) {
		t.Fatal("ticket must verify just before expiry")
	}
	// And must NOT verify after its TTL.
	if VerifyRelayTicket(mk, ticket, now.Add((RelayTicketTTL+1)*time.Second)) {
		t.Fatal("expired ticket must not verify")
	}
}

func TestRelayTicketCorruptMAC(t *testing.T) {
	mk := RelayTicketMasterKey(productionPSK)
	ticket := MintRelayTicket(mk, NetworkIDFromPSK(productionPSK), time.Now())
	// Flip one bit in the MAC region ([40:56]).
	ticket[40] ^= 0x01
	if VerifyRelayTicket(mk, ticket, time.Now()) {
		t.Fatal("ticket with a corrupted MAC must not verify")
	}
}

func TestRelayTicketWrongLength(t *testing.T) {
	mk := RelayTicketMasterKey(productionPSK)
	netID := NetworkIDFromPSK(productionPSK)
	ticket := MintRelayTicket(mk, netID, time.Now())
	// A slice of the ticket cannot exceed its capacity, so the over-long case is
	// built by appending.
	over := append(append([]byte{}, ticket...), 0x00)
	for _, tt := range []struct {
		name string
		t    []byte
	}{
		{"empty", ticket[:0]},
		{"one byte", ticket[:1]},
		{"one short", ticket[:RelayTicketLen-1]},
		{"one long", over},
	} {
		if VerifyRelayTicket(mk, tt.t, time.Now()) {
			t.Errorf("%s: ticket of length %d must not verify", tt.name, len(tt.t))
		}
		if RelayTicketNetID(tt.t) != "" {
			t.Errorf("%s: netID of length %d ticket must be empty", tt.name, len(tt.t))
		}
	}
}

func TestRelayTicketRejectedUnderDifferentMasterKey(t *testing.T) {
	// A ticket minted by one network must not verify under another network's
	// master key: the boot looks up the key by the ticket's embedded netID, so a
	// ticket from network A can never authenticate a peer of network B.
	mkA := RelayTicketMasterKey("network-a-secret")
	mkB := RelayTicketMasterKey("network-b-secret")
	ticket := MintRelayTicket(mkA, NetworkIDFromPSK("network-a-secret"), time.Now())
	if VerifyRelayTicket(mkB, ticket, time.Now()) {
		t.Fatal("ticket minted under one master key must not verify under another")
	}
	if RelayTicketNetID(ticket) != NetworkIDFromPSK("network-a-secret") {
		t.Fatal("netID must be recoverable regardless of the verifying key")
	}
}
