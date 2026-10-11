package routing

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
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
		"s3cret-passphrase1",               // plaintext with mixed classes
		"2024-01-15 12:00 UTC session key", // non-ASCII-adjacent prose
	} {
		// Legacy relay auth token: SHA-256("p2ptap-relay-auth:" + PSK)
		legacyToken := sha256.Sum256([]byte("p2ptap-relay-auth:" + psk))
		if got := RelayAuthToken(psk); got != legacyToken {
			t.Errorf("RelayAuthToken(%q) changed vs legacy formula", psk)
		}
		// Legacy network ID: hex(SHA-256("p2ptap-net:" + PSK)[:8])
		sum := sha256.Sum256([]byte("p2ptap-net:" + psk))
		legacyNetID := hex.EncodeToString(sum[:8])
		if got := NetworkIDFromPSK(psk); got != legacyNetID {
			t.Errorf("NetworkIDFromPSK(%q) changed vs legacy formula", psk)
		}
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
