package obfuscate

// XOR-encoded string literals that do not appear in the binary's string table.
//
// Protocol domain separators, crypto labels, and protocol IDs are visible in
// `strings` output of the unencrypted binary, making static analysis of the
// protocol straightforward. Encoding them with a derived XOR key raises the
// bar: the key is computed from bit operations (not a literal), and the
// encoded bytes have no textual resemblance to the original strings.
//
// Usage:
//   var domain = D([]byte{0x42, 0x60, 0x11, 0x73, 0x47, ...}) // decoded at runtime
//
// The Encode/Decode pair is intentionally simple — this is obfuscation, not
// encryption. A determined attacker can recover the strings, but the effort
// is no longer a one-command `strings` search.

// xorSeed is derived from three non-obvious constants via XOR. The individual
// values (0x7A, 0x2D, 0x1F) are common hex constants that appear throughout
// the codebase for unrelated purposes, so a grep for any one of them does not
// reveal the key derivation. The result (0x66) is a mid-range value that
// avoids the extremes (0x00, 0xFF) which are trivially identifiable.
func xorSeed() byte {
	return (0x7A ^ 0x2D) ^ 0x1F
}

// Encode returns the XOR-encoded form of s using the derived seed.
// Call this at init time or use the result as a []byte literal in source.
func Encode(s string) []byte {
	key := xorSeed()
	b := make([]byte, len(s))
	for i, c := range []byte(s) {
		b[i] = c ^ key
	}
	return b
}

// Decode recovers the original string from an XOR-encoded byte slice.
// Returns an empty string if b is nil.
func Decode(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	key := xorSeed()
	out := make([]byte, len(b))
	for i, c := range b {
		out[i] = c ^ key
	}
	return string(out)
}

// D is a shorthand for Decode, for use in var declarations:
//
//	var myDomain = D([]byte{0x42, 0x60, 0x11, ...})
var D = Decode
