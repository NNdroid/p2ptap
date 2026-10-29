package routing

import (
	"encoding/binary"
	"fmt"

	"github.com/libp2p/go-libp2p/core/peer"
	mh "github.com/multiformats/go-multihash"
)

const (
	// RelayHeaderVersion is the relay header version (0x02), which carries
	// both destination and source peer IDs so the destination can learn the
	// correct reply route through relay hops. In v2 the IDs are base58 CID
	// strings.
	RelayHeaderVersion = 0x02
	// RelayHeaderVersionV3 is the compact relay header (0x03): same layout as
	// v2, but dst and src carry the peer ID's raw multihash bytes instead of
	// its base58 CID string.
	//
	// It exists to remove base58 from a hot path. Packing does
	// finalDst.String() and source.String(), and unpacking does two
	// peer.Decode calls — that is four base58 conversions per relay hop, on
	// every relayed frame, and peer.ID.String() is one of the explicitly
	// listed expensive calls. A peer.ID already IS its multihash bytes, so v3
	// copies them and skips both the encoding and the decoding.
	//
	// v3 is a wire-format change, not a superset: a v2-only reader rejects it.
	// Every relay hop repacks the envelope and boot relays parse it to decide
	// the route, so a mixed-version fleet must keep the emitter on v2 until
	// every node on a possible transit path speaks v3. The reader accepting
	// both is what makes rolling that out safe to prepare.
	RelayHeaderVersionV3 = 0x03
	MaxRelayTTL          = 5
)

// RelayHeaderSize is the fixed part of the v2/v3 header: ver, ttl and the two
// length fields. The peer IDs themselves follow.
const RelayHeaderSize = 1 + 1 + 2 + 2

// PackRelayFrame encapsulates an Ethernet frame with an overlay relay header
// containing both destination and source peer IDs.
//
// Wire format (v2):
//
//	[ver:0x02][ttl:1][dstLen:2][dstPeerID:dstLen][srcLen:2][srcPeerID:srcLen][payload...]
func PackRelayFrame(finalDst, source peer.ID, ttl uint8, payload []byte) ([]byte, error) {
	return packRelayFrame(RelayHeaderVersion, []byte(finalDst.String()), []byte(source.String()), ttl, payload)
}

// PackRelayFrameV3 is PackRelayFrame with the compact 0x03 header. See
// RelayHeaderVersionV3 for the rationale and the mixed-fleet constraint.
//
// Wire format (v3):
//
//	[ver:0x03][ttl:1][dstLen:2][dstMultihash:dstLen][srcLen:2][srcMultihash:srcLen][payload...]
func PackRelayFrameV3(finalDst, source peer.ID, ttl uint8, payload []byte) ([]byte, error) {
	return packRelayFrame(RelayHeaderVersionV3, []byte(finalDst), []byte(source), ttl, payload)
}

// packRelayFrame is the shared layout builder for both header versions; only
// how the caller obtained the ID bytes differs.
func packRelayFrame(ver byte, dstBytes, srcBytes []byte, ttl uint8, payload []byte) ([]byte, error) {
	dstLen := len(dstBytes)
	srcLen := len(srcBytes)

	if dstLen > 65535 {
		return nil, fmt.Errorf("peer ID too long for relay header: dst=%d", dstLen)
	}
	if srcLen > 65535 {
		return nil, fmt.Errorf("peer ID too long for relay header: src=%d", srcLen)
	}

	// header: ver(1) + ttl(1) + dstLen(2) + dst(dstLen) + srcLen(2) + src(srcLen)
	headerLen := RelayHeaderSize + dstLen + srcLen
	buf := make([]byte, headerLen+len(payload))

	buf[0] = ver
	buf[1] = ttl
	binary.BigEndian.PutUint16(buf[2:4], uint16(dstLen))
	copy(buf[4:4+dstLen], dstBytes)

	off := 4 + dstLen
	binary.BigEndian.PutUint16(buf[off:off+2], uint16(srcLen))
	copy(buf[off+2:off+2+srcLen], srcBytes)

	copy(buf[headerLen:], payload)

	return buf, nil
}

// relayIDStrings resolves the wire ID strings for a header version. v3 copies
// the raw multihash bytes (peer.ID IS a multihash) with zero allocation; v2
// base58-encodes them (the historical, expensive path).
func relayIDStrings(ver byte, finalDst, source peer.ID) (dstStr, srcStr string) {
	if ver == RelayHeaderVersionV3 {
		return string(finalDst), string(source)
	}
	return finalDst.String(), source.String()
}

// RelayFrameSize returns the exact packed byte count PackRelayFrameInto (v3==false)
// or PackRelayFrameV3Into (v3==true) will emit for the given peers and payload,
// so a caller can size a pooled destination buffer exactly instead of
// over-allocating a fixed slack on the relay hot path.
func RelayFrameSize(finalDst, source peer.ID, payloadLen int, v3 bool) int {
	ver := byte(RelayHeaderVersion)
	if v3 {
		ver = RelayHeaderVersionV3
	}
	dstStr, srcStr := relayIDStrings(ver, finalDst, source)
	return RelayHeaderSize + len(dstStr) + len(srcStr) + payloadLen
}

// PackRelayFrameInto is PackRelayFrame with a caller-owned destination buffer.
// dst must have cap >= RelayFrameSize(finalDst, source, len(payload), false).
// The returned slice aliases dst; no allocation occurs.
func PackRelayFrameInto(dst []byte, finalDst, source peer.ID, ttl uint8, payload []byte) ([]byte, error) {
	return packRelayFrameInto(dst, RelayHeaderVersion, finalDst, source, ttl, payload)
}

// PackRelayFrameV3Into is PackRelayFrameV3 with a caller-owned destination
// buffer. dst must have cap >= RelayFrameSize(..., true). The returned slice
// aliases dst; no allocation occurs (v3 copies the peer.ID bytes directly).
func PackRelayFrameV3Into(dst []byte, finalDst, source peer.ID, ttl uint8, payload []byte) ([]byte, error) {
	return packRelayFrameInto(dst, RelayHeaderVersionV3, finalDst, source, ttl, payload)
}

// packRelayFrameInto is the shared Into layout builder. It copies the peer ID
// strings directly into dst (copy from a string never allocates), so the v3
// path is fully allocation-free.
func packRelayFrameInto(dst []byte, ver byte, finalDst, source peer.ID, ttl uint8, payload []byte) ([]byte, error) {
	dstStr, srcStr := relayIDStrings(ver, finalDst, source)
	dstLen, srcLen := len(dstStr), len(srcStr)
	if dstLen > 65535 {
		return nil, fmt.Errorf("peer ID too long for relay header: dst=%d", dstLen)
	}
	if srcLen > 65535 {
		return nil, fmt.Errorf("peer ID too long for relay header: src=%d", srcLen)
	}

	// header: ver(1) + ttl(1) + dstLen(2) + dst(dstLen) + srcLen(2) + src(srcLen)
	headerLen := RelayHeaderSize + dstLen + srcLen
	need := headerLen + len(payload)
	if cap(dst) < need {
		// A pooled buffer sized via RelayFrameSize can never hit this; it is a
		// defensive fallback for callers that sized too small.
		return nil, fmt.Errorf("relay frame dst too small: cap=%d need=%d", cap(dst), need)
	}
	buf := dst[:need]

	buf[0] = ver
	buf[1] = ttl
	binary.BigEndian.PutUint16(buf[2:4], uint16(dstLen))
	copy(buf[4:4+dstLen], dstStr)

	off := 4 + dstLen
	binary.BigEndian.PutUint16(buf[off:off+2], uint16(srcLen))
	copy(buf[off+2:off+2+srcLen], srcStr)

	copy(buf[headerLen:], payload)

	return buf, nil
}

// UnpackRelayFrame decapsulates a relay frame header, returning finalDst,
// source, remaining TTL, and inner payload. Both header versions are accepted;
// the version byte selects how dst and source are read.
func UnpackRelayFrame(buf []byte) (finalDst, source peer.ID, ttl uint8, payload []byte, err error) {
	if len(buf) < 4 {
		return "", "", 0, nil, fmt.Errorf("relay frame too short: %d bytes", len(buf))
	}

	ver := buf[0]
	ttl = buf[1]

	if ver != RelayHeaderVersion && ver != RelayHeaderVersionV3 {
		return "", "", 0, nil, fmt.Errorf("unsupported relay header version: 0x%02x (expected 0x%02x or 0x%02x)",
			ver, RelayHeaderVersion, RelayHeaderVersionV3)
	}

	// Clamp attacker-controlled TTL to MaxRelayTTL. Without this, a malicious
	// peer sets ttl=255 for up to 254 relay hops (amplification / long-lived
	// forwarding loops). The intended limit is MaxRelayTTL=5.
	if ttl > MaxRelayTTL {
		ttl = MaxRelayTTL
	}

	dstLen := int(binary.BigEndian.Uint16(buf[2:4]))
	if len(buf) < 4+dstLen+2 {
		return "", "", 0, nil, fmt.Errorf("truncated relay header: len=%d need>=%d", len(buf), 4+dstLen+2)
	}
	srcLen := int(binary.BigEndian.Uint16(buf[4+dstLen : 6+dstLen]))
	headerLen := RelayHeaderSize + dstLen + srcLen
	if len(buf) < headerLen {
		return "", "", 0, nil, fmt.Errorf("truncated relay header: len=%d need=%d", len(buf), headerLen)
	}

	pID, derr := decodeRelayPeerID(ver, buf[4:4+dstLen])
	if derr != nil {
		return "", "", 0, nil, fmt.Errorf("invalid relay final dst peer ID: %w", derr)
	}

	srcID, serr := decodeRelayPeerID(ver, buf[6+dstLen:6+dstLen+srcLen])
	if serr != nil {
		return "", "", 0, nil, fmt.Errorf("invalid relay source peer ID: %w", serr)
	}

	return pID, srcID, ttl, buf[headerLen:], nil
}

// decodeRelayPeerID reads one peer ID from a relay header according to its
// version byte: base58 text for v2, raw multihash for v3.
func decodeRelayPeerID(ver byte, raw []byte) (peer.ID, error) {
	if ver == RelayHeaderVersionV3 {
		return decodeRelayPeerIDMultihash(raw)
	}
	return peer.Decode(string(raw))
}

// decodeRelayPeerIDMultihash is the v3 path. peer.IDFromBytes is not a strict
// validator: mh.Cast only checks that a buffer looks like (code, length,
// digest), with no requirement that the length match the code's canonical
// digest size. A base58 CID string such as "12D3KooW..." therefore parses as a
// multihash (code 0x31, length 50, digest = the rest of the string) and comes
// back as an entirely different peer ID, which would let a frame be attributed
// to an ID an attacker chose.
//
// libp2p peer IDs are only ever identity or sha2-256 multihashes — that is what
// IDFromPublicKey and IDFromPrivateKey emit — so the code byte is checked, and
// a sha2-256 ID must be exactly 34 bytes. Two byte comparisons, which preserves
// the point of v3: no base58 and no second multihash parse.
func decodeRelayPeerIDMultihash(raw []byte) (peer.ID, error) {
	if len(raw) < 2 {
		return "", fmt.Errorf("peer ID too short: %d bytes", len(raw))
	}
	switch raw[0] {
	case mh.IDENTITY:
		// A proto-encoded key, so its length is variable.
	case mh.SHA2_256:
		if len(raw) != 2+32 {
			return "", fmt.Errorf("sha2-256 peer ID must be 34 bytes, got %d", len(raw))
		}
	default:
		return "", fmt.Errorf("peer ID multihash code 0x%02x is not a libp2p key multihash", raw[0])
	}
	return peer.IDFromBytes(raw)
}
