package routing

import (
	"encoding/binary"
	"fmt"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
)

// BootRelayKind distinguishes the two payload classes carried on a single
// boot-relay uplink. Both share one persistent libp2p stream per boot, so the
// node multiplexes the data plane (encrypted TAP frames) and the control plane
// (SeqSync / LSA / Meta / Echo handshake frames for relay-only peers) onto the
// same uplink. The boot itself is a dumb relay-over-backbone bridge: it only
// ever reads src/dst peer IDs + the netID from the header and forwards the
// whole frame, so it does not care which kind a frame is.
//
// Why both kinds share one stream: the boot IS a Circuit-Relay v2 relay, but a
// circuit spans only one boot and cannot cross the boot-to-boot backbone, and
// the boot is not a mesh member so it never terminates a relay-ctrl tunnel.
// Reaching a NAT'd peer through the boot therefore cannot use /p2p-circuit, and
// /p2ptap/relay-ctrl/1.0.0 at the boot would add a stream pair per handshake
// where the uplink already carries them multiplexed. The control handshake is
// tunneled over the very same boot-relay uplink the data plane already uses,
// otherwise two NAT'd peers in the same PSK network would learn each other via
// the peek-map but never establish a SeqSync cipher (and every frame would die
// at the AEAD gate).
const (
	BootRelayKindData    = byte(0) // inner payload = end-to-end-encrypted TAP frame
	BootRelayKindControl = byte(1) // inner payload = raw control-protocol bytes
)

// maxNetIDLen bounds the netID length field of a boot-relay frame. The real
// value is always 16: NetworkIDFromPSK is hex(sha256(psk)[:8]). The bound is
// generous only so that a future change to the derivation cannot be rejected
// out of hand; anything longer is a truncated or adversarial frame, and
// refusing it early turns a 65535-byte netID read into a clear error instead
// of silently consuming most of the buffer.
const maxNetIDLen = 64

// PSK derivatives (NetworkIDFromPSK, RelayAuthToken, PSKKeyBytes) live in psk.go,
// which is the single place that decides how a PSK string becomes key bytes.

// PackBootRelayFrame wraps an overlay relay envelope with a network-ID tag so a
// backbone boot can enforce PSK isolation for relay-over-backbone (relay-over-
// backbone) traffic. Wire layout:
//
//	[netIDLen:2][netID:netIDLen][kind:1][protoLen:2][proto:protoLen][relayEnvelope...]
//
// where relayEnvelope is the output of PackRelayFrame. The boot only ever reads
// src/dst peer IDs and the netID from this frame; the inner TAP payload stays
// end-to-end encrypted for the final destination, exactly like the overlay relay.
//
// kind selects the payload class (Data=encrypted TAP frame, Control=raw control
// protocol bytes). proto carries the control protocol ID for Control frames (it
// is empty/length-zero for Data frames and ignored on the data path). The boot
// forwards the whole frame verbatim, so it never needs to interpret kind/proto.
//
// The inner envelope is always packed with the v2 header. UnpackRelayFrame
// accepts both versions, so the receiver would read a v3 inner envelope fine —
// but PackBootRelayFrame is also how a node asks an UNUPGRADED boot relay to
// forward for it, and that boot parses the inner envelope to route. Keeping it
// on v2 is what lets a node talk to an older boot at all. Node.packRelayFrame
// is the one call site that switches versions.
func PackBootRelayFrame(netID string, kind byte, proto protocol.ID, finalDst, source peer.ID, ttl uint8, payload []byte) ([]byte, error) {
	env, err := PackRelayFrame(finalDst, source, ttl, payload)
	if err != nil {
		return nil, err
	}
	return appendBootRelayPrefix(netID, kind, proto, env), nil
}

// UnpackBootRelayFrame reverses PackBootRelayFrame, returning the in-band
// network ID, the frame kind, the control protocol ID (empty for data frames),
// and the relay envelope fields.
//
// A buffer reaching here has been trusted only at the transport layer: the
// caller has unwrapped exactly one framing layer, so its first two bytes are
// assumed to be the netID length. That assumption breaks if an intermediate
// bridge or a mis-wired relay re-wraps the frame in a second 4-byte
// [big-endian length][payload] envelope (the ReadFrame format in
// pkg/node/framing.go): a real boot-relay frame then reads as a netID that is
// 50+ thousand bytes long and the whole unpack fails, dropping the frame with
// no useful diagnostic.
//
// The old code stripped such a prefix SPECULATIVELY before parsing, which is
// unsafe in the other direction — a well-formed frame whose first four bytes
// happened to equal len-4 was mangled into a hard error. Parse the bytes as
// they were given first, and only retry after stripping when that fails. A
// valid frame is therefore never touched by the heuristic.
func UnpackBootRelayFrame(data []byte) (netID string, kind byte, proto protocol.ID, finalDst, source peer.ID, ttl uint8, payload []byte, err error) {
	netID, kind, proto, finalDst, source, ttl, payload, err = unpackBootRelayFrame(data)
	if err == nil {
		return
	}
	if stripped, ok := stripFramingPrefix(data); ok {
		return unpackBootRelayFrame(stripped)
	}
	return
}

// stripFramingPrefix reports whether data starts with a 4-byte big-endian
// length that is exactly the remainder of the buffer, returning data past it.
// Both ends must agree, which is what makes a false positive on genuine frame
// content improbable.
func stripFramingPrefix(data []byte) ([]byte, bool) {
	if len(data) <= 4 {
		return nil, false
	}
	return data[4:], binary.BigEndian.Uint32(data[:4]) == uint32(len(data)-4)
}

// unpackBootRelayFrame is the unconditional parse; it never guesses at an
// offset. UnpackBootRelayFrame is the recovery wrapper around it.
func unpackBootRelayFrame(data []byte) (netID string, kind byte, proto protocol.ID, finalDst, source peer.ID, ttl uint8, payload []byte, err error) {
	netID, rest, perr := stripNetIDPrefix(data)
	if perr != nil {
		err = perr
		return
	}
	kind, proto, rest, perr = stripKindProtoPrefix(rest)
	if perr != nil {
		err = perr
		return
	}
	finalDst, source, ttl, payload, err = UnpackRelayFrame(rest)
	return
}

func appendBootRelayPrefix(netID string, kind byte, proto protocol.ID, env []byte) []byte {
	nb := []byte(netID)
	pb := []byte(proto)
	out := make([]byte, 2+len(nb)+1+2+len(pb)+len(env))
	off := 0
	binary.BigEndian.PutUint16(out[off:off+2], uint16(len(nb)))
	off += 2
	copy(out[off:off+len(nb)], nb)
	off += len(nb)
	out[off] = kind
	off++
	binary.BigEndian.PutUint16(out[off:off+2], uint16(len(pb)))
	off += 2
	copy(out[off:off+len(pb)], pb)
	off += len(pb)
	copy(out[off:], env)
	return out
}

func stripKindProtoPrefix(data []byte) (kind byte, proto protocol.ID, rest []byte, err error) {
	if len(data) < 1 {
		return 0, "", nil, fmt.Errorf("boot-relay frame truncated: missing kind byte")
	}

	kind = data[0]
	// Reject unknown kinds rather than passing them through. A stray byte here
	// used to be accepted and silently became a boot-relay frame once the rest
	// of the buffer happened to decode as a valid relay envelope.
	if kind != BootRelayKindData && kind != BootRelayKindControl {
		return 0, "", nil, fmt.Errorf("boot-relay frame has unknown kind 0x%02x", kind)
	}
	data = data[1:]
	if len(data) < 2 {
		return 0, "", nil, fmt.Errorf("boot-relay frame truncated: missing proto length")
	}
	n := int(binary.BigEndian.Uint16(data[:2]))
	data = data[2:]
	if len(data) < n {
		return 0, "", nil, fmt.Errorf("boot-relay frame truncated: proto field len %d > %d", n, len(data))
	}
	proto = protocol.ID(string(data[:n]))
	rest = data[n:]
	return kind, proto, rest, nil
}

func stripNetIDPrefix(data []byte) (netID string, rest []byte, err error) {
	if len(data) < 2 {
		return "", nil, fmt.Errorf("boot-relay frame too short for netID length")
	}
	n := int(binary.BigEndian.Uint16(data[0:2]))
	if n > maxNetIDLen {
		return "", nil, fmt.Errorf("boot-relay frame netID length %d exceeds max %d", n, maxNetIDLen)
	}
	if len(data) < 2+n {
		return "", nil, fmt.Errorf("boot-relay frame truncated netID: have %d need %d", len(data), 2+n)
	}
	netID = string(data[2 : 2+n])
	rest = data[2+n:]
	return netID, rest, nil
}
