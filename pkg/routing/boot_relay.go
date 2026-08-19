package routing

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
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
// Why both kinds share one stream: a custom boot is NOT a Circuit-Relay v2 node,
// so it has no relay-ctrl handler. Reaching a NAT'd peer through it therefore
// cannot use the /p2p-circuit or /p2ptap/relay-ctrl/1.0.0 paths — the control
// handshake must instead be tunneled over the very same boot-relay uplink the
// data plane already uses, otherwise two NAT'd peers in the same PSK network
// would learn each other via the peek-map but never establish a SeqSync cipher
// (and every frame would die at the AEAD gate).
const (
	BootRelayKindData    = byte(0) // inner payload = end-to-end-encrypted TAP frame
	BootRelayKindControl = byte(1) // inner payload = raw control-protocol bytes
)

// NetworkIDFromPSK derives the opaque network ID for a PSK. It MUST stay
// byte-for-byte identical to the boot server's networkIDFromPSK: the first 8
// bytes of SHA-256("p2ptap-net:" + PSK) hex-encoded (16 chars). The plaintext
// PSK is never placed on the wire; only this derivative travels, so a backbone
// boot can enforce PSK isolation on relay-over-backbone frames — it only knows
// the net IDs of ITS OWN authenticated clients, so the origin must carry its
// net ID in-band for the receiving boot to compare against the destination's.
func NetworkIDFromPSK(psk string) string {
	sum := sha256.Sum256([]byte("p2ptap-net:" + psk))
	return hex.EncodeToString(sum[:8])
}

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
func UnpackBootRelayFrame(data []byte) (netID string, kind byte, proto protocol.ID, finalDst, source peer.ID, ttl uint8, payload []byte, err error) {
	// Auto-detect and strip accidental 4-byte framing prefix (e.g. from intermediate bridge / double framing)
	if len(data) >= 4 {
		possibleLen := binary.BigEndian.Uint32(data[:4])
		if possibleLen == uint32(len(data)-4) && possibleLen > 0 {
			data = data[4:]
		}
	}
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




func appendNetIDPrefix(netID string, env []byte) []byte {
	nb := []byte(netID)
	out := make([]byte, 2+len(nb)+len(env))
	binary.BigEndian.PutUint16(out[0:2], uint16(len(nb)))
	copy(out[2:2+len(nb)], nb)
	copy(out[2+len(nb):], env)
	return out
}

func stripNetIDPrefix(data []byte) (netID string, rest []byte, err error) {
	if len(data) < 2 {
		return "", nil, fmt.Errorf("boot-relay frame too short for netID length")
	}
	n := int(binary.BigEndian.Uint16(data[0:2]))
	if len(data) < 2+n {
		return "", nil, fmt.Errorf("boot-relay frame truncated netID: have %d need %d", len(data), 2+n)
	}
	netID = string(data[2 : 2+n])
	rest = data[2+n:]
	return netID, rest, nil
}
