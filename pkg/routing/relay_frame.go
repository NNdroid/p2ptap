package routing

import (
	"encoding/binary"
	"fmt"

	"github.com/libp2p/go-libp2p/core/peer"
)

const (
	// RelayHeaderVersion is the relay header version (0x02), which carries
	// both destination and source peer IDs so the destination can learn the
	// correct reply route through relay hops.
	RelayHeaderVersion = 0x02
	MaxRelayTTL        = 5
)

// PackRelayFrame encapsulates an Ethernet frame with an overlay relay header
// containing both destination and source peer IDs.
//
// Wire format (v2):
//
//	[ver:0x02][ttl:1][dstLen:2][dstPeerID:dstLen][srcLen:2][srcPeerID:srcLen][payload...]
func PackRelayFrame(finalDst, source peer.ID, ttl uint8, payload []byte) ([]byte, error) {
	dstStr := finalDst.String()
	dstBytes := []byte(dstStr)
	dstLen := len(dstBytes)

	srcStr := source.String()
	srcBytes := []byte(srcStr)
	srcLen := len(srcBytes)

	if dstLen > 65535 {
		return nil, fmt.Errorf("peer ID string too long for relay header: dst=%d", dstLen)
	}
	if srcLen > 65535 {
		return nil, fmt.Errorf("peer ID string too long for relay header: src=%d", srcLen)
	}

	// header: ver(1) + ttl(1) + dstLen(2) + dst(dstLen) + srcLen(2) + src(srcLen)
	headerLen := 1 + 1 + 2 + dstLen + 2 + srcLen
	buf := make([]byte, headerLen+len(payload))

	buf[0] = RelayHeaderVersion
	buf[1] = ttl
	binary.BigEndian.PutUint16(buf[2:4], uint16(dstLen))
	copy(buf[4:4+dstLen], dstBytes)

	off := 4 + dstLen
	binary.BigEndian.PutUint16(buf[off:off+2], uint16(srcLen))
	copy(buf[off+2:off+2+srcLen], srcBytes)

	copy(buf[headerLen:], payload)

	return buf, nil
}

// UnpackRelayFrame decapsulates a relay frame header, returning finalDst,
// source, remaining TTL, and inner payload.
func UnpackRelayFrame(buf []byte) (finalDst, source peer.ID, ttl uint8, payload []byte, err error) {
	if len(buf) < 4 {
		return "", "", 0, nil, fmt.Errorf("relay frame too short: %d bytes", len(buf))
	}

	ver := buf[0]
	if ver != RelayHeaderVersion {
		return "", "", 0, nil, fmt.Errorf("unsupported relay header version: 0x%02x", ver)
	}

	ttl = buf[1]
	dstLen := int(binary.BigEndian.Uint16(buf[2:4]))
	if len(buf) < 4+dstLen+2 {
		return "", "", 0, nil, fmt.Errorf("truncated relay header: len=%d need>=%d", len(buf), 4+dstLen+2)
	}
	srcLen := int(binary.BigEndian.Uint16(buf[4+dstLen : 6+dstLen]))
	headerLen := 6 + dstLen + srcLen
	if len(buf) < headerLen {
		return "", "", 0, nil, fmt.Errorf("truncated relay header: len=%d need=%d", len(buf), headerLen)
	}

	dstStr := string(buf[4 : 4+dstLen])
	pID, derr := peer.Decode(dstStr)
	if derr != nil {
		return "", "", 0, nil, fmt.Errorf("invalid relay final dst peer ID '%s': %w", dstStr, derr)
	}

	srcStr := string(buf[6+dstLen : 6+dstLen+srcLen])
	srcID, serr := peer.Decode(srcStr)
	if serr != nil {
		return "", "", 0, nil, fmt.Errorf("invalid relay source peer ID '%s': %w", srcStr, serr)
	}

	return pID, srcID, ttl, buf[headerLen:], nil
}
