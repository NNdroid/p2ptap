package packet

// IPv6 extension-header walking shared by the NDP proxy (pkg/node) and the ACL
// engine (pkg/node). Both used to carry their own length arithmetic; they
// disagreed on AH and one of them masked the length field, so the single
// implementation here is the point of truth.

// IPv6 next-header values this package understands as length-encoded extension
// headers. Everything else (transport protocols, ICMPv6, ESP, No Next Header)
// terminates the walk for the caller's own policy.
const (
	IPv6HopByHop     = 0  // Hop-by-Hop Options
	IPv6Routing      = 43 // Routing
	IPv6Fragment     = 44 // Fragment
	IPv6AH           = 51 // Authentication Header
	IPv6DestOpts     = 60 // Destination Options
	IPv6ICMPv6       = 58
	IPv6NoNextHeader = 59
)

// IPv6ExtHeaderLen returns the total byte length of the IPv6 extension header
// whose Next Header value is nh, reading its length field from hdr. hdr[0] is
// the extension header's own Next Header field and hdr[1] its length field, so
// callers pass the header starting at its first byte.
//
//	Options (Hop-by-Hop 0, Routing 43, Destination Options 60):
//	    length = (HdrExtLen + 1) * 8, HdrExtLen is a full 8-bit field
//	    (RFC 8200 §4.3/4.4/4.6). The historical implementations masked it to
//	    4 bits, which misparsed any header longer than 128 bytes.
//	Fragment (44): fixed 8 bytes (RFC 8200 §4.5).
//	AH (51): length = (PayloadLen + 2) * 4 — RFC 4302 §2 counts 4-byte units
//	    MINUS 2, so the +2 adjustment is part of the formula, not optional.
//
// ok is false when nh is not one of those headers or hdr is truncated below
// its length field. The returned length is always >= 8 for ok == true.
func IPv6ExtHeaderLen(nh byte, hdr []byte) (length int, ok bool) {
	if len(hdr) < 2 {
		return 0, false
	}
	switch nh {
	case IPv6HopByHop, IPv6Routing, IPv6DestOpts:
		return (int(hdr[1]) + 1) * 8, true
	case IPv6Fragment:
		return 8, true
	case IPv6AH:
		return (int(hdr[1]) + 2) * 4, true
	}
	return 0, false
}
