// multiaddr_util.go — consolidated multiaddr helpers.
//
// Historically the codebase answered "which transport is this multiaddr?"
// with strings.Contains over the rendered address, duplicated across six
// files. Three of those copies tested "/quic" before "/webtransport",
// misclassifying WebTransport addresses (/udp/N/quic-v1/webtransport)
// as QUIC. This file replaces that with a single canonical function that
// inspects protocol codes instead of strings, and with helpers for the
// other two recurring patterns: /p2p/ stripping and relay-hop extraction.

package node

import (
	"fmt"
	"net"
	"strings"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr/net"
)

// TransportOf returns the canonical transport name for a multiaddr:
// "webtransport", "quic", "webrtc", "tcp", or "" if unrecognised.
//
// The LAST transport-specific protocol component wins, so
// /udp/N/quic-v1/webtransport correctly returns "webtransport"
// (not "quic"). Using protocol codes makes this robust against
// string-matching pitfalls where "quic-v1" appears before "webtransport"
// in the rendered address.
func TransportOf(ma multiaddr.Multiaddr) string {
	transport := ""
	for _, c := range ma {
		switch c.Protocol().Code {
		case multiaddr.P_WEBTRANSPORT:
			transport = "webtransport"
		case multiaddr.P_QUIC_V1, multiaddr.P_QUIC:
			transport = "quic"
		case multiaddr.P_WEBRTC_DIRECT:
			transport = "webrtc"
		case multiaddr.P_TCP:
			transport = "tcp"
		}
	}
	return transport
}

// IsCircuitRelay reports whether ma contains a /p2p-circuit/ component.
// Replaces scattered strings.Contains(s, "/p2p-circuit") calls.
func IsCircuitRelay(ma multiaddr.Multiaddr) bool {
	for _, c := range ma {
		if c.Protocol().Code == multiaddr.P_CIRCUIT {
			return true
		}
	}
	return false
}

// StripP2P removes the trailing /p2p/<peerID> component (if present).
// Iterates backwards so multi-hop circuit paths keep their intermediate hops.
func StripP2P(ma multiaddr.Multiaddr) multiaddr.Multiaddr {
	if len(ma) == 0 {
		return ma
	}
	last := ma[len(ma)-1]
	if last.Protocol().Code == multiaddr.P_P2P {
		return ma[:len(ma)-1]
	}
	return ma
}

// RelayPeerIDs extracts all /p2p/<id> peer IDs from a multiaddr.
// For a circuit path /p2p/A/p2p-circuit/p2p/B, returns [A, B].
func RelayPeerIDs(ma multiaddr.Multiaddr) []peer.ID {
	var ids []peer.ID
	for _, c := range ma {
		if c.Protocol().Code == multiaddr.P_P2P {
			pid, err := peer.Decode(c.Value())
			if err == nil {
				ids = append(ids, pid)
			}
		}
	}
	return ids
}

// TargetPeerID returns the final /p2p/<id> peer ID (the last one in a
// circuit path), or false if the address has no /p2p/ component.
func TargetPeerID(ma multiaddr.Multiaddr) (peer.ID, bool) {
	if len(ma) == 0 {
		return "", false
	}
	last := ma[len(ma)-1]
	if last.Protocol().Code != multiaddr.P_P2P {
		return "", false
	}
	pid, err := peer.Decode(last.Value())
	if err != nil {
		return "", false
	}
	return pid, true
}

// ExtractIP returns the IP address component of ma, or nil.
// Wraps manet.ToIP with a nil-safe return for the hot path.
func ExtractIP(ma multiaddr.Multiaddr) net.IP {
	ip, err := manet.ToIP(ma)
	if err != nil {
		return nil
	}
	return ip
}

// WithPeerID renders ma with a /p2p/<pid> suffix appended.
func WithPeerID(ma multiaddr.Multiaddr, pid peer.ID) string {
	return fmt.Sprintf("%s/p2p/%s", ma.String(), pid.String())
}

// MultiaddrsToStrings converts []multiaddr.Multiaddr to []string.
// Nil elements are represented as "".
func MultiaddrsToStrings(addrs []multiaddr.Multiaddr) []string {
	out := make([]string, len(addrs))
	for i, a := range addrs {
		if a != nil {
			out[i] = a.String()
		}
	}
	return out
}

// ReplaceIPInMultiaddr returns a copy of ma with its IP component replaced
// by newIP. The IP family (ip4/ip6) is preserved; other components are
// rebuilt via their raw bytes.
//
// This replaces the old string-split implementation which was fragile
// because it mutated tokens by index — it would misfire on any address
// whose string form diverges from the /ip<N>/<ip>/<rest> template.
func ReplaceIPInMultiaddr(ma multiaddr.Multiaddr, newIP string) (multiaddr.Multiaddr, error) {
	var result multiaddr.Multiaddr
	for _, c := range ma {
		code := c.Protocol().Code
		if code == multiaddr.P_IP4 || code == multiaddr.P_IP6 {
			ipMA, err := multiaddr.NewMultiaddr("/" + c.Protocol().Name + "/" + newIP)
			if err != nil {
				return nil, err
			}
			result = append(result, ipMA...)
			continue
		}
		result = append(result, c)
	}
	return result, nil
}

// ListenAddrKey returns a normalised string for a listen multiaddr,
// zeroing the ephemeral port so two listeners on the same IP+transport
// but different ports compare equal. Used by the roam reconciler to
// detect address drift without treating port changes as new listeners.
func ListenAddrKey(ma multiaddr.Multiaddr) string {
	transport := TransportOf(ma)
	if transport == "" {
		return ma.String()
	}
	ip := ExtractIP(ma)
	if ip == nil {
		return ma.String()
	}
	family := "ip4"
	if ip.To4() == nil {
		family = "ip6"
	}
	var protoSuffix string
	switch transport {
	case "quic":
		protoSuffix = "/udp/0/quic-v1"
	case "webtransport":
		protoSuffix = "/udp/0/quic-v1/webtransport"
	case "webrtc":
		protoSuffix = "/udp/0/webrtc-direct"
	case "tcp":
		protoSuffix = "/tcp/0"
	default:
		return ma.String()
	}
	return fmt.Sprintf("/%s/%s%s", family, ip.String(), protoSuffix)
}

// containsTransport checks whether ma contains a specific protocol code.
// Replaces scattered strings.Contains(s, "/tcp/") calls.
func containsTransport(ma multiaddr.Multiaddr, protoCode int) bool {
	for _, c := range ma {
		if c.Protocol().Code == protoCode {
			return true
		}
	}
	return false
}

// transportFromStr returns the TransportOf result for a string address.
// Used at call sites that only have a string (e.g. config ListenAddrs).
// Falls back to best-effort string detection for unparseable addrs,
// checking webtransport before quic to avoid misclassification.
func transportFromStr(s string) string {
	ma, err := multiaddr.NewMultiaddr(s)
	if err == nil {
		return TransportOf(ma)
	}
	// Fallback for invalid/lenient addresses.
	if strings.Contains(s, "webtransport") {
		return "webtransport"
	}
	if strings.Contains(s, "quic") {
		return "quic"
	}
	if strings.Contains(s, "webrtc-direct") {
		return "webrtc"
	}
	if strings.Contains(s, "/tcp/") {
		return "tcp"
	}
	return ""
}
