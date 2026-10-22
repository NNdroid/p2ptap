// multiaddr_util.go — consolidated multiaddr helpers.
//
// Historically the codebase answered "which transport is this multiaddr?"
// with strings.Contains over the rendered address, duplicated across six
// files. Three of those copies tested "/quic" before "/webtransport",
// misclassifying WebTransport addresses (/udp/N/quic-v1/webtransport)
// as QUIC. This file replaces that with a single canonical function that
// inspects protocol codes instead of strings, and with helpers for the
// other two recurring patterns: /p2p/ stripping and peer-ID extraction.
//
// Circuit-relay detection and /p2p/ peer-ID extraction live in
// pkg/maddrutil instead: pkg/web needs them too, and pkg/web must not
// import pkg/node, so they live in the shared leaf package.

package node

import (
	"fmt"
	"net"
	"strings"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr/net"

	"p2ptap/pkg/maddrutil"
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

// TransportOfConn returns the canonical transport name for an ESTABLISHED
// connection, using the same vocabulary as TransportOf.
//
// Prefer this over TransportOf(conn.RemoteMultiaddr()) for a live connection.
// Today both happen to agree — the fork's WebTransport transport appends the
// /webtransport component to the address it records, and every other transport
// records its own component too — but that is an implementation detail of the
// fork, not a libp2p guarantee. ConnState().Transport is written by the
// transport that actually carried the bytes, so it stays correct if a future
// upstream revision stops advertising the transport in the address. The two
// stats collectors had drifted apart over this: collectProtocolChannelsAndStreams
// had no "webtransport" arm at all and labelled every WebTransport link "P2P".
func TransportOfConn(c network.Conn) string {
	if ma := c.RemoteMultiaddr(); ma != nil && maddrutil.IsCircuitRelay(ma) {
		return "circuit"
	}
	switch c.ConnState().Transport {
	case "quic-v1", "quic":
		return "quic"
	case "webtransport":
		return "webtransport"
	case "webrtc-direct", "webrtc":
		return "webrtc"
	case "tcp":
		return "tcp"
	}
	if ma := c.RemoteMultiaddr(); ma != nil {
		return TransportOf(ma)
	}
	return ""
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

// AddrsWithPeerID renders each addr with a /p2p/<pid> suffix, for publishers
// that must satisfy a receiver-side "the suffix names the claimed peer" check.
// Addrs already carrying a suffix are passed through unchanged — appending a
// second one would make the string unparseable. Nil elements are skipped.
func AddrsWithPeerID(addrs []multiaddr.Multiaddr, pid peer.ID) []string {
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		if a == nil {
			continue
		}
		if _, ok := TargetPeerID(a); !ok {
			out = append(out, WithPeerID(a, pid))
			continue
		}
		out = append(out, a.String())
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

// ValidateListenAddr checks a configured listen address for problems that
// multiaddr.NewMultiaddr accepts but a transport then refuses. The multiaddr
// parser validates syntax only — it never checks transport layering — so
// "/ip4/0.0.0.0/udp/4003/webtransport" parses cleanly and TransportOf still
// reports "webtransport" (P_WEBTRANSPORT is present), so the transport gate
// lets it through and webtransport.Transport.Listen rejects it. A single
// rejected address is only a log.Warn inside swarm_listen, so the listener
// silently never comes up while libp2p.New returns success and the node looks
// perfectly healthy.
func ValidateListenAddr(aStr string) error {
	if aStr == "" {
		return fmt.Errorf("empty listen address")
	}
	ma, err := multiaddr.NewMultiaddr(aStr)
	if err != nil {
		return err
	}
	switch TransportOf(ma) {
	case "webtransport":
		// WebTransport is QUIC-over-HTTP/3: the /quic-v1/ layer is mandatory.
		if !containsTransport(ma, multiaddr.P_QUIC_V1) && !containsTransport(ma, multiaddr.P_QUIC) {
			return fmt.Errorf("webtransport listens over QUIC, expected .../udp/<port>/quic-v1/webtransport")
		}
	case "quic", "webrtc":
		// UDP-only transports. This also rejects a transport layered on the
		// wrong carrier (e.g. /tcp/N/quic-v1): TransportOf reports the top
		// layer, so the missing UDP layer is what surfaces the bad stack.
		if !containsTransport(ma, multiaddr.P_UDP) {
			return fmt.Errorf("%s listens over UDP, expected .../udp/<port>", TransportOf(ma))
		}
		// Plain "tcp" needs no layer check: TransportOf can only report it when
		// the /tcp/ component is present, so there is nothing to verify.
	}
	if !containsTransport(ma, multiaddr.P_IP4) && !containsTransport(ma, multiaddr.P_IP6) {
		return fmt.Errorf("listen address must contain an /ip4/ or /ip6/ address")
	}
	return nil
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
