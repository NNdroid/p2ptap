package node

import (
	"testing"
)

// TestValidateListenAddr pins the WebTransport listener regression. The boot
// defaults listened on "/udp/4003/webtransport" without the /quic-v1/ layer:
// multiaddr parses it, TransportOf still says "webtransport" because
// P_WEBTRANSPORT is present, the transport gate let it through, and
// webtransport.Transport.Listen then rejected it. A single rejected address is
// only a log.Warn inside swarm_listen, so the listener silently never came up
// while libp2p.New returned success.
func TestValidateListenAddr(t *testing.T) {
	valid := []string{
		"/ip4/0.0.0.0/udp/0/quic-v1",
		"/ip6/::/udp/0/quic-v1",
		"/ip4/0.0.0.0/udp/0/webrtc-direct",
		"/ip4/0.0.0.0/udp/0/quic-v1/webtransport",
		"/ip6/::/udp/0/quic-v1/webtransport",
		"/ip4/0.0.0.0/udp/4003/quic-v1/webtransport",
		"/ip4/0.0.0.0/tcp/0",
		"/ip6/::/tcp/4001",
	}
	for _, a := range valid {
		if err := ValidateListenAddr(a); err != nil {
			t.Errorf("ValidateListenAddr(%q) = %v, want nil", a, err)
		}
	}

	invalid := []string{
		"",
		"not a multiaddr",
		// the exact misconfiguration that was in the boot defaults
		"/ip4/0.0.0.0/udp/4003/webtransport",
		"/ip6/::/udp/4003/webtransport",
		// missing the UDP layer
		"/ip4/0.0.0.0/4001/quic-v1",
		"/ip4/0.0.0.0/4002/webrtc-direct",
		// transport layered on the wrong carrier
		"/ip4/0.0.0.0/tcp/4001/quic-v1",
		"/ip4/0.0.0.0/tcp/4001/webrtc-direct",
		"/ip4/0.0.0.0/tcp/4001/webtransport",
		// no address component
		"/tcp/0",
		"/udp/0/quic-v1",
	}
	for _, a := range invalid {
		if err := ValidateListenAddr(a); err == nil {
			t.Errorf("ValidateListenAddr(%q) = nil, want an error", a)
		}
	}
}

// TestTransportOfRegression pins the classification order: WebTransport
// addresses contain "quic-v1" textually before "webtransport", so any
// string-match implementation that tests quic first misclassifies them.
func TestTransportOfRegression(t *testing.T) {
	for _, a := range []string{
		"/ip4/0.0.0.0/udp/0/quic-v1/webtransport",
		"/ip6/::/udp/4003/quic-v1/webtransport",
	} {
		if got := transportFromStr(a); got != "webtransport" {
			t.Errorf("transportFromStr(%q) = %q, want %q", a, got, "webtransport")
		}
	}
	for _, a := range []string{
		"/ip4/0.0.0.0/udp/0/quic-v1",
		"/ip4/0.0.0.0/udp/0/webrtc-direct",
		"/ip4/0.0.0.0/tcp/0",
	} {
		if got := transportFromStr(a); got == "webtransport" {
			t.Errorf("transportFromStr(%q) = %q, must not be webtransport", a, got)
		}
	}
}
