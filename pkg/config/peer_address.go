package config

import (
	"fmt"
	"strings"

	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"
)

// NormalizePeerAddress requires an endpoint and a remote identity. A bare peer
// ID relies on discovery and is not a self-contained static/bootstrap address.
func NormalizePeerAddress(address string) (string, error) {
	m, err := ma.NewMultiaddr(strings.TrimSpace(address))
	if err != nil {
		return "", fmt.Errorf("expected a multiaddr ending in /p2p/<PeerID>: %w", err)
	}
	info, err := peer.AddrInfoFromP2pAddr(m)
	if err != nil {
		return "", fmt.Errorf("missing or invalid remote /p2p/<PeerID>: %w", err)
	}
	if len(info.Addrs) == 0 {
		return "", fmt.Errorf("peer ID has no endpoint; include its IP/DNS and transport")
	}
	endpoint := info.Addrs[0]
	dialable := false
	for _, p := range endpoint.Protocols() {
		switch p.Code {
		case ma.P_TCP, ma.P_QUIC, ma.P_QUIC_V1, ma.P_WEBTRANSPORT, ma.P_WEBRTC_DIRECT, ma.P_DNSADDR, ma.P_CIRCUIT:
			dialable = true
		}
	}
	if !dialable {
		return "", fmt.Errorf("endpoint has no supported transport or dnsaddr discovery")
	}
	return m.String(), nil
}

func normalizePeerAddresses(field string, addresses []string) ([]string, error) {
	result := make([]string, 0, len(addresses))
	seen := make(map[string]bool, len(addresses))
	for i, address := range addresses {
		normalized, err := NormalizePeerAddress(address)
		if err != nil {
			return nil, fmt.Errorf("%s[%d]: %w", field, i, err)
		}
		if !seen[normalized] {
			result = append(result, normalized)
			seen[normalized] = true
		}
	}
	return result, nil
}
