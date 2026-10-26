package node

import (
	"encoding/binary"
	"net"
	"testing"

	"p2ptap/pkg/config"
	"p2ptap/pkg/logger"
	"p2ptap/pkg/obfuscate"
)

// These benchmarks quantify this round of hot-path work. Each one pairs the new
// implementation with an inlined baseline of the code it replaced, because the
// replaced version no longer exists to measure: comparing against a helper in
// this file is the only way to keep the numbers reproducible.

// benchPackedFrame builds a minimal well-formed PLAINTEXT obfuscate frame (the
// output of FramePacker.Pack without a cipher): header + payload, no padding.
// Both tapPayloadLenFromPackedFrame and its Unpack-based baseline only require
// the length bound, the magic and HeaderLen+pLen <= len(frame).
func benchPackedFrame(b *testing.B, payloadLen int) []byte {
	b.Helper()
	frame := make([]byte, obfuscate.HeaderLen+payloadLen)
	binary.BigEndian.PutUint16(frame[0:2], obfuscate.FrameMagic)
	binary.BigEndian.PutUint16(frame[11:13], uint16(payloadLen))
	for i := obfuscate.HeaderLen; i < len(frame); i++ {
		frame[i] = byte(i)
	}
	return frame
}

// tapPayloadLenUnpackBaseline is the pre-optimisation tapPayloadLenFromPackedFrame,
// which unpacked the whole frame just to ask for its payload length.
func tapPayloadLenUnpackBaseline(packed []byte) int {
	_, payload, err := obfuscate.Unpack(packed)
	if err != nil {
		return 0
	}
	return len(payload)
}

// arp_ping_3node_test.go pins the package-wide level to Debug, and the baseline
// Unpack below emits two DEBUG lines per plaintext frame, so these run at an
// explicit level. The info pair measures the pure parse cost; the debug pair
// measures what the baseline actually cost in plaintext mode before the change.
func BenchmarkTapPayloadLenFromPackedFrame(b *testing.B) {
	benchmarkTapPayloadLen(b, logger.LevelInfo, false)
}

func BenchmarkTapPayloadLenFromPackedFrameUnpackBaseline(b *testing.B) {
	benchmarkTapPayloadLen(b, logger.LevelInfo, true)
}

func BenchmarkTapPayloadLenFromPackedFrameDebugLevel(b *testing.B) {
	benchmarkTapPayloadLen(b, logger.LevelDebug, false)
}

func BenchmarkTapPayloadLenFromPackedFrameUnpackBaselineDebugLevel(b *testing.B) {
	benchmarkTapPayloadLen(b, logger.LevelDebug, true)
}

func benchmarkTapPayloadLen(b *testing.B, level logger.Level, useUnpackBaseline bool) {
	b.Helper()
	logger.SetGlobalLevel(level)
	defer logger.SetGlobalLevel(logger.LevelDebug)
	frame := benchPackedFrame(b, 1400)
	want := 1400
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var got int
		if useUnpackBaseline {
			got = tapPayloadLenUnpackBaseline(frame)
		} else {
			got = tapPayloadLenFromPackedFrame(frame)
		}
		if got != want {
			b.Fatalf("payload len = %d, want %d", got, want)
		}
	}
}

func benchACLConfig() *config.Config {
	return &config.Config{
		ACL: config.ACLConfig{
			Enable:        true,
			DefaultAction: "drop",
			Rules: []config.ACLRule{
				{RuleID: "in-tcp80", Action: "accept", Direction: "inbound", PeerID: "peer-A", IPCIDR: "10.0.0.0/24", Protocol: "tcp", Port: "80"},
				{RuleID: "rng", Action: "accept", Direction: "both", PeerID: "*", IPCIDR: "*", Protocol: "tcp", Port: "8000-9000"},
				{RuleID: "udp53", Action: "accept", Direction: "outbound", Protocol: "udp", Port: "53"},
				{RuleID: "icmp", Action: "deny", Protocol: "icmp"},
				{RuleID: "catch", Action: "deny", PeerID: "*", IPCIDR: "*", Protocol: "any"},
			},
		},
	}
}

// BenchmarkMatchACLCompilePerCall is the pre-optimisation cost: MatchACL parsed
// every rule's direction/protocol/action strings, port spec and CIDR on every
// frame. This is what checkACL paid per frame before the ruleset was compiled.
func BenchmarkMatchACLCompilePerCall(b *testing.B) {
	cfg := benchACLConfig()
	acl := cfg.ACL
	frame := buildMockIPv4Packet("10.0.0.1", "10.0.0.2", 6, 80)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _ = MatchACL(&acl, frame, "peer-A", false); false {
			b.Fatal("unreachable")
		}
	}
}

// BenchmarkMatchACLCompiled is the post-optimisation data-plane path: the
// ruleset is parsed once per config snapshot and each frame is only comparisons.
func BenchmarkMatchACLCompiled(b *testing.B) {
	cfg := benchACLConfig()
	frame := buildMockIPv4Packet("10.0.0.1", "10.0.0.2", 6, 80)
	cmp := (&Node{Config: cfg}).compiledACLFor(cfg)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _ = matchCompiledRules(cmp, frame, "peer-A", false); false {
			b.Fatal("unreachable")
		}
	}
}

func BenchmarkMatchACLDisabled(b *testing.B) {
	frame := buildMockIPv4Packet("10.0.0.1", "10.0.0.2", 6, 80)
	cfg := &config.Config{}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _ = MatchACL(&cfg.ACL, frame, "peer-A", false); false {
			b.Fatal("unreachable")
		}
	}
}

// isLocalAdvertisedSubnetLegacy is the pre-optimisation version, which parsed
// every configured CIDR on every call.
func isLocalAdvertisedSubnetLegacy(cfg *config.Config, ip net.IP) bool {
	if ip == nil {
		return false
	}
	if cfg == nil || len(cfg.AdvertisedSubnets) == 0 {
		return false
	}
	for _, sub := range cfg.AdvertisedSubnets {
		if _, cidr, err := net.ParseCIDR(sub); err == nil && cidr != nil {
			if cidr.Contains(ip) {
				return true
			}
		}
	}
	return false
}

func benchAdvertisedSubnetsConfig() *config.Config {
	return &config.Config{AdvertisedSubnets: []string{
		"192.168.1.0/24", "10.10.0.0/16", "172.16.0.0/12", "2001:db8::/64",
	}}
}

func BenchmarkIsLocalAdvertisedSubnet(b *testing.B) {
	n := &Node{Config: benchAdvertisedSubnetsConfig()}
	ip := net.ParseIP("192.168.1.50")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = n.isLocalAdvertisedSubnet(ip)
	}
}

func BenchmarkIsLocalAdvertisedSubnetLegacy(b *testing.B) {
	cfg := benchAdvertisedSubnetsConfig()
	ip := net.ParseIP("192.168.1.50")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = isLocalAdvertisedSubnetLegacy(cfg, ip)
	}
}

func BenchmarkIsLocalAdvertisedSubnetNone(b *testing.B) {
	n := &Node{Config: &config.Config{}}
	ip := net.ParseIP("192.168.1.50")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = n.isLocalAdvertisedSubnet(ip)
	}
}
