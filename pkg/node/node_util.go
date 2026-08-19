package node

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr/net"

	"p2ptap/pkg/observer"
	"p2ptap/pkg/packet"
	"p2ptap/pkg/tap"
)

// arpIndexEntry is one resolved TAP IP -> (peer, MAC) binding.
type arpIndexEntry struct {
	mac net.HardwareAddr
	pid peer.ID
}

// arpSubnetEntry is one pre-parsed advertised LAN subnet -> (peer, MAC) binding.
// CIDR parsing happens once at index-build time, never on the data path.
type arpSubnetEntry struct {
	net *net.IPNet
	mac net.HardwareAddr
	pid peer.ID
}

// arpIndex is the read-optimized view of peerMeta used for IP→peer resolution.
// Direct TAP IPs are O(1) map lookups; advertised subnets are a short slice
// scan. Both are allocation- and parse-free on the hot path.
type arpIndex struct {
	v4      map[uint32]arpIndexEntry   // direct TAP IPv4 keyed by uint32
	v6      map[[16]byte]arpIndexEntry // direct TAP IPv6 keyed by 16-byte address
	subnets []arpSubnetEntry
}

// parseHWMac is a small helper that returns nil (not an error) for empty/!
// -parseable MAC strings. Used while building the index so a single bad peer
// entry can never break resolution for the others.
func parseHWMac(s string) net.HardwareAddr {
	if s == "" {
		return nil
	}
	if hw, err := net.ParseMAC(s); err == nil {
		return hw
	}
	return nil
}

// isLocalAdvertisedSubnet reports whether target IP falls within any of this
// node's own advertised subnets (i.e. this node is the LAN gateway).
func (n *Node) isLocalAdvertisedSubnet(ip net.IP) bool {
	if ip == nil {
		return false
	}
	c := n.config()
	if c == nil || len(c.AdvertisedSubnets) == 0 {
		return false
	}
	for _, sub := range c.AdvertisedSubnets {
		if _, cidr, err := net.ParseCIDR(sub); err == nil && cidr != nil {
			if cidr.Contains(ip) {
				return true
			}
		}
	}
	return false
}

// storePeerMeta persists peer metadata AND rebuilds the read-optimized ARP index
// so it stays consistent with peerMeta. Must be used at every peerMeta write
// site; do not call n.peerMeta.Store directly for peer records.
func (n *Node) storePeerMeta(pID peer.ID, m PeerMeta) {
	n.peerMeta.Store(pID, m)
	n.rebuildARPIndex()

	// Proactively emit a Gratuitous ARP frame to the local OS TAP adapter so Windows / Linux
	// immediately associates this peer's IP with its MAC without waiting on ARP discovery/timeouts.
	if m.TapIP != "" && m.TapMAC != "" && n.TAP != nil {
		ipStr := strings.Split(m.TapIP, "/")[0]
		if ip := net.ParseIP(ipStr).To4(); ip != nil {
			if mac, err := net.ParseMAC(m.TapMAC); err == nil && len(mac) == 6 {
				garpFrame := tap.BuildARPReplyFrame(mac, net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, ip, ip)
				_, _ = n.tapWrite(garpFrame)
			}
		}
	}
}

// deletePeerMeta removes a peer record and rebuilds the ARP index.
func (n *Node) deletePeerMeta(pID peer.ID) {
	n.peerMeta.Delete(pID)
	n.rebuildARPIndex()
}

// rebuildARPIndex scans peerMeta once and reconstructs the O(1) resolution
// index. Called only on topology changes (peer add/update/remove), never on the
// per-packet path, so the cost is amortized away from packet processing.
//
// It also performs duplicate-IP detection: when more than one peer claims the
// same direct TAP IPv4, the same direct TAP IPv6, or the same advertised subnet
// CIDR, the conflict is arbitrated by the allowed_subnet_peers ordering (earlier
// in the list = higher priority). Only the winning peer is kept in the index;
// losers are suppressed so resolution stays deterministic, and the conflict is
// recorded for alerting via GetDuplicateIPConflicts.
func (n *Node) rebuildARPIndex() {
	// First pass: collect all claimants per resource key instead of overwriting,
	// so duplicates are observable rather than silently last-writer-wins.
	v4Claims := make(map[uint32][]arpIndexEntry)
	v6Claims := make(map[[16]byte][]arpIndexEntry)
	// allSubnets collects every advertised-subnet entry across all peers so
	// exact-duplicate AND overlapping-prefix detection can run over the whole
	// set (a single peer advertising two prefixes never conflicts with itself).
	var allSubnets []arpSubnetEntry
	n.peerMeta.Range(func(key, value any) bool {
		pID, _ := key.(peer.ID)
		meta := value.(PeerMeta)
		effectiveMAC := parseHWMac(meta.TapMAC)
		if obs := n.observedTapMACFrom(pID); len(obs) == 6 {
			// TEMP-DIAG: only fires when the observed wire MAC disagrees with
			// the advertised metadata MAC (the suspected three-node bug).
			if log.IsDebug() && string(obs) != string(effectiveMAC) {
				log.Debug("ARP-DIAG: peer=%s ip=%s overriding metadata MAC %s with OBSERVED wire MAC %s",
					pID.String(), meta.TapIP, effectiveMAC.String(), obs.String())
			}
			effectiveMAC = obs
		}
		if len(effectiveMAC) != 6 {
			if meta.TapIP != "" {
				if ip := net.ParseIP(strings.Split(meta.TapIP, "/")[0]).To4(); ip != nil {
					effectiveMAC = net.HardwareAddr{0x02, 0x00, ip[0], ip[1], ip[2], ip[3]}
				}
			}
			if len(effectiveMAC) != 6 && meta.TapIPv6 != "" {
				if ip6 := net.ParseIP(strings.Split(meta.TapIPv6, "/")[0]).To16(); ip6 != nil {
					effectiveMAC = net.HardwareAddr{0x02, 0x00, ip6[12], ip6[13], ip6[14], ip6[15]}
				}
			}
			if len(effectiveMAC) != 6 {
				effectiveMAC = packet.DefaultTapMAC
			}
		}
		if meta.TapIP != "" {
			if ip := net.ParseIP(strings.Split(meta.TapIP, "/")[0]).To4(); ip != nil {
				k := binary.BigEndian.Uint32(ip)
				v4Claims[k] = append(v4Claims[k], arpIndexEntry{mac: effectiveMAC, pid: pID})
			}
		}
		if meta.TapIPv6 != "" {
			if ip := net.ParseIP(strings.Split(meta.TapIPv6, "/")[0]).To16(); ip != nil {
				var k [16]byte
				copy(k[:], ip)
				v6Claims[k] = append(v6Claims[k], arpIndexEntry{mac: effectiveMAC, pid: pID})
			}
		}
		for _, sub := range meta.AdvertisedSubnets {
			if sub == "" {
				continue
			}
			if _, ipNet, err := net.ParseCIDR(sub); err == nil {
				allSubnets = append(allSubnets, arpSubnetEntry{net: ipNet, mac: effectiveMAC, pid: pID})
			}
		}
		return true
	})

	order := n.allowedSubnetOrder()

	v4 := make(map[uint32]arpIndexEntry, len(v4Claims))
	v6 := make(map[[16]byte]arpIndexEntry, len(v6Claims))
	var subnets []arpSubnetEntry
	var conflicts []DuplicateIPConflict

	// IPv4 direct TAP addresses.
	for k, claimants := range v4Claims {
		if len(claimants) == 1 {
			v4[k] = claimants[0]
			continue
		}
		pids := entriesToPIDs(claimants)
		winner, losers, reason := arbitratePeers(pids, order)
		v4[k] = entryByPID(claimants, winner)
		conflicts = append(conflicts,
			buildConflict("tap_ip_v4", ipv4Str(k), pids, losers, winner, reason))
	}
	// IPv6 direct TAP addresses.
	for k, claimants := range v6Claims {
		if len(claimants) == 1 {
			v6[k] = claimants[0]
			continue
		}
		pids := entriesToPIDs(claimants)
		winner, losers, reason := arbitratePeers(pids, order)
		v6[k] = entryByPID(claimants, winner)
		conflicts = append(conflicts,
			buildConflict("tap_ip_v6", ipv6Str(k), pids, losers, winner, reason))
	}
	// Advertised subnets: detect exact-duplicate AND overlapping-prefix
	// conflicts, arbitrate, and keep only the winning peer's subnet in the
	// routing index (losers are dropped so L2/L3 resolution stays deterministic).
	subnets, subnetConflicts := n.resolveSubnetConflicts(allSubnets, order)
	conflicts = append(conflicts, subnetConflicts...)

	n.arpIndexMu.Lock()
	n.arpIndex = &arpIndex{v4: v4, v6: v6, subnets: subnets}
	n.arpIndexMu.Unlock()

	// Record + alert (deduplicated) conflicts outside the index lock.
	n.setDuplicateIPConflicts(conflicts)
}

// resolveSubnetConflicts detects duplicate and overlapping advertised subnets
// across all peers and arbitrates each conflict. Two CIDR blocks either are
// disjoint or one contains the other, so "overlap" is detected as one block
// containing the other (equal blocks are exact duplicates).
//
// For every conflict the higher-priority peer — by the allowed_subnet_peers
// ordering — keeps its subnet in the routing index; every lower-priority
// overlapping peer is dropped so L2/L3 resolution stays deterministic instead
// of silently falling through to last-writer-wins. The function returns the
// surviving subnet entries plus the recorded conflicts (one per suppressed
// loser), which the caller surfaces for alerting.
//
// A single peer advertising two overlapping prefixes of its own never conflicts
// (a.pid == b.pid is skipped) — overlapping private LANs behind one node are
// legitimate and must all route.
func (n *Node) resolveSubnetConflicts(allSubnets []arpSubnetEntry, order []string) ([]arpSubnetEntry, []DuplicateIPConflict) {
	dropped := make([]bool, len(allSubnets))
	var conflicts []DuplicateIPConflict

	for i := 0; i < len(allSubnets); i++ {
		if dropped[i] {
			continue
		}
		for j := i + 1; j < len(allSubnets); j++ {
			if dropped[j] {
				continue
			}
			a, b := allSubnets[i], allSubnets[j]
			if a.pid == b.pid {
				continue // same peer: its own overlapping prefixes never conflict
			}
			if !netsOverlap(a.net, b.net) {
				continue
			}
			winner, _, arbReason := arbitratePeers([]peer.ID{a.pid, b.pid}, order)
			loserIdx := i
			winnerIdx := j
			if winner == a.pid {
				loserIdx = j
				winnerIdx = i
			}
			if dropped[loserIdx] {
				continue
			}
			dropped[loserIdx] = true
			loser := allSubnets[loserIdx]
			winnerNet := allSubnets[winnerIdx].net

			resourceType := "advertised_subnet_overlap"
			resource := loser.net.String()
			if cidrEqual(a.net, b.net) {
				resourceType = "advertised_subnet"
				resource = a.net.String()
			}
			reason := arbReason + " | subnet " + loser.net.String() +
				" overlaps higher-priority subnet " + winnerNet.String() +
				"; lower-priority subnet suppressed from routing index"
			conflicts = append(conflicts, buildConflict(
				resourceType, resource,
				[]peer.ID{a.pid, b.pid},
				[]peer.ID{loser.pid},
				winner, reason,
			))
		}
	}

	surviving := make([]arpSubnetEntry, 0, len(allSubnets))
	for i, e := range allSubnets {
		if !dropped[i] {
			surviving = append(surviving, e)
		}
	}
	return surviving, conflicts
}

// isSubnetRouteSuppressed reports whether the given advertised subnet from the
// given peer must NOT be installed as an OS route, because a duplicate or
// overlapping subnet was arbitrated in favour of a higher-priority peer. The ARP
// index already suppresses the loser's L2/L3 resolution (resolveSubnetConflicts);
// this keeps the OS routing table consistent so we never install a conflicting
// or blackhole route for the suppressed subnet.
//
// The recorded conflict's Resource is always the LOSER's CIDR (the exact
// duplicate or the smaller overlapping block), so a direct CIDR match against
// cidr is the correct test, and the advertising peer must appear among Losers.
func (n *Node) isSubnetRouteSuppressed(remotePeer peer.ID, cidr string) bool {
	for _, c := range n.GetDuplicateIPConflicts() {
		if c.ResourceType != "advertised_subnet" && c.ResourceType != "advertised_subnet_overlap" {
			continue
		}
		if c.Resource != cidr {
			continue
		}
		for _, l := range c.Losers {
			if l == remotePeer.String() {
				return true
			}
		}
	}
	return false
}

// entriesToPIDs extracts the peer IDs from a slice of arpIndexEntry.
func entriesToPIDs(entries []arpIndexEntry) []peer.ID {
	pids := make([]peer.ID, len(entries))
	for i, e := range entries {
		pids[i] = e.pid
	}
	return pids
}

// entryByPID returns the arpIndexEntry whose pid matches, or the zero value.
func entryByPID(entries []arpIndexEntry, pid peer.ID) arpIndexEntry {
	for _, e := range entries {
		if e.pid == pid {
			return e
		}
	}
	return arpIndexEntry{}
}

// ipv4Str renders a uint32 key back to its dotted-quad form for conflict output.
func ipv4Str(b uint32) string {
	return net.IPv4(byte(b>>24), byte(b>>16), byte(b>>8), byte(b)).String()
}

// ipv6Str renders a 16-byte key back to its canonical string form.
func ipv6Str(b [16]byte) string {
	return net.IP(b[:]).String()
}

func loadOrGenerateNodeKey(keyPath string) (crypto.PrivKey, error) {
	if _, err := os.Stat(keyPath); err == nil {
		keyBytes, err := os.ReadFile(keyPath)
		if err != nil {
			return nil, err
		}
		return crypto.UnmarshalPrivateKey(keyBytes)
	}

	// Generate new Ed25519 keypair
	priv, _, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		return nil, err
	}

	keyBytes, err := crypto.MarshalPrivateKey(priv)
	if err != nil {
		return nil, err
	}

	_ = os.MkdirAll(filepath.Dir(keyPath), 0755)
	if err := os.WriteFile(keyPath, keyBytes, 0600); err != nil {
		log.Warn("Failed to save key file to %s: %v", keyPath, err)
	} else {
		log.Info("Generated new persistent identity key: %s", keyPath)
	}

	return priv, nil
}

func computeKeyFingerprint(keyPath string) string {
	if data, err := os.ReadFile(keyPath); err == nil {
		h := sha256.Sum256(data)
		return hex.EncodeToString(h[:8])
	}
	return "dynamic-key"
}

// IsVirtualIP returns true if webUIIP is in the same subnet as tapIP, but NOT equal to tapIP itself (Category 2).
func IsVirtualIP(webUIIPStr, tapIPStr string) bool {
	if webUIIPStr == "" || webUIIPStr == "0.0.0.0" || webUIIPStr == "127.0.0.1" || webUIIPStr == "auto" {
		return false // Category 1: Non-virtual
	}

	cleanWebUI := strings.Split(webUIIPStr, "/")[0]
	webIP := net.ParseIP(cleanWebUI)
	if webIP == nil {
		return false
	}

	cleanTap, tapSubnet, err := net.ParseCIDR(tapIPStr)
	if err != nil {
		cleanTap = net.ParseIP(strings.Split(tapIPStr, "/")[0])
	}

	// Category 3: Same IP as tap_ip (Non-virtual)
	if cleanTap != nil && webIP.Equal(cleanTap) {
		return false
	}

	// Category 2: Different IP within TAP subnet OR dedicated Virtual IP
	if tapSubnet != nil && tapSubnet.Contains(webIP) {
		return true
	}

	return true
}

func isTapMultiaddr(a multiaddr.Multiaddr, tapIPv4, tapIPv6, webUIPv4, webUIPv6 string) bool {
	if ip4Str, err := a.ValueForProtocol(multiaddr.P_IP4); err == nil && ip4Str != "" {
		if tapIPv4 != "" {
			cleanTapIPv4, _, _ := strings.Cut(tapIPv4, "/")
			if ip4Str == cleanTapIPv4 {
				return true
			}
		}
		if webUIPv4 != "" && webUIPv4 != "0.0.0.0" && webUIPv4 != "127.0.0.1" && webUIPv4 != "auto" {
			cleanWebUIPv4, _, _ := strings.Cut(webUIPv4, "/")
			if ip4Str == cleanWebUIPv4 {
				return true
			}
		}
	}
	if ip6Str, err := a.ValueForProtocol(multiaddr.P_IP6); err == nil && ip6Str != "" {
		if tapIPv6 != "" {
			cleanTapIPv6, _, _ := strings.Cut(tapIPv6, "/")
			if ip6Str == cleanTapIPv6 {
				return true
			}
		}
		if webUIPv6 != "" && webUIPv6 != "::" && webUIPv6 != "auto" {
			cleanWebUIPv6, _, _ := strings.Cut(webUIPv6, "/")
			if ip6Str == cleanWebUIPv6 {
				return true
			}
		}
	}
	return false
}

// filterAdvertisedAddrs returns the subset of addrs that are safe to advertise
// to remote peers during libp2p identify. It drops two classes that must never
// be broadcast:
//
//   - TAP virtual-device addresses (circular P2P dialing risk), and
//   - loopback addresses (127.0.0.0/8 and ::1): these are only reachable from
//     this same host, so a peer that learns them would attempt — and always
//     fail — to dial us on 127.0.0.1 / ::1, which is impossible across
//     machines. Advertising them also pollutes the peer's address book with
//     dead entries.
//
// This is the single source of truth used by libp2p.AddrsFactory (the only
// place that decides which listen addrs get broadcast) and by the local
// circuit-relay registration. Keep it the one filter for outbound addresses.
func filterAdvertisedAddrs(addrs []multiaddr.Multiaddr, tapIP, tapIPv6, webUIListenIP, webUIListenIPv6 string) []multiaddr.Multiaddr {
	filtered := make([]multiaddr.Multiaddr, 0, len(addrs))
	for _, a := range addrs {
		if isTapMultiaddr(a, tapIP, tapIPv6, webUIListenIP, webUIListenIPv6) {
			continue
		}
		if manet.IsIPLoopback(a) {
			continue
		}
		filtered = append(filtered, a)
	}
	return filtered
}

// filterLoopbackAddrs drops any loopback multiaddr (127.0.0.0/8 or ::1) from a
// slice of peer addresses. This is the RECEIVE-side guard that complements
// filterAdvertisedAddrs (the broadcast-side guard): even if a remote peer
// advertises a loopback address (because its own AddrsFactory fix is not
// deployed yet, or its peerstore still carries a stale entry), we must never
// surface it in the WebUI nor attempt to dial it from this node — connecting
// to 127.0.0.1 / ::1 always targets THIS host, never the peer, so such
// addresses are meaningless for reachability.
func filterLoopbackAddrs(addrs []multiaddr.Multiaddr) []multiaddr.Multiaddr {
	if len(addrs) == 0 {
		return addrs
	}
	filtered := make([]multiaddr.Multiaddr, 0, len(addrs))
	for _, a := range addrs {
		if manet.IsIPLoopback(a) {
			continue
		}
		filtered = append(filtered, a)
	}
	return filtered
}

func (n *Node) isLocalWebUIVirtualPacket(payload []byte) bool {
	if len(payload) < 14 {
		return false
	}

	// Check if source or destination MAC is the interceptor's virtual MAC
	if bytes.Equal(payload[0:6], observer.InterceptorMAC) || bytes.Equal(payload[6:12], observer.InterceptorMAC) {
		return true
	}

	ethType := binary.BigEndian.Uint16(payload[12:14])

	// Check for IPv4 packets involving the virtual WebUI IP
	if n.virtualWebUIV4IPUint32 > 0 && ethType == packet.EtherTypeIPv4 && len(payload) >= 34 {
		dstIPUint32 := binary.BigEndian.Uint32(payload[30:34])
		if dstIPUint32 == n.virtualWebUIV4IPUint32 {
			return true
		}
		srcIPUint32 := binary.BigEndian.Uint32(payload[26:30])
		if srcIPUint32 == n.virtualWebUIV4IPUint32 {
			return true
		}
	}

	// Check for ARP packets involving the virtual WebUI IP
	if n.virtualWebUIV4IPUint32 > 0 && ethType == packet.EtherTypeARP && len(payload) >= 42 {
		targetIPUint32 := binary.BigEndian.Uint32(payload[38:42])
		if targetIPUint32 == n.virtualWebUIV4IPUint32 {
			return true
		}
		senderIPUint32 := binary.BigEndian.Uint32(payload[28:32])
		if senderIPUint32 == n.virtualWebUIV4IPUint32 {
			return true
		}
	}

	// Check for IPv6 packets involving the virtual WebUI IP
	if n.virtualWebUIV6IP != nil && ethType == packet.EtherTypeIPv6 && len(payload) >= 54 {
		if bytes.Equal(payload[38:54], n.virtualWebUIV6IP) { // dstIP
			return true
		}
		if bytes.Equal(payload[22:38], n.virtualWebUIV6IP) { // srcIP
			return true
		}
	}

	return false
}

// isExitNodeActive reports whether this node currently has an Exit Node default
// route installed (i.e. system traffic is being hijacked to a remote peer).
// It reads the atomic mirror on the GatewayManager so the data-plane hot path
// does not have to take gm.mu.
func (n *Node) isExitNodeActive() bool {
	if n.Gateway == nil {
		return false
	}
	return n.Gateway.IsExitNodeActive()
}

// getExitPeerMAC returns the TAP MAC of the currently active Exit Node peer, or
// nil when no Exit Node is active / its MAC is unknown.  The Exit Node peer is the
// L2 next hop that transit traffic must be delivered to.
func (n *Node) getExitPeerMAC() net.HardwareAddr {
	if n.Gateway == nil {
		return nil
	}
	pID := n.Gateway.ActiveExitPeerPID()
	if pID == "" {
		if exitPeerID := n.Gateway.ActiveExitPeerID(); exitPeerID != "" {
			pID, _ = peer.Decode(exitPeerID)
		}
	}
	if pID == "" {
		return nil
	}
	return n.lookupPeerTapMAC(pID)
}

// lookupPeerTapMAC returns the effective TAP MAC of the given peer, prioritizing
// the observed wire MAC if available, falling back to metadata TapMAC.
func (n *Node) lookupPeerTapMAC(pID peer.ID) net.HardwareAddr {
	if obs := n.observedTapMACFrom(pID); len(obs) == 6 {
		return obs
	}
	val, ok := n.peerMeta.Load(pID)
	if !ok {
		return nil
	}
	meta := val.(PeerMeta)
	if meta.TapMAC == "" {
		return nil
	}
	hw, err := net.ParseMAC(meta.TapMAC)
	if err != nil {
		return nil
	}
	return hw
}

// extractFrameDstIP parses the destination IPv4/IPv6 address from an Ethernet
// frame payload (the same payload processed by ExtractEthernetMACs).  Returns
// nil for non-IP frames or runt frames.  Used as a fallback in the TAP egress
// path to resolve the owning mesh peer when the MAC table has no entry yet.
func extractFrameDstIP(frame []byte) net.IP {
	if len(frame) < 34 {
		return nil
	}
	etherType := binary.BigEndian.Uint16(frame[12:14])
	switch etherType {
	case 0x0800: // IPv4
		if len(frame) < 34 {
			return nil
		}
		return net.IP(append([]byte(nil), frame[30:34]...))
	case 0x86DD: // IPv6
		if len(frame) < 54 {
			return nil
		}
		return net.IP(append([]byte(nil), frame[38:54]...))
	case 0x0806: // ARP
		if len(frame) < 42 {
			return nil
		}
		return net.IP(append([]byte(nil), frame[38:42]...))
	}
	return nil
}

// lookupPeerMACByIPv4 resolves a peer by its own direct TAP IPv4 address (O(1)
// index lookup). Advertised-subnet targets are handled by the separate
// lookupPeerMACByAdvertisedSubnet stage, mirroring resolveProxyMAC's two-stage
// decision so the proxy "via" classification stays correct.
func (n *Node) lookupPeerMACByIPv4(ip net.IP) (net.HardwareAddr, peer.ID) {
	target := ip.To4()
	if target == nil {
		return nil, ""
	}
	n.arpIndexMu.RLock()
	idx := n.arpIndex
	n.arpIndexMu.RUnlock()
	if idx == nil {
		return nil, ""
	}
	if e, ok := idx.v4[binary.BigEndian.Uint32(target)]; ok {
		return e.mac, e.pid
	}
	return nil, ""
}

// resolvePeerIDByIP is the unified multi-stage fallback resolver for an IP:
// direct TAP IPv4/IPv6, then advertised LAN subnet. O(1) + O(subnets) over the
// read-optimized index, with no per-call CIDR/MAC parsing.
func (n *Node) resolvePeerIDByIP(ip net.IP) (peer.ID, net.HardwareAddr) {
	if ip == nil {
		return "", nil
	}
	n.arpIndexMu.RLock()
	idx := n.arpIndex
	n.arpIndexMu.RUnlock()
	if idx == nil {
		return "", nil
	}
	// 1. Direct match by TAP IP (IPv4 takes the uint32 fast path; IPv6 falls
	// back to the string-keyed map).
	if v4 := ip.To4(); v4 != nil {
		if e, ok := idx.v4[binary.BigEndian.Uint32(v4)]; ok {
			return e.pid, e.mac
		}
	} else if v6 := ip.To16(); v6 != nil {
		var k [16]byte
		copy(k[:], v6)
		if e, ok := idx.v6[k]; ok {
			return e.pid, e.mac
		}
	}
	// 2. Advertised LAN subnet match.
	for _, s := range idx.subnets {
		if s.net.Contains(ip) {
			return s.pid, s.mac
		}
	}
	return "", nil
}

// lookupPeerIDByAdvertisedSubnet resolves a peer by an advertised LAN subnet
// (O(subnets) index scan over pre-parsed CIDRs).  Used to learn the peer's MAC
// into the local MAC table after an ARP/NDP proxy reply so subsequent unicast
// frames route directly instead of being flooded.
// lookupPeerMACByAdvertisedSubnet is the MAC-returning counterpart of the same
// lookup.
func (n *Node) lookupPeerIDByAdvertisedSubnet(ip net.IP) peer.ID {
	if ip == nil {
		return ""
	}
	n.arpIndexMu.RLock()
	idx := n.arpIndex
	n.arpIndexMu.RUnlock()
	if idx == nil {
		return ""
	}
	for _, s := range idx.subnets {
		if s.net.Contains(ip) {
			return s.pid
		}
	}
	return ""
}

func (n *Node) lookupPeerMACByAdvertisedSubnet(ip net.IP) net.HardwareAddr {
	if ip == nil {
		return nil
	}
	n.arpIndexMu.RLock()
	idx := n.arpIndex
	n.arpIndexMu.RUnlock()
	if idx == nil {
		return nil
	}
	for _, s := range idx.subnets {
		if s.net.Contains(ip) {
			return s.mac
		}
	}
	return nil
}

// frameDstIPs extracts the IPv4 and/or IPv6 destination address from an
// Ethernet frame payload (min 14-byte header). Either return value may be nil
// when the frame is not IPv4/IPv6 or too short. Used to apply the unified
// routing decision table (advertised subnet -> mesh, everything else -> exit)
// in both the direct-Rx and relay-Rx paths so they stay consistent.
func frameDstIPs(payload []byte) (v4 net.IP, v6 net.IP) {
	if len(payload) < 14 {
		return nil, nil
	}
	switch binary.BigEndian.Uint16(payload[12:14]) {
	case packet.EtherTypeIPv4: // IPv4
		if len(payload) >= 34 {
			v4 = net.IP(append([]byte(nil), payload[30:34]...))
		}
	case packet.EtherTypeIPv6: // IPv6
		if len(payload) >= 54 {
			v6 = net.IP(append([]byte(nil), payload[38:54]...))
		}
	}
	return v4, v6
}

// lookupPeerMACByIPv6 resolves a peer by its own direct TAP IPv6 address (O(1)
// index lookup). The key is the raw 16-byte address so the hot path performs
// zero allocations (mirroring the uint32 IPv4 map).
func (n *Node) lookupPeerMACByIPv6(ip net.IP) (net.HardwareAddr, peer.ID) {
	target := ip.To16()
	if target == nil {
		return nil, ""
	}
	var k [16]byte
	copy(k[:], target)
	n.arpIndexMu.RLock()
	idx := n.arpIndex
	n.arpIndexMu.RUnlock()
	if idx == nil {
		return nil, ""
	}
	if e, ok := idx.v6[k]; ok {
		return e.mac, e.pid
	}
	return nil, ""
}

// learnPeerAddressFromFrame automatically learns a peer's IPv4/IPv6 from an inbound
// Ethernet frame into peer metadata and injects a gratuitous ARP or Neighbor Advertisement
// into the local TAP device, ensuring the local OS kernel ARP/NDP tables are hot and immediate
// unicast return replies can be emitted without broadcast ARP/NDP resolution delay.
func (n *Node) learnPeerAddressFromFrame(srcPeer peer.ID, srcMAC net.HardwareAddr, payload []byte) {
	if len(payload) < 14 || len(srcMAC) != 6 || srcPeer == "" || (n.Host != nil && srcPeer == n.Host.ID()) {
		return
	}
	ethType := binary.BigEndian.Uint16(payload[12:14])
	// IPv4 (0x0800)
	if ethType == packet.EtherTypeIPv4 && len(payload) >= 34 {
		srcIP := net.IP(payload[26:30]).To4()
		if srcIP != nil && !srcIP.IsUnspecified() && !srcIP.IsMulticast() && !srcIP.IsLoopback() {
			// CRITICAL GUARD: Only learn IP addresses that belong to the local overlay mesh network!
			// External WAN/Internet addresses (e.g. 8.8.8.8) returning from an Exit Node MUST NEVER
			// be learned as the Exit Node's TapIP. Doing so poisons peerMeta, overwrites the peer's
			// real IP in arpIndex, breaks subsequent ARP proxy resolution on both ends, and corrupts routing.
			if n.localV4Net != nil && !n.localV4Net.Contains(srcIP) {
				return
			}
			if n.localV4Net == nil && !srcIP.IsPrivate() && !srcIP.IsLinkLocalUnicast() {
				return
			}
			val, ok := n.peerMeta.Load(srcPeer)
			var m PeerMeta
			if ok {
				m = val.(PeerMeta)
			}
			changed := false
			if m.TapIP == "" {
				m.TapIP = srcIP.String() + "/24"
				changed = true
			}
			cleanTapIP := strings.Split(m.TapIP, "/")[0]
			if (m.TapMAC == "" || m.TapMAC != srcMAC.String()) && cleanTapIP == srcIP.String() {
				m.TapMAC = srcMAC.String()
				changed = true
			}
			if changed {
				n.storePeerMeta(srcPeer, m)
				if n.TAP != nil && (n.localV4Net == nil || n.localV4Net.Contains(srcIP)) {
					garpFrame := tap.BuildARPReplyFrame(srcMAC, net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, srcIP, srcIP)
					_, _ = n.tapWrite(garpFrame)
				}
			}
		}
		return
	}
	// IPv6 (0x86DD)
	if ethType == packet.EtherTypeIPv6 && len(payload) >= 54 {
		srcIP := net.IP(payload[22:38])
		if srcIP != nil && !srcIP.IsUnspecified() && !srcIP.IsMulticast() && !srcIP.IsLoopback() {
			// Only learn IPv6 addresses belonging to the mesh subnet or ULA (fc00::/7) / link-local
			if n.localV6Net != nil && !n.localV6Net.Contains(srcIP) {
				return
			}
			if n.localV6Net == nil && srcIP.IsGlobalUnicast() && (len(srcIP) > 0 && (srcIP[0]&0xfe) != 0xfc) {
				return
			}
			val, ok := n.peerMeta.Load(srcPeer)
			var m PeerMeta
			if ok {
				m = val.(PeerMeta)
			}
			changed := false
			if m.TapIPv6 == "" {
				m.TapIPv6 = srcIP.String() + "/64"
				changed = true
			}
			cleanTapIPv6 := strings.Split(m.TapIPv6, "/")[0]
			if (m.TapMAC == "" || m.TapMAC != srcMAC.String()) && cleanTapIPv6 == srcIP.String() {
				m.TapMAC = srcMAC.String()
				changed = true
			}
			if changed {
				n.storePeerMeta(srcPeer, m)
				if n.TAP != nil && (n.localV6Net == nil || n.localV6Net.Contains(srcIP)) {
					naFrame := tap.BuildIPv6NeighborAdvertisementFrameWithMAC(srcMAC, net.HardwareAddr{0x33, 0x33, 0x00, 0x00, 0x00, 0x01}, srcIP, net.ParseIP("ff02::1"))
					if len(naFrame) > 0 {
						_, _ = n.tapWrite(naFrame)
					}
				}
			}
		}
	}
}

// proxyResolution is the result of resolveProxyMAC: which MAC to answer an ARP/NDP
// request with, and how it was resolved. The four cases (direct peer, advertised
// subnet peer, Exit Node catch-all, local TAP) are identical for IPv4 ARP and IPv6
// NDP — only the lookup functions and the "is this my local IP" test differ by L3
// family. resolveProxyMAC encodes that single decision table so the IPv4 and IPv6
// proxy branches in processTapFrame stay in lockstep.
type proxyResolution struct {
	mac    net.HardwareAddr
	peerID peer.ID // valid only when Via == proxyViaPeer
	via    proxyVia
}

type proxyVia int

const (
	proxyViaNone   proxyVia = iota // not for us → let frame propagate
	proxyViaPeer                   // a known peer's IP (TapIP/TapIPv6)
	proxyViaSubnet                 // a peer's advertised subnet
	proxyViaExit                   // active Exit Node catch-all (or local MAC fallback)
	proxyViaLocal                  // our own TAP IP / WebUI virtual IP
)

func (v proxyVia) String() string {
	switch v {
	case proxyViaPeer:
		return "peer"
	case proxyViaSubnet:
		return "subnet"
	case proxyViaExit:
		return "exit"
	case proxyViaLocal:
		return "local"
	default:
		return "none"
	}
}

// resolveProxyMAC runs the unified four-stage ARP/NDP proxy decision for a single
// target IP. direct resolves a peer by its own TAP IP, subnet resolves a peer by an
// advertised subnet, isLocal reports whether target is one of our own addresses, and
// isExit/exitMAC expose the Exit Node catch-all. The Exit fallback to localMAC mirrors
// the gateway behaviour: the OS only needs *a* MAC to emit the transit frame, which is
// later rewritten to the Exit server's real TAP MAC on arrival.
func (n *Node) resolveProxyMAC(
	target net.IP,
	direct func(net.IP) (net.HardwareAddr, peer.ID),
	subnet func(net.IP) net.HardwareAddr,
	isLocal func(net.IP) bool,
) proxyResolution {
	if mac, pid := direct(target); mac != nil {
		return proxyResolution{mac: mac, peerID: pid, via: proxyViaPeer}
	}
	if mac := subnet(target); mac != nil {
		return proxyResolution{mac: mac, via: proxyViaSubnet}
	}
	if n.isExitNodeActive() {
		exitMAC := n.getExitPeerMAC()
		if len(exitMAC) != 6 {
			exitMAC = n.localMAC
		}
		if len(exitMAC) == 6 {
			return proxyResolution{mac: exitMAC, via: proxyViaExit}
		}
	}
	if isLocal(target) {
		localMAC := n.localMAC
		if len(localMAC) != 6 {
			localMAC = packet.DefaultTapMAC
		}
		return proxyResolution{mac: localMAC, via: proxyViaLocal}
	}
	return proxyResolution{via: proxyViaNone}
}

// extractCleanTransportMA extracts pure IP+Port transport components from exotic multiaddrs
func extractCleanTransportMA(ma multiaddr.Multiaddr) (multiaddr.Multiaddr, error) {
	var components []multiaddr.Component
	multiaddr.ForEach(ma, func(c multiaddr.Component) bool {
		code := c.Protocol().Code
		if code == multiaddr.P_IP4 || code == multiaddr.P_IP6 || code == multiaddr.P_TCP || code == multiaddr.P_UDP {
			components = append(components, c)
			if code == multiaddr.P_TCP || code == multiaddr.P_UDP {
				return false // stop after base transport port
			}
		}
		return true
	})
	if len(components) < 2 {
		return nil, fmt.Errorf("insufficient transport components in %s", ma.String())
	}
	var res multiaddr.Multiaddr
	for _, c := range components {
		if res == nil {
			res = c.Multiaddr()
		} else {
			res = res.Encapsulate(c.Multiaddr())
		}
	}
	return res, nil
}

// Protocol identifiers for the various stream handlers.
const (
	LSAProtocolID          protocol.ID = "/p2ptap/linkstate/1.0.0"
	OverlayRelayProtocolID protocol.ID = "/p2ptap/relay/1.0.0"

	// RelayCtrlProtocolID is the CONTROL-PLANE relay protocol. It tunnels an
	// arbitrary per-peer control stream (SeqSync / LSA / Meta) from an origin
	// peer to a final target peer THROUGH one or more intermediate relay peers,
	// so that two peers which are never directly connected can still negotiate
	// an end-to-end cipher and exchange identity. Unlike OverlayRelayProtocolID
	// (which only forwards TAP data frames hop-by-hop), RelayCtrl carries the
	// inner control handshake bytes verbatim; the intermediate hop(s) never
	// interpret them. The final hop rewrites the stream's logical peer to the
	// true origin so the cipher / identity is keyed on the real counterpart,
	// not on the relay.
	RelayCtrlProtocolID protocol.ID = "/p2ptap/relay-ctrl/1.0.0"

	// BootRelayProtocolID is the DATA-PLANE relay-over-backbone protocol. A
	// node opens one long-lived /p2ptap/boot-relay/1.0.0 stream to each
	// connected boot AFTER PSK auth; every frame it cannot deliver directly or
	// via an overlay-relay peer is wrapped in a routing.PackBootRelayFrame
	// envelope (inner TAP payload stays end-to-end encrypted for the final
	// destination) and written to this uplink. The boot bridges the frame to
	// the destination's own boot-relay uplink — across the boot backbone if the
	// two nodes are attached to different boots — which is exactly what closes
	// the cross-boot data gap that Circuit Relay v2 (per-boot) cannot span.
	// The boot never holds a per-peer cipher with the node (it advertises
	// ObfEnabled=false), so no hop-by-hop obfuscate wrapping is applied; the
	// in-band netID tag (carried by PackBootRelayFrame) is what enforces PSK
	// isolation at the destination boot.
	BootRelayProtocolID protocol.ID = "/p2ptap/boot-relay/1.0.0"
)

// containsSub reports whether substr is within s.
func containsSub(s, substr string) bool {
	return strings.Contains(s, substr)
}
