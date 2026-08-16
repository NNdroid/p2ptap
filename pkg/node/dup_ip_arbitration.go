package node

import (
	"bytes"
	"math"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
)

// DuplicateIPConflict records one detected duplicate-IP (or exactly-duplicate
// advertised-subnet) conflict among peers together with the arbitration verdict
// that resolved it.
//
// A single resource — a direct TAP IPv4, a direct TAP IPv6, or an advertised
// subnet CIDR — is claimed by more than one peer. Only the winning peer keeps
// its entry in the read-optimized ARP index; every loser is suppressed so L2/L3
// resolution stays deterministic instead of silently falling through to
// last-writer-wins (the previous behaviour, which made routing for the
// duplicated address non-deterministic).
type DuplicateIPConflict struct {
	// ResourceType is one of "tap_ip_v4", "tap_ip_v6", "advertised_subnet".
	ResourceType string `json:"resource_type"`
	// Resource is the duplicated address, e.g. "10.0.0.5" or "192.168.1.0/24".
	Resource string `json:"resource"`
	// Claimants lists every peer that advertised the resource (peer IDs).
	Claimants []string `json:"claimants"`
	// Winner is the peer that won the arbitration and keeps the route.
	Winner string `json:"winner"`
	// Losers are the suppressed peers (their index entry is dropped).
	Losers []string `json:"losers"`
	// Reason is a human-readable explanation of why the winner won, referencing
	// its position in allowed_subnet_peers.
	Reason string `json:"reason"`
	// DetectedAt is the time the conflict was last (re)observed.
	DetectedAt time.Time `json:"detected_at"`
}

// hasOrderedPreference reports whether allowed_subnet_peers carries a real
// priority ordering. An empty list, or the single-entry wildcard ["*"], grants
// equal standing to every peer and therefore provides no ordered preference —
// in that case arbitration falls back to a deterministic peer-ID tie-break.
func hasOrderedPreference(order []string) bool {
	if len(order) == 0 {
		return false
	}
	if len(order) == 1 && order[0] == "*" {
		return false
	}
	return true
}

// peerPriority returns the arbitration priority of a peer given the
// allowed_subnet_peers ordering.
//
// The list defines priority BY POSITION: index 0 is highest priority, later
// entries are lower. A peer that appears earlier in the list always wins over
// one that appears later. Rules:
//
//   - Explicit match (peer ID equals a list entry): priority = its index.
//     Explicit matches always outrank the wildcard and unlisted peers.
//   - The "*" wildcard entry: grants trust to every peer, but ranks BELOW any
//     explicitly-named peer (it is used as a catch-all, not a priority slot).
//   - Not listed and no wildcard: lowest possible priority (math.MaxInt).
//
// This makes the arbitration strictly follow the operator's list order while
// keeping "*" semantics (trust all) intact.
func peerPriority(p peer.ID, order []string) int {
	s := p.String()
	wildcardRank := math.MaxInt
	for i, o := range order {
		if o == s {
			return i // explicit, highest authority, ranked by position
		}
		if o == "*" {
			// Wildcard: catch-all, ranked below every explicit entry.
			wildcardRank = len(order)
		}
	}
	return wildcardRank
}

// arbitratePeers resolves a duplicate-IP conflict among claimants using the
// allowed_subnet_peers ordering. It is a pure function (no Node state) so it can
// be unit-tested directly.
//
// The winner is the claimant with the smallest peerPriority; ties (e.g. all
// matched by "*", or none listed) are broken deterministically by lexicographically
// smallest peer ID string. The returned reason explains the verdict in terms of
// the list order.
func arbitratePeers(claimants []peer.ID, order []string) (winner peer.ID, losers []peer.ID, reason string) {
	if len(claimants) == 0 {
		return "", nil, ""
	}
	if len(claimants) == 1 {
		return claimants[0], nil, ""
	}

	sorted := make([]peer.ID, len(claimants))
	copy(sorted, claimants)
	// Sort by (priority asc, then peer-ID asc) so the first element is the
	// deterministic winner. sort.SliceStable is unnecessary but harmless; the
	// peer-ID tie-break already makes the order total.
	sortByArbitration(sorted, order)

	winner = sorted[0]
	losers = make([]peer.ID, 0, len(sorted)-1)
	losers = append(losers, sorted[1:]...)

	var b strings.Builder
	if !hasOrderedPreference(order) {
		b.WriteString("allowed_subnet_peers has no ordered preference (empty or ['*']); winner chosen by lowest peer ID for deterministic arbitration")
	} else {
		b.WriteString("allowed_subnet_peers order = [")
		b.WriteString(strings.Join(order, ", "))
		b.WriteString("]; winner ")
		b.WriteString(winner.String())
		b.WriteString(" (index ")
		b.WriteString(strconv.Itoa(peerPriority(winner, order)))
		b.WriteString(") outranks ")
		parts := make([]string, 0, len(losers))
		for _, l := range losers {
			idx := peerPriority(l, order)
			if idx == math.MaxInt {
				parts = append(parts, l.String()+" (not in list)")
			} else {
				parts = append(parts, l.String()+" (index "+strconv.Itoa(idx)+")")
			}
		}
		b.WriteString(strings.Join(parts, ", "))
	}
	return winner, losers, b.String()
}

// sortByArbitration orders peers by ascending arbitration priority, breaking
// ties by ascending peer-ID string.
func sortByArbitration(peers []peer.ID, order []string) {
	// Simple insertion-friendly sort; claimant counts are tiny (duplicates are
	// rare and involve very few peers), so O(n^2) is fine and avoids importing
	// sort for a trivial comparison.
	for i := 1; i < len(peers); i++ {
		for j := i; j > 0; j-- {
			pi := peerPriority(peers[j-1], order)
			pj := peerPriority(peers[j], order)
			if pi < pj || (pi == pj && peers[j-1].String() <= peers[j].String()) {
				break
			}
			peers[j-1], peers[j] = peers[j], peers[j-1]
		}
	}
}

// buildConflict assembles a DuplicateIPConflict from the arbitration result.
func buildConflict(resourceType, resource string, claimants, losers []peer.ID, winner peer.ID, reason string) DuplicateIPConflict {
	c := DuplicateIPConflict{
		ResourceType: resourceType,
		Resource:     resource,
		Winner:       winner.String(),
		Reason:       reason,
		DetectedAt:   time.Now(),
	}
	c.Claimants = pidsToStrings(claimants)
	c.Losers = pidsToStrings(losers)
	return c
}

func pidsToStrings(pids []peer.ID) []string {
	out := make([]string, len(pids))
	for i, p := range pids {
		out[i] = p.String()
	}
	return out
}

// allowedSubnetOrder returns the arbitration priority list. A nil Config (e.g.
// in unit tests or before configuration load) yields a nil slice, which
// arbitratePeers treats as "no ordered preference".
func (n *Node) allowedSubnetOrder() []string {
	if n.Config == nil {
		return nil
	}
	return n.Config.AllowedSubnetPeers
}

// GetDuplicateIPConflicts returns a snapshot of the currently detected
// duplicate-IP / overlapping-subnet conflicts and their arbitration verdicts.
// Safe for concurrent use; the slice is a copy.
func (n *Node) GetDuplicateIPConflicts() []DuplicateIPConflict {
	n.dupIPConflictsMu.Lock()
	defer n.dupIPConflictsMu.Unlock()
	out := make([]DuplicateIPConflict, len(n.dupIPConflicts))
	copy(out, n.dupIPConflicts)
	return out
}

// setDuplicateIPConflicts stores the latest conflict set and emits a WARN log
// for each conflict that is newly observed or whose verdict changed. This keeps
// the warning stream meaningful (one alert per conflict) instead of re-logging
// the same persistent conflict on every periodic topology rebuild.
func (n *Node) setDuplicateIPConflicts(newConf []DuplicateIPConflict) {
	n.dupIPConflictsMu.Lock()
	old := n.dupIPConflicts
	n.dupIPConflicts = newConf
	n.dupIPConflictsMu.Unlock()

	seen := make(map[string]bool, len(old))
	for _, c := range old {
		seen[conflictKey(c)] = true
	}
	for _, c := range newConf {
		if seen[conflictKey(c)] {
			continue // already reported; avoid spamming
		}
		log.Warn("⚠️ [dup-ip] duplicate %s %s claimed by %d peers %v — arbitration: winner=%s losers=%v | %s",
			c.ResourceType, c.Resource, len(c.Claimants), c.Claimants, c.Winner, c.Losers, c.Reason)
	}
}

// conflictKey uniquely identifies a conflict for change-detection. It uses a
// NUL separator so a Resource string can never collide with the other fields.
func conflictKey(c DuplicateIPConflict) string {
	return c.ResourceType + "\x00" + c.Resource + "\x00" + c.Winner
}

// cidrEqual reports whether two CIDR blocks describe the exact same network.
func cidrEqual(a, b *net.IPNet) bool {
	if a == nil || b == nil {
		return false
	}
	return a.IP.Equal(b.IP) && bytes.Equal(a.Mask, b.Mask)
}

// netsOverlap reports whether two CIDR blocks share any address. CIDR prefix
// blocks form a tree, so two blocks either are disjoint or one contains the
// other (equal blocks count as overlapping). This makes overlap detection a
// single containment test rather than an expensive range intersection.
func netsOverlap(a, b *net.IPNet) bool {
	if a == nil || b == nil {
		return false
	}
	return a.Contains(b.IP) || b.Contains(a.IP)
}
