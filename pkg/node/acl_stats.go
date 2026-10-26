package node

import (
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
)

// checkACL wraps MatchACL and records accept/drop counters + per-rule hits.
// All three call sites in the data path route through here so the WebUI
// status card can show real firewall activity.
//
// Returns true if the frame is allowed (passes), false if dropped.
func (n *Node) checkACL(frame []byte, peerID string, isTx bool) bool {
	c := n.config()
	if c == nil || !c.ACL.Enable {
		return true // ACL disabled — fast path, no recording
	}
	allowed, matchedRuleID := MatchACL(&c.ACL, frame, peerID, isTx)
	if n.aclStats == nil {
		return allowed // counters disabled (e.g. unit test)
	}
	if allowed {
		n.aclStats.recordAccept()
		if matchedRuleID != "" {
			n.aclStats.recordRuleHit(matchedRuleID)
		}
		return true
	}
	// Build a minimal drop record. We deliberately do not deep-parse the
	// frame here (the cost would compete with the data plane); the rule id
	// and direction are enough for the recent-drops log and per-rule hits.
	dir := "inbound"
	if isTx {
		dir = "outbound"
	}
	reason := "default"
	if matchedRuleID != "" {
		reason = "rule:" + matchedRuleID
	}
	n.aclStats.recordDrop(ACLDropRecord{
		Time:   time.Now(),
		PeerID: peerID,
		RuleID: matchedRuleID,
		Reason: reason,
		Dir:    dir,
	})
	return false
}

// checkRelayTransitACL evaluates whether the relay node should forward a relay
// envelope from srcPeer to finalDst. ACL is enforced at the final hop's local
// evaluation, but a relay node that skips ACL entirely lets a blocked peer use
// a third-party relay as a bounce — reaching any peer whose final-hop ACL is
// permissive, while bypassing per-peer rate limits and path pinning. This check
// runs at the relay node and denies forwarding if the ACL would have denied the
// frame locally.
func (n *Node) checkRelayTransitACL(srcPeer, finalDst peer.ID) bool {
	c := n.config()
	if c == nil || !c.ACL.Enable {
		return true // ACL disabled — fast path
	}
	// Direct peer-ID rule evaluation: MatchACL returns early when frame is nil
	// (before reaching the rule loop that checks peer_id), making the old nil
	// call a silent no-op. We evaluate peer_id rules directly here; protocol/
	// port rules only apply at the final hop where the frame is visible.
	//
	// "*" is the catch-all MatchACL applies on the direct path, and it MUST be
	// honoured here too. Skipping it let a {peer_id:"*", action:"deny"} rule
	// block every peer on the direct/final-hop path while traffic kept reaching
	// any peer whose own ACL was permissive via a third-party relay — exactly
	// the bounce bypass this check exists to close, for the one rule shape an
	// operator most naturally writes as "deny everyone".
	//
	// Rules apply in CONFIGURATION ORDER, matching MatchACL's first-match-wins.
	// Deliberately not most-specific-wins: that would let a "* deny" the
	// operator placed ahead of a specific accept be overridden on the relay path
	// only, i.e. under-deny relative to the direct path. Ignoring protocol/port
	// here can only over-deny, which is the safe direction.
	//
	// Two MatchACL guards MUST be mirrored here, or the transit check silently
	// diverges from the direct path it is meant to pre-empt:
	//
	//   - MatchACL treats an EMPTY peer_id as match-all (its guard is
	//     `rule.PeerID != "" && ...`), which is how the WebUI's "deny all" rule
	//     is written. Treating empty as match-nothing let such a rule deny every
	//     direct frame while leaving relay transit wide open — the exact bounce
	//     bypass this check exists to close.
	//   - A relay frame is inbound-like (heading INTO the network toward
	//     finalDst), so `direction:"outbound"` rules do not apply here — the
	//     direct-path twin is MatchACL with isTx=false. Honouring only peer_id
	//     applied an "outbound only" deny to transit traffic that never leaves us.
	src := srcPeer.String()
	for _, rule := range c.ACL.Rules {
		if dir := strings.ToLower(rule.Direction); dir == "outbound" {
			continue
		}
		if rule.PeerID != "" && rule.PeerID != "*" && rule.PeerID != src {
			continue
		}
		allowed := strings.ToLower(rule.Action) == "accept" || strings.ToLower(rule.Action) == "allow"
		n.recordRelayTransitACL(rule.RuleID, src, allowed)
		return allowed
	}
	defAct := strings.ToLower(c.ACL.DefaultAction)
	allowed := defAct == "accept" || defAct == "allow" || defAct == ""
	n.recordRelayTransitACL("", src, allowed)
	return allowed
}

// recordRelayTransitACL folds a relay-transit decision into the same ACL
// counters as the direct path, so the WebUI firewall card shows relay
// activity too. Before this checkRelayTransitACL made decisions that never
// appeared in the counters: a `{peer_id:"*", action:"deny"}` rule would show
// zero hits while still dropping every transited frame, making the drop
// invisible. Best-effort: aclStats is nil in hand-built test nodes.
func (n *Node) recordRelayTransitACL(ruleID, src string, allowed bool) {
	if n.aclStats == nil {
		return
	}
	if allowed {
		n.aclStats.recordAccept()
		n.aclStats.recordRuleHit(ruleID)
		return
	}
	reason := "default"
	if ruleID != "" {
		reason = "rule:" + ruleID
	}
	n.aclStats.recordDrop(ACLDropRecord{
		Time:   time.Now(),
		PeerID: src,
		RuleID: ruleID,
		Reason: reason,
		Dir:    "inbound",
	})
}

// ACLStatsSnapshotDTO is the JSON shape returned to the WebUI. Defined here
// (rather than in observer/) to keep the engine self-contained; the stats
// layer re-exports it via its own DTO so the wire shape can evolve
// independently of the internal counters.
type ACLStatsSnapshotDTO struct {
	Enabled     bool               `json:"enabled"`
	Accepted    uint64             `json:"accepted"`
	Dropped     uint64             `json:"dropped"`
	UptimeSec   int64              `json:"uptime_sec"`
	RuleCount   int                `json:"rule_count"`
	DefaultAct  string             `json:"default_action"`
	RuleHits    []ACLRuleHit       `json:"rule_hits"`
	RecentDrops []ACLDropRecordDTO `json:"recent_drops"`
}

type ACLDropRecordDTO struct {
	Time    time.Time `json:"time"`
	PeerID  string    `json:"peer_id"`
	RuleID  string    `json:"rule_id"`
	Reason  string    `json:"reason"`
	Proto   string    `json:"protocol"`
	SrcIP   string    `json:"src_ip"`
	DstIP   string    `json:"dst_ip"`
	DstPort int       `json:"dst_port"`
	Dir     string    `json:"direction"`
}

// ACLStatsSnapshot is the DTO returned by Node.GetACLStats; the stats
// collector converts to the WebUI-facing shape. Keeping them separate
// lets the engine evolve without breaking the JSON contract.
func (n *Node) GetACLStats() ACLStatsSnapshotDTO {
	dto := ACLStatsSnapshotDTO{}
	// The enforcement path (checkACL) reads config(); the card must show the
	// SAME snapshot or a hot-reloaded ACL policy is displayed stale.
	if c := n.config(); c != nil {
		dto.Enabled = c.ACL.Enable
		dto.RuleCount = len(c.ACL.Rules)
		dto.DefaultAct = c.ACL.DefaultAction
	} else if n.Config != nil {
		dto.Enabled = n.Config.ACL.Enable
		dto.RuleCount = len(n.Config.ACL.Rules)
		dto.DefaultAct = n.Config.ACL.DefaultAction
	}
	if n.aclStats == nil {
		return dto
	}
	snap := n.aclStats.snapshot()
	dto.Accepted = snap.Accepted
	dto.Dropped = snap.Dropped
	dto.UptimeSec = snap.UptimeSec
	dto.RuleHits = snap.RuleHits
	dto.RecentDrops = make([]ACLDropRecordDTO, len(snap.RecentDrops))
	for i, d := range snap.RecentDrops {
		dto.RecentDrops[i] = ACLDropRecordDTO{
			Time: d.Time, PeerID: d.PeerID, RuleID: d.RuleID, Reason: d.Reason,
			Proto: d.Proto, SrcIP: d.SrcIP, DstIP: d.DstIP, DstPort: d.DstPort, Dir: d.Dir,
		}
	}
	return dto
}

// ACLStats tracks live accept/drop counters for the ACL engine.
//
// The engine itself is a pure function (MatchACL); this struct is the
// stateful wrapper that records per-decision counters and a small ring
// buffer of recent drops so the WebUI can show "what the firewall is
// actually doing" without instrumenting the data path with logs.
//
// Safe for concurrent updates from the per-stream goroutines and
// concurrent reads from /api/stats.
type ACLStats struct {
	accepted uint64 // atomic
	dropped  uint64 // atomic

	mu          sync.RWMutex
	startedAt   time.Time
	ruleHits    map[string]*uint64 // rule_id -> atomic hit count
	recentDrops []ACLDropRecord    // fixed-capacity ring, written in place
	dropsStart  int                // index of the OLDEST live drop record
	dropsCount  int                // live drop records, <= len(recentDrops)
}

const recentDropsCap = 50

// ACLDropRecord captures the minimum context the WebUI needs to render a
// human-readable "recent drops" list. The full frame is intentionally not
// stored (privacy + size) — only the matched rule, peer, and direction.
type ACLDropRecord struct {
	Time    time.Time `json:"time"`
	PeerID  string    `json:"peer_id"`
	RuleID  string    `json:"rule_id"` // "" = fell through to default action
	Reason  string    `json:"reason"`  // "rule:r1" or "default"
	Proto   string    `json:"protocol"`
	SrcIP   string    `json:"src_ip"`
	DstIP   string    `json:"dst_ip"`
	DstPort int       `json:"dst_port"`
	Dir     string    `json:"direction"` // "inbound" | "outbound"
}

func newACLStats() *ACLStats {
	return &ACLStats{
		startedAt:   time.Now(),
		ruleHits:    make(map[string]*uint64),
		recentDrops: make([]ACLDropRecord, recentDropsCap),
	}
}

// recordAccept bumps the global accept counter. Per-rule hit counts are
// recorded separately by recordRuleHit so this can stay allocation-free.
func (s *ACLStats) recordAccept() {
	atomic.AddUint64(&s.accepted, 1)
}

// recordRuleHit increments the hit counter for a single rule. Safe under
// concurrent first-time inserts (the second writer wins on which counter
// pointer is stored, but the lost update is bounded to the very first
// race and is negligible for counters).
func (s *ACLStats) recordRuleHit(ruleID string) {
	if ruleID == "" {
		return
	}
	s.mu.RLock()
	cnt, ok := s.ruleHits[ruleID]
	s.mu.RUnlock()
	if !ok {
		s.mu.Lock()
		// Re-check under write lock to avoid duplicate insert.
		cnt, ok = s.ruleHits[ruleID]
		if !ok {
			cnt = new(uint64)
			s.ruleHits[ruleID] = cnt
		}
		s.mu.Unlock()
	}
	atomic.AddUint64(cnt, 1)
}

// recordDrop bumps the global drop counter and appends to the recent-drops
// ring buffer (oldest entry is overwritten when full).
func (s *ACLStats) recordDrop(rec ACLDropRecord) {
	atomic.AddUint64(&s.dropped, 1)
	s.mu.Lock()
	// The ring is fixed-capacity and written in place. dropsStart names the
	// oldest live slot and dropsCount how many slots are live; those two are
	// what snapshot() uses to know which slots are valid, so they must be
	// updated together with the write above.
	if s.dropsCount < len(s.recentDrops) {
		s.recentDrops[(s.dropsStart+s.dropsCount)%len(s.recentDrops)] = rec
		s.dropsCount++
	} else {
		s.recentDrops[s.dropsStart] = rec
		s.dropsStart = (s.dropsStart + 1) % len(s.recentDrops)
	}
	s.mu.Unlock()
}

// snapshot returns a copy of the current counters + recent drops for
// serialization to the WebUI. Callers should treat the returned struct
// as read-only.
type ACLStatsSnapshot struct {
	Accepted    uint64          `json:"accepted"`
	Dropped     uint64          `json:"dropped"`
	UptimeSec   int64           `json:"uptime_sec"`
	RuleHits    []ACLRuleHit    `json:"rule_hits"`
	RecentDrops []ACLDropRecord `json:"recent_drops"`
}

type ACLRuleHit struct {
	RuleID string `json:"rule_id"`
	Hits   uint64 `json:"hits"`
}

func (s *ACLStats) snapshot() ACLStatsSnapshot {
	s.mu.RLock()
	// Copy rule hits into a stable slice and sort by hit count desc so
	// the UI can render the "top matched rules" widget without any
	// extra JS-side sorting.
	hits := make([]ACLRuleHit, 0, len(s.ruleHits))
	for rid, cnt := range s.ruleHits {
		hits = append(hits, ACLRuleHit{RuleID: rid, Hits: atomic.LoadUint64(cnt)})
	}
	s.mu.RUnlock()
	sort.Slice(hits, func(i, j int) bool {
		if hits[i].Hits != hits[j].Hits {
			return hits[i].Hits > hits[j].Hits
		}
		return hits[i].RuleID < hits[j].RuleID
	})

	// Copy the recent-drops ring (oldest first, skipping the unused slots).
	s.mu.RLock()
	drops := make([]ACLDropRecord, s.dropsCount)
	for i := range drops {
		drops[i] = s.recentDrops[(s.dropsStart+i)%len(s.recentDrops)]
	}
	s.mu.RUnlock()

	return ACLStatsSnapshot{
		Accepted:    atomic.LoadUint64(&s.accepted),
		Dropped:     atomic.LoadUint64(&s.dropped),
		UptimeSec:   int64(time.Since(s.startedAt).Seconds()),
		RuleHits:    hits,
		RecentDrops: drops,
	}
}
