package node

import (
	"fmt"
	"strings"
	"sync/atomic"
	"time"
)

// RelayDiag counts frames dropped at each choke point of the TAP-frame
// transiting chain: overlay-relay RX (hop envelope), hop forwarding, boot
// relay-over-backbone, and final local delivery. Every one of these drops is
// deliberately silent in the data path (per-frame logging is unacceptable at
// packet rates), which makes "peers look connected but frames never cross"
// undiagnosable from the outside. The counters are exposed via
// GET /api/relay/diag and as a periodic one-line summary log so a field
// report can be pinned to a stage without logcat spelunking.
//
// Interpretation cheatsheet:
//   - HopGarbage climbs          → our cipher with the HOP diverged (rekey churn)
//   - FinalDecryptFail climbs    → origin↔destination keys diverged (relay-only
//     rekey is throttled to the reconciler cadence)
//   - OriginPskDrop climbs       → PSK network: origin never proved the PSK to us
//     (wrong PSK, or its relay-ctrl handshake never converged)
//   - PoolFull / UplinkGone climb → the forward path itself is congested/dead,
//     not a crypto problem
//   - LoopGuardDrop climbs       → routing table disagrees with reality (LSA skew)
type RelayDiag struct {
	// inbound hop envelope (handleRelayStream, first peel)
	HopGarbage atomic.Uint64 // hop-cipher AEAD open failed → dropped
	EnvBad     atomic.Uint64 // relay envelope header invalid after peel
	// final-destination delivery
	OriginPskDrop    atomic.Uint64 // PSK net: origin without a negotiated cipher
	FinalDecryptFail atomic.Uint64 // end-to-end inner AEAD open failed
	FinalUnpackFail  atomic.Uint64 // end-to-end inner unpack failed
	// transit forwarding decisions
	LoopGuardDrop atomic.Uint64 // nextHop == carrier; would form a cycle
	TtlExpired    atomic.Uint64 // ttl<=1 with destination not us
	SealFail      atomic.Uint64 // hop seal for the next leg failed
	ForwardDrop   atomic.Uint64 // relayPool refused the forward (queue full)
	// boot relay-over-backbone
	UplinkGone atomic.Uint64 // boot uplink Submit failed (no live uplink)
	// volume context so the drop ratios are readable
	FwdIn atomic.Uint64 // relay envelopes received (incl. forwarded)
	Deliv atomic.Uint64 // frames actually sunk into the local TAP
}

// RelayDiagSnapshot is the JSON shape of /api/relay/diag.
type RelayDiagSnapshot struct {
	HopGarbage       uint64 `json:"hop_garbage_drops"`
	EnvBad           uint64 `json:"envelope_invalid_drops"`
	OriginPskDrop    uint64 `json:"origin_psk_drops"`
	FinalDecryptFail uint64 `json:"final_decrypt_fail_drops"`
	FinalUnpackFail  uint64 `json:"final_unpack_fail_drops"`
	LoopGuardDrop    uint64 `json:"loop_guard_drops"`
	TtlExpired       uint64 `json:"ttl_expired_drops"`
	SealFail         uint64 `json:"hop_seal_fail_drops"`
	ForwardDrop      uint64 `json:"forward_pool_full_drops"`
	UplinkGone       uint64 `json:"boot_uplink_gone_drops"`
	ForwardedIn      uint64 `json:"relay_envelopes_in"`
	DeliveredToTap   uint64 `json:"delivered_to_tap"`
}

// nil-safe bump helpers — hand-constructed test nodes may leave relayDiag
// nil; a nil-receiver method keeps every data-path call site branch-free.
func (d *RelayDiag) hopGarbage() {
	if d != nil {
		d.HopGarbage.Add(1)
	}
}
func (d *RelayDiag) envBad() {
	if d != nil {
		d.EnvBad.Add(1)
	}
}
func (d *RelayDiag) originPsk() {
	if d != nil {
		d.OriginPskDrop.Add(1)
	}
}
func (d *RelayDiag) finalDecFail() {
	if d != nil {
		d.FinalDecryptFail.Add(1)
	}
}
func (d *RelayDiag) finalUnpack() {
	if d != nil {
		d.FinalUnpackFail.Add(1)
	}
}
func (d *RelayDiag) loopGuard() {
	if d != nil {
		d.LoopGuardDrop.Add(1)
	}
}
func (d *RelayDiag) ttlExpired() {
	if d != nil {
		d.TtlExpired.Add(1)
	}
}
func (d *RelayDiag) sealFail() {
	if d != nil {
		d.SealFail.Add(1)
	}
}
func (d *RelayDiag) fwdPoolFull() {
	if d != nil {
		d.ForwardDrop.Add(1)
	}
}
func (d *RelayDiag) uplinkGone() {
	if d != nil {
		d.UplinkGone.Add(1)
	}
}
func (d *RelayDiag) recv() {
	if d != nil {
		d.FwdIn.Add(1)
	}
}
func (d *RelayDiag) delivered() {
	if d != nil {
		d.Deliv.Add(1)
	}
}

func (d *RelayDiag) snapshot() RelayDiagSnapshot {
	if d == nil {
		return RelayDiagSnapshot{}
	}
	return RelayDiagSnapshot{
		HopGarbage:       d.HopGarbage.Load(),
		EnvBad:           d.EnvBad.Load(),
		OriginPskDrop:    d.OriginPskDrop.Load(),
		FinalDecryptFail: d.FinalDecryptFail.Load(),
		FinalUnpackFail:  d.FinalUnpackFail.Load(),
		LoopGuardDrop:    d.LoopGuardDrop.Load(),
		TtlExpired:       d.TtlExpired.Load(),
		SealFail:         d.SealFail.Load(),
		ForwardDrop:      d.ForwardDrop.Load(),
		UplinkGone:       d.UplinkGone.Load(),
		ForwardedIn:      d.FwdIn.Load(),
		DeliveredToTap:   d.Deliv.Load(),
	}
}

// summary returns a one-line non-zero-fields digest, or "" when everything is
// zero (the healthy case must never spam the log).
func (d *RelayDiag) summary() string {
	s := d.snapshot()
	var b strings.Builder
	add := func(name string, v uint64) {
		if v > 0 {
			if b.Len() > 0 {
				b.WriteString(" ")
			}
			fmt.Fprintf(&b, "%s=%d", name, v)
		}
	}
	add("hopGarbage", s.HopGarbage)
	add("envBad", s.EnvBad)
	add("originPSK", s.OriginPskDrop)
	add("finalDecFail", s.FinalDecryptFail)
	add("finalUnpackFail", s.FinalUnpackFail)
	add("loopGuard", s.LoopGuardDrop)
	add("ttlExpired", s.TtlExpired)
	add("sealFail", s.SealFail)
	add("fwdPoolFull", s.ForwardDrop)
	add("uplinkGone", s.UplinkGone)
	if b.Len() == 0 {
		return ""
	}
	return fmt.Sprintf("relay drops: %s (in=%d delivered=%d)", b.String(), s.ForwardedIn, s.DeliveredToTap)
}

// GetRelayDiag is the WebUI-facing snapshot (/api/relay/diag).
func (n *Node) GetRelayDiag() RelayDiagSnapshot { return n.relayDiag.snapshot() }

// relayDiagSummaryLoop logs a one-line drop digest once per minute, but ONLY
// while new drops are accumulating — an idle or healthy node stays silent.
// Plain ticker: this loop emits nothing on the wire, so it needs no jitter.
func (n *Node) relayDiagSummaryLoop() {
	defer n.wg.Done()
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	prev := n.relayDiag.snapshot()
	var lastSum string
	for {
		select {
		case <-n.ctx.Done():
			return
		case <-ticker.C:
			s := n.relayDiag.snapshot()
			if s == prev {
				continue
			}
			prev = s
			if sum := n.relayDiag.summary(); sum != "" && sum != lastSum {
				lastSum = sum
				log.Info("%s", sum)
			}
		}
	}
}
