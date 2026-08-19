package node

import (
	"fmt"
	"sync/atomic"
	"time"
)

// ChannelTrafficCounter holds lock-free atomic counters for TX/RX frames, bytes,
// sync/handshake events, and error counts on a specific protocol channel.
type ChannelTrafficCounter struct {
	txFrames     atomic.Uint64
	rxFrames     atomic.Uint64
	txBytes      atomic.Uint64
	rxBytes      atomic.Uint64
	syncEvents   atomic.Uint64
	errorCount   atomic.Uint64
	lastActiveNs atomic.Int64
}

// RecordTx adds transmitted frames and bytes to the channel counter.
func (c *ChannelTrafficCounter) RecordTx(frames uint64, bytes uint64) {
	c.txFrames.Add(frames)
	c.txBytes.Add(bytes)
	c.lastActiveNs.Store(time.Now().UnixNano())
}

// RecordRx adds received frames and bytes to the channel counter.
func (c *ChannelTrafficCounter) RecordRx(frames uint64, bytes uint64) {
	c.rxFrames.Add(frames)
	c.rxBytes.Add(bytes)
	c.lastActiveNs.Store(time.Now().UnixNano())
}

// RecordSyncEvent increments the handshake / re-key / sync event counter.
func (c *ChannelTrafficCounter) RecordSyncEvent() {
	c.syncEvents.Add(1)
	c.lastActiveNs.Store(time.Now().UnixNano())
}

// RecordError increments the channel error or drop counter.
func (c *ChannelTrafficCounter) RecordError() {
	c.errorCount.Add(1)
}

// Snapshot returns a point-in-time copy of all metrics for this channel.
func (c *ChannelTrafficCounter) Snapshot() (txFrames, rxFrames, txBytes, rxBytes, syncEvents, errCount uint64, lastActiveAgo string) {
	txFrames = c.txFrames.Load()
	rxFrames = c.rxFrames.Load()
	txBytes = c.txBytes.Load()
	rxBytes = c.rxBytes.Load()
	syncEvents = c.syncEvents.Load()
	errCount = c.errorCount.Load()
	ns := c.lastActiveNs.Load()
	if ns > 0 {
		t := time.Unix(0, ns)
		lastActiveAgo = formatDurationAgo(t)
	}
	return
}

// ProtocolTrafficTracker encapsulates traffic and lifecycle telemetry for all protocol channels.
type ProtocolTrafficTracker struct {
	Data      ChannelTrafficCounter // Virtual TAP Datapath (/p2ptap/1.0.0)
	RelayData ChannelTrafficCounter // Overlay Relay Data (/p2ptap/overlay-relay/1.0.0)
	BootRelay ChannelTrafficCounter // Backbone Relay Data (/p2ptap/boot-relay/1.0.0)
	SeqSync   ChannelTrafficCounter // Sequence Sync & Key Exchange (/p2ptap/seqsync/1.0.0)
	LSA       ChannelTrafficCounter // LSA Mesh Routing (/p2ptap/lsa/1.0.0)
	PeekMap   ChannelTrafficCounter // Peek-Map & Meta (/p2ptap/peek-map/1.0.0, /p2ptap/meta/1.0.0)
	Auth      ChannelTrafficCounter // Mesh Authentication (/p2ptap/relay-auth/1.0.0)
	RelayCtrl ChannelTrafficCounter // Relay Control Tunnel (/p2ptap/relay-ctrl/1.0.0)
	Echo      ChannelTrafficCounter // Diagnostic Echo & Speedtest (/p2ptap/echo/1.0.0)
	Ping      ChannelTrafficCounter // libp2p Ping (/ipfs/ping/1.0.0)
	DCUtR     ChannelTrafficCounter // DCUtR & Circuit Relay (/libp2p/dcutr)
}

// NewProtocolTrafficTracker creates an initialized ProtocolTrafficTracker.
func NewProtocolTrafficTracker() *ProtocolTrafficTracker {
	return &ProtocolTrafficTracker{}
}

// formatDurationAgo formats a timestamp into a human-readable relative time string.
func formatDurationAgo(t time.Time) string {
	d := time.Since(t)
	if d < 0 {
		return "just now"
	}
	if d < 2*time.Second {
		return "just now"
	}
	if d < time.Minute {
		return fmt.Sprintf("%ds ago", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	}
	return fmt.Sprintf("%dd ago", int(d.Hours()/24))
}
