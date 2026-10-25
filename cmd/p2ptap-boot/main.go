package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	mathrand "math/rand/v2"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"p2ptap/pkg/bootweb"
	"p2ptap/pkg/logger"
	"p2ptap/pkg/maddrutil"
	"p2ptap/pkg/meta"
	"p2ptap/pkg/node"
	"p2ptap/pkg/routing"
	"p2ptap/pkg/version"

	"github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	libp2pconnmgr "github.com/libp2p/go-libp2p/core/connmgr"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/libp2p/go-libp2p/core/pnet"
	"github.com/libp2p/go-libp2p/core/protocol"
	tpt "github.com/libp2p/go-libp2p/core/transport"
	rcmgr "github.com/libp2p/go-libp2p/p2p/host/resource-manager"
	connmgr "github.com/libp2p/go-libp2p/p2p/net/connmgr"
	circuit "github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/proto"
	"github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/relay"
	"github.com/libp2p/go-libp2p/p2p/protocol/holepunch"
	quict "github.com/libp2p/go-libp2p/p2p/transport/quic"
	quicreuse "github.com/libp2p/go-libp2p/p2p/transport/quicreuse"
	tcpt "github.com/libp2p/go-libp2p/p2p/transport/tcp"
	webrtc "github.com/libp2p/go-libp2p/p2p/transport/webrtc"
	webtransport "github.com/libp2p/go-libp2p/p2p/transport/webtransport"
	"github.com/multiformats/go-multiaddr"
)

var log = logger.New("Boot")
var bootAlerts = bootweb.NewAlertBuffer(300)

// boundAddrs records every listener libp2p actually opened, captured by the
// AddrsFactory before it drops loopback. The AddrsFactory runs concurrently
// with the rest of startup, so every reader takes boundMu. verifyListeners
// compares it to the configured listen_addrs after libp2p.New; without that
// check a listener that never bound is indistinguishable from a healthy boot.
var (
	boundMu    sync.Mutex
	boundAddrs []multiaddr.Multiaddr
)

// maxBootRelayEnvelope is the largest possible boot-relay frame on the wire:
//
//	obfuscate.MaxSealedFrameSize (65551) + relay header (~98B for two 46-char
//	peer.IDs) + boot-relay prefix (21B) = 65670 bytes.
//
// readFrame rejects any frame larger than its destination buffer ("frame too
// large") and drops it silently, so every relay read path MUST allocate at
// least this much or max-size envelopes are lost. 64 KiB (65536) is 134 bytes
// too small for the envelope alone, which silently dropped the largest valid
// frames. The constant is rounded up to 66000 for headroom; the extra 330
// bytes are negligible at one allocation per stream.
const maxBootRelayEnvelope = 66000

// relayConnLowWater and relayConnHighWater are this relay's connection
// envelope. They are handed to BOTH the connection manager (which trims back
// toward the low water mark) and the resource manager (which hard-rejects
// above the high water mark) so the two managers cannot silently disagree
// about how many connections the relay is allowed to hold. See
// relayResourceManager for why the two must be given the same number.
const (
	relayConnLowWater  = 2048
	relayConnHighWater = 8192

	// The relay's own capacity envelope (relay.Resources). Every resource
	// manager limit below is DERIVED from these rather than set independently,
	// so the relay cannot advertise a circuit budget its resource manager
	// silently refuses.
	relayMaxCircuits     = 1024
	relayMaxReservations = 1024
	relayBufferSize      = 8192

	// relayStreamPerDir is the resource manager's stream ceiling in ONE
	// direction. Each relayed circuit holds one inbound stream (the hop from
	// the source) and one outbound stream (the stop to the destination), so
	// MaxCircuits needs MaxCircuits streams per direction before auth,
	// boot-relay tunnel and control streams are even counted; the second copy
	// of MaxCircuits is headroom for those, which share the same connections.
	relayStreamPerDir = 2 * relayMaxCircuits

	// relayCircuitMemory bounds the buffered bytes the circuit relay may hold:
	// a read and a write buffer of relayBufferSize per relayed connection, plus
	// the hop/stop framing buffers that sit on top of them. Derived rather than
	// hard-coded so it tracks BufferSize and MaxCircuits.
	relayCircuitMemory = 4 * relayMaxCircuits * relayBufferSize
)

// Global subsystems initialized in main() and used by bootDataProviderImpl.
var (
	gSessions         *sessionTracker
	gTraffic          *trafficHistory
	gGeoIP            *GeoIPResolver
	gSecurity         *SecurityManager
	gPeerConnectTimes sync.Map // peer.ID → time.Time (when peer first connected)
	// relayAllowedDedup prevents flooding the alert buffer with relay_allowed
	// events when the same src→dst pair is established in rapid succession.
	// A pair is suppressed for 10 seconds after its first recorded alert.
	relayAllowedDedup sync.Map // string → time.Time
	// relayDeniedDedup prevents alert flooding on repeated dial retries to offline peers.
	relayDeniedDedup sync.Map // string → time.Time
)

type clientNodeInfo struct {
	PeerID            string   `json:"peer_id"`
	NodeName          string   `json:"node_name,omitempty"`
	TapIP             string   `json:"tap_ip,omitempty"`
	TapIPv6           string   `json:"tap_ipv6,omitempty"`
	TapMAC            string   `json:"tap_mac,omitempty"`
	OS                string   `json:"os,omitempty"`
	Arch              string   `json:"arch,omitempty"`
	Version           string   `json:"version,omitempty"`
	IsExitNode        bool     `json:"is_exit_node,omitempty"`
	AdvertisedSubnets []string `json:"advertised_subnets,omitempty"`
	HopDistance       int      `json:"hop_distance,omitempty"`
	Addrs             []string `json:"addrs,omitempty"`
	IsBoot            bool     `json:"is_boot,omitempty"`
	ObfsAlgo          string   `json:"obfs_algo,omitempty"`
	ObfsMode          string   `json:"obfs_mode,omitempty"`
}

var peerInfoCache sync.Map // peer.ID -> clientNodeInfo

// maxAuthStreamsInflight caps the number of concurrent PSK auth handshakes.
// Every handler goroutine may be parked for the full 30s read deadline (a peer
// that opens the stream and sends nothing), and RecordFailure's progressive
// backoff makes each attempt sleep for seconds. Both rate limits are keyed per
// identity, so an attacker that fans out parallel streams under freshly
// generated libp2p identities pins one goroutine per stream — the per-IP and
// per-peer-ID limits never trip. The cap is far above any real deployment's
// auth load and bounds the parked-goroutine count regardless of fan-out.
const maxAuthStreamsInflight = 64

var authStreamInflight atomic.Int64

const (
	authProtocolID protocol.ID = "/p2ptap/auth/1.0.0"
	echoProtocolID protocol.ID = "/p2ptap/echo/1.0.0"
	// PeekMapProtocolID is the pub/sub broadcast channel. Clients open a
	// long-lived stream to the boot node and exchange PeekMapMessage frames.
	// The boot node acts purely as a router: it does NOT cache any node data.
	// Every message received from one client is forwarded to all other
	// connected clients. This makes peek-map a universal broadcast pipe for
	// node-info / subnet / route exchange as a supplement to P2P streams.
	PeekMapProtocolID protocol.ID = "/p2ptap/peek-map/1.0.0"
	// SeqSyncProtocolID mirrors pkg/node's seqsync control protocol. The boot
	// node registers a *minimal* responder so clients can complete the handshake
	// symmetrically (no more "protocols not supported" retry spam). The boot node
	// never exchanges encrypted TAP frames, so it answers with ObfEnabled=false
	// (no ECDH) and lets the client fall back to plaintext for the boot peer.
	SeqSyncProtocolID protocol.ID = "/p2ptap/seqsync/1.0.0"
	// BootRelayProtocolID is the data-plane relay-over-backbone protocol. A
	// node opens one long-lived /p2ptap/boot-relay/1.0.0 stream to this boot
	// after PSK auth; every frame it cannot deliver directly is wrapped in a
	// routing.PackBootRelayFrame envelope (inner stays end-to-end encrypted for
	// the final destination) and written here. The boot bridges it to the
	// destination's own boot-relay uplink — across the boot backbone if the two
	// nodes are attached to DIFFERENT boots — closing the cross-boot data gap
	// that Circuit Relay v2 (per-boot) cannot span.
	BootRelayProtocolID protocol.ID = "/p2ptap/boot-relay/1.0.0"
	// BootRelayBackboneProtocolID is the relay-over-backbone equivalent of the
	// peek-map backbone: each boot opens one /p2ptap/boot-relay-backbone/1.0.0
	// stream to every peer boot in its -mesh list, so relay frames for a client
	// of a REMOTE boot can be bridged. Like the peek-map backbone, a frame is
	// bounded to a single backbone hop (frames arriving over the backbone are
	// local-delivery-only), so the backbone must be a full mesh.
	BootRelayBackboneProtocolID protocol.ID = "/p2ptap/boot-relay-backbone/1.0.0"
)

// PeekMap message types exchanged over the bootstrap pub/sub channel.
const PeekMapUpdate = "update" // a node's identity/subnets; hub rebroadcasts to all others

// PeekMapMessage is the envelope for all peek-map broadcast traffic. The boot
// node is a stateless router: it only rewrites From and rebroadcasts; it never
// inspects Payload.
type PeekMapMessage struct {
	Type    string          `json:"type"`
	From    string          `json:"from"`              // sender peer.ID (set by boot hub)
	NetID   string          `json:"net_id,omitempty"`  // network isolation tag (PSK mode); empty in open mode
	Payload json.RawMessage `json:"payload,omitempty"` // opaque node info, not inspected by hub
}

// peekMapMaxJSONBytes caps the total wire bytes decoded per PeekMapMessage. A
// 64KB payload base64-encodes to ~85KB; adding the JSON envelope (type/from/
// net_id keys, quotes, commas) keeps the total under 90KB. We round up to
// 128KB to leave headroom for field-name growth. json.Decoder reads ahead in
// bufio-sized chunks, so a raw LimitReader on the stream would accumulate
// across messages; this reader resets the counter per Decode call instead.
const peekMapMaxJSONBytes = 128 * 1024

// cappedMsgReader enforces a per-message byte cap on a json.Decoder's input
// stream. It counts bytes read since the last reset(); once the limit is hit,
// it returns io.EOF, which makes the current Decode call fail (and the
// json.Decoder treats it as a fatal parse error, closing the listener stream).
// Without this, a single client could send a multi-gigabyte JSON payload and
// force the decoder to allocate the entire thing in memory before the post-
// decode len(msg.Payload) check fires — a straightforward memory-amplification
// DoS that also rebroadcasts the oversized payload to every other client.
type cappedMsgReader struct {
	src   io.Reader
	limit int64
	count int64
}

func (c *cappedMsgReader) Read(p []byte) (int, error) {
	if c.count >= c.limit {
		return 0, io.EOF
	}
	remaining := c.limit - c.count
	if int64(len(p)) > remaining {
		p = p[:remaining]
	}
	n, err := c.src.Read(p)
	c.count += int64(n)
	return n, err
}

func (c *cappedMsgReader) reset() {
	c.count = 0
}

// bootNodeInfo is the minimal identity the boot node publishes about itself over
// the peek-map channel so every connected client learns it (name/os/arch/version)
// instead of showing it as an "Unnamed Node". Field names intentionally match
// pkg/node.PeekMapNodeInfo's JSON tags so clients can ingest it directly via
// ingestPeekMapNodeInfo. The boot has no TAP interface, so tap_ip/mac are empty.
type bootNodeInfo struct {
	PeerID   string `json:"peer_id"`
	NodeName string `json:"node_name,omitempty"`
	OS       string `json:"os,omitempty"`
	Arch     string `json:"arch,omitempty"`
	Version  string `json:"version,omitempty"`
	// HopDistance 0 marks it as directly attached to this (its own) boot.
	HopDistance int `json:"hop_distance,omitempty"`
	// Addrs are this boot's dialable multiaddrs. Clients in a REMOTE cluster
	// learn this boot only through the backbone, so without endpoints they can
	// see it but never attach to it — and attaching is what gives the two
	// clusters a shared Circuit Relay v2 anchor.
	Addrs []string `json:"addrs,omitempty"`
	// IsBoot tells receivers this announcement describes a boot/relay node, so
	// they can attach to it rather than treating it as a mesh member.
	IsBoot bool `json:"is_boot"`
}

// peekMapHub is a stateless pub/sub router: it rebroadcasts every frame from
// one client to all other connected clients. It holds no node data.
//
// Boot-mesh (multi-cluster interconnect): peer boots listed in -mesh are marked
// via markMesh and are treated as PEERS of this hub rather than leaf clients.
// They still appear in `listener` (each side subscribes to the other's peek-map,
// so the remote boot's subscription lands in our normal handler), but the
// forwarding rules differ, and that difference is what keeps the backbone
// loop-free:
//
//	frame from a LOCAL client -> broadcast to everyone except its sender,
//	                             INCLUDING peer boots (that is the uplink)
//	frame from a PEER BOOT    -> broadcast to local clients ONLY
//	                             (broadcastToLocalOnly)
//
// Without the second rule a 3-boot full mesh would circulate frames forever:
// A->B, B->C (excluding only A), C->A (excluding only B), A->B ... Excluding
// *every* mesh peer on re-entry caps each frame at exactly one backbone hop.
// The trade-off is that the backbone must be a FULL mesh (every boot lists all
// the others) for complete coverage; a chain A-B-C would not propagate A's
// clients to C. This is documented on the -mesh flag.
type peekMapHub struct {
	mu       sync.RWMutex
	listener map[peer.ID]network.Stream // peer -> its long-lived listener stream
	mesh     map[peer.ID]struct{}       // peer boots (backbone), not leaf clients
	// netResolver maps a connected peer to its network ID (derived from the PSK
	// it authenticated with). It is nil in open mode, in which case discovery is
	// NOT isolated (every peer sees every other peer, the pre-multi-PSK
	// behaviour). When set, a broadcast frame tagged with a NetID is delivered
	// ONLY to listeners whose resolver returns the same NetID — that is what
	// keeps the different PSK networks invisible to one another in the WebUI /
	// peer list. Backbone (mesh) peers are exempt from this filter because the
	// remote boot re-applies it on its own side.
	netResolver func(peer.ID) string
}

func newPeekMapHub() *peekMapHub {
	return &peekMapHub{
		listener: make(map[peer.ID]network.Stream),
		mesh:     make(map[peer.ID]struct{}),
	}
}

// markMesh records a peer as a backbone boot. Called at startup for every
// -mesh entry, BEFORE any stream can arrive, so the very first frame from a
// peer boot is already classified correctly.
func (h *peekMapHub) markMesh(p peer.ID) {
	h.mu.Lock()
	h.mesh[p] = struct{}{}
	h.mu.Unlock()
}

func (h *peekMapHub) isMesh(p peer.ID) bool {
	h.mu.RLock()
	_, ok := h.mesh[p]
	h.mu.RUnlock()
	return ok
}

func (h *peekMapHub) register(p peer.ID, s network.Stream) {
	h.mu.Lock()
	h.listener[p] = s
	count := len(h.listener)
	h.mu.Unlock()
	log.Debug("[peek-map] listener registered for %s (total: %d)", p.ShortString(), count)
}

func (h *peekMapHub) unregister(p peer.ID) {
	h.mu.Lock()
	delete(h.listener, p)
	count := len(h.listener)
	h.mu.Unlock()
	log.Debug("[peek-map] listener unregistered for %s (total: %d)", p.ShortString(), count)
}

// unregisterStream removes the listener for p ONLY if it is still the given
// stream s. This prevents a stale duplicate listener (e.g. a previous
// connection's peek-map stream that is still alive while the client reconnects
// on a new connection) from evicting the LIVE listener when it finally errors
// out: register() overwrites the map entry with the newest stream, so deleting
// by peer-ID alone would delete the live one and silently stop the peer's
// discovery broadcasts. The genuine full-disconnect path (DisconnectedF) keeps
// using unregister(), which deletes regardless of which stream is current.
func (h *peekMapHub) unregisterStream(p peer.ID, s network.Stream) {
	h.mu.Lock()
	if h.listener[p] == s {
		delete(h.listener, p)
	}
	count := len(h.listener)
	h.mu.Unlock()
	log.Debug("[peek-map] listener unregistered for %s (total: %d)", p.ShortString(), count)
}

// broadcast forwards a raw frame to every connected client except 'exclude'.
// Peer boots are included, so a locally-published frame reaches the backbone.
// netID, when non-empty (PSK mode), restricts delivery to listeners in the same
// network; backbone peers are always included because the remote boot re-filters.
func (h *peekMapHub) broadcast(frame []byte, exclude peer.ID, netID string) {
	h.fanout(frame, exclude, false, netID)
}

// broadcastToLocalOnly forwards a frame that ARRIVED FROM the backbone. Every
// mesh peer is skipped (not just the sender), which bounds a frame to a single
// backbone hop and makes a full-mesh of boots loop-free. See peekMapHub docs.
// netID restricts delivery to local listeners of the same network.
func (h *peekMapHub) broadcastToLocalOnly(frame []byte, netID string) {
	h.fanout(frame, "", true, netID)
}

func (h *peekMapHub) fanout(frame []byte, exclude peer.ID, skipMesh bool, netID string) {
	// Snapshot the target streams under RLock, then release before doing any
	// network I/O. Writing under the lock let a single hung peer block every
	// subsequent broadcast for up to the 10s write-deadline, and starved
	// concurrent register/unregister calls. The snapshot can go stale (a peer
	// may disconnect between snapshot and write), but a failed write is
	// handled by the unregister sweep below, so the eventual consistency is
	// fine.
	type target struct {
		peer   peer.ID
		stream network.Stream
	}
	h.mu.RLock()
	targets := make([]target, 0, len(h.listener))
	for p, s := range h.listener {
		if p == exclude {
			continue
		}
		if skipMesh {
			if _, isMesh := h.mesh[p]; isMesh {
				continue
			}
		}
		// Network isolation (PSK mode only): a frame tagged with a NetID is
		// delivered only to listeners of the same network. Backbone peers are
		// intentionally exempt — they receive everything and the remote boot
		// re-applies the same filter for its own local clients.
		if netID != "" {
			if _, isMesh := h.mesh[p]; !isMesh {
				if h.netResolver == nil || h.netResolver(p) != netID {
					continue
				}
			}
		}
		targets = append(targets, target{peer: p, stream: s})
	}
	h.mu.RUnlock()

	var failed []peer.ID
	for _, t := range targets {
		_ = t.stream.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if _, err := t.stream.Write(frame); err != nil {
			log.Debug("[peek-map] broadcast write to %s failed: %v", t.peer.ShortString(), err)
			failed = append(failed, t.peer)
		}
	}
	// Evict dead listeners outside the lock so a dead peer can't head-of-line
	// block every subsequent broadcast (each failed write would otherwise cost
	// up to the 10s write-deadline on every frame).
	for _, p := range failed {
		h.unregister(p)
	}
}

// publishBootInfo sends a synthetic UPDATE frame describing this boot node to
// every connected client. Unlike the stateless router behaviour (which only
// rebroadcasts client frames), this actively announces the boot's own identity
// so clients can display it in the discovery/security panels instead of as an
// "Unnamed Node". hop_distance is 0 (the boot is the source). It is safe to call
// repeatedly (e.g. on every new client connect) and harmless when no clients are
// connected yet.
func (h *peekMapHub) publishBootInfo(self host.Host, nodeName, version string) {
	info := bootNodeInfo{
		PeerID:      self.ID().String(),
		NodeName:    nodeName,
		OS:          runtime.GOOS,
		Arch:        runtime.GOARCH,
		Version:     version,
		HopDistance: 0,
		Addrs:       node.MultiaddrsToStrings(self.Addrs()),
		IsBoot:      true,
	}
	payload, err := json.Marshal(info)
	if err != nil {
		log.Warn("[peek-map] marshal boot info failed: %v", err)
		return
	}
	msg := PeekMapMessage{
		Type:    PeekMapUpdate,
		From:    self.ID().String(),
		Payload: payload,
	}
	frame, err := json.Marshal(msg)
	if err != nil {
		log.Warn("[peek-map] marshal boot info frame failed: %v", err)
		return
	}
	// broadcast with exclude="" sends to ALL clients including none skipped.
	// netID="" => no network filter (the boot's own identity is visible to every
	// connected client regardless of which PSK network it belongs to).
	h.broadcast(frame, "", "")
	log.Debug("[peek-map] published boot node info (name=%q, id=%s)", nodeName, self.ID().String())
}

// broadcastPeerAddrFrame tells every other local client what this boot just
// observed about pID's direct reachability: addrs are the endpoints that
// should now be dialed, removed are the stale ones that must be dropped
// immediately instead of waiting out the 1h peerstore TTL.
//
// It reuses the peek-map channel rather than adding a protocol. A frame about
// peer X that this boot originates is safe for a receiver to apply: both
// registerPeekMapAddrs and removePeekMapAddrs only accept addresses whose
// /p2p/<id> suffix names the peer being described, and the frame arrives on an
// already-PSK-authenticated stream from the boot, so the trust gate in
// ingestPeekMapNodeInfo passes on the viaPeer basis alone.
func (h *peekMapHub) broadcastPeerAddrFrame(from, pID peer.ID, addrs, removed []string, netID, nodeName string) {
	if len(addrs) == 0 && len(removed) == 0 {
		return
	}
	info := node.PeekMapNodeInfo{
		PeerID:      pID.String(),
		NodeName:    nodeName,
		Addrs:       addrs,
		AddrsRemove: removed,
		// IsBoot stays false: the described peer is a mesh member.
		// HopDistance 0 means "directly attached to the boot that announced
		// me", which is true here; the receiver clamps it to 1 for edge
		// weighting anyway. 0 also keeps the peer nested under the right boot
		// in recordPeekMapOrigin, where a fabricated 1 would look like a
		// backbone hop.
		HopDistance: 0,
	}
	payload, err := json.Marshal(info)
	if err != nil {
		log.Warn("[peek-map] marshal peer addr frame failed: %v", err)
		return
	}
	msg := PeekMapMessage{
		Type:    PeekMapUpdate,
		From:    from.String(),
		Payload: payload,
	}
	frame, err := json.Marshal(msg)
	if err != nil {
		log.Warn("[peek-map] marshal peer addr frame failed: %v", err)
		return
	}
	// skipMesh=true: a NAT mapping is only meaningful to peers attached to
	// THIS boot. Relaying it across the backbone would push one cluster's
	// mappings into another's.
	// netID scopes delivery to the described peer's own PSK network. This is
	// deliberately NOT "" like publishBootInfo uses: the boot's own identity is
	// meant to be visible to every network, but a peer's address is not.
	h.fanout(frame, pID, true, netID)
	log.Debug("[peek-map] announced peer %s addrs=%d removed=%d net=%q", pID.ShortString(), len(addrs), len(removed), netID)
}

// directPhysicalIP returns the peer's real public IP as observed on a direct
// connection, or "" when the peer only has circuit-relayed connections.
//
// This distinction matters: on a circuit-relay inbound connection the visible
// source IP is THIS boot's own relay IP, not the peer's. Reporting that as the
// peer's address puts the boot's geo-location on every peer attached through
// it, which is how the world map and the physical_ip column used to be
// polluted. "" is the honest answer — the peer's public address is unknown to
// us.
func directPhysicalIP(conns []network.Conn, skip network.Conn) string {
	for _, c := range conns {
		if skip != nil && sameConn(c, skip) {
			continue
		}
		ma := c.RemoteMultiaddr()
		if ma == nil || maddrutil.IsCircuitRelay(ma) {
			continue
		}
		if ip := node.ExtractIP(ma); ip != nil {
			return ip.String()
		}
	}
	return ""
}

// observedPeerAddrs renders every DIRECT source address a peer currently has a
// connection on in the dialable /p2p/<id>-suffixed form, plus the distinct
// transport labels those connections use.
//
// Circuit-relay connections are excluded for the same reason as
// directPhysicalIP. skip is the connection a DisconnectedF callback is firing
// for, which libp2p may still list in ConnsToPeer at the moment the callback
// runs.
func observedPeerAddrs(conns []network.Conn, pID peer.ID, skip network.Conn) (addrs, transports []string) {
	var direct []multiaddr.Multiaddr
	for _, c := range conns {
		if skip != nil && sameConn(c, skip) {
			continue
		}
		ma := c.RemoteMultiaddr()
		if ma == nil || maddrutil.IsCircuitRelay(ma) {
			continue
		}
		direct = append(direct, ma)
		if t := node.TransportOfConn(c); t != "" {
			transports = appendUniqueString(transports, t)
		}
	}
	if len(direct) == 0 {
		return nil, nil
	}
	return dedupStrings(node.AddrsWithPeerID(direct, pID)), transports
}

// sameConn reports whether a and b are the same connection, without ever
// comparing the two interface values directly. `c == skip` panics when the
// dynamic type is uncomparable, and network.Conn is a plain interface — the
// comparison is only safe today because every real libp2p conn is a pointer.
// Conn.ID is unique per host per run, so it is the correct identity here.
func sameConn(a, b network.Conn) bool {
	if a == nil {
		return b == nil
	}
	if b == nil {
		return false
	}
	return a.ID() == b.ID()
}

// appendUniqueString appends v to out unless it is already present or empty.
// An empty entry would be a signalling failure (a broken transport detector),
// so it is dropped rather than propagated into every snapshot.
func appendUniqueString(out []string, v string) []string {
	if v == "" {
		return out
	}
	for _, x := range out {
		if x == v {
			return out
		}
	}
	return append(out, v)
}

// dedupStrings drops duplicates from a whole slice, keeping first-seen order.
// A peer can hold two connections to the same address; recording it twice would
// rebroadcast the same endpoint twice and pad every WebUI row.
func dedupStrings(in []string) []string {
	if len(in) < 2 {
		return in
	}
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, v := range in {
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

// peerAddrReplayTTL is how long a replayed address is trusted in this boot's
// own peerstore. It is a bridge, not a record: the goal is to let a pending
// circuit CONNECT be answered before the peer reconnects and re-announces.
// Deliberately not PermanentAddrTTL — a NAT mapping that survived a restart is
// usually already dead, and pinning it would hide the peer's real address for
// as long as it stays offline.
const peerAddrReplayTTL = 10 * time.Minute

// peerAddrReplayBudget caps the wall-clock length of a whole replay so a large
// cache cannot hold up startup for minutes.
const peerAddrReplayBudget = 2 * time.Minute

// replayPeerAddrs re-broadcasts cached peer endpoints after a restart and
// re-seeds this boot's own peerstore.
//
// The broadcast is for the other clients: a peer whose STUN is fully blocked
// can never advertise its own public address, so without replay it stays stuck
// on the relay until the mesh happens to relearn it by accident.
//
// The peerstore re-seed is for this boot itself: circuit Relay v2 refuses to
// dial a destination it holds no address for, and after a restart the peerstore
// is empty until the peer reconnects.
func replayPeerAddrs(ctx context.Context, h host.Host, hub *peekMapHub, entries []*peerAddrEntry) (broadcast, reseeded int) {
	if h == nil || hub == nil || len(entries) == 0 {
		return 0, 0
	}
	// Fanout writes inline with a 10s deadline per listener and a stream is not
	// safe for concurrent writes, so the loop is deliberately sequential and the
	// stagger is what spreads the load instead of goroutines.
	stagger := peerAddrReplayBudget / time.Duration(len(entries))
	for _, e := range entries {
		select {
		case <-ctx.Done():
			return broadcast, reseeded
		case <-time.After(time.Duration(mathrand.Int64N(int64(stagger) + 1))):
		}
		pID, err := peer.Decode(e.PeerID)
		if err != nil || pID == "" {
			continue
		}
		if len(e.Addrs) > 0 {
			reseeded += reseedPeerAddrs(h, pID, e.Addrs)
		}
		hub.broadcastPeerAddrFrame(h.ID(), pID, e.Addrs, nil, e.NetworkID, e.NodeName)
		broadcast++
	}
	return broadcast, reseeded
}

// reseedPeerAddrs loads addrs into this boot's own peerstore under
// peerAddrReplayTTL and returns how many were accepted.
func reseedPeerAddrs(h host.Host, pID peer.ID, addrs []string) int {
	var mas []multiaddr.Multiaddr
	for _, s := range addrs {
		ma, err := multiaddr.NewMultiaddr(s)
		if err != nil {
			continue
		}
		mas = append(mas, ma)
	}
	if len(mas) == 0 {
		return 0
	}
	h.Peerstore().AddAddrs(pID, mas, peerAddrReplayTTL)
	return len(mas)
}

// incrementPeekMapHop adds 1 to the payload's "hop_distance" field so that
// cascaded boot nodes accumulate the number of boot relays between the
// publisher and each downstream receiver. Every other payload field is
// preserved verbatim (we re-marshal only the decoded map, never touch the
// fields we don't understand). Frames without a hop_distance field get one
// initialized to 1 (they entered through this boot). Unparsable frames are
// returned unchanged.
func incrementPeekMapHop(frame []byte) []byte {
	var msg PeekMapMessage
	if err := json.Unmarshal(frame, &msg); err != nil || len(msg.Payload) == 0 {
		return frame
	}
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(msg.Payload, &payload); err != nil {
		return frame
	}
	hops := 1
	if raw, ok := payload["hop_distance"]; ok {
		var v int
		if err := json.Unmarshal(raw, &v); err == nil {
			hops = v + 1
		}
	}
	b, err := json.Marshal(hops)
	if err != nil {
		return frame
	}
	payload["hop_distance"] = b
	newPayload, err := json.Marshal(payload)
	if err != nil {
		return frame
	}
	msg.Payload = newPayload
	out, err := json.Marshal(msg)
	if err != nil {
		return frame
	}
	return out
}

// pskACLFilter implements relay.ACLFilter to restrict relay usage to authenticated
// peers, and — in multi-network mode — to peers in the SAME network. The network a
// peer belongs to is the hash of the PSK it authenticated with (networkIDFromPSK),
// never the plaintext PSK, so the map stores only the opaque net ID.
type pskACLFilter struct {
	mu         sync.RWMutex
	netOf      map[peer.ID]string // peer -> network ID (sha256(psk) prefix); "" means not authenticated
	pskEnabled bool
	host       host.Host
}

func newPSKACLFilter(pskEnabled bool) *pskACLFilter {
	return &pskACLFilter{
		netOf:      make(map[peer.ID]string),
		pskEnabled: pskEnabled,
	}
}

func (f *pskACLFilter) SetHost(h host.Host) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.host = h
}

// AddAuthenticated records that p authenticated successfully under the given
// network ID. Called once per successful PSK handshake.
func (f *pskACLFilter) AddAuthenticated(p peer.ID, netID string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.netOf[p] = netID
	log.Info("[acl] peer %s authenticated for relay (net=%s)", p.String(), netID)
}

func (f *pskACLFilter) RemoveAuthenticated(p peer.ID) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.netOf, p)
}

// IsAuthenticated reports whether p has completed a PSK handshake.
func (f *pskACLFilter) IsAuthenticated(p peer.ID) bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	_, ok := f.netOf[p]
	return ok
}

// waitForAuth waits briefly if peer p is physically connected but still in the
// process of completing its PSK authentication stream (/p2ptap/auth/1.0.0).
// This eliminates false-positive relay_denied races where a peer attempts to
// reserve or connect milliseconds before the remote peer's auth stream finishes.
//
// With the auth-stall fix (handleAuthStream replies 0x01 before reading the
// version record), authentication completes in milliseconds, so these waits
// are short. The 200ms timeout is more than enough for the auth stream to
// complete; longer timeouts only add latency to the relay hot path.
func (f *pskACLFilter) waitForAuth(p peer.ID, timeout time.Duration) {
	f.mu.RLock()
	h := f.host
	f.mu.RUnlock()

	if h != nil && h.Network().Connectedness(p) == network.Connected {
		deadline := time.Now().Add(timeout)
		for time.Now().Before(deadline) {
			time.Sleep(20 * time.Millisecond)
			if f.IsAuthenticated(p) {
				return
			}
			if h.Network().Connectedness(p) != network.Connected {
				return
			}
		}
	}
}

// RequireAuth reports whether p is allowed to use a non-relay stream protocol
// (peek-map, meta, echo, seqsync). In open mode every peer is allowed. In PSK
// mode the peer must have completed PSK authentication; because the auth stream
// and these streams are opened concurrently, a brief wait absorbs the race.
// Without this gate an unauthenticated peer that advertises the protocol gets
// full access to topology broadcasts, the boot's metadata, echo ping-pong, and
// the SeqSync handshake — all of which are control-plane primitives that should
// be restricted to known members.
func (f *pskACLFilter) RequireAuth(p peer.ID) bool {
	if !f.pskEnabled {
		return true
	}
	if f.IsAuthenticated(p) {
		return true
	}
	f.waitForAuth(p, 3*time.Second)
	return f.IsAuthenticated(p)
}

// NetworkOf returns the network ID p authenticated under, or "" if not
// authenticated. It is wired into peekMapHub.netResolver so discovery routing
// can enforce the same isolation as relay access.
func (f *pskACLFilter) NetworkOf(p peer.ID) string {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.netOf[p]
}

// AllowReserve decides whether a peer can make a relay reservation.
func (f *pskACLFilter) AllowReserve(p peer.ID, a multiaddr.Multiaddr) bool {
	if !f.pskEnabled {
		return true
	}
	if !f.IsAuthenticated(p) {
		f.waitForAuth(p, 200*time.Millisecond)
	}
	authed := f.IsAuthenticated(p)
	log.Debug("[acl] relay reserve %s for peer %s (addr: %s)", boolToAllow(authed), p.String(), a.String())
	if authed {
		bootAlerts.Add("info", "relay_reserve_ok", p.ShortString(),
			fmt.Sprintf("Relay reservation granted: %s", p.ShortString()))
	} else {
		bootAlerts.Add("warn", "relay_reserve_denied", p.ShortString(),
			fmt.Sprintf("Relay reservation denied: %s not authenticated", p.ShortString()))
	}
	return authed
}

// AllowConnect decides whether a peer can connect through the relay to a
// destination. Both ends must be authenticated AND in the same network; a node in
// PSK network A must never be able to relay through to a node in PSK network B.
func (f *pskACLFilter) AllowConnect(src peer.ID, srcAddr multiaddr.Multiaddr, dest peer.ID) bool {
	if !f.pskEnabled {
		return true
	}

	now := time.Now()

	// 1. Check source authentication (wait briefly if auth stream is in-flight)
	if !f.IsAuthenticated(src) {
		f.waitForAuth(src, 2*time.Second)
	}
	if !f.IsAuthenticated(src) {
		log.Debug("[acl] relay connect DENIED: src=%s not authenticated (dest=%s)", src.String(), dest.String())
		key := "src:" + src.String()
		if last, ok := relayDeniedDedup.Load(key); !ok || now.Sub(last.(time.Time)) > 30*time.Second {
			relayDeniedDedup.Store(key, now)
			bootAlerts.Add("warn", "relay_denied", src.ShortString(), fmt.Sprintf("Relay connect denied: src %s not authenticated", src.ShortString()))
		}
		return false
	}

	// 2. Check destination authentication (wait briefly if destination just connected and is handshaking)
	if !f.IsAuthenticated(dest) {
		f.waitForAuth(dest, 500*time.Millisecond)
	}
	if !f.IsAuthenticated(dest) {
		log.Debug("[acl] relay connect DENIED: dest=%s not authenticated (src=%s)", dest.String(), src.String())
		// Only emit dashboard warning if dest is actively connected (PSK mismatch / pending).
		// Normal dial attempts to offline/disconnected peers are dropped silently to avoid alert spam.
		f.mu.RLock()
		h := f.host
		f.mu.RUnlock()
		if h != nil && h.Network().Connectedness(dest) == network.Connected {
			key := "dest:" + dest.String()
			if last, ok := relayDeniedDedup.Load(key); !ok || now.Sub(last.(time.Time)) > 30*time.Second {
				relayDeniedDedup.Store(key, now)
				bootAlerts.Add("warn", "relay_denied", dest.ShortString(), fmt.Sprintf("Relay connect denied: dest %s is connected but not authenticated (PSK mismatch or pending)", dest.ShortString()))
			}
		}
		return false
	}

	srcNet := f.NetworkOf(src)
	dstNet := f.NetworkOf(dest)
	if srcNet != dstNet {
		log.Debug("[acl] relay connect DENIED: src=%s (net=%s) and dest=%s (net=%s) are different networks",
			src.String(), srcNet, dest.String(), dstNet)
		key := "mismatch:" + src.String() + "->" + dest.String()
		if last, ok := relayDeniedDedup.Load(key); !ok || now.Sub(last.(time.Time)) > 30*time.Second {
			relayDeniedDedup.Store(key, now)
			bootAlerts.Add("warn", "relay_denied", src.ShortString()+"->"+dest.ShortString(), fmt.Sprintf("Relay connect denied: network isolation mismatch (%s != %s)", srcNet, dstNet))
		}
		return false
	}
	log.Debug("[acl] relay connect ALLOWED: src=%s -> dest=%s (net=%s)", src.String(), dest.String(), srcNet)
	// Record the relay session for the WebUI session tracker.
	if gSessions != nil {
		gSessions.Add(src, dest, srcNet)
	}
	// Emit a deduplicated relay_allowed alert (same pair suppressed for 10 s).
	key := src.String() + "->" + dest.String()
	if last, ok := relayAllowedDedup.Load(key); !ok || now.Sub(last.(time.Time)) > 10*time.Second {
		relayAllowedDedup.Store(key, now)
		bootAlerts.Add("info", "relay_allowed", src.ShortString(),
			fmt.Sprintf("Relay circuit established: %s -> %s (net=%s)", src.ShortString(), dest.ShortString(), srcNet))
	}
	return true
}

func boolToAllow(b bool) string {
	if b {
		return "ALLOWED"
	}
	return "DENIED"
}

// relayRouter bridges relay-over-backbone (boot-relay) frames between locally
// attached clients and peer boots over the backbone. It is intentionally a
// stateless bridge: it reads the src/dst peer IDs and the in-band network ID
// from each frame and never inspects or decrypts the inner TAP payload (that is
// end-to-end sealed for the final destination by the origin node).
//
// Topology:
//   - clientStreams maps a locally-connected client peer to the boot-relay
//     uplink stream it opened (BootRelayProtocolID). A frame whose finalDst is a
//     local client is delivered straight to that stream.
//   - meshStreams maps a peer boot to the boot-relay backbone stream (one per
//     -mesh entry, BootRelayBackboneProtocolID). A frame whose finalDst is NOT a
//     local client is flooded to every peer boot (single backbone hop; a full
//     mesh of boots is required for complete coverage, exactly like the peek-map
//     backbone). Frames arriving over a backbone stream are local-delivery-only,
//     which bounds them to one backbone hop and prevents loops.
type relayRouter struct {
	mu            sync.RWMutex
	clientStreams map[peer.ID]network.Stream
	meshStreams   map[peer.ID]network.Stream
	acl           *pskACLFilter
	pskEnabled    bool

	// frameLimiter bounds each client's (and each mesh boot's) boot-relay frame
	// rate. It is deliberately generous, so a healthy link is never touched.
	frameLimiter *PeerRateLimiter
}

func newRelayRouter(acl *pskACLFilter, pskEnabled bool) *relayRouter {
	return &relayRouter{
		clientStreams: make(map[peer.ID]network.Stream),
		meshStreams:   make(map[peer.ID]network.Stream),
		acl:           acl,
		pskEnabled:    pskEnabled,
		frameLimiter:  newPeerRateLimiter(bootRelayFrameRate, bootRelayFrameBurst),
	}
}

// bootRelayFrameRate / bootRelayFrameBurst bound how many boot-relay frames a
// single client (or mesh boot) may push per second. A gigabit L2 link carries
// at most ~84k 1500-byte frames per second, so 50k/s never caps a real link;
// it only bites on pathological tiny-frame floods, which would otherwise burn
// the boot's CPU and amplify into backbone bandwidth at every mesh peer.
const (
	bootRelayFrameRate  = 50000.0
	bootRelayFrameBurst = 100000.0
)

// bootRelayFrameMaxWait is how long a frame may wait for a token before it is
// dropped. Waiting applies back-pressure instead of silently losing packets,
// which an L2 tunnel has no way to recover; the bound keeps a pathological
// sender from pinning the read goroutine indefinitely.
const bootRelayFrameMaxWait = 100 * time.Millisecond

func (r *relayRouter) registerClient(p peer.ID, s network.Stream) {
	r.mu.Lock()
	r.clientStreams[p] = s
	r.mu.Unlock()
}

func (r *relayRouter) unregisterClient(p peer.ID) {
	r.mu.Lock()
	delete(r.clientStreams, p)
	r.mu.Unlock()
}

// unregisterClientStream removes the client uplink for p ONLY if it is still the
// given stream, so a stale uplink (e.g. a reconnecting client's previous stream)
// cannot evict the live one when it finally errors out.
func (r *relayRouter) unregisterClientStream(p peer.ID, s network.Stream) {
	r.mu.Lock()
	if r.clientStreams[p] == s {
		delete(r.clientStreams, p)
	}
	r.mu.Unlock()
}

func (r *relayRouter) registerMesh(p peer.ID, s network.Stream) {
	r.mu.Lock()
	r.meshStreams[p] = s
	r.mu.Unlock()
}

func (r *relayRouter) unregisterMesh(p peer.ID) {
	r.mu.Lock()
	delete(r.meshStreams, p)
	r.mu.Unlock()
}

// route bridges one boot-relay frame. fromMesh distinguishes a frame that
// arrived over the backbone (local-delivery-only) from one that arrived from a
// local client uplink (may be delivered locally OR flooded to the backbone).
func (r *relayRouter) route(data []byte, fromMesh bool, fromPeer peer.ID) {
	netID, _, _, finalDst, srcPeer, ttl, _, err := routing.UnpackBootRelayFrame(data)
	if err != nil {
		log.Debug("[boot-relay] unpack error: %v", err)
		return
	}
	// Anti-spoofing: a local client uplink must not forge a srcPeer other than its own peer ID.
	if !fromMesh && srcPeer != fromPeer {
		log.Warn("[boot-relay] drop spoofed frame: stream peer %s claims src %s", fromPeer.ShortString(), srcPeer.ShortString())
		unauthTracker.Record(unauthTypeSpoofed, fromPeer.ShortString(),
			fmt.Sprintf("Spoofed srcPeer: stream peer claims %s", srcPeer.ShortString()))
		return
	}
	// Source isolation: a LOCAL client uplink must come from an authenticated
	// peer. For a backbone frame the origin is a client of another boot; we
	// cannot look it up in our ACL, so we trust the in-band netID and enforce
	// isolation at the destination instead (a frame whose netID does not match
	// the destination's network is dropped on local delivery).
	if !fromMesh && r.pskEnabled && r.acl.NetworkOf(srcPeer) == "" {
		log.Debug("[boot-relay] drop unauthenticated source %s", srcPeer.ShortString())
		unauthTracker.Record(unauthTypeRelayFrame, srcPeer.ShortString(),
			"Data frame dropped: unauthenticated source")
		return
	}
	// Anti-spoofing (source-network): the in-band netID is set by the sender and
	// is fully forgeable, so it MUST equal the authenticated sender's real
	// network. Without this, an authenticated member of net A could stamp
	// netID=B on a frame aimed at a net-B peer: it would pass the destination
	// check (netID==NetworkOf(dst)==B) and be injected into net B as a B member.
	// The dst-side check alone cannot catch this because it compares against the
	// (forged) netID rather than the true sender network.
	if !fromMesh && r.pskEnabled && netID != r.acl.NetworkOf(srcPeer) {
		log.Warn("[boot-relay] drop spoofed netID: authenticated source %s (net=%s) claims netID=%s",
			srcPeer.ShortString(), r.acl.NetworkOf(srcPeer), netID)
		unauthTracker.Record(unauthTypeSpoofed, srcPeer.ShortString(),
			fmt.Sprintf("Spoofed netID: %s claims %s", srcPeer.ShortString(), netID))
		return
	}
	// Local delivery?
	r.mu.RLock()
	ls := r.clientStreams[finalDst]
	r.mu.RUnlock()
	if ls != nil {
		if r.pskEnabled {
			if r.acl.NetworkOf(finalDst) != netID {
				// Network mismatch: the destination is in a different PSK network
				// than the frame's origin. Drop rather than leak across networks.
				log.Debug("[boot-relay] drop cross-net frame src=%s dst=%s (net %s != %s)",
					srcPeer.ShortString(), finalDst.ShortString(), netID, r.acl.NetworkOf(finalDst))
				unauthTracker.Record(unauthTypeRelayFrame, srcPeer.ShortString(),
					fmt.Sprintf("Cross-net drop: dst %s (net %s != %s)", finalDst.ShortString(), r.acl.NetworkOf(finalDst), netID))
				return
			}
		}
		// Write length-prefixed (NOT raw): the destination node's downlink
		// reader uses ReadFrame (4-byte big-endian length prefix), so the frame
		// must be framed exactly like the node's uplink writes it. A raw write
		// here would make the destination misread the first 4 bytes as a bogus
		// length and corrupt the downlink.
		_ = ls.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if werr := writeFrame(ls, data); werr != nil {
			log.Debug("[boot-relay] write to local client %s failed: %v; dropping uplink", finalDst.ShortString(), werr)
			r.unregisterClientStream(finalDst, ls)
		}
		return
	}

	// Not a local client. A frame that already arrived over the backbone is
	// local-delivery-only and is never re-flooded: this is what caps every
	// backbone frame at exactly one hop.
	if fromMesh {
		return
	}
	// A self-addressed frame is a client's own uplink heartbeat (finalDst ==
	// srcPeer == the sender; the node's bootRelayWriteLoop). It is delivered
	// above while the uplink is registered, and it must NEVER be flooded — that
	// is the loop guard this check used to be. Dropping it BEFORE local
	// delivery (as it was) meant the heartbeat never came back, so the
	// destination's downlink reader never saw a byte and its 60s read deadline
	// (set as 4× the 15s heartbeat) tore the uplink down every minute.
	if finalDst == srcPeer {
		return
	}
	// Flood to the backbone (single hop only).
	if ttl <= 1 || len(r.meshStreams) == 0 {
		return
	}
	r.mu.RLock()
	peers := make([]peer.ID, 0, len(r.meshStreams))
	for bp := range r.meshStreams {
		peers = append(peers, bp)
	}
	r.mu.RUnlock()
	for _, bp := range peers {
		r.mu.RLock()
		ms := r.meshStreams[bp]
		r.mu.RUnlock()
		if ms == nil {
			continue
		}
		// Write length-prefixed: the receiving boot's backbone handler reads
		// with readFrame (4-byte length prefix), so the flood must be framed
		// the same way (a raw write would desync the remote reader).
		_ = ms.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if werr := writeFrame(ms, data); werr != nil {
			log.Debug("[boot-relay] write to backbone boot %s failed: %v; dropping uplink", bp.ShortString(), werr)
			r.unregisterMesh(bp)
		}
	}
}

// makeBootRelayHandler is the server side of a local client's boot-relay uplink.
// It registers the client, then bridges every frame the client sends up.
func makeBootRelayHandler(rr *relayRouter) func(network.Stream) {
	return func(s network.Stream) {
		remotePeer := s.Conn().RemotePeer()
		if rr.pskEnabled {
			if !rr.acl.IsAuthenticated(remotePeer) {
				rr.acl.waitForAuth(remotePeer, 2*time.Second)
			}
			if !rr.acl.IsAuthenticated(remotePeer) {
				log.Debug("[boot-relay] rejecting unauthenticated client %s", remotePeer.ShortString())
				bootAlerts.Add("warn", "boot_relay_denied", remotePeer.ShortString(),
					fmt.Sprintf("Boot-relay access denied: %s not authenticated", remotePeer.ShortString()))
				unauthTracker.Record(unauthTypeBootRelay, remotePeer.ShortString(),
					"Boot-relay access denied: unauthenticated client")
				_ = s.Close()
				return
			}
		}
		rr.registerClient(remotePeer, s)
		bootAlerts.Add("info", "boot_relay_join", remotePeer.ShortString(),
			fmt.Sprintf("Boot-relay client connected: %s", remotePeer.ShortString()))
		defer func() {
			rr.unregisterClientStream(remotePeer, s)
			bootAlerts.Add("info", "boot_relay_leave", remotePeer.ShortString(),
				fmt.Sprintf("Boot-relay client disconnected: %s", remotePeer.ShortString()))
			_ = s.Close()
		}()
		buf := make([]byte, maxBootRelayEnvelope)
		dropped := int64(0)
		for {
			_ = s.SetReadDeadline(time.Now().Add(5 * time.Minute))
			n, err := readFrame(s, buf)
			if err != nil || n == 0 {
				return
			}
			// Frame rate limit: waiting applies back-pressure rather than
			// silently dropping packets an L2 tunnel cannot recover.
			if !rr.frameLimiter.Acquire(remotePeer, bootRelayFrameMaxWait) {
				if drops := atomic.AddInt64(&dropped, 1); drops == 1 || drops%1024 == 0 {
					log.Warn("[boot-relay] client %s at %d/s — dropped %d frames",
						remotePeer.ShortString(), int(bootRelayFrameRate), drops)
				}
				continue
			}
			rr.route(buf[:n], false, remotePeer)
		}
	}
}

// makeBootRelayBackboneHandler is the server side of a peer boot's backbone
// uplink. Frames arriving here are local-delivery-only. Only peers in the
// configured -mesh list are accepted; any other peer would be treated as a
// backbone boot (fromMesh=true) and could forge srcPeer/netID, bypassing
// anti-spoofing and network isolation checks.
func makeBootRelayBackboneHandler(rr *relayRouter, hub *peekMapHub) func(network.Stream) {
	return func(s network.Stream) {
		remotePeer := s.Conn().RemotePeer()
	if !hub.isMesh(remotePeer) {
				log.Warn("[boot-relay] rejecting backbone stream from non-mesh peer %s", remotePeer.ShortString())
				bootAlerts.Add("warn", "boot_relay_backbone_denied", remotePeer.ShortString(),
					fmt.Sprintf("Boot-relay backbone access denied: %s is not a configured mesh peer", remotePeer.ShortString()))
				unauthTracker.Record(unauthTypeBootRelay, remotePeer.ShortString(),
					"Boot-relay backbone denied: not a configured mesh peer")
				_ = s.Close()
				return
			}
		rr.registerMesh(remotePeer, s)
		defer func() {
			rr.unregisterMesh(remotePeer)
			_ = s.Close()
		}()
		buf := make([]byte, maxBootRelayEnvelope)
		dropped := int64(0)
		for {
			_ = s.SetReadDeadline(time.Now().Add(5 * time.Minute))
			n, err := readFrame(s, buf)
			if err != nil || n == 0 {
				return
			}
			// Frames arriving over the backbone are local-delivery-only, so a
			// misbehaving mesh boot can flood only us — but it is still CPU and
			// downstream bandwidth we did not ask for.
			if !rr.frameLimiter.Acquire(remotePeer, bootRelayFrameMaxWait) {
				if drops := atomic.AddInt64(&dropped, 1); drops == 1 || drops%1024 == 0 {
					log.Warn("[boot-relay|mesh] boot %s at %d/s — dropped %d frames",
						remotePeer.ShortString(), int(bootRelayFrameRate), drops)
				}
				continue
			}
			rr.route(buf[:n], true, remotePeer)
		}
	}
}

const RelayCtrlProtocolID protocol.ID = "/p2ptap/relay-ctrl/1.0.0"

// allowedRelayCtrlInnerProtos is the set of inner control protocols a relay-ctrl
// tunnel may carry. The boot dials the target with hdr.Proto, and hdr.Proto
// comes from attacker-controlled JSON — without this allowlist an authenticated
// client can open a raw tunnel to a mesh peer on ANY protocol that peer
// advertises, and the boot never checks the target-side PSK gate for it. The
// set mirrors the node's dispatchRelayCtrlInner allowlist exactly: the boot
// never terminates the inner protocol, so a proto the node would reject is
// equally useless on the boot.
var allowedRelayCtrlInnerProtos = map[protocol.ID]struct{}{
	node.SeqSyncProtocolID:     {},
	node.LSAProtocolID:         {},
	meta.MetaProtocolID:        {},
	node.EchoProtocolID:        {},
	node.TapProbeAckProtocolID: {},
}

// maxRelayTunnels caps concurrent relay-ctrl tunnels. Every tunnel pins two
// proxy goroutines plus one inbound and one outbound libp2p stream, and it is
// opened by a client inside the PSK — so an authenticated node can exhaust the
// boot's streams regardless of the auth limits above. The cap is well above any
// real control-plane fan-out.
const maxRelayTunnels = 256

var relayTunnelsInflight atomic.Int64

// RelayCtrlHeader is the wire header of a relay-ctrl tunnel. The tags are the
// mesh node's compact format (node.RelayCtrlHeader: o/t/p/h/s) — the boot and
// the nodes share one protocol ID, so they must speak one dialect.
//
// Before this was aligned the boot used origin/target/proto/hops. Neither side
// parsed the other's header (json drops unknown keys), so every relay-ctrl
// header carried Origin == "" and was dropped as malformed at line 985 below:
// relay-ctrl tunnels through the boot were dead in BOTH directions, not just in
// a PSK network. There is deliberately no dual-dialect reader — encoding/json
// binds a struct field to its FIRST json tag only, so "json:\"o\" json:\"origin\""
// does not read either spelling — and the only writer of the long tags was a
// pre-upgrade boot, which cannot be a relay-ctrl Target anyway (boots are not
// mesh members, and this handler dials hdr.Target directly rather than choosing
// a peer boot as the next hop), so no live peer boot sends the old dialect.
type RelayCtrlHeader struct {
	Origin peer.ID `json:"o"`
	Target peer.ID `json:"t"`
	Proto  string  `json:"p"`
	Hops   uint8   `json:"h"`
	Stamp  string  `json:"s,omitempty"`
}

// makeRelayCtrlHandler handles /p2ptap/relay-ctrl/1.0.0 control streams on the boot node.
// It allows clients to establish overlay control tunnels (SeqSync / Meta / LSA) through the boot node.
func makeRelayCtrlHandler(h host.Host, acl *pskACLFilter, hub *peekMapHub, entries []pskEntry) func(network.Stream) {
	return func(s network.Stream) {
		defer s.Close()
		remotePeer := s.Conn().RemotePeer()

		hdrBuf := make([]byte, 4096)
		n0, err := readFrame(s, hdrBuf)
		if err != nil || n0 == 0 {
			return
		}
		var hdr RelayCtrlHeader
		if err := json.Unmarshal(hdrBuf[:n0], &hdr); err != nil {
			return
		}
		if hdr.Origin == "" || hdr.Target == "" {
			return
		}

		// ---- Origin-claim gate + PSK-keyed endorsement (node.RelayCtrlAttest) ----
		// hdr.Origin is the peer the target must bind its per-peer state to (cipher
		// slot, dedup anchor, meta identity). Without a credential on that claim an
		// attacker who can open a relay-ctrl stream to a victim could set Origin to
		// any legitimate mesh peer and run its handshake "as" that peer. The boot
		// therefore stamps a claim it verified directly through the transport, and
		// refuses to forward a claim it cannot verify.
		//
		// WITHOUT THIS THE BOOT IS A DEAD RELAY IN A PSK NETWORK: it rebuilt the
		// header below with no Stamp, so the target saw Origin != transport peer
		// with an empty stamp, node.verifyRelayCtrlStamp rejected it, and every
		// seqsync/meta/echo tunnel through the boot was dropped at the last hop.
		// The stamp is minted with the ORIGIN's network PSK: the mesh node mints
		// with its single config PSK, and AllowConnect below already restricts the
		// tunnel to the origin's own network, so both ends derive the same key.
		netID := ""
		if acl != nil {
			netID = acl.NetworkOf(hdr.Origin)
		}
		psk := lookupStampPSK(entries, netID)

		switch {
		case hdr.Origin == remotePeer:
			// Direct claim, verified by libp2p: endorse it. Empty psk (open mode or
			// an unknown network) mints "" — correct, because in a PSK-less mesh
			// stamps are neither minted nor required.
			hdr.Stamp = node.StampRelayCtrlOrigin(psk, hdr.Origin, hdr.Target, protocol.ID(hdr.Proto))
		case node.VerifyRelayCtrlStamp(psk, hdr.Origin, hdr.Target, protocol.ID(hdr.Proto), hdr.Stamp):
			// Already endorsed by an upstream first relay: carry the stamp through.
			log.Debug("[relay-ctrl] endorsed tunnel %s -> %s relayed via %s (hops=%d)",
				hdr.Origin.ShortString(), hdr.Target.ShortString(), remotePeer.ShortString(), hdr.Hops)
		case hub != nil && hub.isMesh(remotePeer):
			// A backbone boot relayed a claim it did not itself verify, and no
			// valid endorsement came with it. Refusing here is what keeps the boot
			// from being an open relay for origin forgery against the targets it
			// dials directly; it also makes the boot consistent with the mesh
			// node's transit gate (pkg/node/relay_ctrl.go).
			log.Warn("[relay-ctrl] refused: peer %s claims origin %s with no valid endorsement",
				remotePeer.ShortString(), hdr.Origin.ShortString())
			return
		default:
			log.Warn("[relay-ctrl] spoofing attempt: direct client %s claims origin %s; dropping",
				remotePeer.ShortString(), hdr.Origin.ShortString())
			return
		}

		if acl != nil && acl.pskEnabled {
			// The gate only exists when PSKs are configured. In open mode there is
			// no handshake for IsAuthenticated to see, so it is false for every
			// peer and this handler would silently drop all tunnels — exactly how
			// the data-plane makeBootRelayHandler scopes the same check.
		if !acl.IsAuthenticated(remotePeer) {
			acl.waitForAuth(remotePeer, 2*time.Second)
		}
		if !acl.IsAuthenticated(remotePeer) {
			unauthTracker.Record(unauthTypeRelayCtrl, remotePeer.ShortString(),
				"Relay-ctrl tunnel dropped: unauthenticated peer")
			return
		}
			if !acl.AllowConnect(hdr.Origin, nil, hdr.Target) {
				return
			}
		}

		if hdr.Hops >= 8 {
			return
		}

		// hdr.Proto is attacker-controlled JSON. Without this gate an
		// authenticated client can dial an arbitrary protocol at a mesh peer
		// through the boot, since the boot never runs the target-side PSK gate
		// for whatever the dial lands on.
		if hdr.Proto != "" {
			if _, ok := allowedRelayCtrlInnerProtos[protocol.ID(hdr.Proto)]; !ok {
				log.Warn("[relay-ctrl] refusing tunnel: non-allowlisted inner proto %q (client %s)",
					hdr.Proto, remotePeer.ShortString())
				return
			}
		}

		if n := relayTunnelsInflight.Add(1); n > maxRelayTunnels {
			relayTunnelsInflight.Add(-1)
			log.Warn("[relay-ctrl] refusing tunnel: %d already open (limit %d)", n-1, maxRelayTunnels)
			return
		}
		defer relayTunnelsInflight.Add(-1)

		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()

		sub, err := h.NewStream(ctx, hdr.Target, RelayCtrlProtocolID)
		if err != nil {
			if hdr.Proto != "" {
				sub, err = h.NewStream(ctx, hdr.Target, protocol.ID(hdr.Proto))
			}
			if err != nil {
				return
			}
		} else {
			final := RelayCtrlHeader{
				Origin: hdr.Origin,
				Target: hdr.Target,
				Proto:  hdr.Proto,
				Hops:   hdr.Hops + 1,
				Stamp:  hdr.Stamp,
			}
			fb, _ := json.Marshal(final)
			if err := writeFrame(sub, fb); err != nil {
				sub.Close()
				return
			}
		}
		if gSessions != nil {
			netID := ""
			if acl != nil {
				netID = acl.NetworkOf(hdr.Origin)
			}
			gSessions.Add(hdr.Origin, hdr.Target, netID)
		}
		bootAlerts.Add("info", "relay_allowed", hdr.Origin.ShortString(),
			fmt.Sprintf("🔀 Relay-Ctrl 隧道已建立: %s → %s (%s)", hdr.Origin.ShortString(), hdr.Target.ShortString(), hdr.Proto))

		proxyStreams(s, sub)
	}
}

// relayCtrlProxyBufSize bounds each proxy read. The inner control protocols are
// length-prefixed and already bounded by readFrame, so the buffer only trades
// syscalls for memory.
const relayCtrlProxyBufSize = 64 << 10

// relayCtrlTunnelIdleTimeout tears a relay-ctrl tunnel down once it has carried
// no bytes in EITHER direction for this long. Without it a stalled inner
// handshake pins both proxy goroutines and both streams until an endpoint dies.
// 15 minutes comfortably covers the slowest legitimate inner exchange while
// still bounding how long a half-open tunnel can squat.
const relayCtrlTunnelIdleTimeout = 15 * time.Minute

// relayCtrlTunnelIdleCheck is the watchdog poll interval. It is deliberately a
// fraction of the timeout so a stalled tunnel dies soon after, not long after,
// the threshold.
const relayCtrlTunnelIdleCheck = 10 * time.Second

func proxyStreams(s1, s2 network.Stream) {
	var lastActivity atomic.Int64
	lastActivity.Store(time.Now().UnixNano())
	done := make(chan struct{})

	// Watchdog: closing both streams makes both Reads below fail, which is what
	// unwinds the tunnel. It only fires when BOTH directions are quiet, so a
	// legitimately one-directional inner stream is not killed by silence on the
	// return path.
	go func() {
		ticker := time.NewTicker(relayCtrlTunnelIdleCheck)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case now := <-ticker.C:
				quiet := now.Sub(time.Unix(0, lastActivity.Load()))
				if quiet > relayCtrlTunnelIdleTimeout {
					log.Warn("[relay-ctrl] tunnel quiet for %s — tearing down", quiet.Round(time.Second))
					_ = s1.Close()
					_ = s2.Close()
					return
				}
			}
		}
	}()

	// copyTunnel drains src into dst. Close() — not CloseWrite() — signals the
	// remote end (FIN/RESET) AND tears down the local read side, so the reverse
	// goroutine's Read unblocks. Without the full Close, a peer that ignores the
	// half-close FIN leaves it blocked on Read forever, pinning both streams and
	// this proxy.
	copyTunnel := func(dst, src network.Stream) {
		buf := make([]byte, relayCtrlProxyBufSize)
		for {
			n, err := src.Read(buf)
			if n > 0 {
				lastActivity.Store(time.Now().UnixNano())
				if _, werr := dst.Write(buf[:n]); werr != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
		_ = dst.Close()
		_ = src.Close()
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		copyTunnel(s2, s1)
	}()
	go func() {
		defer wg.Done()
		copyTunnel(s1, s2)
	}()
	wg.Wait()
	close(done)
}

// bootRelayMeshUplinkLoop keeps a boot-relay backbone uplink open to ONE peer
// boot (mirrors meshUplinkLoop). The remote boot symmetrically subscribes to us,
// so relay frames for each other's clients flow both ways over the single
// bidirectional stream.
func bootRelayMeshUplinkLoop(ctx context.Context, h host.Host, rr *relayRouter, info peer.AddrInfo) {
	backoff := 2 * time.Second
	const maxBackoff = 60 * time.Second
	for {
		if ctx.Err() != nil {
			return
		}
		err := runBootRelayMeshUplink(ctx, h, rr, info)
		if ctx.Err() != nil {
			return
		}
		log.Debug("[boot-relay|mesh] uplink to %s ended (%v), retrying in %v", info.ID.ShortString(), err, backoff)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff < maxBackoff {
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		}
	}
}

// meshDialJitter is the maximum random pre-dial pause applied before opening a
// boot-relay backbone uplink. Two peer boots configured to mesh with each other
// BOTH dial on startup; if those dials land at the same instant libp2p's TLS
// handshake collides (both ends send a ClientHello, neither sends a
// ServerHello) and the dial fails. A short randomized pause breaks the
// symmetry so exactly one side wins the connection and the other reuses it (or
// retries on its own jitter). Re-randomized on every attempt, so even a
// lockstep retry after a collision drifts apart and converges.
const meshDialJitter = 2 * time.Second

func runBootRelayMeshUplink(ctx context.Context, h host.Host, rr *relayRouter, info peer.AddrInfo) error {
	h.Peerstore().AddAddrs(info.ID, info.Addrs, peerstore.PermanentAddrTTL)

	// Break the simultaneous-dial TLS collision (see meshDialJitter).
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(time.Duration(mathrand.Int64N(int64(meshDialJitter)))):
	}

	dialCtx, cancelDial := context.WithTimeout(ctx, 20*time.Second)
	defer cancelDial()
	if err := h.Connect(dialCtx, info); err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	// A backbone link must never be trimmed by the ConnManager.
	h.ConnManager().Protect(info.ID, "mesh-boot-relay")

	s, err := h.NewStream(ctx, info.ID, BootRelayBackboneProtocolID)
	if err != nil {
		return fmt.Errorf("open boot-relay backbone stream: %w", err)
	}
	defer s.Close()
	rr.registerMesh(info.ID, s)
	defer rr.unregisterMesh(info.ID)
	fmt.Printf("[boot-relay|mesh] Backbone uplink established to boot %s\n", info.ID.String())
	bootAlerts.Add("info", "mesh_connected", info.ID.ShortString(),
		fmt.Sprintf("Mesh backbone connected: boot %s", info.ID.ShortString()))

	buf := make([]byte, maxBootRelayEnvelope)
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		_ = s.SetReadDeadline(time.Now().Add(10 * time.Minute))
		n, err := readFrame(s, buf)
		if err != nil || n == 0 {
			bootAlerts.Add("warn", "mesh_disconnected", info.ID.ShortString(),
				fmt.Sprintf("Mesh backbone disconnected: boot %s", info.ID.ShortString()))
			return fmt.Errorf("read: %w", err)
		}
		// Frames from the remote boot are for OUR local clients only.
		rr.route(buf[:n], true, info.ID)
	}
}

func main() {
	if exePath, err := os.Executable(); err == nil {
		_ = os.Chdir(filepath.Dir(exePath))
	}
	// Command-line flags: only -c (config path) and -version are accepted. All
	// operational settings — listen port, key file, PSKs, node name, mesh peers,
	// log level — live in the JSON config file (default boot.json). This keeps a
	// single source of truth for deployment and avoids silent mismatches between
	// CLI overrides and the on-disk config.
	configPath := flag.String("c", "boot.json", "Path to JSON boot configuration file (created with defaults on first run)")
	showVersion := flag.Bool("version", false, "Display version information and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(version.Full())
		return
	}

	// Load config (writes a default boot.json on first run). All settings come
	// from the JSON file; there are no CLI overrides.
	cfg, err := LoadBootConfig(*configPath)
	if err != nil {
		fmt.Printf("Error loading boot config %s: %v\n", *configPath, err)
		os.Exit(1)
	}

	// Apply the configured log level early so the rest of startup honors it.
	logger.SetGlobalLevel(logger.ParseLevel(cfg.LogLevel))

	nodeNameVal := cfg.NodeName
	psks := cfg.PSKs
	meshSpec := strings.Join(cfg.MeshPeers, ",")

	// Load or generate persistent Identity Keypair
	privKey, err := loadOrGenerateKey(cfg.KeyFile)
	if err != nil {
		fmt.Printf("Error with identity key: %v\n", err)
		os.Exit(1)
	}

	pskEnabled := len(psks) > 0
	if pskEnabled {
		log.Info("[+] PSK authentication enabled — %d network(s); only authenticated peers can use relay", len(psks))
	} else {
		log.Warn("[!] WARNING: No PSK set — relay is OPEN to all peers. Set psks[] in %s to restrict access.", *configPath)
	}

	ctx, cancel := context.WithCancel(context.Background())

	// Load the peer address store before anything can observe a connection, so
	// the first peer that connects is recorded. A read failure is not fatal:
	// the store holds derived, rebuildable state, and the flush will report the
	// write-side failure repeatedly if the path is genuinely unusable.
	var peerAddrs *peerAddrStore
	if cfg.EnablePeerAddrCache {
		var serr error
		peerAddrs, serr = LoadStore(cfg.PeerAddrFile, 0)
		if serr != nil {
			fmt.Printf("Warning: could not load peer address store %s: %v (starting with an empty store)\n", cfg.PeerAddrFile, serr)
		} else {
			fmt.Printf("[+] Peer address cache: %s\n", cfg.PeerAddrFile)
		}
	} else {
		fmt.Println("[!] Peer address cache disabled (enable_peer_addr_cache=false)")
	}
	defer cancel()

	// Initialize hub BEFORE any stream handler is registered. The PSK auth
	// handler closure captures this variable; if it is nil when a peer
	// authenticates (before step 7 below), hub.publishBootInfo panics with a
	// nil-pointer dereference and crashes the entire boot server.
	hub := newPeekMapHub()

	listenAddrs := cfg.ListenAddrs
	if len(listenAddrs) == 0 {
		fmt.Printf("Error: listen_addrs in boot config %s cannot be empty!\n", *configPath)
		os.Exit(1)
	}

	var mAddrs []multiaddr.Multiaddr
	for _, aStr := range listenAddrs {
		if err := node.ValidateListenAddr(aStr); err != nil {
			log.Warn("invalid listen address %q skipped, so nothing will listen on it: %v", aStr, err)
			continue
		}
		ma, _ := multiaddr.NewMultiaddr(aStr)
		mAddrs = append(mAddrs, ma)
	}
	// A boot server with no valid listener serves nothing — it would still start
	// its WebUI, print the relay banner and look healthy while every peer behind
	// NAT times out against it. Fail here instead.
	if len(mAddrs) == 0 {
		fmt.Printf("Error: every listen address in %s failed validation, so this boot server would have no listener at all. Fix listen_addrs.\n", *configPath)
		os.Exit(1)
	}

	// Build Host with Public Server Options for NAT Traversal
	//
	// ConnectionManager: a relay server must keep its links to reserved peers
	// alive at all times. circuitv2's relay refuses to dial the destination
	// (status 203 / CONNECTION_FAILED) unless the destination currently has a
	// live connection to the relay, so a silently-trimmed idle connection is a
	// direct cause of "relay can't connect". We therefore (a) install an explicit
	// ConnManager with generous watermarks and a long SilencePeriod so idle
	// relay links are never trimmed for inactivity, and (b) Protect() every
	// connected peer from trimming in the connection Notifiee below, and (c) run
	// a periodic echo keepalive (relayKeepaliveLoop) that keeps NAT/firewall UDP
	// mappings open and surfaces dead links.
	cm, err := connmgr.NewConnManager(
		relayConnLowWater, relayConnHighWater,
		connmgr.WithGracePeriod(30*time.Second),
		connmgr.WithSilencePeriod(time.Hour),
	)
	if err != nil {
		fmt.Printf("Error building connection manager: %v\n", err)
		os.Exit(1)
	}
	rm, err := relayResourceManager()
	if err != nil {
		fmt.Printf("Error building resource manager: %v\n", err)
		os.Exit(1)
	}
	// WebRTC transport with STUN/TURN servers — replaces the stock WebRTC
	// transport so ICE candidate gathering uses the configured servers.
	// Boot has no TAP interface, so we pass through the injected
	// ListenUDPFn (unlike the mesh node which binds to a protected socket).
	hostOpts := []libp2p.Option{
		libp2p.Identity(privKey),
		libp2p.ListenAddrs(mAddrs...),
		libp2p.ConnectionManager(cm),
		libp2p.ResourceManager(rm),
		libp2p.NATPortMap(),
		libp2p.EnableNATService(),
		libp2p.EnableRelay(),
		// libp2p's built-in default is 10s and the mesh node dials with 15s, so
		// the boot was aborting its side of a punch before a peer behind symmetric
		// NAT had finished bringing its socket up. Keep the two in lockstep.
		libp2p.EnableHolePunching(holepunch.DirectDialTimeout(cfg.HolePunchTimeout)),
	}
	// WebRTC transport is registered UNCONDITIONALLY. Gating the whole
	// registration on "do we have any STUN/TURN servers" silently deleted the
	// /webrtc-direct listener whenever both lists were empty, while the
	// ListenAddrs below still advertised one — peers saw an address and got a
	// permanent connection-refused. ICE servers are optional inputs to the
	// transport (none means host/reflexive candidates only), so only the
	// individual options are conditional.
	hostOpts = append(hostOpts, libp2p.Transport(
		func(key crypto.PrivKey, psk pnet.PSK, gater libp2pconnmgr.ConnectionGater, rcmgr network.ResourceManager, ludp webrtc.ListenUDPFn, transportOpts ...webrtc.Option) (tpt.Transport, error) {
			allOpts := transportOpts
			if len(cfg.StunServers) > 0 {
				allOpts = append(allOpts, webrtc.WithSTUNServers(cfg.StunServers))
				log.Info("WebRTC configured with %d STUN server(s)", len(cfg.StunServers))
			}
			turnURLs, turnUser, turnCred, turnDropped := node.IceTURNConfig(cfg.TurnServers)
			if len(turnURLs) > 0 {
				allOpts = append(allOpts,
					webrtc.WithTURNServers(turnURLs),
					webrtc.WithTURNCredentials(turnUser, turnCred),
				)
				log.Info("WebRTC configured with %d TURN server(s) with ICE credentials", len(turnURLs))
			}
			if turnDropped > 0 {
				log.Warn("%d TURN server(s) lack ?username=...&credential=... and are excluded from "+
					"WebRTC ICE: pion rejects a credential-less TURN server and aborts the whole peer "+
					"connection, which would take down every WebRTC link. The QUIC relay binder skips "+
					"them too — add credentials to use them.", turnDropped)
			}
			return webrtc.New(key, psk, gater, rcmgr, ludp, allOpts...)
		},
	))

	// QUIC transport with TURN relay override: when the QUIC ConnManager
	// creates a UDP socket for a TURN relay address, return the pre-allocated
	// relay PacketConn instead of creating a new socket (which would fail
	// because the relay address is not a local address). Without this
	// override the boot server advertises TURN relay addresses via
	// AddrsFactory but peers can never actually connect to them via QUIC.
	//
	// The manager is built through node.QUICReuseOption, the same constructor
	// the p2ptap node uses, so the two binaries share one wiring of
	// ConnContext / VerifySourceAddress and one idea of which listener owns
	// which ALPN. VerifySourceAddress must stay set: the boot server is the one
	// node every peer dials at once, so address validation is the only thing
	// standing between an unauthenticated inbound packet and a full connection.
	hostOpts = append(hostOpts, node.QUICReuseOption(func(network string, laddr *net.UDPAddr) (net.PacketConn, error) {
		if conn, ok := node.GetTURNRelayConn(laddr.String()); ok {
			log.Debug("QUIC ConnManager: using TURN relay connection for %s", laddr.String())
			return conn, nil
		}
		return net.ListenUDP(network, laddr)
	}))
	hostOpts = append(hostOpts, libp2p.Transport(
		func(key crypto.PrivKey, cm *quicreuse.ConnManager, psk pnet.PSK, gater libp2pconnmgr.ConnectionGater, rcmgr network.ResourceManager, transportOpts ...quict.Option) (tpt.Transport, error) {
			return quict.NewTransport(key, cm, psk, gater, rcmgr, transportOpts...)
		},
	))
	log.Info("QUIC transport registered (with TURN relay support)")

	// TCP transport. Boot has no TAP interface, so there is no tunnel to keep P2P
	// traffic out of and no socket-protection hook to wire — only the dialer
	// timeouts, which must match the mesh node so a peer's half of a TCP dial is
	// not abandoned while the boot is still accepting it.
	hostOpts = append(hostOpts, libp2p.Transport(tcpt.NewTCPTransport,
		tcpt.WithDialerForAddr(func(raddr multiaddr.Multiaddr) (tcpt.ContextDialer, error) {
			return &net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 15 * time.Second,
			}, nil
		}),
	))
	log.Info("TCP transport registered")

	// WebTransport (/udp/N/quic-v1/webtransport) reuses the same quicreuse
	// ConnManager as the QUIC transport above — injected by QUICReuseOption,
	// never built here — so both share sockets and demultiplex incoming
	// connections by ALPN instead of racing the kernel over the same address.
	//
	// Without this registration a /quic-v1/webtransport entry in listen_addrs is
	// silently dropped by libp2p: the address is never advertised, so peers on
	// networks that block QUIC but allow HTTP/3 had no reachable path to the
	// boot at all, even though the default config configured a listener for it.
	hostOpts = append(hostOpts, libp2p.Transport(
		func(key crypto.PrivKey, psk pnet.PSK, cm *quicreuse.ConnManager, gater libp2pconnmgr.ConnectionGater, rcmgr network.ResourceManager, transportOpts ...webtransport.Option) (tpt.Transport, error) {
			return webtransport.New(key, psk, cm, gater, rcmgr, transportOpts...)
		},
	))
	log.Info("WebTransport transport registered (shares the QUIC ConnManager)")

	// AddrsFactory: filter loopback and append STUN/TURN reflexive + relay
	// addresses so peers behind NAT can reach this boot server.
	hostOpts = append(hostOpts, libp2p.AddrsFactory(
		func(addrs []multiaddr.Multiaddr) []multiaddr.Multiaddr {
			boundMu.Lock()
			boundAddrs = append(boundAddrs, addrs...)
			boundMu.Unlock()
			// Drop loopback — it's never useful for external peers.
			filtered := make([]multiaddr.Multiaddr, 0, len(addrs)+8)
			for _, a := range addrs {
				if v, _ := a.ValueForProtocol(multiaddr.P_IP4); v == "127.0.0.1" {
					continue
				}
				if v, _ := a.ValueForProtocol(multiaddr.P_IP6); v == "::1" {
					continue
				}
				filtered = append(filtered, a)
			}
			// Append STUN-discovered reflexive addresses (UDP + TCP).
			if stunAddrs := node.GetSTUNReflexiveAddrs(); len(stunAddrs) > 0 {
				filtered = append(filtered, stunAddrs...)
			}
			if tcpStunAddrs := node.GetTCPStunReflexiveAddrs(); len(tcpStunAddrs) > 0 {
				filtered = append(filtered, tcpStunAddrs...)
			}
			// Append TURN relay addresses.
			if turnAddrs := node.GetTURNRelayAddrs(); len(turnAddrs) > 0 {
				filtered = append(filtered, turnAddrs...)
			}
			return filtered
		},
	))

	h, err := libp2p.New(hostOpts...)
	if err != nil {
		fmt.Printf("Error starting bootstrap host: %v\n", err)
		os.Exit(1)
	}

	verifyListeners(mAddrs)

	// Start STUN/TURN binders — these discover the boot server's reflexive
	// addresses so peers behind NAT can reach it. The AddrsFactory above
	// reads from the package-level atomics that these binders populate.
	if len(cfg.StunServers) > 0 {
		node.StartBootSTUNBinder(ctx, cfg.StunServers)
	}
	if len(cfg.TurnServers) > 0 {
		node.StartBootTURNBinder(ctx, h, cfg.TurnServers)
	}

	// 1. Enable Kademlia DHT in Server Mode
	kdht, err := dht.New(h, dht.Mode(dht.ModeServer))
	if err != nil {
		fmt.Printf("Error starting DHT server: %v\n", err)
	} else {
		_ = kdht.Bootstrap(ctx)
	}

	// 2. Setup PSK ACL filter for relay
	gSecurity = newSecurityManager()
	aclFilter := newPSKACLFilter(pskEnabled)
	aclFilter.SetHost(h)

	// 3. Enable Circuit Relay v2 with ACL and resource limits.
	relayRes := relayResources()

	_, err = relay.New(h,
		relay.WithACL(aclFilter),
		relay.WithResources(relayRes),
	)
	if err != nil {
		// A boot whose circuit relay failed to initialise is not a working relay.
		// It would still serve the p2ptap overlay relay, keep the WebUI happy, and
		// print the "Circuit Relay v2 enabled" banner — so peers behind symmetric
		// NAT would time out against a server that claims to relay for them. Fail
		// the process instead of advertising a broken capability.
		fmt.Printf("Error starting Circuit Relay v2: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("[+] Circuit Relay v2 enabled with ACL and resource limits")

	// 4. Register PSK authentication stream handler. Each configured PSK becomes
	//    one network; a handshake token is accepted if it matches ANY PSK, and
	//    the peer is bound to that PSK's network ID.
	var pskEntries []pskEntry
	if pskEnabled {
		for _, p := range psks {
			pskEntries = append(pskEntries, pskEntry{hash: computePSKHash(p), netID: networkIDFromPSK(p), psk: p})
		}
		h.SetStreamHandler(authProtocolID, func(s network.Stream) {
			handleAuthStream(s, pskEntries, aclFilter, h, hub, nodeNameVal)
		})
		fmt.Printf("[+] PSK auth handler registered for %d network(s) (protocol: %s)\n", len(pskEntries), authProtocolID)
	}

	// 5. Register Metadata stream handler for WebUI Node Name exchange
	startTime := time.Now()

	// Initialize global subsystems for WebUI dashboard
	gSessions = newSessionTracker()
	gTraffic = newTrafficHistory(60)

	// Try to load GeoLite2-City.mmdb from configured geoip_path (falls back to next to binary / CWD)
	geoDBPath := cfg.GeoIPPath
	if geoDBPath == "" {
		geoDBPath = "GeoLite2-City.mmdb"
	}
	geoResolver, geoErr := newGeoIPResolver(geoDBPath)
	if geoErr != nil && !filepath.IsAbs(geoDBPath) {
		binGeoPath := filepath.Join(filepath.Dir(os.Args[0]), geoDBPath)
		geoResolver, geoErr = newGeoIPResolver(binGeoPath)
	}
	if geoErr == nil && geoResolver != nil {
		gGeoIP = geoResolver
		defer gGeoIP.Close()
		fmt.Printf("[+] GeoIP: GeoLite2-City database loaded from %s — geographic features enabled\n", geoDBPath)
	} else {
		fmt.Printf("[!] GeoIP: database (%s) not found — geographic features disabled (configure geoip_path in %s to enable)\n", geoDBPath, *configPath)
	}

	h.SetStreamHandler(meta.MetaProtocolID, func(s network.Stream) {
		defer s.Close()
		if !aclFilter.RequireAuth(s.Conn().RemotePeer()) {
			log.Warn("[meta] refusing unauthenticated peer %s", s.Conn().RemotePeer().ShortString())
			unauthTracker.Record(unauthTypeMeta, s.Conn().RemotePeer().ShortString(),
				"Meta request rejected: unauthenticated peer")
			return
		}
		// The p2ptap client speaks a LENGTH-FRAMED meta protocol (see
		// pkg/node/meta.go: WriteFrame/ReadFrame = 4-byte big-endian length
		// prefix + payload). A bare JSON write here would be mis-read by the
		// client's ReadFrame as a multi-gigabyte frame ("frame too large"),
		// so syncMetadataToPeer/broadcastMetadata would ALWAYS fail. Mirror
		// the relay/echo framing: read one request frame, answer with one
		// length-framed response frame.
		_ = s.SetReadDeadline(time.Now().Add(10 * time.Second))
		reqBuf := make([]byte, 64*1024)
		_, _ = readFrame(s, reqBuf) // request payload is ignored; boot only echoes its own identity

		// Respond with Bootstrap Node's metadata (length-framed).
		payload := meta.NodeMetaPayload{
			NodeName:     nodeNameVal,
			TapIP:        "",
			TapIPv6:      "",
			OS:           runtime.GOOS,
			Arch:         runtime.GOARCH,
			Version:      version.Version,
			UptimeSec:    int64(time.Since(startTime).Seconds()),
			Reachability: "Public Server",
		}
		data, _ := json.Marshal(payload)
		_ = writeFrame(s, data)
	})
	fmt.Printf("[+] Metadata handler registered (Node Name: '%s', protocol: %s)\n", nodeNameVal, meta.MetaProtocolID)

	// 6. Register Echo stream handler for liveness ping-pong probes
	h.SetStreamHandler(echoProtocolID, func(s network.Stream) {
		defer s.Close()
		if !aclFilter.RequireAuth(s.Conn().RemotePeer()) {
			log.Warn("[echo] refusing unauthenticated peer %s", s.Conn().RemotePeer().ShortString())
			unauthTracker.Record(unauthTypeEcho, s.Conn().RemotePeer().ShortString(),
				"Echo request rejected: unauthenticated peer")
			return
		}
		// Backstop: a legitimate echo (used by relayKeepaliveLoop) finishes in
		// milliseconds, but an abusive peer could hold the stream open and pump
		// arbitrary bytes. Cap the lifetime and the total reflected bytes so a
		// single echo stream can't become a bandwidth/memory sink.
		_ = s.SetDeadline(time.Now().Add(60 * time.Second))
		_, _ = io.Copy(s, io.LimitReader(s, 64<<20)) // 64 MiB cap
	})
	fmt.Printf("[+] Echo ping-pong handler registered (protocol: %s)\n", echoProtocolID)

	// Register a minimal seqsync responder so client nodes can complete the
	// handshake against the boot node symmetrically. The boot node is a pure
	// relay/coordinator that never sends or receives encrypted TAP frames, so
	// it advertises ObfEnabled=false and a fixed MySeq=0; the client's local
	// anchorDedupForPeer/negotiateObfWithPeer simply mark the boot peer usable.
	h.SetStreamHandler(SeqSyncProtocolID, func(s network.Stream) {
		if !aclFilter.RequireAuth(s.Conn().RemotePeer()) {
			log.Warn("[seqsync] refusing unauthenticated peer %s", s.Conn().RemotePeer().ShortString())
			unauthTracker.Record(unauthTypeSeqSync, s.Conn().RemotePeer().ShortString(),
				"SeqSync request rejected: unauthenticated peer")
			_ = s.Close()
			return
		}
		handleSeqSyncStream(s)
	})
	fmt.Printf("[+] SeqSync responder registered (protocol: %s)\n", SeqSyncProtocolID)

	// 7. Register peek-map pub/sub broadcast hub. The boot node acts purely as
	//    a stateless router: every client opens a long-lived stream, and each
	//    UPDATE frame is rebroadcast to all other clients. No node data cached.
	// hub was already initialized early (before handler registration) to avoid
	// a nil-pointer panic if a peer authenticates before this point.
	// In PSK mode, discovery is isolated per network: route frames only to peers
	// in the same network as the sender. nil resolver => open mode (no isolation).
	if pskEnabled {
		hub.netResolver = aclFilter.NetworkOf
	}
	h.SetStreamHandler(PeekMapProtocolID, makePeekMapHandler(h, hub, nodeNameVal, aclFilter))
	fmt.Printf("[+] Peek-map pub/sub broadcast hub registered (protocol: %s)\n", PeekMapProtocolID)
	// Announce this boot node immediately so peers already connected (before the
	// first new peek-map client triggers a re-broadcast) learn its identity.
	hub.publishBootInfo(h, nodeNameVal, version.Version)

	// 7b. Register the boot-relay (relay-over-backbone) handlers. A node opens a
	// /p2ptap/boot-relay/1.0.0 uplink after PSK auth; the boot bridges its frames
	// to the destination (across the backbone if the destination is on another
	// boot). This closes the cross-boot data gap that Circuit Relay v2 (per-boot)
	// cannot span.
	relayRouter := newRelayRouter(aclFilter, pskEnabled)
	h.SetStreamHandler(BootRelayProtocolID, makeBootRelayHandler(relayRouter))
	h.SetStreamHandler(BootRelayBackboneProtocolID, makeBootRelayBackboneHandler(relayRouter, hub))
	h.SetStreamHandler(RelayCtrlProtocolID, makeRelayCtrlHandler(h, aclFilter, hub, pskEntries))
	fmt.Printf("[+] Boot-relay & relay-control handlers registered (protocols: %s, %s, %s)\n",
		BootRelayProtocolID, BootRelayBackboneProtocolID, RelayCtrlProtocolID)

	// Remember what this boot observes about a peer's direct endpoints and tell
	// the other local clients about the change. conns is the peer's current
	// connection set; skip is the link being dropped (may still be listed);
	// gone means the peer has no links left at all.
	//
	// Always dispatched to its own goroutine: broadcastPeerAddrFrame calls
	// fanout, which writes inline with a 10s deadline per listener. Running that
	// inside libp2p's notify callback would stall the notify thread behind one
	// unresponsive peer and block every other connection notification.
	onPeerAddrChange := func(pID peer.ID, conns []network.Conn, skip network.Conn, gone bool) {
		if peerAddrs == nil {
			return
		}
		// Both values must be read while the peer is still registered: the
		// cleanup below RemoveAuthenticated's and un-caches it, after which both
		// would read empty.
		netID := aclFilter.NetworkOf(pID)
		nodeName := ""
		if v, ok := peerInfoCache.Load(pID); ok {
			if ci, ok := v.(clientNodeInfo); ok {
				nodeName = ci.NodeName
			}
		}
		go func() {
			var addrs, removed []string
			if gone {
				removed = peerAddrs.MarkGone(pID)
			} else {
				var transports []string
				addrs, transports = observedPeerAddrs(conns, pID, skip)
				removed = peerAddrs.RecordPeerAddrs(pID, addrs, transports, netID, nodeName)
			}
			hub.broadcastPeerAddrFrame(h.ID(), pID, addrs, removed, netID, nodeName)
		}()
	}

	// 8. Log peer connection/disconnection events.
	// Protect() every connected peer from the ConnManager so relay links are
	// never silently trimmed (a trimmed link is the root cause of circuitv2
	// 203/CONNECTION_FAILED: the relay can't dial a destination it no longer
	// has a live connection to). We only Unprotect once the peer has fully
	// disconnected, so a multi-transport peer that drops one link keeps its
	// remaining link protected.
	h.Network().Notify(&network.NotifyBundle{
		ConnectedF: func(n network.Network, conn network.Conn) {
			pID := conn.RemotePeer()
			h.ConnManager().Protect(pID, "relay-peer")
			maStr := conn.RemoteMultiaddr().String()
			fmt.Printf("[Peer] Connected: %s via %s\n", pID.String(), maStr)
			// Record connect time for duration tracking on disconnect.
			gPeerConnectTimes.Store(pID, time.Now())
			// Record the endpoints this link reveals. This is the only place
			// RecordPeerAddrs is reached: the disconnect path only ever retracts,
			// and MarkGone is a no-op for a peer that was never recorded, so a
			// boot with this call missing never wrote its address cache at all.
			// No skip conn — a fresh connect is always an observed address.
			onPeerAddrChange(pID, h.Network().ConnsToPeer(pID), nil, false)
			// Determine transport name for the alert message.
			transportName := "TCP"
			switch node.TransportOfConn(conn) {
			case "quic":
				transportName = "QUIC"
			case "webrtc":
				transportName = "WebRTC"
			case "webtransport":
				transportName = "WebTransport"
			}
			phyIP := directPhysicalIP(h.Network().ConnsToPeer(pID), nil)
			bootAlerts.Add("info", "peer_connect", pID.ShortString(),
				fmt.Sprintf("Peer connected: %s via %s (%s)", pID.ShortString(), transportName, phyIP))
			// Trigger initial ping probe to immediately measure RTT.
			go func(p peer.ID) {
				time.Sleep(300 * time.Millisecond)
				pingCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
				defer cancel()
				s, err := h.NewStream(pingCtx, p, echoProtocolID)
				if err != nil {
					return
				}
				defer s.Close()
				start := time.Now()
				if err := writeFrame(s, []byte("PING")); err != nil {
					return
				}
				_ = s.SetReadDeadline(time.Now().Add(2 * time.Second))
				buf := make([]byte, 16)
				if _, err := readFrame(s, buf); err == nil {
					h.Peerstore().RecordLatency(p, time.Since(start))
				}
			}(pID)
		},
		DisconnectedF: func(n network.Network, conn network.Conn) {
			peerID := conn.RemotePeer()
			fmt.Printf("[Peer] Disconnected: %s\n", peerID.String())
			// Only release relay state once the peer is TRULY gone (no other
			// transport still connected). A multi-transport peer that drops a
			// single link must keep its auth + peek-map listener alive on the
			// surviving link; otherwise its existing circuits keep working but
			// every NEW circuit CONNECT is denied (auth removed) and it silently
			// stops receiving peer-discovery broadcasts.
			if h.Network().Connectedness(peerID) != network.Connected {
				// The peer is gone for good: mark its cached endpoints as
				// retracted and tell the mesh to drop them now rather than
				// waiting out the 1h peerstore TTL.
				onPeerAddrChange(peerID, h.Network().ConnsToPeer(peerID), conn, true)
				h.ConnManager().Unprotect(peerID, "relay-peer")
				aclFilter.RemoveAuthenticated(peerID)
				hub.unregister(peerID)
				peerInfoCache.Delete(peerID)
				h.Peerstore().ClearAddrs(peerID)
				if gSecurity != nil {
					gSecurity.PeekMap.Remove(peerID)
				}
				// Clean up relay sessions and compute online duration.
				if gSessions != nil {
					gSessions.RemoveForPeer(peerID)
				}
				duration := "unknown"
				if ct, ok := gPeerConnectTimes.LoadAndDelete(peerID); ok {
					duration = time.Since(ct.(time.Time)).Round(time.Second).String()
				}
				bootAlerts.Add("info", "peer_disconnect", peerID.ShortString(),
					fmt.Sprintf("Peer disconnected: %s (online %s)", peerID.ShortString(), duration))
			} else {
				// A link dropped but the peer is still attached on another one.
				// Re-record the surviving set so the dropped link's address is
				// retracted here too — otherwise it stays in the mesh until the
				// 1h peerstore TTL expires.
				onPeerAddrChange(peerID, h.Network().ConnsToPeer(peerID), conn, false)
			}
		},
	})

	// 9. Relay keepalive: periodically echo-ping every connected peer so that
	// NAT/firewall UDP mappings stay open and dead links surface quickly. This
	// keeps reserved peers' connections warm, which is what lets circuitv2
	// actually bridge them (relay refuses to dial a destination without a live
	// connection — status 203).
	go relayKeepaliveLoop(ctx, h, 30*time.Second)
	fmt.Printf("[+] Relay keepalive loop started (echo ping every 30s to keep peer links warm)\n")

	// 9b. Background maintenance sweeper: periodically prunes expired relay sessions,
	// deduplication caches, and stale peer metadata for 24/7/365 long-term reliability.
	go runMaintenanceSweeper(ctx, h, aclFilter, hub, gSessions)
	fmt.Printf("[+] Background maintenance sweeper started (prunes expired relay sessions, dedup caches and stale states every 1m)\n")

	// 10. Boot backbone: interconnect with peer boots so clients attached to
	// DIFFERENT boots discover each other. Mesh peers are registered with the hub
	// before any uplink starts, so their frames are classified as backbone (and
	// therefore not re-forwarded onto the backbone) from the very first frame.
	meshInfos := parseMeshPeers(meshSpec, h.ID())
	for _, mi := range meshInfos {
		hub.markMesh(mi.ID)
	}
	for _, mi := range meshInfos {
		go meshUplinkLoop(ctx, h, hub, mi, nodeNameVal)
		// Relay-over-backbone backbone: bridge data-plane relay frames for clients
		// attached to DIFFERENT boots across the same peer-boot mesh.
		go bootRelayMeshUplinkLoop(ctx, h, relayRouter, mi)
	}
	if len(meshInfos) > 0 {
		fmt.Printf("[+] Boot backbone enabled: interconnecting with %d peer boot(s) (discovery + relay-over-backbone)\n", len(meshInfos))
	}

	// 11. Start embedded WebUI monitoring dashboard
	var webServer *bootweb.Server
	if cfg.WebUI.Enable {
		provider := &bootDataProviderImpl{
			h:           h,
			nodeName:    nodeNameVal,
			startTime:   startTime,
			pskEnabled:  pskEnabled,
			pskCount:    len(psks),
			acl:         aclFilter,
			hub:         hub,
			relayRes:    relayRes,
			relayRouter: relayRouter,
			meshInfos:   meshInfos,
			geoIP:       gGeoIP,
			geoIPPath:   geoDBPath,
			sessions:    gSessions,
			traffic:     gTraffic,
			peerAddrs:   peerAddrs,
			listenAddrs: listenAddrs,
		}

		// Start traffic history sampler (records peer+relay count every minute)
		runTrafficSampler(ctx, gTraffic,
			func() int {
				if h != nil {
					return len(h.Network().Peers())
				}
				return 0
			},
			func() int {
				if gSessions != nil {
					return gSessions.Count()
				}
				return 0
			},
		)

		webServer = bootweb.NewServer(provider, cfg.WebUI.Listen, cfg.WebUI.AuthToken)
		if err := webServer.Start(); err != nil {
			fmt.Printf("Warning: Failed to start WebUI server on %s: %v\n", cfg.WebUI.Listen, err)
		} else {
			fmt.Fprintf(os.Stderr, "[+] WebUI Dashboard started on http://%s\n", webServer.GetListenAddr())
			// Only print the auto-generated token — a user-specified token is
			// already known and printing it to logs leaks it to anyone with
			// read access to the process stdout/stderr (e.g. systemd journal,
			// container log drivers).
			if cfg.WebUI.AuthToken == "" {
				fmt.Fprintf(os.Stderr, "    Token (auto-generated, store securely): %s\n", webServer.GetAuthToken())
			}
		}
	}

	printBootstrapBanner(h, nodeNameVal, pskEnabled, webServer)

	// Replay cached peer addresses now that the hub is live, so a restart does
	// not leave the mesh without the endpoints it had before. Window-filtered,
	// because NAT mappings rarely survive a day.
	if peerAddrs != nil {
		if n, m := replayPeerAddrs(ctx, h, hub, peerAddrs.SnapshotWithin(cfg.PeerAddrRebroadcastWindow)); n > 0 {
			fmt.Printf("[+] Replayed %d cached peer address record(s) covering %d address(es)\n", n, m)
		}
	}

	// Wait for OS shutdown signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	fmt.Println("\nShutting down bootstrap server...")
	if peerAddrs != nil {
		peerAddrs.Close()
	}
	if webServer != nil {
		_ = webServer.Stop(context.Background())
	}
	_ = h.Close()
	fmt.Println("Shutdown complete.")
}

type bootDataProviderImpl struct {
	h           host.Host
	nodeName    string
	startTime   time.Time
	pskEnabled  bool
	pskCount    int
	acl         *pskACLFilter
	hub         *peekMapHub
	relayRes    relay.Resources
	relayRouter *relayRouter
	meshInfos   []peer.AddrInfo
	geoIP       *GeoIPResolver
	geoIPPath   string
	sessions    *sessionTracker
	traffic     *trafficHistory
	peerAddrs   *peerAddrStore
	listenAddrs []string
}

func (p *bootDataProviderImpl) GetHost() host.Host {
	return p.h
}

// GetRelayLimits reports the circuit relay's actual resource limits, read off the
// relay.Resources this server was built with. It exists because the dashboard used
// to hard-code libp2p's defaults, which disagree with what the boot enforces.
func (p *bootDataProviderImpl) GetRelayLimits() bootweb.RelayStatsDTO {
	d := bootweb.RelayStatsDTO{
		Enabled:         true,
		MaxCircuits:     p.relayRes.MaxCircuits,
		MaxReservations: p.relayRes.MaxReservations,
		// Enforced per-peer cap is 1 (see the MaxReservationsPerPeer note where
		// relayRes is built); the field itself is dead code in libp2p.
		MaxPerPeer:        1,
		MaxPerIP:          p.relayRes.MaxReservationsPerIP,
		MaxPerASN:         p.relayRes.MaxReservationsPerASN,
		ReservationTTLSec: int(p.relayRes.ReservationTTL.Seconds()),
	}
	if p.relayRes.Limit != nil {
		d.DurationLimitSec = int(p.relayRes.Limit.Duration.Seconds())
		d.DataLimitMB = int(p.relayRes.Limit.Data / (1 << 20))
	}
	// A nil Limit leaves both fields at 0, which is the "no circuit lifetime or
	// data quota" encoding rather than a missing value — libp2p's own reservation
	// limit says "If 0, there is no limit". relayResources sets Limit to nil on
	// purpose, so 0/0 is the honest report.
	return d
}

func (p *bootDataProviderImpl) GetNodeName() string {
	return p.nodeName
}

func (p *bootDataProviderImpl) GetStartTime() time.Time {
	return p.startTime
}

func (p *bootDataProviderImpl) IsPSKEnabled() bool {
	return p.pskEnabled
}

func (p *bootDataProviderImpl) GetPSKCount() int {
	return p.pskCount
}

func (p *bootDataProviderImpl) IsPeerAuthenticated(id peer.ID) bool {
	if p.acl == nil {
		return false
	}
	return p.acl.IsAuthenticated(id)
}

func (p *bootDataProviderImpl) GetPeerNetworkID(id peer.ID) string {
	if p.acl == nil {
		return ""
	}
	return p.acl.NetworkOf(id)
}

func (p *bootDataProviderImpl) HasPeekMapListener(id peer.ID) bool {
	if p.hub == nil {
		return false
	}
	p.hub.mu.RLock()
	defer p.hub.mu.RUnlock()
	_, ok := p.hub.listener[id]
	return ok
}

func (p *bootDataProviderImpl) GetPeekMapListenerCount() int {
	if p.hub == nil {
		return 0
	}
	p.hub.mu.RLock()
	defer p.hub.mu.RUnlock()
	return len(p.hub.listener)
}

func (p *bootDataProviderImpl) HasBootRelayClient(id peer.ID) bool {
	if p.relayRouter == nil {
		return false
	}
	p.relayRouter.mu.RLock()
	defer p.relayRouter.mu.RUnlock()
	_, ok := p.relayRouter.clientStreams[id]
	return ok
}

func (p *bootDataProviderImpl) GetPeerNodeInfo(id peer.ID) (string, string, string, string, string, string, string, []string, bool, string, string) {
	if v, ok := peerInfoCache.Load(id); ok {
		info := v.(clientNodeInfo)
		return info.NodeName, info.TapIP, info.TapIPv6, info.TapMAC, info.OS, info.Arch, info.Version, info.AdvertisedSubnets, info.IsExitNode, info.ObfsAlgo, info.ObfsMode
	}
	return "", "", "", "", "", "", "", nil, false, "", ""
}

func (p *bootDataProviderImpl) GetPeerObservedAddrs(id peer.ID) *bootweb.ObservedAddrsDTO {
	e := p.peerAddrs.Entry(id)
	if e == nil {
		return nil
	}
	return &bootweb.ObservedAddrsDTO{
		Addrs:       e.Addrs,
		Transports:  e.Transports,
		NetworkID:   e.NetworkID,
		FirstSeenAt: formatPeerAddrTime(e.FirstSeen),
		LastSeenAt:  formatPeerAddrTime(e.LastSeen),
		SeenCount:   e.SeenCount,
	}
}

func (p *bootDataProviderImpl) GetPeerConnectedSince(id peer.ID) (time.Time, bool) {
	if v, ok := gPeerConnectTimes.Load(id); ok {
		if t, ok := v.(time.Time); ok {
			return t, true
		}
	}
	return time.Time{}, false
}

func (p *bootDataProviderImpl) GetLastSeenPeers(limit int) []bootweb.LastSeenPeerDTO {
	if limit <= 0 {
		limit = 200
	}
	h := p.GetHost()
	connected := make(map[peer.ID]bool)
	if h != nil {
		for _, pid := range h.Network().Peers() {
			if h.Network().Connectedness(pid) == network.Connected {
				connected[pid] = true
			}
		}
	}
	now := time.Now()
	var out []bootweb.LastSeenPeerDTO
	for _, e := range p.peerAddrs.Snapshot() {
		pid, err := peer.Decode(e.PeerID)
		if err != nil || connected[pid] {
			continue
		}
		// An empty node name is usually a peer whose info frame we saw only
		// after it had already disconnected; the short ID is still useful.
		// Not pid.ShortString(): that renders as "<peer.ID 12*kSnUg6>", which
		// reads as an unwrapped type diagnostic rather than a display name.
		name := e.NodeName
		if name == "" {
			name = formatShortPeerID(pid)
		}
		out = append(out, bootweb.LastSeenPeerDTO{
			PeerID:      e.PeerID,
			ShortID:     formatShortPeerID(pid),
			NodeName:    name,
			Addrs:       e.Addrs,
			Transports:  e.Transports,
			NetworkID:   e.NetworkID,
			FirstSeenAt: formatPeerAddrTime(e.FirstSeen),
			LastSeenAt:  formatPeerAddrTime(e.LastSeen),
			LastSeenAgo: humanDuration(now.Sub(e.LastSeen)),
			SeenCount:   e.SeenCount,
		})
		if len(out) >= limit {
			break
		}
	}
	return out
}

// formatPeerAddrTime renders a store timestamp for the WebUI. Zero times render
// as "" rather than "0001-01-01", which would read as a bug.
func formatPeerAddrTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format("2006-01-02 15:04:05")
}

// formatShortPeerID duplicates the WebUI's short-ID convention so the boot's
// own provider output matches the dashboard's peer rows.
func formatShortPeerID(pid peer.ID) string {
	s := pid.String()
	if len(s) <= 16 {
		return s
	}
	return s[:7] + "..." + s[len(s)-6:]
}

// humanDuration renders a duration the way an operator expects to read it in
// a "last seen" column.
func humanDuration(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds ago", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
}

func (p *bootDataProviderImpl) GetMeshPeers() []bootweb.MeshPeerInfo {
	out := make([]bootweb.MeshPeerInfo, 0, len(p.meshInfos))
	for _, mi := range p.meshInfos {
		out = append(out, bootweb.MeshPeerInfo{
			ID:    mi.ID,
			Addrs: mi.Addrs,
		})
	}
	return out
}

func (p *bootDataProviderImpl) GetRecentAlerts() []bootweb.AlertEventDTO {
	return bootAlerts.GetAll()
}

func (p *bootDataProviderImpl) GetUnauthStats() bootweb.UnauthStatsDTO {
	stats := unauthTracker.Stats()
	dto := bootweb.UnauthStatsDTO{
		TotalDropped: stats.TotalDropped,
		ByType:       stats.ByType,
	}
	if len(stats.RecentEvents) > 0 {
		dto.RecentEvents = make([]bootweb.UnauthEventDTO, len(stats.RecentEvents))
		for i, ev := range stats.RecentEvents {
			dto.RecentEvents[i] = bootweb.UnauthEventDTO{
				Timestamp: ev.Timestamp,
				Type:      ev.Type,
				PeerID:    ev.PeerID,
				Detail:    ev.Detail,
			}
		}
	}
	return dto
}

func (p *bootDataProviderImpl) GetRelaySessions() []bootweb.RelaySessionDTO {
	if p.sessions == nil {
		return nil
	}
	raw := p.sessions.GetAll()
	out := make([]bootweb.RelaySessionDTO, 0, len(raw))
	for _, s := range raw {
		srcName, _, _, _, _, _, _, _, _, _, _ := p.GetPeerNodeInfo(s.SrcPeer)
		dstName, _, _, _, _, _, _, _, _, _, _ := p.GetPeerNodeInfo(s.DstPeer)
		out = append(out, bootweb.RelaySessionDTO{
			SrcPeerID:   s.SrcPeer.String(),
			SrcShortID:  s.SrcPeer.ShortString(),
			SrcName:     srcName,
			DstPeerID:   s.DstPeer.String(),
			DstShortID:  s.DstPeer.ShortString(),
			DstName:     dstName,
			NetworkID:   s.NetworkID,
			StartTime:   s.StartTime.Format("15:04:05"),
			DurationSec: int64(time.Since(s.StartTime).Seconds()),
		})
	}
	return out
}

func (p *bootDataProviderImpl) GetGeoNodes() []bootweb.GeoNodeDTO {
	h := p.GetHost()
	if h == nil || p.geoIP == nil || !p.geoIP.Available() {
		return nil
	}
	out := make([]bootweb.GeoNodeDTO, 0)
	for _, pid := range h.Network().Peers() {
		conns := h.Network().ConnsToPeer(pid)
		if len(conns) == 0 {
			continue
		}
		phyIP := directPhysicalIP(conns, nil)
		lat, lon, country, city := p.geoIP.Lookup(phyIP)
		if lat == 0 && lon == 0 {
			continue
		}
		nodeName, _, _, _, _, _, _, _, _, _, _ := p.GetPeerNodeInfo(pid)
		latMs := int64(0)
		if l := h.Peerstore().LatencyEWMA(pid); l > 0 {
			latMs = l.Milliseconds()
		}
		out = append(out, bootweb.GeoNodeDTO{
			PeerID:     pid.String(),
			ShortID:    pid.ShortString(),
			NodeName:   nodeName,
			PhysicalIP: phyIP,
			Country:    country,
			City:       city,
			Lat:        lat,
			Lon:        lon,
			NetworkID:  p.GetPeerNetworkID(pid),
			IsAuthed:   p.IsPeerAuthenticated(pid),
			LatencyMs:  latMs,
		})
	}
	return out
}

func (p *bootDataProviderImpl) GetGeoArcs() []bootweb.GeoArcDTO {
	if p.sessions == nil || p.geoIP == nil || !p.geoIP.Available() {
		return nil
	}
	h := p.GetHost()
	if h == nil {
		return nil
	}
	sessions := p.sessions.GetAll()
	out := make([]bootweb.GeoArcDTO, 0, len(sessions))
	for _, s := range sessions {
		srcConns := h.Network().ConnsToPeer(s.SrcPeer)
		dstConns := h.Network().ConnsToPeer(s.DstPeer)
		if len(srcConns) == 0 || len(dstConns) == 0 {
			continue
		}
		srcIP := directPhysicalIP(srcConns, nil)
		dstIP := directPhysicalIP(dstConns, nil)
		srcLat, srcLon, _, _ := p.geoIP.Lookup(srcIP)
		dstLat, dstLon, _, _ := p.geoIP.Lookup(dstIP)
		if (srcLat == 0 && srcLon == 0) || (dstLat == 0 && dstLon == 0) {
			continue
		}
		srcName, _, _, _, _, _, _, _, _, _, _ := p.GetPeerNodeInfo(s.SrcPeer)
		dstName, _, _, _, _, _, _, _, _, _, _ := p.GetPeerNodeInfo(s.DstPeer)
		out = append(out, bootweb.GeoArcDTO{
			SrcLat:    srcLat,
			SrcLon:    srcLon,
			DstLat:    dstLat,
			DstLon:    dstLon,
			NetworkID: s.NetworkID,
			SrcName:   srcName,
			DstName:   dstName,
		})
	}
	return out
}

func (p *bootDataProviderImpl) GetTrafficHistory() []bootweb.TrafficPoint {
	if p.traffic == nil {
		return nil
	}
	samples := p.traffic.GetAll()
	out := make([]bootweb.TrafficPoint, 0, len(samples))
	for _, s := range samples {
		out = append(out, bootweb.TrafficPoint{
			Time:       s.At.Format("15:04"),
			PeerCount:  s.PeerCount,
			RelayCount: s.RelayCount,
		})
	}
	return out
}

func (p *bootDataProviderImpl) GetHealth(peers []bootweb.PeerItemDTO) bootweb.HealthCheckDTO {
	total := len(peers)
	authed := 0
	orphan := 0
	issues := make([]bootweb.HealthIssue, 0)
	for _, peer := range peers {
		if peer.IsAuthenticated {
			authed++
		}
		if !peer.HasPeekMapStream && !peer.HasBootRelay {
			orphan++
		}
	}
	if orphan > 0 {
		issues = append(issues, bootweb.HealthIssue{
			Severity: "warn",
			Message:  fmt.Sprintf("%d peer(s) connected but have no active stream (handshaking or negotiation failure)", orphan),
		})
	}
	if p.pskEnabled && authed < total {
		issues = append(issues, bootweb.HealthIssue{
			Severity: "warn",
			Message:  fmt.Sprintf("%d peer(s) not authenticated via PSK", total-authed),
		})
	}
	// Check mesh backbone health
	for _, mi := range p.meshInfos {
		h := p.GetHost()
		if h != nil {
			if h.Network().Connectedness(mi.ID) != network.Connected {
				issues = append(issues, bootweb.HealthIssue{
					Severity: "error",
					Message:  fmt.Sprintf("Backbone peer boot %s is currently offline", mi.ID.ShortString()),
				})
			}
		}
	}
	return bootweb.HealthCheckDTO{
		Healthy:     len(issues) == 0,
		TotalPeers:  total,
		AuthedPeers: authed,
		OrphanPeers: orphan,
		Issues:      issues,
	}
}

func (p *bootDataProviderImpl) GetConfigSummary() bootweb.ConfigSummaryDTO {
	listenAddrs := p.listenAddrs
	if listenAddrs == nil {
		listenAddrs = []string{}
	}
	geoAvail := false
	if p.geoIP != nil {
		geoAvail = p.geoIP.Available()
	}
	return bootweb.ConfigSummaryDTO{
		NodeName:        p.nodeName,
		PSKCount:        p.pskCount,
		MeshPeerCount:   len(p.meshInfos),
		ListenAddrs:     listenAddrs,
		RelayTTLSec:     3600,
		SessionLimitSec: 300,
		DataLimitMB:     512,
		GeoIPPath:       p.geoIPPath,
		GeoIPAvailable:  geoAvail,
	}
}

// seqSyncMsg mirrors the JSON wire format used by pkg/node's seqsync protocol.
// Field tags MUST stay in sync with node.SeqSyncMsg; only the fields the boot
// node actually populates are read here, but the same JSON keys are produced.
type seqSyncMsg struct {
	Type       string `json:"t"` // "sync" | "request" | "ack" | "ready"
	NodeID     string `json:"n"` // sender PeerID (string)
	MySeq      uint64 `json:"s"` // next structured SeqID (0 — boot never sends TAP frames)
	ConnEpoch  uint64 `json:"e"` // per-instance epoch for anti-replay
	Timestamp  int64  `json:"ts"`
	ObfEnabled bool   `json:"oe"`  // false: boot performs no per-peer encryption
	ObfAlgos   []byte `json:"oas"` // nil
	ObfMode    string `json:"ob"`  // ""
	ObfPub     []byte `json:"opk"` // nil: encryption disabled

	// Authenticated key exchange fields (node.SeqSyncMsg). Declared for wire
	// format completeness only: the boot node is stateless for seqsync — it
	// never derives a per-peer cipher, so it neither signs nor verifies them.
	// These are left nil, and clients' signatures pass straight through: the
	// relay-ctrl proxy below is byte-transparent, so a tunnelled seqsync keeps
	// its auth fields intact all the way to the target node, which verifies.
	HandshakeVer    uint32 `json:"hv"`
	ObfPubSig       []byte `json:"opksig"`
	ObfPubSignerPub []byte `json:"opksigner"`
}

// handleSeqSyncStream is the boot node's minimal seqsync responder. It speaks
// just enough of the protocol to let a client complete the handshake without
// error: read the client's sync/request, reply with an ack, read the client's
// ready, reply with a ready. The boot node advertises ObfEnabled=false so the
// client's negotiateObfWithPeer falls back to plaintext for the boot peer
// (correct — the boot node never decrypts TAP payloads). We never anchor or
// store any dedup/encryption state; the boot node is stateless for seqsync.
func handleSeqSyncStream(s network.Stream) {
	defer s.Close()
	_ = s.SetDeadline(time.Now().Add(5 * time.Second))

	remotePeer := s.Conn().RemotePeer()
	var req seqSyncMsg
	// Cap the decode: a bare json.NewDecoder(s) would buffer an unbounded
	// JSON value in memory (a peer can stream a multi-GB sync payload before
	// the 5s stream deadline trips), a memory-exhaustion DoS. Mirror the
	// client's readSeqSyncMsg, which caps at io.LimitReader(s, 4096).
	if err := json.NewDecoder(io.LimitReader(s, 4096)).Decode(&req); err != nil {
		log.Debug("[seqsync] read error from %s: %v", remotePeer.String(), err)
		return
	}
	if req.Type != "sync" && req.Type != "request" {
		log.Debug("[seqsync] unexpected msg type %q from %s", req.Type, remotePeer.String())
		return
	}

	// Reject stale messages (replay defense). Only enforced for HandshakeVer >= 2
	// (the timestamp is covered by the message signature). Legacy peers and
	// unsigned messages are accepted.
	if req.Timestamp != 0 && req.HandshakeVer >= 2 {
		age := time.Now().Unix() - req.Timestamp/1000
		if age < 0 {
			age = -age
		}
		if age > 300 { // 5 minutes
			log.Debug("[seqsync] stale message from %s (age %ds)", remotePeer.String(), age)
			return
		}
	}

	// Reply with an ack carrying our identity. MySeq=0 and a fresh random
	// ConnEpoch are sufficient: the boot node issues no TAP frames, so the
	// client's anchorDedupForPeer just records these as the boot peer's window.
	ack := seqSyncMsg{
		Type:       "ack",
		NodeID:     s.Conn().LocalPeer().String(),
		MySeq:      0,
		ConnEpoch:  connEpochBoot(),
		Timestamp:  time.Now().UnixMilli(),
		ObfEnabled: false,
	}
	if err := json.NewEncoder(s).Encode(ack); err != nil {
		log.Debug("[seqsync] ack write to %s failed: %v", remotePeer.String(), err)
		return
	}

	// Await the client's reciprocal "ready", then echo our own ready back so
	// the client's handshake completes. A missing reciprocal is tolerated.
	var ready seqSyncMsg
	// Same cap as above: the reciprocal "ready" must not be an unbounded
	// JSON value either.
	if err := json.NewDecoder(io.LimitReader(s, 4096)).Decode(&ready); err == nil && ready.Type == "ready" {
		// Defense-in-depth: reject stale ready messages.
		if ready.Timestamp != 0 && ready.HandshakeVer >= 2 {
			age := time.Now().Unix() - ready.Timestamp/1000
			if age < 0 {
				age = -age
			}
			if age > 300 {
				log.Debug("[seqsync] stale ready from %s (age %ds)", remotePeer.String(), age)
				return
			}
		}
		_ = json.NewEncoder(s).Encode(seqSyncMsg{
			Type:       "ready",
			NodeID:     s.Conn().LocalPeer().String(),
			Timestamp:  time.Now().UnixMilli(),
			ObfEnabled: false,
		})
	}
	log.Debug("[seqsync] handshake completed with %s", remotePeer.String())
}

// connEpochBoot returns a fresh random 12-bit epoch for this boot instance.
func connEpochBoot() uint64 {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return uint64(binary.BigEndian.Uint32(b[:])) & 0xFFF
}

// computePSKHash derives the 32-byte relay auth token for a configured PSK. It
// delegates to the shared routing.RelayAuthToken so the boot and the node
// cannot derive different tokens for the same key — and so a hex PSK is
// treated case-insensitively on both sides.
func computePSKHash(psk string) [32]byte {
	return routing.RelayAuthToken(psk)
}

// networkIDFromPSK derives the opaque network ID for a PSK. It delegates to the
// shared routing.NetworkIDFromPSK so the boot, the node (for tagging cross-boot
// relay envelopes) and any future consumer all compute the ID identically — a
// mismatch would silently break PSK isolation on relay-over-backbone frames.
func networkIDFromPSK(psk string) string {
	return routing.NetworkIDFromPSK(psk)
}

// pskEntry pairs a PSK's authentication hash with the network ID it maps to. The
// boot server holds one entry per configured PSK; a handshake token is accepted
// if it matches ANY entry, and the matching entry's netID is what the peer is
// then bound to (for both relay ACL and discovery routing).
type pskEntry struct {
	hash  [32]byte
	netID string
	// psk keeps the plaintext PSK alongside its opaque network ID so a first
	// relay can mint the relay-ctrl origin endorsement with the same key bytes
	// a mesh node derives from its own single config PSK. The ACL map itself
	// stores only the net ID, never this.
	psk string
}

// lookupStampPSK returns the SHA-256 PSK key bytes for a network ID, or nil if
// the network is unknown (open mode, or a network this boot does not serve). A
// nil psk means "no stamp exists", which is exactly the PSK-less-mesh
// behaviour, so the relay-ctrl handler needs no special case for open mode.
func lookupStampPSK(entries []pskEntry, netID string) []byte {
	if netID == "" {
		return nil
	}
	for _, e := range entries {
		if e.netID == netID {
			return routing.PSKKeyBytes(e.psk)
		}
	}
	return nil
}

// handleAuthStream handles incoming PSK authentication requests. It validates the
// 32-byte token against EVERY configured PSK (multi-network support): the first
// match wins, and the peer is bound to that PSK's network ID. A peer that fails
// all PSKs is rejected and is left unauthenticated (so it cannot reserve/connect
// and, in discovery-isolation mode, cannot see or be seen by other networks).
func handleAuthStream(s network.Stream, entries []pskEntry, acl *pskACLFilter, h host.Host, hub *peekMapHub, nodeName string) {
	defer s.Close()

	if n := authStreamInflight.Add(1); n > maxAuthStreamsInflight {
		authStreamInflight.Add(-1)
		log.Warn("[auth] rejected auth stream from %s: %d concurrent handshakes in flight (limit %d)",
			s.Conn().RemotePeer().ShortString(), n-1, maxAuthStreamsInflight)
		_, _ = s.Write([]byte{0x00}) // Auth failed response
		return
	}
	defer authStreamInflight.Add(-1)

	// Bound the auth handshake: an unauthenticated peer that opens the stream
	// and sends nothing would otherwise pin this goroutine until the underlying
	// connection is torn down. Reject a stalled handshake.
	_ = s.SetReadDeadline(time.Now().Add(30 * time.Second))

	remotePeer := s.Conn().RemotePeer()
	// manet.ToIP returns the FIRST IP component of the multiaddr, so for a
	// connection that traverses a circuit relay that is the RELAY's public IP,
	// not the client's — banning it would ban every other client routed through
	// the same relay. An attacker behind a shared public relay could therefore
	// DoS all its neighbours by brute-forcing its own token. In that case the IP
	// is not a usable identity key and is dropped from the ban lookup; the
	// per-peer-ID half still applies and a relay cannot forge peer IDs.
	phyIP := ""
	if ma := s.Conn().RemoteMultiaddr(); ma != nil && !maddrutil.IsCircuitRelay(ma) {
		if ip := node.ExtractIP(ma); ip != nil {
			phyIP = ip.String()
		}
	}
	log.Debug("[auth] incoming PSK auth request from %s via %s", remotePeer.String(), s.Conn().RemoteMultiaddr().String())

	// 1. Check if the IP or Peer ID is currently in a temporary ban state due to brute force
	if gSecurity != nil && gSecurity.Auth.IsBanned(phyIP, remotePeer) {
		log.Warn("[auth] connection dropped from banned IP/peer: %s (%s)", remotePeer.ShortString(), phyIP)
		_, _ = s.Write([]byte{0x00})
		return
	}

	// Read 32-byte auth token from peer
	var token [32]byte
	if _, err := io.ReadFull(s, token[:]); err != nil {
		log.Debug("[auth] peer %s sent incomplete auth data: %v", remotePeer.String(), err)
		if gSecurity != nil {
			_, delay := gSecurity.Auth.RecordFailure(phyIP, remotePeer)
			if delay > 0 {
				time.Sleep(delay)
			}
		}
		_, _ = s.Write([]byte{0x00}) // Auth failed response
		return
	}

	// Verify the token against each configured PSK with a constant-time compare
	// so a mismatched PSK does not leak, byte-by-byte via timing, how much of the
	// 32-byte hash matched.
	for _, e := range entries {
		if subtle.ConstantTimeCompare(token[:], e.hash[:]) == 1 {
			// Success! Clear any failure count for this IP/peer
			if gSecurity != nil {
				gSecurity.Auth.RecordSuccess(phyIP, remotePeer)
			}
			// Reply auth success FIRST, before reading the optional version
			// record. The old code read the version record before replying,
			// which meant a client that sends only the token (no version
			// record) would block for the full 30-second read deadline before
			// receiving its 0x01 success reply. This made auth appear to take
			// 30 seconds and caused relay connection timeouts.
			// Best-effort read the peer's version/capability record with a
			// short timeout. An OLD node sends only the 32-byte token and
			// closes, so a short read means "unknown version" — we then
			// authenticate without the extra compatibility gate (the node
			// side does the same, so an old node never gets hard-rejected).
			_ = s.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			var nodeRec version.Record
			_ = nodeRec.ReadRecord(s)

			// PSK matches — assess version/envelope compatibility. A plain build
			// difference with an identical envelope is safe (Warn, allowed); only
			// a genuinely incompatible envelope (no common version) is Danger,
			// and even that is allowed unless StrictVersionCheck is enabled.
			// This gate runs BEFORE AddAuthenticated so a rejected peer is never
			// left in the ACL as "authenticated".
			switch lvl, reason := version.CurrentRecord().CompatibleWith(nodeRec); lvl {
			case version.CompatOK:
				// identical build or unknown peer — nothing to gate on
			case version.CompatWarn:
				log.Warn("[auth] peer %s version differs but safe to connect: %s (peer commit=%s)",
					remotePeer.String(), reason, nodeRec.Commit)
			case version.CompatDanger:
				log.Error("[auth] peer %s version INCOMPATIBLE — risk of silent relay corruption: %s (local commit=%s, peer commit=%s)",
					remotePeer.String(), reason, version.ShortCommit(), nodeRec.Commit)
				if version.StrictVersionCheck {
					bootAlerts.Add("error", "auth_version_mismatch", remotePeer.ShortString(),
						fmt.Sprintf("Peer %s rejected: %s (peer commit=%s)", remotePeer.ShortString(), reason, nodeRec.Commit))
					unauthTracker.Record(unauthTypeAuthFail, remotePeer.ShortString(),
						fmt.Sprintf("Version mismatch: %s (peer commit=%s)", reason, nodeRec.Commit))
					_, _ = s.Write([]byte{0x00}) // Auth failed response
					return
				}
				log.Warn("[auth] peer %s version incompatible but StrictVersionCheck=false — allowing: %s (peer commit=%s)",
					remotePeer.String(), reason, nodeRec.Commit)
			}

			// Version gate passed (or not enforced) — now authenticate.
			acl.AddAuthenticated(remotePeer, e.netID)
			_, _ = s.Write([]byte{0x01}) // Auth success response
			// Hand our version record back so the node can also verify (and so
			// an old node harmlessly sees a closed stream after the 0x01).
			_ = s.SetWriteDeadline(time.Now().Add(5 * time.Second))
			_ = version.CurrentRecord().WriteRecord(s)
			log.Debug("[auth] peer %s authenticated for relay (net=%s)", remotePeer.String(), e.netID)
			bootAlerts.Add("info", "auth_success", remotePeer.ShortString(), fmt.Sprintf("PSK authenticated successfully (network: net=%s)", e.netID))
			// Announce this boot to the freshly authenticated client so it shows
			// up in peer discovery instead of as an "Unnamed Node".
			hub.publishBootInfo(h, nodeName, version.Version)
			return
		}
	}

	// Mismatched PSK: record failure and apply progressive backoff / ban
	log.Debug("[auth] peer %s provided an incorrect PSK (no matching network)", remotePeer.String())
	if gSecurity != nil {
		banned, delay := gSecurity.Auth.RecordFailure(phyIP, remotePeer)
	if banned {
				bootAlerts.Add("error", "auth_banned", remotePeer.ShortString(),
					fmt.Sprintf("🛑 触发防暴力破解封禁: %s (%s) 认证错误过多，临时封禁 5 分钟", remotePeer.ShortString(), phyIP))
				unauthTracker.Record(unauthTypeAuthFail, remotePeer.ShortString(),
					fmt.Sprintf("PSK auth banned: %s (%s) — too many failures", remotePeer.ShortString(), phyIP))
			} else {
				bootAlerts.Add("error", "auth_failed", remotePeer.ShortString(),
					fmt.Sprintf("Peer %s failed PSK authentication (no matching network)", remotePeer.ShortString()))
				unauthTracker.Record(unauthTypeAuthFail, remotePeer.ShortString(),
					"PSK authentication failed (no matching network)")
			}
		if delay > 0 {
			time.Sleep(delay)
		}
	} else {
			bootAlerts.Add("error", "auth_failed", remotePeer.ShortString(),
				fmt.Sprintf("Peer %s failed PSK authentication (no matching network)", remotePeer.ShortString()))
			unauthTracker.Record(unauthTypeAuthFail, remotePeer.ShortString(),
				"PSK authentication failed (no matching network)")
		}
	_, _ = s.Write([]byte{0x00}) // Auth failed response
}

func loadOrGenerateKey(keyPath string) (crypto.PrivKey, error) {
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
		fmt.Printf("Warning: Failed to save key file to %s: %v\n", keyPath, err)
	} else {
		fmt.Printf("[+] Generated new persistent identity key: %s\n", keyPath)
	}

	return priv, nil
}

func printBootstrapBanner(h host.Host, name string, pskEnabled bool, webServer *bootweb.Server) {
	fmt.Println("=========================================================")
	fmt.Println("         p2ptap Standalone Bootstrap Server              ")
	fmt.Println("=========================================================")
	fmt.Printf(" Node Name        : %s\n", name)
	fmt.Printf(" Bootstrap Peer ID : %s\n", h.ID())
	fmt.Println(" Features          : DHT Server, Circuit Relay v2,")
	fmt.Println("                     AutoNAT, Hole Punching")
	if pskEnabled {
		fmt.Println(" Relay Access      : PSK authenticated peers only")
	} else {
		fmt.Println(" Relay Access      : OPEN (no PSK — add a \"psks\" entry to the")
		fmt.Println("                     config file (-c) or set it in the WebUI to")
		fmt.Println("                     restrict relay access to PSK peers)")
	}
	if webServer != nil {
		fmt.Printf(" WebUI Dashboard   : http://%s\n", webServer.GetListenAddr())
		// Token is already printed at startup; avoid repeating it in the banner.
	}
	// Mirror the WebUI dashboard: MaxPerPeer is 1 because libp2p's
	// MaxReservationsPerPeer field is deprecated and never enforced — the limiter
	// removes a peer's old reservation before granting a new one, so 16 was a
	// number we never granted. "none" for the circuit lifetime and data quota:
	// see relayResources for why the boot must not cap either.
	relayLimits := []string{
		"MaxReservations=1024", "MaxCircuits=1024",
		"MaxPerPeer=1", "MaxPerIP=64", "MaxPerASN=256",
		"ReservationTTL=1h", "ConnDuration=none", "ConnData=none",
	}
	fmt.Printf(" Relay Limits      : %s\n", strings.Join(relayLimits, ", "))
	fmt.Println(" Copy-paste any of the following Multiaddrs into your")
	fmt.Println(" p2ptap 'bootstrap_peers' configuration list:")
	fmt.Println("---------------------------------------------------------")
	for _, a := range h.Addrs() {
		fmt.Printf("   \"%s/p2p/%s\",\n", a.String(), h.ID())
	}
	fmt.Println("=========================================================")
}

// relayResources builds the circuit relay's resource envelope. It is extracted
// from main() so the envelope can be asserted in tests: the one value that must
// not change is Limit, and a regression there was invisible from the relay's
// advertised capacity.
func relayResources() relay.Resources {
	relayRes := relay.DefaultResources()
	relayRes.ReservationTTL = 1 * time.Hour
	relayRes.MaxReservations = relayMaxReservations
	relayRes.MaxCircuits = relayMaxCircuits
	// Note: relay.Resources.MaxReservationsPerPeer is deliberately NOT set. It is
	// marked Deprecated in libp2p ("We only need 1 reservation per peer") and the
	// field is never read by any limiter — constraints.Reserve removes the peer's
	// existing reservation before appending the new one, so the enforced per-peer
	// cap is 1 regardless of this value. Setting it to 16 here made the WebUI
	// advertise 16 reservations per peer that the relay could never grant.
	relayRes.MaxReservationsPerIP = 64
	// MaxReservationsPerASN is left at libp2p's default of 32, which means all
	// peers behind a single ISP ASN (office networks, CGNAT, mobile carriers)
	// share a 32-slot pool. A boot serving many peers on one ISP exhausts this
	// and denies reservations silently — the denial comes from libp2p's resource
	// limiter, not pskACLFilter, so it doesn't appear in the WebUI alerts.
	// Override with a generous value. Note constraints.Reserve applies the ASN
	// cap to IPv6 reservations only (it gates on ip.To4() == nil), so IPv4
	// clients are bounded by MaxReservationsPerIP instead.
	relayRes.MaxReservationsPerASN = 256
	// BufferSize defaults to 2048 bytes per relayed connection, which throttles
	// throughput on high-bandwidth links. Raise it for a dedicated relay.
	relayRes.BufferSize = relayBufferSize
	// No per-circuit Duration or Data limit. A non-nil Limit makes the relay do
	// s.SetDeadline(now+Duration) and bs.SetDeadline(now+Duration) on both
	// directions of every relayed connection and wrap each direction in
	// io.LimitReader(..., Data); there is no circuit-renewal message in relay v2,
	// so a circuit simply dies. 5 minutes capped every p2ptap peer-to-peer
	// session riding on a circuit, and 512 MiB filled in seconds on a gigabit
	// link. The reservation TTL above is unrelated: it bounds how long a
	// reservation is offered, not how long a circuit may live.
	//
	// Nil is the correct answer for a dedicated PSK relay — the resource the
	// limit was throttling is exactly the resource the relay exists to serve,
	// and abuse is already bounded at reservation time (the PSK ACL, the
	// MaxReservations / PerIP / PerASN pools) and by the resource manager's
	// memory, fd and stream ceilings. Acceptable cost: a hostile peer can now
	// hold its reservations and circuits open indefinitely, so it can occupy up
	// to MaxReservationsPerIP slots forever instead of losing them after 5
	// minutes. That is the right trade for this service.
	relayRes.Limit = nil
	return relayRes
}

// relayResourceManager builds the resource manager for this relay.
//
// libp2p's default resource manager auto-scales EVERY limit off totalMemory/8,
// so on a small host the system connection cap collapses far below the
// connection manager's high water mark: 1974 MB of RAM yields 158 connections
// against a high water mark of 8192. libp2p then logs
// "rcmgr limit conflicts with connmgr limit" and enforces the LOWER of the
// two, so 158 becomes the real ceiling and the envelope this relay was tuned
// for is unreachable.
//
// The system connection envelope is therefore pinned to relayConnHighWater, the
// same number handed to the connection manager, so the two cannot silently
// disagree. Everything else stays auto-scaled: memory, fd and all per-peer /
// per-protocol limits keep their host-derived backstops, so an uncooperative
// peer still cannot exhaust the box.
//
// The stream ceilings are the same disease in the stream dimension, and they
// are pinned too. Streams are limited at THREE levels, all of them auto-scaled
// off memory, and all three must clear MaxCircuits for a circuit to be granted:
// on a 1974 MB host the relay service caps streams at 317 and each circuit
// protocol at 793, so the relay refused circuits at 317 while the WebUI still
// reported MaxCircuits=1024. Only per-Peer caps stay auto-scaled on purpose:
// they are the fairness guard that keeps one peer from taking the whole relay.
func relayResourceManager() (network.ResourceManager, error) {
	scaling := rcmgr.DefaultLimits
	// The same per-service / per-protocol limits the default resource manager
	// installs (identify, ping, autonat, holepunch, circuit relay). Without
	// them the relay service would fall back to the generic stream limits.
	libp2p.SetDefaultServiceLimits(&scaling)

	// System memory and fd stay auto-scaled: they are the OOM and fd backstops.
	system := rcmgr.ResourceLimits{
		Conns:           relayConnHighWater,
		ConnsInbound:    relayConnHighWater,
		ConnsOutbound:   relayConnHighWater,
		Streams:         2 * relayStreamPerDir,
		StreamsInbound:  relayStreamPerDir,
		StreamsOutbound: relayStreamPerDir,
	}
	// The relay service and the two circuit protocols are subsets of system
	// streams, so they need the same envelope, and their memory too -- at the
	// auto-scaled 19 MiB the memory limit would become the new silent cap
	// immediately after the stream limit is raised.
	circuits := rcmgr.ResourceLimits{
		Streams:         2 * relayStreamPerDir,
		StreamsInbound:  relayStreamPerDir,
		StreamsOutbound: relayStreamPerDir,
		Memory:          rcmgr.LimitVal64(relayCircuitMemory),
	}
	limits := rcmgr.PartialLimitConfig{
		System:  system,
		Service: map[string]rcmgr.ResourceLimits{relay.ServiceName: circuits},
		Protocol: map[protocol.ID]rcmgr.ResourceLimits{
			circuit.ProtoIDv2Hop:  circuits,
			circuit.ProtoIDv2Stop: circuits,
		},
	}.Build(scaling.AutoScale())
	return rcmgr.NewResourceManager(rcmgr.NewFixedLimiter(limits))
}

// verifyListeners reports every configured listen address that did not actually
// bind, so a silently missing listener can never again look like a healthy boot.
//
// Without this check the failure is invisible end to end: swarm.Listen logs one
// failed address at Warn and returns an error only when *every* address fails,
// so libp2p.New succeeds, the relay banner prints, and the server accepts peers
// on the transports that did bind. That is exactly how this boot lost its /tcp/
// and /quic-v1/webtransport/ listeners — the config asked for four protocols and
// the process reported no problem at all.
//
// Matching is on transport + port, not IP, because a wildcard configured address
// (/ip4/0.0.0.0, /ip6/::) is bound per physical interface and is reported with
// NIC IPs. An IP comparison would flag every wildcard listener as missing.
//
// Callers pass the addrs that already passed ValidateListenAddr: an addr that
// was rejected at parse time can never bind, and warning twice about it would
// only bury the real signal.
func verifyListeners(configured []multiaddr.Multiaddr) {
	boundMu.Lock()
	bound := make([]multiaddr.Multiaddr, 0, len(boundAddrs))
	seen := make(map[string]struct{}, len(boundAddrs))
	for _, a := range boundAddrs {
		if _, dup := seen[a.String()]; dup {
			continue
		}
		seen[a.String()] = struct{}{}
		bound = append(bound, a)
	}
	boundMu.Unlock()

	for _, want := range configured {
		wf, wp := transportAndPort(want)
		if wf == "" {
			continue
		}
		boundIt := false
		for _, got := range bound {
			gf, gp := transportAndPort(got)
			if gf == wf && wp != "" && wp == gp {
				boundIt = true
				break
			}
		}
		if !boundIt {
			log.Warn("configured listen address %q did not bind — no listener came up for it. Check that the port is free and that the transport layering is right (WebTransport needs /udp/<port>/quic-v1/webtransport, WebRTC needs /udp/<port>/webrtc-direct).", want)
		}
	}
}

// transportAndPort returns the transport family and port of a listen address.
func transportAndPort(a multiaddr.Multiaddr) (family, port string) {
	family = node.TransportOf(a)
	if p, _ := a.ValueForProtocol(multiaddr.P_TCP); p != "" {
		port = p
	} else if p, _ := a.ValueForProtocol(multiaddr.P_UDP); p != "" {
		port = p
	}
	return family, port
}

// relayKeepaliveLoop periodically echo-pings every currently connected peer to
// keep NAT/firewall UDP mappings open and to surface dead connections.
//
// Why this matters for relay robustness: circuitv2's relay refuses to dial the
// destination (status 203 / CONNECTION_FAILED) unless the destination currently
// has a LIVE connection to the relay — the relay never proactively dials the
// destination itself (network.WithNoDial). If a destination sits idle behind a
// NAT, its UDP mapping is silently expired and the relay's NewStream(dest) fails
// with 203 even though the reservation is still valid. By pinging connected
// peers on a steady cadence we hold those mappings open and turn a hard 203 into
// a quick self-heal. Combined with the ConnManager Protect() in the connection
// Notifiee, relay links stay warm indefinitely.
//
// Only peers that are ALREADY connected are pinged (h.Network().Peers() returns
// connected peers), so this never triggers an outbound dial to a NAT'd peer that
// can't be reached — such a peer must reconnect from its own side.
// writeFrame/readFrame mirror pkg/node/framing.go EXACTLY: a 4-byte big-endian
// length prefix followed by the payload. The relay and the p2ptap client must
// speak the identical /p2ptap/echo/1.0.0 framing, otherwise the client's
// handleEcho mis-reads the first 4 bytes of a bare "PING" (0x50494E47 =
// 1346981447) as a 1.3 GB frame length and logs "frame too large". Keep these
// in sync with pkg/node/framing.go.
func writeFrame(w io.Writer, data []byte) error {
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(data)))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return err
	}
	if _, err := w.Write(data); err != nil {
		return err
	}
	return nil
}

func readFrame(r io.Reader, buf []byte) (int, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return 0, err
	}
	frameLen := binary.BigEndian.Uint32(lenBuf[:])
	if frameLen == 0 {
		return 0, nil
	}
	if frameLen > uint32(len(buf)) {
		return 0, fmt.Errorf("frame too large: %d > %d", frameLen, len(buf))
	}
	if _, err := io.ReadFull(r, buf[:frameLen]); err != nil {
		return 0, err
	}
	return int(frameLen), nil
}

// makePeekMapHandler builds the server side of the peek-map pub/sub channel:
// register the caller as a listener, then rebroadcast everything it publishes to
// the other listeners.
//
// Extracted from main so the boot-backbone behaviour can be exercised in tests
// with real hosts.
func makePeekMapHandler(h host.Host, hub *peekMapHub, nodeName string, acl *pskACLFilter) func(network.Stream) {
	return func(s network.Stream) {
		remotePeer := s.Conn().RemotePeer()

		// PSK auth gate: refuse to register an unauthenticated peer as a
		// listener. Without this, any peer that advertises the peek-map
		// protocol can receive topology broadcasts from ALL other clients
		// (including cross-network peers when the resolver is nil), leaking
		// the entire mesh topology to a non-member.
		if acl != nil && !acl.RequireAuth(remotePeer) {
				log.Warn("[peek-map] refusing unauthenticated peer %s", remotePeer.ShortString())
				bootAlerts.Add("warn", "unauth_peek_map", remotePeer.ShortString(),
					fmt.Sprintf("Peer %s opened peek-map without PSK auth; connection refused", remotePeer.ShortString()))
				unauthTracker.Record(unauthTypePeekMap, remotePeer.ShortString(),
					"Peek-map connection refused: unauthenticated peer")
				_ = s.Close()
				return
			}

		hub.register(remotePeer, s)
		// Announce this boot node to the freshly connected client (and, since
		// broadcast fans out to all clients, to everyone else too) so the boot
		// shows up in peer discovery instead of as an "Unnamed Node".
		hub.publishBootInfo(h, nodeName, version.Version)
		bootAlerts.Add("info", "peek_map_join", remotePeer.ShortString(),
			fmt.Sprintf("Peek-map topology subscription joined: %s", remotePeer.ShortString()))
		defer func() {
			hub.unregisterStream(remotePeer, s)
			bootAlerts.Add("info", "peek_map_leave", remotePeer.ShortString(),
				fmt.Sprintf("Peek-map topology subscription left: %s", remotePeer.ShortString()))
			_ = s.Close()
		}()

		// Streaming JSON decoder: the client sends newline-delimited
		// PeekMapMessage values via json.NewEncoder(s).Encode, which may arrive
		// split across reads OR several values coalesced into one TCP segment.
		// A naive s.Read + json.Unmarshal only parsed the FIRST value and
		// dropped the tail (or failed on a split value), silently losing
		// peer-discovery updates. json.NewDecoder handles both cases correctly.
		//
		// Each incoming message is capped (and given a generous per-message read
		// deadline) so a single client cannot pin this goroutine with a stalled
		// partial JSON value, nor blow up memory by sending a multi-gigabyte
		// payload that we would then rebroadcast to every other client
		// (amplification). Oversized/garbled messages make Decode fail and the
		// listener stream is closed.
		//
		// The cap is enforced at the reader level (cappedMsgReader) so that the
		// JSON decoder never allocates more than peekMapMaxJSONBytes per
		// message, regardless of what the client sends. The post-decode
		// len(msg.Payload) > 64*1024 check below is a secondary guard that
		// catches messages whose decoded payload exceeds the broadcast limit
		// (the JSON envelope + base64 encoding can make the wire size smaller
		// than the decoded payload size).
		capped := &cappedMsgReader{src: s, limit: peekMapMaxJSONBytes}
		dec := json.NewDecoder(capped)
		for {
			_ = s.SetReadDeadline(time.Now().Add(5 * time.Minute))
			capped.reset()
			var msg PeekMapMessage
			if err := dec.Decode(&msg); err != nil {
				log.Debug("[peek-map] listener for %s closed: %v", remotePeer.ShortString(), err)
				return
			}
			// Message payload size limit (max 64KB per message to prevent memory/broadcast amplification)
			if len(msg.Payload) > 64*1024 {
				log.Warn("[peek-map] payload exceeds 64KB limit from %s (%d bytes); dropping", remotePeer.ShortString(), len(msg.Payload))
				continue
			}
			// Token-bucket rate limiting for direct peers to prevent broadcast storming
			if gSecurity != nil && !hub.isMesh(remotePeer) && !gSecurity.PeekMap.Allow(remotePeer) {
				log.Debug("[peek-map] rate limit exceeded for peer %s, dropping update", remotePeer.ShortString())
				continue
			}
			// Re-stamp the sender so receivers trust the source, then rebroadcast
			// to every other client.
			msg.From = remotePeer.String()

			// Network isolation (PSK mode only). In open mode netResolver is nil
			// and deliverNetID stays "", which means "no filtering" — the original
			// behaviour. In PSK mode:
			//   - a frame from a BACKBONE boot keeps the NetID it was stamped with
			//     by the origin boot's local client (we never re-derive it from the
			//     mesh peer itself), then is delivered to this boot's LOCAL clients
			//     of that network only;
			//   - a frame from a LOCAL client is dropped unless it has authenticated
			//     (unauthenticated peers must not learn or pollute any network's
			//     topology), and is otherwise tagged with that client's network and
			//     delivered to same-network local clients AND the backbone.
			var deliverNetID string
			if hub.isMesh(remotePeer) {
				deliverNetID = msg.NetID
			} else if hub.netResolver != nil {
				netID := hub.netResolver(remotePeer)
				if netID == "" {
					// The /p2ptap/auth and /p2ptap/peek-map streams are opened
					// concurrently by the client so this UPDATE frame can arrive
					// before handleAuthStream has called AddAuthenticated. Wait up
					// to 3 s (polling every 50 ms) for auth to complete rather than
					// dropping the frame immediately. In practice auth finishes in
					// < 10 ms so the very first 50 ms sleep resolves the race.
					deadline := time.Now().Add(3 * time.Second)
					for netID == "" && time.Now().Before(deadline) {
						time.Sleep(50 * time.Millisecond)
						netID = hub.netResolver(remotePeer)
					}
					if netID == "" {
						log.Debug("[peek-map] drop unauthenticated frame from %s (auth deadline exceeded)", remotePeer.ShortString())
						bootAlerts.Add("warn", "unauth_frame", remotePeer.ShortString(), fmt.Sprintf("Peer %s unauthenticated; topology broadcast frame dropped", remotePeer.ShortString()))
						continue
					}
				}
				msg.NetID = netID
				deliverNetID = netID
			}

			// Cache client node info for WebUI display
			if msg.Type == PeekMapUpdate && len(msg.Payload) > 0 {
				var info clientNodeInfo
				if err := json.Unmarshal(msg.Payload, &info); err == nil {
					peerInfoCache.Store(remotePeer, info)
				}
			}

			frame, err := json.Marshal(msg)
			if err != nil {
				log.Debug("[peek-map] marshal failed for %s: %v", remotePeer.ShortString(), err)
				continue
			}
			// Each boot traversal is one relay hop: increment hop_distance so a
			// cascaded boot (a boot that is itself a client of this boot) can
			// accumulate depth and build a multi-level interconnect tree.
			frame = incrementPeekMapHop(frame)
			// A frame arriving FROM a backbone boot must not be pushed back onto
			// the backbone, or a full mesh of boots would circulate it forever.
			if hub.isMesh(remotePeer) {
				hub.broadcastToLocalOnly(frame, deliverNetID)
				continue
			}
			hub.broadcast(frame, remotePeer, deliverNetID)
		}
	}
}

// parseMeshPeers turns the -mesh flag into one AddrInfo per DISTINCT peer boot.
//
// Two operational details matter here:
//   - Multiple addresses for the SAME boot (e.g. its QUIC and its TCP address)
//     must be merged into one AddrInfo. Treating them as separate entries would
//     open two uplink streams to one boot, doubling every forwarded frame for
//     that cluster's clients.
//   - Listing THIS boot in its own -mesh (a very easy copy/paste mistake when
//     the same flag string is deployed to every boot) must be ignored rather
//     than producing a self-dial that fails forever in the retry loop.
func parseMeshPeers(spec string, self peer.ID) []peer.AddrInfo {
	if strings.TrimSpace(spec) == "" {
		return nil
	}
	merged := make(map[peer.ID][]multiaddr.Multiaddr)
	order := make([]peer.ID, 0, 4)
	for _, raw := range strings.Split(spec, ",") {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			continue
		}
		ma, err := multiaddr.NewMultiaddr(entry)
		if err != nil {
			fmt.Printf("[mesh] Warning: invalid multiaddr %q skipped: %v\n", entry, err)
			continue
		}
		info, err := peer.AddrInfoFromP2pAddr(ma)
		if err != nil {
			fmt.Printf("[mesh] Warning: multiaddr %q has no /p2p/<id> component, skipped: %v\n", entry, err)
			continue
		}
		if info.ID == self {
			fmt.Printf("[mesh] Note: skipping self (%s) in mesh list\n", self.ShortString())
			continue
		}
		if _, seen := merged[info.ID]; !seen {
			order = append(order, info.ID)
		}
		merged[info.ID] = append(merged[info.ID], info.Addrs...)
	}
	out := make([]peer.AddrInfo, 0, len(order))
	for _, id := range order {
		out = append(out, peer.AddrInfo{ID: id, Addrs: merged[id]})
	}
	return out
}

// meshUplinkLoop keeps a peek-map subscription open to ONE peer boot, so the
// two clusters exchange peer discovery.
//
// This boot acts as an ordinary peek-map CLIENT of the remote boot: it opens a
// /p2ptap/peek-map/1.0.0 stream, publishes its own boot identity once, then
// reads the remote hub's rebroadcasts forever. Each frame is re-stamped with one
// extra hop_distance (traversing this boot IS a relay hop, exactly like the
// server-side handler does) and injected into the local hub for local clients
// only.
//
// The remote side symmetrically subscribes to us, so both directions flow. We do
// NOT need to forward anything up this stream beyond our own identity: frames
// travel toward the remote cluster through the remote boot's own subscription,
// where we are just another listener in our hub's fanout.
//
// Reconnect uses exponential backoff capped at 60s so a boot that is temporarily
// down does not turn into a dial storm, and a permanently misconfigured entry
// costs one goroutine parked on a long sleep.
func meshUplinkLoop(ctx context.Context, h host.Host, hub *peekMapHub, info peer.AddrInfo, selfName string) {
	backoff := 250 * time.Millisecond
	const maxBackoff = 30 * time.Second
	for {
		if ctx.Err() != nil {
			return
		}
		err := runMeshUplink(ctx, h, hub, info, selfName)
		if ctx.Err() != nil {
			return
		}
		jitter := time.Duration(mathrand.Int64N(int64(250 * time.Millisecond)))
		sleepDur := backoff + jitter
		log.Debug("[mesh] uplink to %s ended (%v), retrying in %v", info.ID.ShortString(), err, sleepDur)
		select {
		case <-ctx.Done():
			return
		case <-time.After(sleepDur):
		}
		if backoff < maxBackoff {
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		}
	}
}

// runMeshUplink performs one connect+subscribe+pump cycle. It returns when the
// stream dies, so the caller can back off and retry.
func runMeshUplink(ctx context.Context, h host.Host, hub *peekMapHub, info peer.AddrInfo, selfName string) error {
	h.Peerstore().AddAddrs(info.ID, info.Addrs, peerstore.PermanentAddrTTL)

	// Break simultaneous-dial collision between peer boots
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(time.Duration(mathrand.Int64N(int64(150 * time.Millisecond)))):
	}

	dialCtx, cancelDial := context.WithTimeout(ctx, 20*time.Second)
	defer cancelDial()
	if err := h.Connect(dialCtx, info); err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	// A backbone link must never be trimmed by the ConnManager: losing it
	// silently splits the two clusters' discovery.
	h.ConnManager().Protect(info.ID, "mesh-boot")

	s, err := h.NewStream(ctx, info.ID, PeekMapProtocolID)

	if err != nil {
		return fmt.Errorf("open peek-map stream: %w", err)
	}
	defer s.Close()
	fmt.Printf("[mesh] Backbone uplink established to boot %s\n", info.ID.String())

	// Publish our own identity upstream so the REMOTE cluster's clients can see
	// this boot. The remote handler re-stamps From to our peer ID and fans it
	// out to its clients.
	selfInfo := bootNodeInfo{
		PeerID:   h.ID().String(),
		NodeName: selfName,
		OS:       runtime.GOOS,
		Arch:     runtime.GOARCH,
		Version:  version.Version,
		// 0 = "this is the source"; the remote boot increments it to 1 as it
		// forwards, so its clients record a one-hop boot edge.
		HopDistance: 0,
		// Endpoints + the boot marker are what let the REMOTE cluster's clients
		// attach to us, giving both clusters a shared relay anchor.
		Addrs:  node.MultiaddrsToStrings(h.Addrs()),
		IsBoot: true,
	}
	if payload, merr := json.Marshal(selfInfo); merr == nil {
		msg := PeekMapMessage{Type: PeekMapUpdate, From: h.ID().String(), Payload: payload}
		_ = s.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if err := json.NewEncoder(s).Encode(msg); err != nil {
			return fmt.Errorf("publish self: %w", err)
		}
		_ = s.SetWriteDeadline(time.Time{})
	}

	// Pump the remote hub's rebroadcasts into our local hub.
	dec := json.NewDecoder(s)
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		// The remote hub is idle-quiet between client updates; allow a long gap
		// but not forever, so a half-open TCP connection is eventually noticed.
		_ = s.SetReadDeadline(time.Now().Add(10 * time.Minute))
		var msg PeekMapMessage
		if err := dec.Decode(&msg); err != nil {
			return fmt.Errorf("read: %w", err)
		}
		// Never re-inject our own identity if it echoes back.
		if msg.From == h.ID().String() {
			continue
		}
		frame, err := json.Marshal(msg)
		if err != nil {
			continue
		}
		// Crossing THIS boot is one more relay hop for the receiving clients.
		frame = incrementPeekMapHop(frame)
		// Propagate the origin network so the local delivery filter keeps the
		// frame inside the same PSK network it came from.
		hub.broadcastToLocalOnly(frame, msg.NetID)
	}
}

func relayKeepaliveLoop(ctx context.Context, h host.Host, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for _, p := range h.Network().Peers() {
				if p == h.ID() {
					continue
				}
				go func(p peer.ID) {
					pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
					defer cancel()
					s, err := h.NewStream(pingCtx, p, echoProtocolID)
					if err != nil {
						// Peer not reachable on its current connection; it will
						// reconnect from its side if it still wants relay access.
						return
					}
					defer s.Close()
					// The p2ptap client's echo handler (handleEcho) reads a
					// length-prefixed frame ([4-byte BE length][payload]) — see
					// pkg/node/framing.go. Send a properly framed PING so the
					// client can parse and echo it back; a bare s.Write("PING")
					// makes the client read those 4 bytes as a 1.3 GB length and
					// log "frame too large: 1346981447 > 64". The relay's own
					// echo handler stays io.Copy(s, s), which reflects the framed
					// bytes verbatim and works for either direction.
					start := time.Now()
					if err := writeFrame(s, []byte("PING")); err != nil {
						return
					}
					_ = s.SetReadDeadline(time.Now().Add(3 * time.Second))
					buf := make([]byte, 16)
					if _, err := readFrame(s, buf); err != nil {
						log.Debug("[keepalive] echo ping to %s returned no reply: %v", p.ShortString(), err)
						return
					}
					rtt := time.Since(start)
					h.Peerstore().RecordLatency(p, rtt)
				}(p)
			}
		}
	}
}

// runMaintenanceSweeper runs periodic garbage collection and stale-state pruning
// to guarantee bounded memory usage and prevent resource leaks during long-term (24/7/365) running.
func runMaintenanceSweeper(ctx context.Context, h host.Host, acl *pskACLFilter, hub *peekMapHub, sessions *sessionTracker) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := time.Now()

			// 1. Prune relayAllowedDedup & relayDeniedDedup entries older than 30 seconds
			relayAllowedDedup.Range(func(key, val any) bool {
				if t, ok := val.(time.Time); ok {
					if now.Sub(t) > 30*time.Second {
						relayAllowedDedup.Delete(key)
					}
				}
				return true
			})
			relayDeniedDedup.Range(func(key, val any) bool {
				if t, ok := val.(time.Time); ok {
					if now.Sub(t) > 30*time.Second {
						relayDeniedDedup.Delete(key)
					}
				}
				return true
			})

			// 2. Prune expired relay sessions (> 10 minutes)
			if sessions != nil {
				sessions.PruneStale(10 * time.Minute)
			}

			// 3. Collect active connected peers set
			connectedMap := make(map[peer.ID]bool)
			for _, p := range h.Network().Peers() {
				if h.Network().Connectedness(p) == network.Connected {
					connectedMap[p] = true
				}
			}

			// 4. Sweep orphan peerInfoCache entries
			peerInfoCache.Range(func(key, _ any) bool {
				if pid, ok := key.(peer.ID); ok {
					if !connectedMap[pid] {
						peerInfoCache.Delete(pid)
						h.Peerstore().ClearAddrs(pid)
					}
				}
				return true
			})

			// 5. Sweep orphan gPeerConnectTimes entries
			gPeerConnectTimes.Range(func(key, _ any) bool {
				if pid, ok := key.(peer.ID); ok {
					if !connectedMap[pid] {
						gPeerConnectTimes.Delete(pid)
					}
				}
				return true
			})

			// 6. Sweep disconnected ACL auth map entries
			if acl != nil {
				acl.mu.Lock()
				for pid := range acl.netOf {
					if !connectedMap[pid] {
						delete(acl.netOf, pid)
					}
				}
				acl.mu.Unlock()
			}

			// 7. Sweep dead peek-map listener entries
			if hub != nil {
				hub.mu.Lock()
				for pid := range hub.listener {
					if !connectedMap[pid] {
						delete(hub.listener, pid)
					}
				}
				hub.mu.Unlock()
			}

			// 8. Sweep security rate limiters and expired bans
			if gSecurity != nil {
				gSecurity.Cleanup()
			}
		}
	}
}
