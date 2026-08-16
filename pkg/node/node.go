package node

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/fnv"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	libp2pconnmgr "github.com/libp2p/go-libp2p/core/connmgr"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/libp2p/go-libp2p/core/pnet"
	tpt "github.com/libp2p/go-libp2p/core/transport"
	"github.com/libp2p/go-libp2p/p2p/discovery/mdns"
	yamux "github.com/libp2p/go-libp2p/p2p/muxer/yamux"
	quict "github.com/libp2p/go-libp2p/p2p/transport/quic"
	quicreuse "github.com/libp2p/go-libp2p/p2p/transport/quicreuse"
	webrtc "github.com/libp2p/go-libp2p/p2p/transport/webrtc"
	webtransport "github.com/libp2p/go-libp2p/p2p/transport/webtransport"
	tcpt "github.com/libp2p/go-libp2p/p2p/transport/tcp"
	"github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr/net"
	quic "github.com/quic-go/quic-go"

	"p2ptap/pkg/config"
	"p2ptap/pkg/logger"
	"p2ptap/pkg/meta"
	"p2ptap/pkg/obfuscate"
	"p2ptap/pkg/observer"
	"p2ptap/pkg/routing"
	vswitch "p2ptap/pkg/switch"
	"p2ptap/pkg/tap"
)

var log = logger.New("Node")

type PeerMeta struct {
	NodeName          string    `json:"node_name"`
	TapIP             string    `json:"tap_ip"`
	TapIPv6           string    `json:"tap_ipv6"`
	TapMAC            string    `json:"tap_mac"`
	OSArch            string    `json:"os_arch"`
	Version           string    `json:"version"`
	UptimeSec         int64     `json:"uptime_sec"`
	Reachability      string    `json:"reachability"`
	IsExitNode        bool      `json:"is_exit_node"`
	ExitNAT           bool      `json:"exit_nat"`
	TxSpeed           uint64    `json:"tx_speed"`
	RxSpeed           uint64    `json:"rx_speed"`
	TotalTx           uint64    `json:"total_tx"`
	TotalRx           uint64    `json:"total_rx"`
	AdvertisedSubnets []string  `json:"advertised_subnets"`
	SyncSource        string    `json:"sync_source"`
	LastSync          time.Time `json:"last_sync"`
}

type Node struct {
	Host         host.Host
	DHT          *dht.IpfsDHT
	Config       *config.Config
	TAP          tap.TAPDevice
	MACTable     *vswitch.ShardedMACTable
	Packer       *obfuscate.FramePacker
	dedupPeers   map[peer.ID]*obfuscate.Deduplicator
	dedupPeersMu sync.RWMutex
	// peerLocalEpochs holds the PER-PEER anti-replay epoch this node stamps into
	// the SeqID of every frame it sends to each remote peer. Unlike the old
	// single node-wide conn epoch, rotating the epoch for ONE reconnecting peer
	// (refreshEpochOnReconnect) only mutates that peer's entry here — the dedup
	// windows of every OTHER peer are untouched, so a reconnect of peer A never
	// disrupts B or C. The epoch is independent of the negotiated cipher and is
	// re-anchored on the peer during every SeqSync handshake / lightweight
	// epochSync.
	peerLocalEpochs sync.Map       // peer.ID -> uint64 (12-bit epoch)
	bcastDedup      bcastDedupRing // content-based dedup for bcast/mcast frames from multiple peers
	Dispatcher      *StrategyDispatcher
	// Collector is the WebUI telemetry sink. It is an interface (observer.Collector)
	// so the domain core never imports the concrete web package.
	Collector observer.Collector
	// WebSrv is the running WebUI server, exposed only through its Shutdown method.
	WebSrv observer.WebServer
	// Interceptor is the userspace TAP interceptor (WebUI virtual-IP handling),
	// injected by the cmd layer so node stays free of the web package.
	Interceptor observer.FrameFilter
	// WebUI wiring hooks injected by cmd to keep node from importing web directly.
	MakeCollector          func() observer.Collector
	MakeInterceptor        func(virtualIP, virtualIPv6 string, port int, collector observer.Collector, cfg *config.Config, cfgPath string) observer.FrameFilter
	StartWebServer         func(collector observer.Collector, bindIP, bindIPv6 string, port int, cfg *config.Config, cfgPath string, socketProtectHook func(network, address string, c syscall.RawConn) error) (observer.WebServer, error)
	IPTracker              *IPTrafficTracker
	Router                 *routing.Router
	Gateway                *GatewayManager
	NFTManager             *NFTManager
	virtualWebUIV4IP       net.IP
	virtualWebUIV4IPUint32 uint32
	virtualWebUIV6IP       net.IP
	localV4IP              net.IP
	localV4Net             *net.IPNet
	localV6IP              net.IP
	localV6Net             *net.IPNet
	localMAC               net.HardwareAddr
	peerMeta               sync.Map
	// arpIndex is a read-optimized, parse-free view of peerMeta for O(1) IP→peer
	// resolution used by the ARP/NDP proxy and the unicast-fallback path. It is
	// rebuilt on every peerMeta mutation (store/delete) so it stays consistent;
	// lookups never parse CIDRs or MACs, eliminating the per-packet allocation
	// and parsing that the previous peerMeta.Range() scans performed.
	arpIndexMu sync.RWMutex
	arpIndex   *arpIndex
	// dupIPConflicts holds the currently detected duplicate-IP / duplicate-subnet
	// conflicts and their arbitration verdicts (see dup_ip_arbitration.go). It is
	// rebuilt alongside arpIndex on every topology change and surfaced via
	// GetDuplicateIPConflicts for alerting/observability.
	dupIPConflictsMu    sync.Mutex
	dupIPConflicts      []DuplicateIPConflict
	cachedRoutesMu      sync.RWMutex
	cachedRoutes        map[peer.ID]routing.RouteInfo
	cachedRoutesAt      time.Time
	relayLatencyMu      sync.RWMutex
	relayLatency        map[peer.ID]time.Duration // per-relay-peer RTT cache
	relayAuthMu         sync.Mutex
	relayAuthInProgress map[peer.ID]bool // dedup ConnectedF-triggered relay auth per peer

	// relayOnlyPeers tracks peers whose ONLY working path is a circuit relay
	// (e.g. mDNS-discovered peers on a private subnet we cannot reach directly).
	// Such peers must be dialed relay-first (Fix 1) and kept alive (Fix 2) so
	// their end-to-end circuit is not silently cut on idle.
	relayOnlyMu    sync.RWMutex
	relayOnlyPeers map[peer.ID]bool
	// relayCtrlSyncAt records the last time the relay-control reconciler kicked
	// a control-plane sync (SeqSync + Meta) for a relay-only peer, so it can
	// apply a per-peer cooldown instead of re-triggering every tick.
	relayCtrlSyncAt sync.Map
	ctx                 context.Context
	cancel              context.CancelFunc
	wg                  sync.WaitGroup
	// closeOnce makes Close idempotent; it can be invoked from the signal
	// handler, the tray UI and the web shutdown endpoint concurrently.
	closeOnce sync.Once

	// --- Roam (network interface change) handling ---
	// netMon watches OS link/address changes; roamDeb coalesces them into a
	// debounced reconcile that re-binds libp2p listeners to the current NIC
	// set and refreshes the cached egress interface. Long-lived listen sockets
	// are rotated (not restarted), so in-flight peer connections survive a roam.
	netMon            NetMon
	roamDeb           *roamDebouncer
	roamCancel        context.CancelFunc
	parsedListenAddrs []multiaddr.Multiaddr
	parsedListenMu    sync.Mutex

	// Bounded dispatch worker pool to prevent unbounded goroutine explosion
	// in the TAP-to-P2P forwarding path (was root cause of 75% ICMP packet loss).
	dispatchCh        chan dispatchTask
	dispatchDropCount uint64 // atomic: number of frames dropped due to full channel

	// ACL hit/drop counters — see acl_stats.go. nil when the firewall is
	// disabled (NewNodeWithTAP always initialises one for consistency, but
	// tests / future callers may opt out).
	aclStats *ACLStats

	// Protect against rapid transport churn: tracks whether we saw a direct
	// (non-relay) connection.  DisconnectedF consults this to avoid purging
	// peer state when only a stray relay transport drops.
	directConnected   map[peer.ID]bool
	directConnectedMu sync.Mutex

	// Guards broadcastLSA so the periodic ticker and the on-connect immediate
	// trigger do not race on shared Node state (Collector/Config).
	lsaMu sync.Mutex

	// Ping-pong keepalive: fail counts for each peer
	pingPongFailCount map[peer.ID]int
	pingPongFailMu    sync.Mutex

	// Reconnect cooldown per peer to prevent rapid-fire reconnect loops on send failures
	lastReconnectTime map[peer.ID]time.Time

	// Urgent TAP write path: frames flagged urgent (e.g. TAP-probe echo
	// replies during diagnostics) are injected ahead of normal overlay->TAP
	// traffic. tapWriteUrgent enqueues; tapWriteUrgentLoop drains with
	// priority so diagnostics are not starved behind a busy forwarding queue.
	urgentWriteCh chan []byte

	// urgentDispatchCh is the symmetric priority queue for the SEND side:
	// time-critical P2P frames (e.g. TAP-probe requests) are queued here and
	// drained ahead of the normal dispatchCh so they reach the overlay first
	// instead of waiting behind a backlog of ordinary TAP egress frames.
	urgentDispatchCh chan dispatchTask

	reconnectTimeMu sync.Mutex

	// Persistent relay stream pool — one long-lived OverlayRelayProtocolID
	// stream per relay hop, eliminating per-frame stream open handshakes.
	relayPool *relayStreamPool

	// bootRelayConns holds the persistent boot-relay uplink to each connected
	// boot (relay-over-backbone). Frames addressed to a peer that is not
	// directly connected and has no overlay-relay hop are wrapped in a
	// routing.PackBootRelayFrame envelope and written to the uplink of a
	// connected boot, which bridges them to the destination across the boot
	// backbone. Guarded by bootRelayMu. bootRelayNetID is the node's own
	// network ID (sha256("p2ptap-net:"+PSK) prefix), attached in-band to every
	// boot-relay envelope so the destination boot can enforce PSK isolation.
	bootRelayMu    sync.Mutex
	bootRelayConns map[peer.ID]*bootRelayConn
	// bootRelayStarted records boots for which the uplink goroutine has been
	// spawned, so reconnects do not spawn duplicates (the uplink self-heals).
	bootRelayStarted map[peer.ID]struct{}
	bootRelayNetID   string
	// bootRelayCtrlMu guards bootRelayCtrlStreams. bootRelayCtrlStreams maps a
	// per-conversation convID to the multiplexed control stream simulator that
	// tunnels the inner control protocol (SeqSync / LSA / Meta / Echo) over the
	// boot-relay uplink. Each openControlStream call mints a fresh convID, so the
	// leader's handshake and a follower's rekeyReq nudge (same peer, same proto)
	// never share a byte pipe. It is how NAT'd peers complete their handshake
	// with a relay-only peer whose only path is the boot-relay.
	bootRelayCtrlMu       sync.Mutex
	bootRelayCtrlStreams  map[string]*bootRelayCtrlStream

	// lsaPool and metaPool reuse ONE long-lived stream per peer for the
	// periodic control traffic (LSA topology broadcast + metadata handshake).
	// This collapses the previous O(N) NewStream-per-15s-tick storm into
	// steady-state zero new streams. See lsa_pool.go.
	lsaPool  *lsaStreamPool
	metaPool *lsaStreamPool
	// echoPool reuses ONE long-lived echo stream per peer for the unified
	// liveness/health probe, replacing the old per-tick NewStream-per-peer echo
	// storm.
	echoPool *lsaStreamPool

	// lastLSAJSON caches the JSON of the last broadcast LSA so we can skip
	// re-broadcasting when the topology/identity is unchanged (gossip throttle).
	lastLSAJSON []byte
	lastLSAMu   sync.Mutex

	// lsaSeq is the SINGLE source of monotonically increasing LSA sequence
	// numbers for this node. It MUST be shared by every broadcastLSA call site
	// (periodic ticker + on-connect/on-disconnect force pushes).
	//
	// History (real bug): the ticker used a local counter starting at 1 while
	// the force-push sites used time.Now().UnixNano() (~1.7e18). Router.ProcessLSA
	// rejects lsa.Seq <= lastSeq, so the first force push poisoned the peer's
	// seqMap and made EVERY subsequent periodic LSA look stale. Because
	// Router.lastUpdated[origin] is only refreshed by an ACCEPTED LSA, and
	// CleanStaleNodes(60s) purges anything not refreshed within 60s, the whole
	// mesh dropped that origin from its topology graph ~60s after any
	// connect/disconnect event — silently breaking multi-hop routing until the
	// purge deleted seqMap and a later LSA got re-accepted (a 60s flap loop).
	lsaSeq atomic.Uint64

	// lsaCache retains the last ACCEPTED link-state payload per origin so a
	// newly connected peer can be handed a full topology snapshot immediately
	// instead of waiting for every other origin's LSA content to change.
	//
	// Without this, a node joining an established mesh only receives our OWN
	// LSA on connect, so it learns our links but never the links of peers two
	// or more hops away — i.e. a static-peer-only node (no bootstrap) could not
	// converge on the full graph and had no next-hop for distant peers.
	lsaCache   map[peer.ID]*routing.LinkStatePayload
	lsaCacheMu sync.RWMutex

	// discoveredBoots tracks boot nodes we attached to because they were
	// announced over a federated boot backbone (as opposed to being configured
	// in BootstrapPeers). Used both for idempotency and to cap how many extra
	// boots one node will join (maxDiscoveredBoots).
	discoveredBoots sync.Map // peer.ID -> struct{}

	// peekMapOrigin records, per peer, which boot rebroadcast its announcement
	// and how many boot-backbone hops it crossed — the cluster-membership data
	// the topology view needs but the link-state graph cannot express.
	peekMapOrigin sync.Map // peer.ID -> peekMapOrigin

	// startTime records when the node was created, used for uptime calculation
	// in metadata exchange.
	startTime time.Time

	// nodeName is the resolved display name (auto → hostname).  Cached locally
	// because the Collector interface no longer exposes a readable NodeName field.
	nodeName string
	// activePeers caches the last pushed PeerInfoDTO slice so node-internal
	// lookups (PeekPeerID, resolvePeerIDByName) do not need to read back from
	// the Collector interface.  Protected by activePeersMu.
	activePeersMu sync.RWMutex
	activePeers   []observer.PeerInfoDTO

	// perPeerBytes tracks local sent/received bytes per peer for accurate
	// per-peer speed display in the WebUI mesh topology.  Atomic counters
	// keep the datapath lock-free; BuildPeerStats snapshots deltas periodically.
	perPeerBytesMu sync.RWMutex
	perPeerLastTx  map[peer.ID]uint64 // snapshot of total bytes sent to peer at last speed calc
	perPeerLastRx  map[peer.ID]uint64 // snapshot of total bytes received from peer at last speed calc
	perPeerTxSpeed map[peer.ID]uint64 // computed tx speed (bytes/sec) toward peer
	perPeerRxSpeed map[peer.ID]uint64 // computed rx speed (bytes/sec) from peer

	// Hot-path atomic per-peer byte counters (sync.Map avoids global lock).
	peerTxBytes sync.Map // peer.ID → *atomic.Uint64 (total bytes sent TO peer)
	peerRxBytes sync.Map // peer.ID → *atomic.Uint64 (total bytes received FROM peer)

	// lastPeerSpeedCalc records the timestamp of the previous per-peer speed
	// snapshot (taken inside updateWebCollectorState, which runs on a 10s ticker).
	// Used to divide byte deltas by the REAL elapsed interval so the displayed
	// speed is an accurate bytes/sec value.
	lastPeerSpeedCalc time.Time
	lastPeerSpeedMu   sync.Mutex

	// fragRX reassembles tunnel-level fragments of obfuscated TAP frames so
	// large frames can traverse the QUIC path MTU without IP fragmentation.
	fragRX *fragReassembler

	// obfKeyPair is the node's long-lived ECDH(P256) key pair used for identity
	// display (Fingerprint) and as the fallback when per-handshake ephemeral keys
	// are unavailable. Per-peer AEAD keys are now derived from ONE-SHOT ephemeral
	// keys (minted locally per handshake and passed straight into negotiateObfWithPeer,
	// NOT stored in a shared per-peer slot) so that compromising a node later
	// cannot decrypt past traffic (perfect forward secrecy). nil only when
	// encryption is disabled.
	obfKeyPair *obfuscate.ObfKeyPair
	// rekeyPeers guards ALL (re)key handshakes for a peer — both the proactive
	// per-peer rotation (TX-path nonce-counter-window check) and the reactive
	// self-heal (lost reciprocal-ready / sustained decrypt failures). Exactly
	// one re-key round is ever in flight per peer, which is what stops two
	// concurrent handshakes from producing mismatched keys and a permanent
	// decrypt-fail loop. The leader election (isResyncLeader) further ensures
	// only the leader ever initiates, so this guard plus the leader check
	// together prevent the storm.
	rekeyPeers sync.Map
	// handshakeMu serialises ALL SeqSync handshakes (initiator AND responder)
	// per peer. Without this, two concurrent libp2p connections to the same peer
	// (e.g. DIRECT + CIRCUIT-RELAY) can each drive handleSeqSync →
	// negotiateObfWithPeer independently, overwriting the per-peer cipher slot
	// with different ECDH generations — producing the exact "ring=N fundamentally
	// divergent key" symptom where neither side's txKey matches the other's rxKey.
	// The rekeyPeers map above only guards the initiator side (triggerPeerRekey);
	// this map covers BOTH roles so a responder on a relay connection cannot race
	// with an initiator on a direct connection.
	handshakeMu sync.Map // peer.ID → *sync.Mutex
	// cachedHandshakeEph caches the one-shot ephemeral ECDH key pair used for the
	// CURRENT (re)handshake round with each peer. Every retry within a round and
	// every self-heal re-sync REUSES the same pair instead of minting a fresh one,
	// which makes the negotiated per-peer cipher DETERMINISTIC for the round: no
	// matter which attempt's ack finally gets through a lossy circuit-relay, both
	// sides derive the SAME key and therefore can never land on divergent cipher
	// generations. This is the direct fix for the "Rx 100% decrypt-fail,
	// rxKeyFP constant, ring=N, fundamentally divergent key" outage, which was
	// caused by the responder committing a NEW generation on every ack-send while
	// the initiator (whose ack-reads were being dropped) stayed pinned to one —
	// the two ends forever disagreed on the generation. The cache is cleared by
	// clearCachedHandshakeEph once the round completes (both ready exchanged) or
	// the peer disconnects, so the next rotation still mints a FRESH key (PFS).
	cachedHandshakeEph   map[peer.ID]*obfuscate.ObfKeyPair
	cachedHandshakeEphMu sync.Mutex
	// handshakeFingerprint is the fingerprint of the most recent ephemeral key
	// actually used in a completed handshake. Exposed via ObfFingerprint so the
	// WebUI (and operators) can confirm every (re)connection negotiated a FRESH
	// key — the visible proof that per-handshake forward secrecy is in effect.
	handshakeFingerprint atomic.Pointer[string]
	// perPeerObf holds the negotiated obfuscation/encryption state per peer,
	// established at handshake time. A missing entry means no encryption was
	// negotiated (plaintext obfuscation only).
	//
	// Hot-path access (every TX/RX packet) reads it via an atomic.Pointer with
	// copy-on-write: the table is replaced as a whole on handshake changes
	// (rare) and read lock-free on the data path, so per-packet encryption adds
	// zero mutex contention. peerObf() returns the *PeerObf directly so callers
	// read negotiated/cipher in a single atomic load.
	perPeerObf atomic.Pointer[map[peer.ID]*PeerObf]
	// rxKeyGrace retains the just-cleared RX cipher for a briefly-disconnected
	// peer so that frames still in flight on a LINGERING old connection — where
	// the peer had not yet torn down its previous session and keeps sealing with
	// the previous key for a few seconds after we cleared ours — can still be
	// decrypted on the post-clear re-handshake instead of being dropped.
	// negotiateObfWithPeer seeds it into prevRxCipher when a fresh (re)connection
	// negotiates after a clear. Entries carry a short TTL and are ignored once
	// expired, so we never hold a stale key as a fallback indefinitely.
	rxKeyGrace sync.Map // peer.ID -> *rxGraceKey
	// peerReady records, per peer, whether the mutual "ready" handshake has
	// completed: both sides have finished ECDH + SeqSync key exchange AND have
	// exchanged a reciprocal ready acknowledgement. TAP application data is only
	// transmitted to a peer once it is marked ready, so neither side ever sends
	// an encrypted frame before the other has a cipher to open it (this closes
	// the handshake-window race that previously produced spurious "Decrypt Fail"
	// states). Cleared on disconnect alongside the cipher.
	peerReady sync.Map // peer.ID -> *atomic.Bool
	// Hot-path atomic per-peer frame decryption counters, used to derive the
	// WebUI "data flow" stage (ConnState stage 4). sync.Map avoids a global lock
	// on the RX path. peerRxDecryptOK = frames decrypted successfully;
	// peerRxDecryptErrs = frames that failed AEAD authentication. The remotePeer
	// keyed here is the actual frame source (for relayed traffic this is the relay
	// hop, not the final destination peer).
	peerRxDecryptOK   sync.Map // peer.ID → *atomic.Uint64
	peerRxDecryptErrs sync.Map // peer.ID → *atomic.Uint64
	// peerRxDecryptRecentErrs is a *reset-on-success* window: a success zeroes it
	// for that peer. Unlike the cumulative counters above, it never sticks a lone
	// historical handshake-window failure onto the connection state — the UI only
	// reports Decrypt Fail when the peer is *still* actively failing right now.
	peerRxDecryptRecentErrs sync.Map // peer.ID → *atomic.Uint64
	// decryptResyncCooldown rate-limits the self-healing SeqSync re-handshake
	// triggered by sustained decryption failures, so a transient key desync
	// cannot spawn a resync storm. peer.ID → time.Time of the last resync kick.
	decryptResyncCooldown sync.Map
	// rekeyReqCooldown rate-limits the follower→leader rekeyReq nudge so a burst
	// of decrypt failures cannot spam the leader with rekey requests. peer.ID →
	// time.Time of the last nudge sent.
	rekeyReqCooldown sync.Map
	// rekeyEscalation marks a follower that is currently waiting out its NAT
	// fallback window before escalating to a self-initiated handshake. Prevents
	// stacking multiple escalation timers for the same peer. peer.ID → struct{}.
	rekeyEscalation sync.Map
	// lastRekeySuccess records, per peer, the wall-clock time the last reactive
	// or connect-time (re)key handshake *converged*. Used to suppress a re-key
	// storm: right after a converge, in-flight frames encrypted with the
	// PREVIOUS key are still arriving and would otherwise re-trigger a re-key,
	// oscillating the link. We keep quiet for settleWindow (see
	// maybeResyncOnDecryptFail) unless failures clearly indicate a real
	// divergence. peer.ID → time.Time.
	lastRekeySuccess sync.Map

	// seqsyncHandshakeStart records, per peer, the wall-clock time we began a
	// SeqSync handshake (first SyncSeqToPeer call for this peer since it became
	// ready/unknown). Used to compute handshake convergence latency: how long it
	// took from "we tried to set up crypto" to "the link is usable" — a useful
	// operator signal for relay/NAT flakiness.
	seqsyncHandshakeStart sync.Map // peer.ID → time.Time
	// seqsyncConvergeMs records, per peer, the measured convergence latency in
	// milliseconds once the handshake completed (markPeerReady). 0 means unknown.
	seqsyncConvergeMs sync.Map // peer.ID → *atomic.Uint64
}

// recordPeerRxDecrypt records the outcome of decrypting a frame from remotePeer.
func (n *Node) recordPeerRxDecrypt(remotePeer peer.ID, ok bool) {
	m := &n.peerRxDecryptOK
	if !ok {
		m = &n.peerRxDecryptErrs
	}
	v, _ := m.LoadOrStore(remotePeer, &atomic.Uint64{})
	v.(*atomic.Uint64).Add(1)
	// Recent-window: a success clears the peer's recent error count so an old
	// handshake-window failure can never stick the connection in "Decrypt Fail".
	if ok {
		if rv, ok2 := n.peerRxDecryptRecentErrs.Load(remotePeer); ok2 {
			rv.(*atomic.Uint64).Store(0)
		}
	} else {
		rv, _ := n.peerRxDecryptRecentErrs.LoadOrStore(remotePeer, &atomic.Uint64{})
		rv.(*atomic.Uint64).Add(1)
	}
}

// peerRxDecryptStats returns (okCount, errCount) for remotePeer.
func (n *Node) peerRxDecryptStats(remotePeer peer.ID) (uint64, uint64) {
	var ok, err uint64
	if v, ok2 := n.peerRxDecryptOK.Load(remotePeer); ok2 {
		ok = v.(*atomic.Uint64).Load()
	}
	if v, ok2 := n.peerRxDecryptErrs.Load(remotePeer); ok2 {
		err = v.(*atomic.Uint64).Load()
	}
	return ok, err
}

// peerRxDecryptRecentErrsStats returns the reset-on-success recent failure
// count for remotePeer. A successful decrypt zeroes it, so it only reflects
// *current* decryption trouble — used by the UI to avoid sticking a stale
// single handshake-window failure onto the connection state.
func (n *Node) peerRxDecryptRecentErrsStats(remotePeer peer.ID) uint64 {
	if v, ok2 := n.peerRxDecryptRecentErrs.Load(remotePeer); ok2 {
		return v.(*atomic.Uint64).Load()
	}
	return 0
}

// peerSeqSyncConvergeMs returns the measured handshake convergence latency (ms)
// for remotePeer, or 0 if not yet measured / unknown.
func (n *Node) peerSeqSyncConvergeMs(remotePeer peer.ID) uint64 {
	if v, ok2 := n.seqsyncConvergeMs.Load(remotePeer); ok2 {
		return v.(*atomic.Uint64).Load()
	}
	return 0
}

// recordPeerTxBytes atomically adds n bytes to the send counter for targetPeer.
func (n *Node) recordPeerTxBytes(targetPeer peer.ID, nBytes int) {
	if nBytes <= 0 {
		return
	}
	v, _ := n.peerTxBytes.LoadOrStore(targetPeer, new(atomic.Uint64))
	v.(*atomic.Uint64).Add(uint64(nBytes))
}

// recordPeerRxBytes atomically adds n bytes to the receive counter for sourcePeer.
func (n *Node) recordPeerRxBytes(sourcePeer peer.ID, nBytes int) {
	if nBytes <= 0 {
		return
	}
	v, _ := n.peerRxBytes.LoadOrStore(sourcePeer, new(atomic.Uint64))
	v.(*atomic.Uint64).Add(uint64(nBytes))
}

// getPeerSpeed returns the locally-computed tx/rx speed (bytes/sec) for a peer.
func (n *Node) getPeerSpeed(pID peer.ID) (txSpd, rxSpd uint64) {
	n.perPeerBytesMu.RLock()
	defer n.perPeerBytesMu.RUnlock()
	txSpd = n.perPeerTxSpeed[pID]
	rxSpd = n.perPeerRxSpeed[pID]
	return
}

// dispatchTask represents a single P2P frame send job picked up by a dispatch worker.
type dispatchTask struct {
	kind      uint8            // 0=unicast, 1=broadcast, 2=relay
	target    peer.ID          // unicast/relay destination
	relayHop  peer.ID          // relay next-hop (only for kind=2)
	dstMAC    net.HardwareAddr // L2 destination (unicast circuit-breaker key)
	data      []byte
	relayData []byte // relay-wrapped data (only for kind=2)
	origLen   int    // original Ethernet frame length (TX bytes to count on success)
	urgent    bool   // when true, queued on urgentDispatchCh (front of send queue)
	// owned marks data as pooled (acquireFrameBuf). When true the consumer must
	// release it with releaseFrameBuf after transmitting; urgent frames from
	// callers and relay fallbacks are NOT pooled and stay false.
	owned bool
}

// bcastDedupRing is a lightweight content-based deduplication ring for
// broadcast/multicast frames that arrive from multiple peers.  Without this,
// the same L2 frame written to TAP N times (once per peer stream) wastes
// kernel CPU and can confuse upper-layer protocols.
type bcastDedupRing struct {
	mu     sync.Mutex
	hashes [4096]uint64
	next   int
}

func (r *bcastDedupRing) isDuplicate(h uint64) bool {
	if h == 0 {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range r.hashes {
		if r.hashes[i] == h {
			return true
		}
	}
	r.hashes[r.next] = h
	r.next = (r.next + 1) % len(r.hashes)
	return false
}

// fnvHash64 returns a FNV-1a 64-bit hash of data (fast, good distribution).
func fnvHash64(data []byte) uint64 {
	h := fnv.New64a()
	h.Write(data)
	return h.Sum64()
}

// isBroadcastOrMulticastMAC returns true if mac is a group address
// (broadcast FF:FF:FF:FF:FF:FF, or multicast with bit 0 of first byte set).
func isBroadcastOrMulticastMAC(mac net.HardwareAddr) bool {
	if len(mac) < 1 {
		return false
	}
	return mac[0]&1 == 1
}

type mdnsNotifee struct {
	h host.Host
}

func (m *mdnsNotifee) HandlePeerFound(pi peer.AddrInfo) {
	if pi.ID == m.h.ID() {
		return
	}
	// mDNS fires repeatedly for peers already connected (and on every network
	// change); skip redialing an established session to avoid connection churn.
	if m.h.Network().Connectedness(pi.ID) == network.Connected {
		return
	}
	log.Info("mDNS discovered local LAN peer %s, connecting...", pi.ID.String())
	go func(info peer.AddrInfo) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := m.h.Connect(ctx, info); err != nil {
			log.Debug("mDNS connect to peer %s failed: %v", info.ID.String(), err)
		} else {
			log.Info("mDNS connected to peer %s successfully", info.ID.String())
		}
	}(pi)
}

// NewNode builds a Node using the supplied observer.Collector as the WebUI
// telemetry sink. The collector must be created by the caller (e.g. the web
// package's StatsCollector) so that the domain core never imports the web
// package.
func NewNode(cfg *config.Config, collector observer.Collector) (*Node, error) {
	return NewNodeWithTAP(cfg, nil, collector)
}

// physicalNICIPs returns the global (non-loopback, non-link-local, non-overlay,
// non-virtual) IP addresses of all up physical interfaces. These are the
// addresses the node should actually listen on for multi-NIC inbound.
func physicalNICIPs() ([]net.IP, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []net.IP
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 {
			continue
		}
		if isVirtualInterface(ifc.Name) {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipNet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip := ipNet.IP
			if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
				continue
			}
			if isOverlayIPAddress(ip.String()) {
				continue
			}
			out = append(out, ip)
		}
	}
	return out, nil
}

// replaceIPInMultiaddr returns a copy of addr with its ip4/ip6 component value
// replaced by newIP, leaving the rest of the multiaddr (port, transport, ...)
// intact.
func replaceIPInMultiaddr(addr multiaddr.Multiaddr, newIP string) (multiaddr.Multiaddr, error) {
	parts := strings.Split(addr.String(), "/")
	for i := 1; i < len(parts)-1; i += 2 {
		if parts[i] == "ip4" || parts[i] == "ip6" {
			parts[i+1] = newIP
			break
		}
	}
	return multiaddr.NewMultiaddr(strings.Join(parts, "/"))
}

// expandListenAddr expands a listen multiaddr whose IP component is the
// wildcard (0.0.0.0 / ::) into one multiaddr per eligible physical NIC IP,
// preserving the transport/port. Concrete-IP or non-IP addrs are returned
// unchanged. If no eligible NIC IP exists the original addr is returned as a
// fallback (it then binds via the cached default egress interface). This gives
// libp2p true multi-NIC inbound: each listener ends up on its own NIC, and the
// per-NIC socket hook pins its reply path off the TAP.
func expandListenAddr(addr multiaddr.Multiaddr) []multiaddr.Multiaddr {
	var family string
	if ip4, err := addr.ValueForProtocol(multiaddr.P_IP4); err == nil {
		family = "ip4"
		if ip4 != "0.0.0.0" {
			return []multiaddr.Multiaddr{addr}
		}
	} else if ip6, err := addr.ValueForProtocol(multiaddr.P_IP6); err == nil {
		family = "ip6"
		if ip6 != "::" {
			return []multiaddr.Multiaddr{addr}
		}
	} else {
		return []multiaddr.Multiaddr{addr}
	}

	ips, err := physicalNICIPs()
	if err != nil || len(ips) == 0 {
		return []multiaddr.Multiaddr{addr}
	}
	var expanded []multiaddr.Multiaddr
	for _, ip := range ips {
		if family == "ip4" && ip.To4() == nil {
			continue
		}
		if family == "ip6" && ip.To4() != nil {
			continue
		}
		newAddr, e := replaceIPInMultiaddr(addr, ip.String())
		if e != nil {
			log.Warn("failed to expand listen addr %s with %s: %v", addr, ip, e)
			continue
		}
		expanded = append(expanded, newAddr)
	}
	if len(expanded) == 0 {
		return []multiaddr.Multiaddr{addr}
	}
	return expanded
}

func NewNodeWithTAP(cfg *config.Config, overrideTAP tap.TAPDevice, collector observer.Collector) (*Node, error) {
	ctx, cancel := context.WithCancel(context.Background())

	if collector == nil {
		collector = noopCollector{}
	}

	var tapDev tap.TAPDevice
	var err error
	if overrideTAP != nil {
		tapDev = overrideTAP
	} else {
		tapDev, err = tap.CreateTAPDevice(cfg.TapName, cfg.TapIP, cfg.TapIPv6, cfg.TapMAC, cfg.DriverType, cfg.MTU)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("failed to create TAP device: %w", err)
		}
	}

	// Learn the TAP device's real MAC if the config did not explicitly specify
	// one. The device always has a MAC (auto-assigned by the OS/driver), and it
	// must be advertised to peers via metadata so the proxy-ARP can answer with
	// the peer's REAL MAC instead of a synthetic one. Without this, relay peers
	// would report an empty TapMAC and their own TAP IPs (e.g. 10.0.0.2) would
	// be unreachable across the mesh. node.localMac is derived from cfg.TapMAC
	// later (after node is constructed).
	if cfg.TapMAC == "" {
		if devMAC := tapDev.MAC(); devMAC != "" {
			cfg.TapMAC = devMAC
			log.Info("TAP MAC auto-detected from device %s: %s", cfg.TapName, devMAC)
		}
	}

	// Register the TAP interface so socket protection never binds P2P sockets
	// onto the local tunnel device (which would route egress into the tunnel
	// and cause "unreachable network" dial errors on the physical network).
	RegisterProtectedExcludeInterface(cfg.TapName)

	// Probe and cache the system default egress interface NOW — before any Exit
	// Node default route hijacks the TAP device. Once the TAP becomes the
	// default gateway, "which interface is the default" can no longer be derived
	// from the routing table, so we must remember the real physical NIC up front
	// and bind every P2P socket to it for the lifetime of the process.
	DetectDefaultEgressInterface()

	// Pre-parse bootstrap peers into AddrInfo for relay and connection
	var bootstrapRelays []peer.AddrInfo
	for _, bStr := range cfg.BootstrapPeers {
		ma, err := multiaddr.NewMultiaddr(bStr)
		if err != nil {
			log.Debug("Invalid bootstrap multiaddr '%s': %v", bStr, err)
			continue
		}
		info, err := peer.AddrInfoFromP2pAddr(ma)
		if err != nil {
			log.Debug("Cannot parse AddrInfo from bootstrap '%s': %v", bStr, err)
			continue
		}
		bootstrapRelays = append(bootstrapRelays, *info)
	}
	log.Debug("Parsed %d bootstrap peers as relay candidates", len(bootstrapRelays))

	yamuxOpt := *yamux.DefaultTransport
	yamuxOpt.MaxStreamWindowSize = 16 * 1024 * 1024 // 16 MB stream window for Gigabit+ throughput

	opts := []libp2p.Option{
		libp2p.Muxer("/yamux/1.0.0", &yamuxOpt),
		libp2p.NATPortMap(),
		libp2p.EnableNATService(),
		// Force reachability to private: ensures relay addresses are always advertised
		// and DCUtR hole punching is used even when AutoNAT is unreliable.
		// Without this, libp2p may misidentify a NAT'd node as "public" and skip
		// relay advertisement, causing connection failures for peers behind NAT.
		libp2p.ForceReachabilityPrivate(),
		libp2p.AddrsFactory(func(addrs []multiaddr.Multiaddr) []multiaddr.Multiaddr {
			filtered := filterAdvertisedAddrs(addrs, cfg.TapIP, cfg.TapIPv6, cfg.WebUI.ListenIP, cfg.WebUI.ListenIPv6)
			if len(filtered) > 0 {
				return filtered
			}
			return addrs
		}),
	}

	// Circuit relay + DCUtR hole-punching. Gated by Transports.DisableRelay so a
	// direct-only experiment can confirm whether a slow/reachable peer was being
	// auto-relayed through a static relay (disable_relay=true → that peer becomes
	// unreachable instead of slow). p2ptap's own overlay relay is unaffected.
	if cfg.Transports.DisableRelay {
		log.Warn("DisableRelay=true: libp2p circuit-relay, AutoRelay and hole-punching are OFF (direct-only mode). Peers behind symmetric NAT may become unreachable.")
	} else {
		opts = append(opts,
			libp2p.EnableRelay(),
			libp2p.EnableHolePunching(),
		)
		// Enable AutoRelay with bootstrap peers as static relay servers
		if len(bootstrapRelays) > 0 {
			opts = append(opts, libp2p.EnableAutoRelayWithStaticRelays(bootstrapRelays))
			log.Info("AutoRelay enabled with %d static relay servers", len(bootstrapRelays))
		} else {
			log.Warn("No bootstrap peers configured — NAT traversal via relay will be unavailable")
		}
	}

	// Persistent Node Identity Key
	if cfg.NodeKeyFile != "" {
		log.Debug("Loading persistent identity key from: %s", cfg.NodeKeyFile)
		privKey, err := loadOrGenerateNodeKey(cfg.NodeKeyFile)
		if err != nil {
			log.Warn("Failed to load key from %s (%v), fallback to ephemeral key", cfg.NodeKeyFile, err)
		} else {
			opts = append(opts, libp2p.Identity(privKey))
			log.Debug("Persistent identity key loaded successfully")
		}
	}

	// Parse listen addrs according to enabled transport flags
	var addrs []multiaddr.Multiaddr
	for _, aStr := range cfg.ListenAddrs {
		if !cfg.Transports.EnableQUICReuse && (containsSub(aStr, "quic-v1") || containsSub(aStr, "quic")) {
			log.Debug("Skipping disabled QUIC listen addr: %s", aStr)
			continue
		}
		if !cfg.Transports.EnableWebRTC && containsSub(aStr, "webrtc-direct") {
			log.Debug("Skipping disabled WebRTC listen addr: %s", aStr)
			continue
		}
		if !cfg.Transports.EnableWebTransport && containsSub(aStr, "webtransport") {
			log.Debug("Skipping disabled WebTransport listen addr: %s", aStr)
			continue
		}
		if !cfg.Transports.EnableTCPReuse && containsSub(aStr, "/tcp/") {
			log.Debug("Skipping disabled TCP listen addr: %s", aStr)
			continue
		}
		ma, err := multiaddr.NewMultiaddr(aStr)
		if err == nil {
			addrs = append(addrs, expandListenAddr(ma)...)
		} else {
			log.Warn("Invalid listen multiaddr '%s': %v", aStr, err)
		}
	}
	if len(addrs) > 0 {
		opts = append(opts, libp2p.ListenAddrs(addrs...))
		log.Debug("Configured %d listen addresses (physical-NIC expanded)", len(addrs))
	}

	// Use NullResourceManager to prevent stream limits from dropping high-rate TAP forwarding frames
	opts = append(opts, libp2p.ResourceManager(&network.NullResourceManager{}))

	// Socket protection: bind every P2P TCP socket (dialed by this process) to
	// the physical interface so that when the TAP adapter becomes the default
	// gateway (exit node mode) the P2P control plane never loops back into the
	// tunnel. This is the program-level "exclude all sockets from this process"
	// mechanism that complements the per-endpoint host routes.
	opts = append(opts, libp2p.Transport(tcpt.NewTCPTransport,
		tcpt.WithDialerForAddr(func(raddr multiaddr.Multiaddr) (tcpt.ContextDialer, error) {
			return &net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 15 * time.Second,
				Control:   GetSocketControlHook(""),
			}, nil
		}),
		// Pin TCP listen sockets to their interface (SO_BINDTODEVICE /
		// IP_BOUND_IF) so inbound connections do not loop into the TAP tunnel
		// under Exit Node. Combined with per-NIC listen addrs below this
		// enables true multi-NIC inbound for the TCP transport.
		tcpt.WithListenControl(listenerProtectControl),
	))

	// Socket protection for QUIC (UDP): libp2p's QUIC transport routes every UDP
	// socket — both listening and dialing — through a single ConnManager factory
	// (quicreuse). By overriding that factory with OverrideListenUDP we bind all
	// QUIC sockets to the physical interface, again preventing them from looping
	// back into the TAP tunnel when it becomes the default gateway. This is the
	// same program-level exclusion as the TCP path above but applied to UDP.
	opts = append(opts, libp2p.Transport(
		func(key crypto.PrivKey, _ *quicreuse.ConnManager, psk pnet.PSK, gater libp2pconnmgr.ConnectionGater, rcmgr network.ResourceManager, transportOpts ...quict.Option) (tpt.Transport, error) {
			var srk quic.StatelessResetKey
			var tk quic.TokenGeneratorKey
			if _, err := rand.Read(srk[:]); err != nil {
				return nil, err
			}
			if _, err := rand.Read(tk[:]); err != nil {
				return nil, err
			}
			cm, err := quicreuse.NewConnManager(srk, tk, quicreuse.OverrideListenUDP(ProtectedListenUDP))
			if err != nil {
				return nil, err
			}
			return quict.NewTransport(key, cm, psk, gater, rcmgr, transportOpts...)
		},
	))

	// Socket protection for WebRTC (UDP): the ICE agent creates its own UDP
	// sockets via a pion transport.Net. We inject a wrapper that binds every
	// listen/dial socket to the physical interface, mirroring the QUIC/TCP
	// protection so WebRTC ICE candidate traffic never loops into the TAP tunnel
	// under Exit Node. The listen socket additionally uses ProtectedListenUDP so a
	// concrete listen IP binds to its own NIC (true multi-NIC inbound).
	// Registration is gated by EnableWebRTC.
	if cfg.Transports.EnableWebRTC {
		opts = append(opts, libp2p.Transport(
			func(key crypto.PrivKey, psk pnet.PSK, gater libp2pconnmgr.ConnectionGater, rcmgr network.ResourceManager, _ webrtc.ListenUDPFn, transportOpts ...webrtc.Option) (tpt.Transport, error) {
				protectedNet, err := NewProtectNet()
				if err != nil {
					return nil, err
				}
				return webrtc.New(key, psk, gater, rcmgr, ProtectedListenUDP, append(transportOpts, webrtc.WithNet(protectedNet))...)
			},
		))
		log.Info("WebRTC transport registered (socket-protected)")
	}

	// Socket protection for WebTransport (QUIC-over-HTTP/3): it reuses the same
	// quicreuse.ConnManager machinery as the QUIC transport, so by constructing
	// its ConnManager with OverrideListenUDP(ProtectedListenUDP) every
	// WebTransport socket is already bound to the physical interface.
	// Registration is gated by EnableWebTransport.
	if cfg.Transports.EnableWebTransport {
		opts = append(opts, libp2p.Transport(
			func(key crypto.PrivKey, psk pnet.PSK, _ *quicreuse.ConnManager, gater libp2pconnmgr.ConnectionGater, rcmgr network.ResourceManager, transportOpts ...webtransport.Option) (tpt.Transport, error) {
				var srk quic.StatelessResetKey
				var tk quic.TokenGeneratorKey
				if _, err := rand.Read(srk[:]); err != nil {
					return nil, err
				}
				if _, err := rand.Read(tk[:]); err != nil {
					return nil, err
				}
				cm, err := quicreuse.NewConnManager(srk, tk, quicreuse.OverrideListenUDP(ProtectedListenUDP))
				if err != nil {
					return nil, err
				}
				return webtransport.New(key, psk, cm, gater, rcmgr, transportOpts...)
			},
		))
		log.Info("WebTransport transport registered (socket-protected)")
	}

	h, err := libp2p.New(opts...)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create libp2p host: %w", err)
	}
	log.Info("libp2p host created, PeerID: %s", h.ID().String())

	// Initialize Kademlia DHT for Peer discovery
	kdht, err := dht.New(ctx, h)
	if err != nil {
		log.Warn("DHT init error: %v", err)
	} else {
		_ = kdht.Bootstrap(ctx)
		log.Debug("DHT bootstrapped")
	}

	// Initialize mDNS LAN Auto-Discovery if enabled
	if cfg.EnableMDNS {
		notifee := &mdnsNotifee{h: h}
		s := mdns.NewMdnsService(h, "_p2ptap-discovery._udp.local", notifee)
		if err := s.Start(); err != nil {
			log.Warn("mDNS start error: %v", err)
		} else {
			log.Info("mDNS LAN Auto-Discovery enabled")
		}
	}

	macTable := vswitch.NewMACTable()
	obfCfg := cfg.Obfuscation
	packer := obfuscate.NewFramePackerFull(&obfCfg)
	packer.SetSourceIdentity(h.ID().String())
	dispatcher := NewStrategyDispatcher(h, cfg.TransportStrategy)
	// SetNode called after node is constructed below (node var not yet in scope here).

	nodeName := cfg.NodeName
	if nodeName == "" || nodeName == "auto" {
		if hostName, err := os.Hostname(); err == nil && hostName != "" {
			nodeName = hostName
		} else {
			nodeName = "p2ptap-node"
		}
	}

	collector.SetNodeInfo(nodeName, h.ID().String(), cfg.TapIP, cfg.TapIPv6, cfg.TransportStrategy)
	collector.SetTAPSelfTest(func() map[string]interface{} {
		if tapDev == nil {
			return map[string]interface{}{"available": false, "detail": "TAP device is nil"}
		}
		return tapDev.SelfTest()
	})

	pskStatus := "🌐 Public (Unencrypted)"
	if cfg.PSK != "" {
		pskStatus = "🔐 Encrypted Overlay (Noise/PSK)"
	}

	obfsMode := "Disabled"
	if cfg.Obfuscation.Enable {
		obfsMode = fmt.Sprintf("🛡️ Active (%s mode, %dB)", cfg.Obfuscation.Mode, cfg.Obfuscation.FixedSize)
	}

	collector.SetSecurity(pskStatus, obfsMode, computeKeyFingerprint(cfg.NodeKeyFile))

	node := &Node{
		Host:                h,
		DHT:                 kdht,
		Config:              cfg,
		TAP:                 tapDev,
		MACTable:            macTable,
		Packer:              packer,
		dedupPeers:          make(map[peer.ID]*obfuscate.Deduplicator),
		fragRX:              newFragReassembler(),
		perPeerObf:          *newPeerObfTable(),
		Dispatcher:          dispatcher,
		Collector:           collector,
		IPTracker:           NewIPTrafficTracker(),
		Router:              routing.NewRouter(h.ID()),
		Gateway:             NewGatewayManager(cfg.TapName),
		NFTManager:          NewNFTManager(&cfg.ExitNode),
		relayLatency:        make(map[peer.ID]time.Duration),
		relayAuthInProgress: make(map[peer.ID]bool),
		directConnected:     make(map[peer.ID]bool),
		pingPongFailCount:   make(map[peer.ID]int),
		aclStats:            newACLStats(),
		dispatchCh:          make(chan dispatchTask, 8192), // bounded buffer: 8192 frames for high-throughput scaling
		urgentWriteCh:       make(chan []byte, 64),         // urgent TAP-inject queue (diagnostics)
		urgentDispatchCh:    make(chan dispatchTask, 64),   // urgent SEND queue (symmetric to receive)
		perPeerLastTx:       make(map[peer.ID]uint64),
		perPeerLastRx:       make(map[peer.ID]uint64),
		perPeerTxSpeed:      make(map[peer.ID]uint64),
		perPeerRxSpeed:      make(map[peer.ID]uint64),
		ctx:                 ctx,
		cancel:              cancel,
		startTime:           time.Now(),
		nodeName:            nodeName,
		arpIndex:            &arpIndex{v4: make(map[uint32]arpIndexEntry), v6: make(map[[16]byte]arpIndexEntry)},
		lsaCache:            make(map[peer.ID]*routing.LinkStatePayload),
	}
	// Seed the LSA sequence counter from wall-clock nanoseconds so a RESTARTED
	// node never re-uses a sequence its peers already recorded (they would
	// reject every LSA from us as stale until CleanStaleNodes purged us, i.e.
	// up to 60s of invisibility after every restart).
	node.lsaSeq.Store(uint64(time.Now().UnixNano()))
	node.relayPool = newRelayStreamPool(ctx, h)
	// Boot-relay (relay-over-backbone) uplink pool. The network ID is derived
	// from the configured PSK so cross-boot envelopes carry the right isolation
	// tag; in open mode (no PSK) it is empty and the boot accepts all.
	node.bootRelayConns = make(map[peer.ID]*bootRelayConn)
	node.bootRelayStarted = make(map[peer.ID]struct{})
	node.bootRelayCtrlStreams = make(map[string]*bootRelayCtrlStream)
	node.bootRelayNetID = routing.NetworkIDFromPSK(node.Config.PSK)
	node.lsaPool = newLSAStreamPool(node, LSAProtocolID)
	node.metaPool = newLSAStreamPool(node, meta.MetaProtocolID)
	node.echoPool = newLSAStreamPool(node, EchoProtocolID)
	dispatcher.SetNode(node)

	// Ephemeral ECDH(P256) key pair for per-peer obfuscation key agreement.
	// The public key is exchanged during the SeqSync handshake; the derived
	// shared secret is never transmitted, giving forward secrecy without
	// static pre-shared keys.
	if kp, err := obfuscate.GenerateObfKeyPair(); err != nil {
		log.Warn("failed to generate obfuscation ECDH key pair: %v", err)
	} else {
		node.obfKeyPair = kp
	}
	// The ObfType byte written into outgoing frames tells receivers which
	// algorithm family to expect. Payload encryption is applied per-peer at
	// send time (see strategy.go SendToPeer); the packer stays plaintext.
	node.Packer.SetSendAlgo(node.sendAlgo())

	// Expose all known VPN peers (including relay-only ones) to the broadcast
	// fan-out so ARP/NDP reach peers not present in Network().Peers(). Without
	// this, relay-only peers never learn each other's MAC and unicast frames
	// (e.g. pings) stay unresolved.
	node.Dispatcher.SetKnownPeersProvider(func() []peer.ID {
		var peers []peer.ID
		node.peerMeta.Range(func(key, _ any) bool {
			if pID, ok := key.(peer.ID); ok {
				peers = append(peers, pID)
			}
			return true
		})
		return peers
	})

	// Enrich captured TAP frames with from/to peer labels for the WebUI pcap view.
	node.Collector.SetPeerResolver(func(mac net.HardwareAddr) string {
		if len(mac) < 6 {
			return ""
		}
		// Recognize configured local TAP MAC and Windows 02:a9:xx:xx:xx:xx synthetic MACs as "self"
		if bytes.Equal(mac, node.localMAC) || (mac[0] == 0x02 && mac[1] == 0xa9) {
			return "self"
		}
		if isBroadcastOrMulticastMAC(mac) {
			if node.isExitNodeActive() {
				if exitPID := node.Gateway.ActiveExitPeerPID(); exitPID != "" {
					return exitPID.ShortString() + " (exit)"
				}
			}
			return "broadcast"
		}
		if node.MACTable != nil {
			if pid, ok := node.MACTable.Lookup(mac); ok {
				if pid == h.ID() {
					return "self"
				}
				return pid.ShortString()
			}
		}
		if node.isExitNodeActive() {
			if exitPID := node.Gateway.ActiveExitPeerPID(); exitPID != "" {
				return exitPID.ShortString() + " (exit)"
			}
		}
		return ""
	})

	// Feed every known direct peer endpoint to the GatewayManager so that
	// activating an Exit Node installs bypass host routes for all peers at
	// once (including those reached via relay). The peerstore is the
	// authoritative source of direct peer addresses.
	node.Gateway.SetPeerEndpointProvider(func() []string {
		var eps []string
		seen := make(map[string]bool)
		addIP := func(ip net.IP) {
			if ip != nil && !ip.IsLoopback() {
				s := ip.String()
				if !seen[s] {
					seen[s] = true
					eps = append(eps, s)
				}
			}
		}
		for _, pID := range h.Peerstore().Peers() {
			for _, a := range filterLoopbackAddrs(h.Peerstore().Addrs(pID)) {
				if ip, err := manet.ToIP(a); err == nil {
					addIP(ip)
				}
			}
		}
		for _, bStr := range cfg.BootstrapPeers {
			if ma, err := multiaddr.NewMultiaddr(bStr); err == nil {
				if ip, err := manet.ToIP(ma); err == nil {
					addIP(ip)
				}
			}
		}
		return eps
	})

	// Populate TAP interface state for WebUI diagnostics
	collector.SetTAPState(&observer.TAPStateDTO{
		InterfaceName:   cfg.TapName,
		IPv4:            cfg.TapIP,
		IPv6:            cfg.TapIPv6,
		MAC:             cfg.TapMAC,
		MTU:             cfg.MTU,
		IsUp:            true,
		RouteConfigured: cfg.TapIP != "",
	})

	// Wire collector callbacks so web handlers can resolve peer addresses and
	// trigger Exit Node NAT reconfiguration after hot-reload.
	collector.SetCallbacks(observer.CollectorConfig{
		ResolvePeerAddrs: func(peerIDStr string) []string {
			pid, err := peer.Decode(peerIDStr)
			if err != nil {
				return nil
			}
			var ips []string
			for _, a := range filterLoopbackAddrs(h.Peerstore().Addrs(pid)) {
				multiaddr.ForEach(a, func(c multiaddr.Component) bool {
					if c.Protocol().Code == multiaddr.P_IP4 || c.Protocol().Code == multiaddr.P_IP6 {
						ips = append(ips, c.Value())
					}
					return true
				})
			}
			return ips
		},
		OnExitNodeChanged: func() {
			node.NFTManager.UpdateConfig(&node.Config.ExitNode)
			if node.Config.ExitNode.Enable {
				_ = node.NFTManager.SetupExitNodeNAT(node.Config.ExitNode.WANInterface, node.Config.TapName, computeExitMSS(node.Config.MTU, node.Config.Obfuscation.Mode))
			} else {
				_ = node.NFTManager.CleanupExitNodeNAT()
			}
			// Exit-node state changed -> announce updated node info to the
			// peek-map broadcast channel so every other client sees the new state.
			go node.publishPeekMapSelf()
		},
		OnObfuscationChanged: func() {
			if node.Packer != nil {
				node.Packer.UpdateConfig(&node.Config.Obfuscation)
				node.Packer.SetSendAlgo(node.sendAlgo())
				log.Info("Obfuscation config hot-reloaded: mode=%s algo=%s", node.Packer.Mode, obfuscate.AlgoName(node.sendAlgo()))
			}
			// Obfuscation/transport state changed -> re-announce node info.
			go node.publishPeekMapSelf()
		},
		OnSubnetsChanged: func() {
			// Advertised subnets changed -> re-broadcast our LAN subnet
			// advertisements over the peek-map channel so every peer updates its
			// routed subnets / ARP proxy entries for us.
			log.Debug("Advertised subnets changed (%v) — re-announcing over peek-map", node.Config.AdvertisedSubnets)
			go node.publishPeekMapSelf()
		},
		TestPeerMultiaddrs: func(peerIDStr string) []observer.MultiaddrTestResultEntry {
			return node.TestMultiaddrLatency(peerIDStr)
		},
		DiagnoseLink: func(multiaddrStr string) *observer.LinkDiagnosis {
			return node.DiagnoseLink(multiaddrStr)
		},
		ProbePeerEcho: func(peerIDStr string) *observer.PeerEchoResultDTO {
			return node.ProbePeerEcho(peerIDStr)
		},
		ProbePeerEchoAddr: func(peerIDStr string, targetAddrStr string) *observer.PeerEchoResultDTO {
			return node.ProbePeerEchoAddr(peerIDStr, targetAddrStr)
		},
		ProbeTapForward: func(peerIDStr string) *observer.TapProbeResultDTO {
			pid, err := peer.Decode(peerIDStr)
			if err != nil {
				return &observer.TapProbeResultDTO{PeerID: peerIDStr, Success: false, Error: "invalid peer ID: " + err.Error()}
			}
			res, err := node.ProbeTapForward(pid)
			if err != nil {
				res.Success = false
			}
			return &observer.TapProbeResultDTO{
				PeerID:    res.PeerID,
				PeerName:  res.PeerName,
				TapIP:     res.TapIP,
				Success:   res.Success,
				RTTMills:  res.RTTMills,
				SentBytes: res.SentBytes,
				Error:     res.Error,
			}
		},
		AddStaticPeer: func(multiaddrStr string) error {
			ma, err := multiaddr.NewMultiaddr(multiaddrStr)
			if err != nil {
				return fmt.Errorf("invalid multiaddr: %w", err)
			}
			info, err := peer.AddrInfoFromP2pAddr(ma)
			if err != nil {
				return fmt.Errorf("invalid peer multiaddr (must contain /p2p/PeerID): %w", err)
			}
			h.Peerstore().AddAddrs(info.ID, info.Addrs, peerstore.PermanentAddrTTL)
			log.Info("Manually added static peer %s (%v)", info.ID.String(), info.Addrs)
			go node.connectWithRetry(*info, "static-manual", 3*time.Second, 5)
			return nil
		},
		OnSubnetToggle: func(cidr string, enable bool) error {
			if node.Gateway != nil {
				_, err := node.Gateway.ToggleSubnetRoute(cidr, enable)
				if err != nil {
					return err
				}
				node.reconcileSubnetRoutes()
				node.updateWebCollectorState()
				return nil
			}
			return fmt.Errorf("gateway manager unavailable")
		},
		GetACLStats: func() observer.ACLStatsDTO {
			dto := node.GetACLStats()
			out := observer.ACLStatsDTO{
				Enabled:    dto.Enabled,
				Accepted:   dto.Accepted,
				Dropped:    dto.Dropped,
				UptimeSec:  dto.UptimeSec,
				RuleCount:  dto.RuleCount,
				DefaultAct: dto.DefaultAct,
			}
			out.RuleHits = make([]observer.ACLRuleHit, len(dto.RuleHits))
			for i, h := range dto.RuleHits {
				out.RuleHits[i] = observer.ACLRuleHit{RuleID: h.RuleID, Hits: h.Hits}
			}
			out.RecentDrops = make([]observer.ACLDropDTO, len(dto.RecentDrops))
			for i, d := range dto.RecentDrops {
				out.RecentDrops[i] = observer.ACLDropDTO{
					Time: d.Time, PeerID: d.PeerID, RuleID: d.RuleID, Reason: d.Reason,
					Proto: d.Proto, SrcIP: d.SrcIP, DstIP: d.DstIP, DstPort: d.DstPort, Dir: d.Dir,
				}
			}
			return out
		},
		ProbePeerConnectivity: func(peerIDStr string) *observer.PeerConnectivityResult {
			result := &observer.PeerConnectivityResult{
				PeerID:   peerIDStr,
				ProbedAt: time.Now(),
			}
			var pid peer.ID
			decodedPID, err := peer.Decode(peerIDStr)
			if err == nil {
				pid = decodedPID
			} else if pidStr, ok := peekPeerIDFromList(node.getActivePeers(), peerIDStr); ok {
				if parsed, derr := peer.Decode(pidStr); derr == nil {
					pid = parsed
					result.PeerID = pidStr
				}
			}
			if pid == "" {
				result.Error = fmt.Sprintf("cannot resolve target '%s' to a connected peer ID", peerIDStr)
				return result
			}

			// Bootstrap/relay nodes are pure Circuit-Relay hops: they do NOT register
			// the application data protocol (/p2ptap/application/1.0.0), so probing them with a
			// /p2ptap/application/1.0.0 stream would always fail with "protocols not supported".
			// Treat them as reachable relays and skip the app-layer stream probe.
			if node.isBootstrapPeer(pid) {
				result.RelayOk = true
				result.Reachable = true
				result.Error = ""
				log.Debug("Connectivity probe skipped for bootstrap/relay node %s (relay role, no app protocol)", pid.ShortString())
				return result
			}

			// 1. Multiaddr-level probes (real SYN/TCP-connect RTT per address)
			result.Results = node.TestMultiaddrLatency(peerIDStr)
			for _, r := range result.Results {
				if r.Reachable {
					if r.IsActive {
						result.DirectOk = true
					}
					if r.RTTMs > 0 && (r.RTTMs < result.RTTMs || result.RTTMs == 0) {
						result.RTTMs = r.RTTMs
					}
				}
			}

			// 2. Check if there's a relay path
			if !result.DirectOk {
				relayAddrs := node.SynthesizeRelayCircuitAddrs(pid)
				for _, ra := range relayAddrs {
					ctx, cancel := context.WithTimeout(node.ctx, 3*time.Second)
					start := time.Now()
					err := node.Host.Connect(ctx, peer.AddrInfo{ID: pid, Addrs: []multiaddr.Multiaddr{ra}})
					elapsed := time.Since(start)
					cancel()
					if err == nil {
						result.RelayOk = true
						result.RTTMs = elapsed.Milliseconds()
						result.Reachable = true
						break
					}
				}
			}

			// 3. Stream-level check: open a protocol stream
			checkStream := func() (bool, int64) {
				ctx, cancel := context.WithTimeout(node.ctx, 4*time.Second)
				defer cancel()
				start := time.Now()
				s, err := node.Host.NewStream(ctx, pid, ProtocolID)
				elapsed := time.Since(start).Milliseconds()
				if err != nil {
					return false, 0
				}
				s.Close()
				return true, elapsed
			}

			for i := 0; i < 3; i++ {
				ok, rtt := checkStream()
				if ok {
					result.StreamsOk++
					if rtt > 0 && (rtt < result.RTTMs || result.RTTMs == 0) {
						result.RTTMs = rtt
					}
				} else {
					result.StreamsErr++
				}
			}

			result.Reachable = result.DirectOk || result.RelayOk || result.StreamsOk > 0
			if !result.Reachable {
				result.Error = "peer unreachable via direct or relay paths"
			}
			return result
		},
	})

	if cfg.TapIP != "" {
		cleanIP, _, _ := strings.Cut(cfg.TapIP, "/")
		node.localV4IP = net.ParseIP(cleanIP)
		if _, ipNet, err := net.ParseCIDR(cfg.TapIP); err == nil {
			node.localV4Net = ipNet
		}
	}
	if cfg.TapIPv6 != "" {
		cleanIP, _, _ := strings.Cut(cfg.TapIPv6, "/")
		node.localV6IP = net.ParseIP(cleanIP)
		if _, ipNet, err := net.ParseCIDR(cfg.TapIPv6); err == nil {
			node.localV6Net = ipNet
		}
	}
	if cfg.TapMAC != "" {
		if hw, err := net.ParseMAC(cfg.TapMAC); err == nil {
			node.localMAC = hw
		}
	}
	node.Dispatcher.SetOutgoingStreamHandler(node.handleStream)

	// Set libp2p stream handler
	h.SetStreamHandler(ProtocolID, node.handleStream)
	log.Debug("Stream handler registered for protocol: %s", ProtocolID)

	h.SetStreamHandler(LSAProtocolID, node.handleLSAStream)
	log.Debug("Stream handler registered for LSA protocol: %s", LSAProtocolID)

	h.SetStreamHandler(OverlayRelayProtocolID, node.handleRelayStream)
	log.Debug("Stream handler registered for Overlay Relay protocol: %s", OverlayRelayProtocolID)

	h.SetStreamHandler(RelayCtrlProtocolID, node.handleRelayCtrl)
	log.Debug("Stream handler registered for Relay-Ctrl (control-plane tunnel) protocol: %s", RelayCtrlProtocolID)

	// Echo protocol doubles as the unified liveness/health probe (see
	// peerPingPongLoop); the old separate HealthCheck protocol was removed to
	// avoid two independent per-peer NewStream probe storms every 5s+30s.
	h.SetStreamHandler(EchoProtocolID, node.handleEcho)
	log.Debug("Stream handler registered for Echo protocol: %s", EchoProtocolID)

	node.registerTapProbeHandler()

	node.registerSeqSyncHandler()
	log.Debug("Stream handler registered for SeqSync protocol: %s", SeqSyncProtocolID)

	node.registerMetaStreamHandler()
	node.registerPeekMapHandler()

	// Register network event notifier for connection/disconnection logging & state cleanup
	h.Network().Notify(&network.NotifyBundle{
		ConnectedF: func(netw network.Network, conn network.Conn) {
			pID := conn.RemotePeer()
			addrStr := conn.RemoteMultiaddr().String()
			isCircuitRelay := strings.Contains(addrStr, "/p2p-circuit")

			// Protect P2P socket route: when exit node is active, ensure the
			// peer's physical IP has a /32 host route via the physical gateway
			// so P2P traffic does not get sucked into the TAP default route.
			if node.Gateway != nil {
				remoteAddr := conn.RemoteMultiaddr()
				if ip, err := manet.ToIP(remoteAddr); err == nil && !ip.IsLoopback() {
					_ = node.Gateway.ProtectEndpoint(ip.String())
				}
			}

			if isCircuitRelay {
				relayID := relayPeerIDOf(addrStr)
				if relayID != "" {
					log.Info("Peer connected via CIRCUIT RELAY: %s via relay %s (ma=%s)", pID.String(), relayID, addrStr)
				} else {
					log.Info("Peer connected via CIRCUIT RELAY: %s (ma=%s)", pID.String(), addrStr)
				}
				// p2p-circuit provides transparent L3 connectivity, so register
				// it as a direct link for routing purposes.
				rttMs := node.getPeerLatency(pID)
				node.directConnectedMu.Lock()
				hadDirect := node.directConnected[pID]
				node.directConnectedMu.Unlock()
				if !hadDirect {
					node.Router.UpdateDirectLink(pID, rttMs, routing.LinkCircuit)
				}
				if node.isBootstrapPeer(pID) {
					node.recordRelayLatency(pID, time.Duration(rttMs)*time.Millisecond)
				}
				// A non-bootstrap peer reached only via circuit relay is relay-only.
				if !node.isBootstrapPeer(pID) {
					node.directConnectedMu.Lock()
					hadDirect2 := node.directConnected[pID]
					node.directConnectedMu.Unlock()
					if !hadDirect2 {
						node.markRelayOnlyPeer(pID)
					}
				}
			} else {
				log.Info("Peer connected DIRECT: %s via %s", pID.String(), addrStr)
				node.directConnectedMu.Lock()
				node.directConnected[pID] = true
				node.directConnectedMu.Unlock()
				node.clearRelayOnlyPeer(pID)
				rttMs := node.getPeerLatency(pID)
				if rttMs <= 0 {
					rttMs = 10
				}
				node.Router.UpdateDirectLink(pID, rttMs, routing.LinkDirect)
			}

			// ── Bootstrap peer: PSK auth then peek-map. Stop here. ──────────
			if node.isBootstrapPeer(pID) {
				go func() {
					// Single-flight dedup: ConnectedF fires once per transport.
					// Hold relayAuthInProgress for the whole span so concurrent
					// transport-upgrade events don't pile up concurrent auth streams.
					node.relayAuthMu.Lock()
					if node.relayAuthInProgress[pID] {
						node.relayAuthMu.Unlock()
						return
					}
					node.relayAuthInProgress[pID] = true
					node.relayAuthMu.Unlock()

					authOK := node.authenticateWithRelay(pID, false)

					node.relayAuthMu.Lock()
					delete(node.relayAuthInProgress, pID)
					node.relayAuthMu.Unlock()

					if !authOK {
						// Auth failed: PSK mismatch, no PSK configured, or exchange
						// error. Do NOT open the peek-map stream — the boot would
						// reject every frame as unauthenticated. The reconnect loop
						// will retry on the next connection.
						log.Warn("PSK auth with bootstrap %s failed — peek-map NOT opened. Check PSK configuration.", pID.ShortString())
						return
					}

					// Open peek-map AFTER auth so boot never receives an
					// unauthenticated frame (boot-side also waits 3 s but
					// serialising here is the belt-and-suspenders guarantee).
					node.ensurePeekMapListener(pID)

					// Establish the boot-relay (relay-over-backbone) uplink.
					node.bootRelayMu.Lock()
					if _, ok := node.bootRelayStarted[pID]; !ok {
						node.bootRelayStarted[pID] = struct{}{}
						node.bootRelayMu.Unlock()
						go node.openBootRelayUplink(pID)
					} else {
						node.bootRelayMu.Unlock()
					}
				}()
				return
			}

			// ── Non-bootstrap peer: rekey + LSA + snapshot + meta ───────────

			// Trigger metadata sync immediately for circuit-relay peers which may
			// not appear in broadcastMetadata's peer scan at connect time.
			go node.syncMetadataToPeer(pID)

			// ECDH re-key on every (re)connect so both sides converge on the
			// same cipher after a restart, even when in-memory keys were retained.
			go func() {
				if node.isResyncLeader(pID) {
					node.triggerPeerRekey(pID)
					return
				}
				// Follower waits to give the leader time to open its stream first.
				// Circuit-relay paths get a shorter delay to avoid plaintext
				// frames on the new link before cipher is negotiated.
				followerDelay := 5 * time.Second
				if isCircuitRelay {
					followerDelay = 2 * time.Second
				}
				time.Sleep(followerDelay)
				node.triggerPeerRekey(pID)
			}()

			// Broadcast our LSA so the new peer learns our current link state.
			go func() {
				node.lsaMu.Lock()
				defer node.lsaMu.Unlock()
				node.lastLSAMu.Lock()
				node.lastLSAJSON = nil // force-send even if content unchanged
				node.lastLSAMu.Unlock()
				node.broadcastLSA(node.nextLSASeq())
			}()

			// Push a full topology snapshot (every third-party LSA we hold) so
			// the new peer converges on the whole mesh without waiting for a
			// change-triggered LSA flood from every other node.
			go node.pushLSASnapshotToPeer(pID)
		},
		DisconnectedF: func(netw network.Network, conn network.Conn) {
			pID := conn.RemotePeer()
			addrStr := conn.RemoteMultiaddr().String()
			isCircuitRelay := strings.Contains(addrStr, "/p2p-circuit")
			remaining := len(netw.ConnsToPeer(pID))

			if remaining > 0 {
				if isCircuitRelay {
					log.Debug("Relay transport dropped for %s (direct connection still active, %d remaining)", pID.String(), remaining)
				} else {
					log.Debug("Direct transport dropped for %s (%d other transports still active)", pID.String(), remaining)
				}
				return
			}

			// All transports gone — debounce: if we had a direct connection that just
			// dropped, wait 2s to see if it comes back (e.g. due to dialInParallel race).
			node.directConnectedMu.Lock()
			hadDirect := node.directConnected[pID]
			delete(node.directConnected, pID)
			node.directConnectedMu.Unlock()

			if hadDirect {
				debounceID := pID
				go func() {
					time.Sleep(2 * time.Second)
					if node.Host.Network().Connectedness(debounceID) == network.Connected ||
						len(node.Host.Network().ConnsToPeer(debounceID)) > 0 {
						log.Debug("Peer %s recovered within debounce window, not purging", debounceID.String())
						node.directConnectedMu.Lock()
						node.directConnected[debounceID] = true
						node.directConnectedMu.Unlock()
						return
					}
					log.Info("Peer disconnected: %s (last transport lost, purging links, metadata & MAC table)", debounceID.String())
				node.Router.RemoveDirectLink(debounceID)
				node.deletePeerMeta(debounceID)
				node.MACTable.CleanPeer(debounceID)
				node.Dispatcher.RemovePeer(debounceID)
				node.dedupPeersMu.Lock()
				delete(node.dedupPeers, debounceID)
				node.dedupPeersMu.Unlock()
				node.removePeerObf(debounceID)
				node.reconcileSubnetRoutes()
				// Drop cached persistent control streams so the next use re-opens
				// cleanly instead of hitting a dead stream (10s NewStream timeout).
				node.lsaPool.Invalidate(debounceID)
				node.metaPool.Invalidate(debounceID)
				node.echoPool.Invalidate(debounceID)
				// Re-flood LSA so peers drop the now-stale edge to this peer
				// instead of holding a phantom link. Fresh seq + reset gossip
				// throttle guarantees propagation even if our neighbour set is
				// otherwise unchanged.
				go func() {
					node.lsaMu.Lock()
					defer node.lsaMu.Unlock()
					node.lastLSAMu.Lock()
					node.lastLSAJSON = nil
					node.lastLSAMu.Unlock()
					node.broadcastLSA(node.nextLSASeq())
				}()
				}()
			} else {
			log.Info("Peer disconnected: %s via %s (last transport lost, purging links, metadata & MAC table)", pID.String(), addrStr)
			node.Router.RemoveDirectLink(pID)
			node.deletePeerMeta(pID)
			node.MACTable.CleanPeer(pID)
			node.Dispatcher.RemovePeer(pID)
			node.dedupPeersMu.Lock()
			delete(node.dedupPeers, pID)
			node.dedupPeersMu.Unlock()
			node.removePeerObf(pID)
			node.reconcileSubnetRoutes()
			// Drop cached persistent control streams (see above).
			node.lsaPool.Invalidate(pID)
			node.metaPool.Invalidate(pID)
			node.echoPool.Invalidate(pID)
			// Re-flood LSA so peers drop the now-stale edge to this peer
			// instead of holding a phantom link (see debounce branch above).
			go func() {
				node.lsaMu.Lock()
				defer node.lsaMu.Unlock()
				node.lastLSAMu.Lock()
				node.lastLSAJSON = nil
				node.lastLSAMu.Unlock()
				node.broadcastLSA(node.nextLSASeq())
			}()
			}
		},
	})

	// Start Web UI Server if configured. The concrete web objects are created by
	// the cmd layer via the injected MakeInterceptor / StartWebServer hooks, so
	// the domain core never imports the web package.
	if cfg.WebUI.Enable {
		if err := node.SetupWebUI(); err != nil {
			log.Warn("WebUI setup failed: %v", err)
		}
	}

	// Periodic reaper for tunnel-fragment reassembly buffers so an incomplete
	// fragment group (e.g. a dropped QUIC packet) cannot leak memory.
	go func() {
		ticker := time.NewTicker(reasmTimeout)
		defer ticker.Stop()
		for {
			select {
			case <-node.ctx.Done():
				return
			case <-ticker.C:
				node.fragRX.reap()
			}
		}
	}()

	return node, nil
}

// SetupWebUI wires the WebUI layer into the node. It is idempotent and only
// acts when the cmd layer has injected the MakeInterceptor / StartWebServer
// hooks (otherwise it is a no-op, e.g. in tests without a web frontend).
// The hooks are supplied by the concrete web package and receive the node's
// observer.Collector, keeping node free of any web import.
func (n *Node) SetupWebUI() error {
	cfg := n.Config
	listenIP := cfg.WebUI.ListenIP
	listenIPv6 := cfg.WebUI.ListenIPv6

	isVirtualV4 := IsVirtualIP(listenIP, cfg.TapIP)
	isVirtualV6 := IsVirtualIP(listenIPv6, cfg.TapIPv6)

	var virtualIP, virtualIPv6, localIP, localIPv6 string

	if isVirtualV4 {
		virtualIP = listenIP
		v4 := net.ParseIP(strings.Split(listenIP, "/")[0]).To4()
		if v4 != nil {
			n.virtualWebUIV4IP = v4
			n.virtualWebUIV4IPUint32 = binary.BigEndian.Uint32(v4)
		}
	} else {
		localIP = listenIP
	}

	if isVirtualV6 {
		virtualIPv6 = listenIPv6
		n.virtualWebUIV6IP = net.ParseIP(strings.Split(listenIPv6, "/")[0])
	} else {
		localIPv6 = listenIPv6
	}

	// 1. Start Userspace Packet Interceptor for any virtual IPs
	if (isVirtualV4 || isVirtualV6) && n.MakeInterceptor != nil {
		n.Interceptor = n.MakeInterceptor(virtualIP, virtualIPv6, cfg.WebUI.Port, n.Collector, cfg, cfg.ConfigPath)
		log.Info("WebUI Virtual IP Interceptor active (v4: %s, v6: %s) on port %d", virtualIP, virtualIPv6, cfg.WebUI.Port)
		if setter, ok := n.TAP.(interface{ SetWebUIIP(string) }); ok {
			if virtualIP != "" {
				setter.SetWebUIIP(virtualIP)
			} else if virtualIPv6 != "" {
				setter.SetWebUIIP(virtualIPv6) // Fallback for platforms that need at least one
			}
		}
	}

	// 2. Start Native OS WebServer for any non-virtual, local IPs
	if (localIP != "" || localIPv6 != "") && n.StartWebServer != nil {
		bindIP := localIP
		bindIPv6 := localIPv6
		if bindIPv6 == "" || bindIPv6 == "auto" {
			bindIPv6 = "::" // Bind to all IPv6 addresses if not specified
		}
		log.Info("WebUI listening on (v4: %s, v6: %s) on port %d (native OS stack mode)", bindIP, bindIPv6, cfg.WebUI.Port)
		// NOTE: the WebUI is an *inbound* management listener. It must NOT be
		// pinned to the egress NIC via SO_BINDTODEVICE/IP_UNICAST_IF — doing so
		// (GetSocketControlHookTolerant) restricts the socket to a single
		// physical interface and breaks access from other interfaces (e.g. the
		// LAN on a multi-homed router, where the dashboard IP lives on a
		// different NIC than the egress one), presenting as "listening on *:port
		// but connection refused from a local IP". The protect hook exists for
		// *outbound* P2P transport sockets to avoid TAP-default-route loops; an
		// inbound listener has no such loop, so we pass nil and let it bind
		// wildcard on every interface.
		webSrv, err := n.StartWebServer(n.Collector, bindIP, bindIPv6, cfg.WebUI.Port, cfg, cfg.ConfigPath, nil)
		if err != nil {
			return err
		}
		n.WebSrv = webSrv
	}

	return nil
}

// computeExitMSS returns the TCP MSS to clamp on the Exit Node server's
// POSTROUTING chain so client tunnel traffic survives the real (reduced) path
// MTU. We must NOT shrink the client's TAP MTU (#2 is explicitly forbidden), so
// instead we advertise a smaller MSS. The actual wire path is a QUIC stream
// (path MTU ~1200) plus obfuscation framing overhead (14-byte header + 16-byte
// AEAD tag) and IP/TCP headers, so the clamp must subtract that overhead;
// otherwise large TCP segments get fragmented/blackholed through the tunnel and
// web browsing / data exchange on the Exit Node client crawls.
//
// #3: the value accounts for obfuscation overhead rather than lowering the TAP
// MTU.
func computeExitMSS(mtu int, obfMode string) int {
	if mtu <= 0 {
		mtu = 1500
	}
	pathMTU := 1200 // conservative QUIC path MTU
	if mtu > pathMTU {
		mtu = pathMTU
	}
	// 40 (IP, v6-safe) + 20 (TCP) + 14 (obfuscation header) + 16 (AEAD tag)
	overhead := 40 + 20 + 14 + 16
	mss := mtu - overhead
	if mss < 512 {
		mss = 512
	}
	return mss
}

func (n *Node) Start() {
	// Connect to Bootstrap Peers with retry
	for _, bStr := range n.Config.BootstrapPeers {
		ma, err := multiaddr.NewMultiaddr(bStr)
		if err != nil {
			log.Debug("Invalid bootstrap multiaddr '%s': %v", bStr, err)
			continue
		}
		info, err := peer.AddrInfoFromP2pAddr(ma)
		if err == nil {
			n.Host.Peerstore().AddAddrs(info.ID, info.Addrs, peerstore.PermanentAddrTTL)
			go n.connectWithRetry(*info, "bootstrap", 5*time.Second, 10)
		}
	}

	// Connect to Static Peers with retry
	for _, sStr := range n.Config.StaticPeers {
		ma, err := multiaddr.NewMultiaddr(sStr)
		if err != nil {
			log.Debug("Invalid static peer multiaddr '%s': %v", sStr, err)
			continue
		}
		info, err := peer.AddrInfoFromP2pAddr(ma)
		if err == nil {
			n.Host.Peerstore().AddAddrs(info.ID, info.Addrs, peerstore.PermanentAddrTTL)
			go n.connectWithRetry(*info, "static", 5*time.Second, 10)
		}
	}

	// Start TAP Read Pipeline Goroutine
	n.wg.Add(1)
	go n.tapReadLoop()
	log.Debug("TAP read loop started")

	// Start urgent TAP-write loop (priority injection for diagnostics)
	n.wg.Add(1)
	go n.tapWriteUrgentLoop()
	log.Debug("Urgent TAP write loop started")

	// Start urgent dispatch loop (priority SEND queue, symmetric to receive)
	n.wg.Add(1)
	go n.urgentDispatchLoop()
	log.Debug("Urgent dispatch loop started")

	// Start bounded dispatch worker pool for TAP->P2P forwarding
	for i := 0; i < dispatchWorkerCount; i++ {
		n.startDispatchWorker(i)
	}
	log.Debug("Dispatch worker pool started (%d workers, buffer=%d)", dispatchWorkerCount, cap(n.dispatchCh))

	// Start Background MAC Cleaning Goroutine
	n.wg.Add(1)
	go n.macCleanLoop()
	log.Debug("MAC clean loop started")

	// Start persistent bootstrap/relay reconnection loop
	n.wg.Add(1)
	go n.bootstrapKeepAliveLoop()
	log.Debug("Bootstrap keep-alive loop started")

	// Start unified liveness/health probe loop (echo-based, 10s). Replaces the
	// old separate HealthCheck(30s)+PingPong(5s) pair to avoid two independent
	// per-peer NewStream probe storms every cycle.
	n.wg.Add(1)
	go n.peerPingPongLoop()
	log.Debug("Unified ping-pong/health probe loop started")

	// Start P2P metadata synchronization loop
	n.wg.Add(1)
	go n.metaSyncLoop()

	// Start the relay-control reconciler: brings up the SeqSync cipher + Meta
	// identity for peers reachable ONLY through a relay hop (e.g. A↔C via relay
	// B) so the end-to-end control plane converges even when the two peers are
	// never directly connected. See relay_ctrl.go.
	n.wg.Add(1)
	go n.relayControlReconciler()
	log.Debug("Relay-control reconciler started")
	log.Debug("Metadata synchronization loop started")

	// Start Link-State Advertisement loop
	n.wg.Add(1)
	go n.lsaLoop()
	log.Debug("Link-State Advertisement loop started")

	// Start DHT Discovery Loop based on PSK
	if n.Config.PSK != "" {
		n.wg.Add(1)
		go n.discoveryLoop()
		log.Info("DHT discovery loop started for PSK network")
	}

	// Setup Exit Node NAT if enabled in config
	if n.Config.ExitNode.Enable {
		_ = n.NFTManager.SetupExitNodeNAT(n.Config.ExitNode.WANInterface, n.Config.TapName, computeExitMSS(n.Config.MTU, n.Config.Obfuscation.Mode))
	}

	// Start roam handling: watch for NIC changes and rotate listeners.
	n.startRoamWatcher()
}

// connectWithRetry attempts to connect to a peer with exponential backoff retry.
// First attempt uses parallel direct+relay racing; subsequent attempts use standard Connect.

// sendAlgo returns the ObfType byte written into frames this node sends. It is
// the strongest algorithm this node is willing to use (first entry of the local
// preference order produced by mySupportedAlgos). Per-peer negotiation may pick
// a weaker common algorithm, but the header ObfType only needs to tell the
// receiver which family to attempt; the actual key is per-peer.
func (n *Node) sendAlgo() byte {
	algos := n.mySupportedAlgos()
	if len(algos) == 0 {
		return obfuscate.ObfAlgoNone
	}
	return algos[0]
}

// newPeerObfTable returns a pointer to an atomic.Pointer pre-loaded with an
// empty per-peer obfuscation table. Returned as *atomic.Pointer (and stored via
// the field's value type by dereferencing) to avoid copying the noCopy guard.
func newPeerObfTable() *atomic.Pointer[map[peer.ID]*PeerObf] {
	p := new(atomic.Pointer[map[peer.ID]*PeerObf])
	m := make(map[peer.ID]*PeerObf)
	p.Store(&m)
	return p
}

// lenOpt returns the length of an optional table pointer (0 if nil), so callers
// can size allocations without a nil check.
func lenOpt(m *map[peer.ID]*PeerObf) int {
	if m == nil {
		return 0
	}
	return len(*m)
}

// peerObf is the lock-free hot-path lookup used by every TX/RX packet. It loads
// the current copy-on-write table once and reads the peer entry; no mutex is
// taken, so concurrent encryption on many peers never contends.
func (n *Node) peerObf(p peer.ID) *PeerObf {
	tbl := n.perPeerObf.Load()
	if tbl == nil {
		return nil
	}
	return (*tbl)[p]
}

// obfCipherForPeer returns the per-peer cipher used to ENCRYPT frames sent TO
// the given peer (the TX direction). Returns nil if no encryption was negotiated
// (encryption disabled or handshake not yet completed) — callers must then fall
// back to plaintext obfuscation. Lock-free: a single atomic load of the table.
// Note: receiving frames uses obfDecryptCipherForPeer (the RX direction), which
// is a DISTINCT key by design — see PeerObf for the rationale.
// obfRekeyFrameThreshold is the number of frames a single negotiated key may
// protect before we proactively rotate it. It is kept comfortably below the
// 2^32 size of the structured nonce counter field so a (key, nonce) pair can
// never be reused — the one catastrophic failure mode of AES-GCM / ChaCha20.
// It bounds BOTH the global safety-net delta (negotiatedAtSeq) and the
// per-peer frame count (framesSinceRekey) — see obfCipherForPeer.
const obfRekeyFrameThreshold = uint64(0xFFFFFFFF) - (1 << 28)

// sealPeerFrame encrypts data with the per-peer cipher AND accounts the frame
// against that peer's proactive re-key budget. It is the ONE place every
// AEAD-encrypted frame to a specific peer flows through, so the per-peer count
// it maintains is exact: each physical frame (including every fragment re-seal)
// bumps framesSinceRekey once, matching one-to-one the number of nonces spent
// under this key. Counting per-peer (not the process-wide FramePacker counter)
// means a chatty peer rotates promptly while a quiet peer keeps its key longer
// — but the GLOBAL safety net in obfCipherForPeer still guarantees rotation
// before the 32-bit structured counter (shared node-wide) could wrap and reuse
// a nonce for a quiet peer, so per-peer counting can never break nonce safety.
func (n *Node) sealPeerFrame(p peer.ID, cipher obfuscate.ObfCipher, data []byte) ([]byte, error) {
	if cipher == nil {
		return nil, fmt.Errorf("sealPeerFrame: nil cipher for peer %s — refusing to ship frame unsealed", p.String())
	}
	enc, err := obfuscate.EncryptPayloadRegion(data, cipher)
	if err != nil {
		return nil, err
	}
	if po := n.peerObf(p); po != nil {
		po.framesSinceRekey.Add(1)
	}
	return enc, nil
}

func (n *Node) obfCipherForPeer(p peer.ID) obfuscate.ObfCipher {
	po := n.peerObf(p)
	if po == nil || !po.negotiated {
		log.Debug("Tx: NO negotiated cipher for %s (po=%v) — sending payload in PLAINTEXT (obfuscation only, NOT encrypted)",
			p.String(), po != nil)
		return nil
	}
	// Proactively rotate the per-peer key before a nonce could be reused under
	// this key. Two independent triggers, each a single atomic load; the actual
	// re-handshake is fire-and-forget and guarded per-peer so it cannot spam.
	//
	//  1. GLOBAL safety net: the AEAD nonce is derived from the frame header's
	//     32-bit structured-counter field, which is shared node-wide (only the
	//     12-bit per-peer epoch differs). So even a quiet peer that has sent
	//     few frames of its own must rotate once THIS node has shipped ~2^32
	//     frames total — otherwise the global counter recycles and reuses a
	//     (key, nonce) pair for it. negotiatedAtSeq anchors this delta.
	//  2. PER-PEER trigger: a chatty peer rotates promptly even when the node as
	//     a whole is quiet (e.g. one busy peer among many idle ones). It counts
	//     only frames actually sealed to this peer (framesSinceRekey), which is
	//     a strictly tighter signal than the global delta for that case.
	if n.Packer != nil {
		if delta := n.Packer.CurrentCounter() - po.negotiatedAtSeq; delta > obfRekeyFrameThreshold {
			log.Debug("Tx: proactive re-key (global counter) triggered for %s (counter delta=%d > threshold=%d); re-handshaking in background",
				p.String(), delta, obfRekeyFrameThreshold)
			n.triggerPeerRekey(p)
		}
	}
	if po.framesSinceRekey.Load() > obfRekeyFrameThreshold {
		log.Debug("Tx: proactive re-key (per-peer frame count) triggered for %s (framesSinceRekey=%d > threshold=%d); re-handshaking in background",
			p.String(), po.framesSinceRekey.Load(), obfRekeyFrameThreshold)
		n.triggerPeerRekey(p)
	}
	log.Debug("Tx: encrypting to %s with algo=%s forward-secret=%v txKeyFP=%s",
		p.String(), obfuscate.AlgoName(po.algo), po.pfsPubKey != nil, obfuscate.KeyFingerprint(po.txKey))
	return po.txCipher
}

// triggerPeerRekey schedules a background SeqSync re-handshake for peer p to
// rotate its per-peer AEAD key before the structured nonce counter wraps under
// the current key. It is a no-op if a re-key is already in flight for that
// peer, and silently does nothing if the peer is disconnected.
func (n *Node) triggerPeerRekey(p peer.ID) {
	if n.Host.Network().Connectedness(p) != network.Connected && n.relayHopForTarget(p) == "" {
		return
	}
	if n.isResyncLeader(p) {
		// LEADER: own the single handshake round for this peer pair. The leader
		// rule is what guarantees exactly ONE handshake stream is ever opened for
		// a given re-key event — without it, both peers can independently call
		// ForceSyncSeq (each accumulating 8 decrypt failures) and open streams to
		// each other simultaneously, producing four divergent ECDH secrets and a
		// permanent decrypt-fail loop. isResyncLeader is deterministic by PeerID,
		// so the two ends always agree on who initiates and the round can never
		// cross generations. The rekeyPeers single-flight below additionally
		// serialises rounds on this node so a single node never runs two at once.
		if _, busy := n.rekeyPeers.LoadOrStore(p, struct{}{}); busy {
			return
		}
		go func() {
			defer n.rekeyPeers.Delete(p)
			log.Debug("SeqSync: starting re-key loop for %s (iAmResyncLeader=%v) — driving handshake to break any decrypt-fail deadlock", p.String(), n.isResyncLeader(p))
			// Persistent retry: SyncSeqToPeer already retries 8× with backoff, but if
			// every attempt fails (e.g. the circuit-relay is congested and NewStream
			// keeps timing out) we must NOT give up — a single abandoned round leaves
			// the link permanently dead even after the relay heals. Keep retrying with
			// a backoff while the peer stays connected; stop only when the handshake
			// succeeds or the peer goes away. Circuit-relay paths get shorter retry
			// intervals because they are often unstable (connection resets every
			// ~500ms) and the 20s default is far too long to converge.
		for {
			// A relay-only peer is never "directly connected" yet is still
			// reachable through an overlay-relay hop (or a boot circuit), so we
			// must NOT bail on the NotConnected state — otherwise the LEADER
			// would abandon the single authoritative handshake round for that
			// peer and the A↔C cipher (relayed through B) would never converge.
			// Only give up when the peer is genuinely unreachable: not directly
			// connected AND with no usable relay hop. This matches the guard in
			// triggerPeerRekey above and the retry guard inside SyncSeqToPeer.
			if n.Host.Network().Connectedness(p) != network.Connected &&
				n.relayHopForTarget(p) == "" {
				return
			}
			if err := n.SyncSeqToPeer(p); err == nil {
					log.Info("SeqSync: rotated/anchored encryption key with %s (re-key converged)", p.String())
					n.lastRekeySuccess.Store(p, time.Now())
					return
				}
				retryDelay := 20 * time.Second
				if n.peerHasCircuitRelayConn(p) || n.relayHopForTarget(p) != "" {
					retryDelay = 5 * time.Second
				}
				log.Warn("SeqSync: re-key to %s failed; retrying in %v (peer still connected, awaiting relay recovery)", p.String(), retryDelay)
				select {
				case <-n.ctx.Done():
					return
				case <-time.After(retryDelay):
				}
			}
		}()
		return
	}
	// FOLLOWER: do NOT open our own re-key stream. Two independent initiators is
	// exactly the crossed-handshake that produces four divergent ECDH secrets and
	// a permanent decrypt-fail loop. Instead nudge the leader to initiate: the
	// leader's handleSeqSync answers a rekeyReq by calling triggerPeerRekey on
	// its (leader) side, which opens the single handshake stream; we then answer
	// it as the responder and converge onto the SAME key the leader negotiates.
	// This also breaks the old follower-deadlock: a follower that sees dropped
	// frames but whose leader does not would otherwise never trigger a re-key
	// (the leader, receiving the follower's frames fine, had no reason to) — now
	// the follower's rekeyReq forces the leader to act.
	n.sendRekeyRequest(p)
	// NAT / hard-reachability fallback: if the leader cannot dial us (e.g. a
	// symmetric NAT where only inbound streams work) the rekeyReq above never
	// converges — the leader's handshake stream to us keeps failing. After a
	// sustained window of no readiness, escalate to initiating our own handshake
	// as a last resort. This re-opens the brief crossed-handshake window, but the
	// RX key ring absorbs the transient mismatched generation and both sides
	// settle on one key shortly after, so the link self-heals rather than dying.
	if _, pending := n.rekeyEscalation.LoadOrStore(p, struct{}{}); !pending {
		go func() {
			defer n.rekeyEscalation.Delete(p)
			select {
			case <-n.ctx.Done():
				return
			case <-time.After(30 * time.Second):
			}
			if n.Host.Network().Connectedness(p) != network.Connected {
				return
			}
			if n.isPeerReady(p) {
				return
			}
			log.Warn("SeqSync: follower rekeyReq to leader for %s did not converge in 30s; escalating to self-initiated handshake (NAT fallback)", p.String())
			_ = n.SyncSeqToPeer(p)
		}()
	}
}

// sendRekeyRequest sends a lightweight rekeyReq nudge to the leader for peer p,
// prompting the leader to initiate the single authoritative handshake round. It
// is best-effort and rate-limited (rekeyReqCooldown) so a burst of decrypt
// failures cannot spam the leader; it opens its own short-lived control stream
// and does NOT negotiate any key itself (the leader does that on its own round).
func (n *Node) sendRekeyRequest(p peer.ID) {
	if v, loaded := n.rekeyReqCooldown.LoadOrStore(p, time.Now()); loaded {
		if time.Since(v.(time.Time)) < 3*time.Second {
			return
		}
		n.rekeyReqCooldown.Store(p, time.Now())
	}
	log.Debug("SeqSync: follower sending rekeyReq to leader for %s (nudging leader to initiate re-key)", p.String())
	go func() {
		ctx, cancel := context.WithTimeout(n.ctx, 10*time.Second)
		defer cancel()
		// Use the unified control-stream opener so a relay-only leader (reachable
		// only through an overlay hop) still receives the nudge — a plain direct
		// NewStream would fail for such a peer and the leader would never re-key.
		s, err := n.openControlStream(ctx, p, SeqSyncProtocolID)
		if err != nil {
			return
		}
		defer s.Close()
		_ = s.SetDeadline(time.Now().Add(5 * time.Second))
		if err := writeSeqSyncMsg(s, n.buildSeqSyncMsg("rekeyReq", p, nil)); err != nil {
			return
		}
		// The leader answers by opening its OWN handshake stream (not on this one),
		// so just drain/close this stream. An EOF here is expected.
		_, _ = readSeqSyncMsg(s)
	}()
}

// obfDecryptCipherForPeer returns the per-peer cipher used to DECRYPT frames
// received FROM the given peer (the RX direction). It is a different key than
// obfCipherForPeer (TX) so the two directions never share a (key, nonce) pair.
func (n *Node) obfDecryptCipherForPeer(p peer.ID) obfuscate.ObfCipher {
	po := n.peerObf(p)
	if po == nil || !po.negotiated {
		log.Debug("Rx: NO negotiated cipher for %s — frame will be treated as PLAINTEXT", p.String())
		return nil
	}
	log.Debug("Rx: will decrypt from %s with algo=%s forward-secret=%v rxKeyFP=%s",
		p.String(), obfuscate.AlgoName(po.algo), po.pfsPubKey != nil, obfuscate.KeyFingerprint(po.rxKey))
	return po.rxCipher
}

// decryptPeerFrame attempts per-peer payload decryption. It returns a 3-tuple:
//
//	out       — the decrypted plaintext when decrypted==true; otherwise the
//	            ORIGINAL bytes (caller must NOT forward them to the TAP when
//	            garbage==true).
//	decrypted — true iff a cipher was negotiated for this peer AND AEAD-open
//	            succeeded.
//	garbage   — true ONLY when a cipher WAS negotiated but AEAD-open FAILED. The
//	            bytes are therefore ciphertext we cannot open (key mismatch / the
//	            peer rotated its key / corruption) and MUST be dropped — never
//	            forwarded to the TAP as if they were plaintext Ethernet. (If no
//	            cipher is negotiated at all, the frame is legitimately plaintext:
//	            that returns (data, false, false), NOT garbage.)
//
// This three-way split closes the "plaintext branch pollution" hole: historically
// a decrypt failure returned the raw ciphertext unchanged and relied on Unpack
// (called with a nil cipher) to reject it. But Unpack's magic check only inspects
// the frame HEADER, which is never encrypted — so a ciphertext frame sails
// through Unpack and gets written straight onto the LAN as garbage. Now the RX
// path sees garbage==true and drops the frame before it can reach the TAP.
// Shared by the direct-frame and relay-envelope RX paths so the
// decrypt-then-validate contract lives in exactly one place.
func (n *Node) decryptPeerFrame(data []byte, remotePeer peer.ID) (out []byte, decrypted bool, garbage bool) {
	cipher := n.obfDecryptCipherForPeer(remotePeer)
	if cipher == nil {
		// No cipher negotiated (encryption disabled / mixed-config peer): the
		// frame is legitimately plaintext. Never flag as garbage.
		log.Debug("Rx: decrypt skipped for %s (no cipher); assuming frame is plaintext", remotePeer.String())
		return data, false, false
	}
	// Log the nonce (via NonceHex) so it can be correlated with the sender's
	// EncryptPayloadRegion log: identical nonce ⇒ we received exactly the frame
	// the peer sealed.
	dec, derr := obfuscate.DecryptPayloadRegion(data, cipher)
	if derr != nil {
		// STRUCTURAL failure first: ErrFrameCorrupted means the input is not a
		// well-formed obfuscate frame at all (its declared payload length does not
		// fit inside the buffer). No key can change that, so walking the whole
		// fallback ring is pure waste — and, worse, reporting it as garbage made
		// every call site invoke maybeResyncOnDecryptFail, so a stream of non-frame
		// bytes triggered repeated pointless key renegotiations that destabilised
		// otherwise-healthy links. Classify it as "not decrypted, not garbage" and
		// let the caller's own parser reject it: Unpack's magic check still stops
		// any non-frame from reaching the TAP device, so the security contract that
		// ciphertext is never forwarded as plaintext continues to hold.
		if errors.Is(derr, obfuscate.ErrFrameCorrupted) {
			log.Debug("Rx: frame from %s is not a well-formed obfuscate frame (%v) — structural, not a key failure; skipping resync",
				remotePeer.String(), derr)
			return data, false, false
		}
		// Multi-key fallback: the peer may still be sealing frames with a key
		// other than our CURRENT one. This happens for three benign reasons, all
		// of which we must tolerate instead of dropping the frame:
		//   1. Key rotation: the peer has not yet flipped to our freshly
		//      negotiated key because the reciprocal "ready" was dropped over a
		//      lossy circuit-relay.
		//   2. Lingering old-connection frame: a straggler sealed on the peer's
		//      previous session that had not yet torn down.
		//   3. Multiple live connections: the peer holds a SEPARATE cipher per
		//      connection (DIRECT vs CIRCUIT-RELAY each ran its own SeqSync
		//      handshake) and round-robins outbound traffic, so frames arrive
		//      under several different keys. A single prevRxCipher slot cannot
		//      represent more than one extra key, so we try the whole bounded
		//      ring of recent RX ciphers (newest-first) first, then the single
		//      prevRxCipher, before declaring the frame garbage.
		if po := n.peerObf(remotePeer); po != nil {
			for i := len(po.rxRing) - 1; i >= 0; i-- {
				slot := po.rxRing[i]
				if dec2, derr2 := obfuscate.DecryptPayloadRegion(data, slot.cipher); derr2 == nil {
					log.Debug("Rx: decrypted from %s with RING rxKeyFP=%s (currentRxKeyFP=%s) — peer still sealing with a prior-gen / other-connection key; link tolerated",
						remotePeer.String(), obfuscate.KeyFingerprint(slot.key), obfuscate.KeyFingerprint(po.rxKey))
					n.recordPeerRxDecrypt(remotePeer, true)
					n.maybeMarkReadyOnDecrypt(remotePeer, true)
					return dec2, true, false
				}
			}
			if po.prevRxCipher != nil {
				if dec2, derr2 := obfuscate.DecryptPayloadRegion(data, po.prevRxCipher); derr2 == nil {
					log.Debug("Rx: decrypted from %s with PREVIOUS rxKeyFP=%s (currentRxKeyFP=%s) — peer still sealing with old gen during rollover; link tolerated",
						remotePeer.String(), obfuscate.KeyFingerprint(po.prevRxKey), obfuscate.KeyFingerprint(po.rxKey))
					n.recordPeerRxDecrypt(remotePeer, true)
					n.maybeMarkReadyOnDecrypt(remotePeer, true)
					return dec2, true, false
				}
			}
		}
		// A cipher IS negotiated but AEAD-open failed (and none of our recent
		// keys opened it either) ⇒ the frame is genuine ciphertext we cannot
		// open (key mismatch / corruption). This is NOT plaintext: forwarding it
		// to the TAP would inject raw ciphertext bytes onto the LAN. Flag as
		// garbage so the RX path drops it and counts a real decryption failure
		// (which feeds the self-healing resync below).
		fallbackNote := ""
		if po := n.peerObf(remotePeer); po != nil && (po.prevRxCipher != nil || len(po.rxRing) > 0) {
			fallbackNote = fmt.Sprintf(" (ring=%d prevRxCipher staged but did not open — fundamentally divergent key)", len(po.rxRing))
		} else {
			fallbackNote = " (no fallback — lingering old-connection frame or divergent key)"
		}
		// derr is an AEAD "message authentication failed". We deliberately do
		// NOT log the raw stdlib string verbatim: it floods the log for every
		// genuinely-corrupt / divergent frame and conveys no more than the
		// classified fallbackNote already does. The frame is still flagged as
		// garbage and dropped (ciphertext ⇒ DROP) so the security contract holds.
		log.Debug("Rx: decrypt FAILED for %s algo=%s nonce=%s (ciphertext ⇒ DROP, never forwarded as plaintext)%s",
			remotePeer.String(), obfuscate.AlgoName(cipher.Algo()), obfuscate.NonceHex(data), fallbackNote)
		return data, false, true
	}
	// Genuine AEAD success: record a valid decryption and self-heal readiness.
	n.recordPeerRxDecrypt(remotePeer, true)
	n.maybeMarkReadyOnDecrypt(remotePeer, true)
	log.Debug("Rx: decrypted frame from %s algo=%s nonce=%s", remotePeer.String(), obfuscate.AlgoName(cipher.Algo()), obfuscate.NonceHex(data))
	return dec, true, false
}

// maybeResyncOnDecryptFail triggers a background SeqSync re-handshake when a
// peer's decryption failures accumulate, so a desynchronised key (e.g. after a
// one-sided proactive re-key the peer never completed) self-heals instead of the
// link staying permanently dead. It is rate-limited per peer (a cooldown window)
// so a burst of decrypt failures cannot spawn a resync storm; the recent-error
// window (reset on any successful decrypt) is the trigger signal.
func (n *Node) maybeResyncOnDecryptFail(remotePeer peer.ID) {
	const (
		// threshold: consecutive (reset-on-success) decrypt failures before we
		// reactively re-key. Raised 8 → 16 so a brief burst of line-noise /
		// single corrupted frames (old-key stragglers the RX ring already opens)
		// no longer trips a re-key.
		threshold = 16
		// cooldown: minimum gap between two reactive re-keys for the same peer.
		// Raised 3s → 30s so a degraded spell cannot spawn a re-key storm.
		cooldown = 30 * time.Second
		// settleWindow: after a re-key *succeeds*, stay quiet for this long.
		// In-flight frames encrypted with the PREVIOUS key keep arriving right
		// after convergence; the RX ring opens most, but any that slip through
		// would otherwise re-trigger a re-key and oscillate the link. 90s covers
		// straggler drain without hiding a genuine divergence (which keeps
		// climbing past escalationCap and still fires).
		settleWindow = 90 * time.Second
		// escalationCap: within settleWindow, only force a re-key if failures
		// blow past this — a real ongoing divergence, not just stragglers.
		escalationCap = 64
	)
	rv, ok := n.peerRxDecryptRecentErrs.Load(remotePeer)
	if !ok {
		return
	}
	if v := rv.(*atomic.Uint64).Load(); v < threshold {
		return
	}
	// Post-success settle: do not re-key again so soon after a converge unless
	// failures clearly indicate a real divergence rather than stragglers.
	if t, ok := n.lastRekeySuccess.Load(remotePeer); ok {
		if since := time.Since(t.(time.Time)); since < settleWindow && rv.(*atomic.Uint64).Load() < escalationCap {
			return
		}
	}
	if v, loaded := n.decryptResyncCooldown.LoadOrStore(remotePeer, time.Now()); loaded {
		if time.Since(v.(time.Time)) < cooldown {
			return
		}
		n.decryptResyncCooldown.Store(remotePeer, time.Now())
	}
	log.Info("Rx: %s has %d sustained decryption failures — triggering SeqSync re-handshake to re-anchor keys",
		remotePeer.String(), rv.(*atomic.Uint64).Load())
	// Surface the key generation currently failing so a debug trace can tell
	// whether the peer is mid-rotation (we hold prevRxCipher) or the ciphers are
	// fundamentally divergent (no fallback matches). prevRxKeyFP is "(none)" when
	// no rollover fallback is staged.
	if po := n.peerObf(remotePeer); po != nil && po.negotiated {
		prevFP := "(none)"
		if po.prevRxCipher != nil {
			prevFP = obfuscate.KeyFingerprint(po.prevRxKey)
		}
		log.Info("Rx: %s decrypt-fail context — currentRxKeyFP=%s prevRxKeyFP=%s ring=%d algo=%s (fallback-opened frames so far may have kept link alive)",
			remotePeer.String(), obfuscate.KeyFingerprint(po.rxKey), prevFP, len(po.rxRing), obfuscate.AlgoName(po.algo))
	}
	go n.ForceSyncSeq(remotePeer)
}

// storePeerObf upserts a peer's obfuscation state via copy-on-write: it clones
// the current table, applies the change, and swaps it in atomically. Called only
// from the handshake path (rare), so the O(peers) copy is negligible.
func (n *Node) storePeerObf(p peer.ID, po *PeerObf) {
	for {
		cur := n.perPeerObf.Load()
		var next map[peer.ID]*PeerObf
		if cur == nil {
			next = make(map[peer.ID]*PeerObf, 1)
		} else {
			next = make(map[peer.ID]*PeerObf, len(*cur)+1)
			for k, v := range *cur {
				next[k] = v
			}
		}
		next[p] = po
		if n.perPeerObf.CompareAndSwap(cur, &next) {
			return
		}
	}
}

// isPeerReady reports whether the mutual "ready" handshake has completed with
// the given peer (both sides exchanged ready acknowledgements). TAP data is only
// sent to a peer once this returns true.
func (n *Node) isPeerReady(p peer.ID) bool {
	if v, ok := n.peerReady.Load(p); ok {
		return v.(*atomic.Bool).Load()
	}
	return false
}

// relayPeerIDOf extracts the relay peer ID from a circuit-relay multiaddr
// string. A relayed connection's remote multiaddr looks like:
//
//	/ip4/<relayIP>/tcp/<port>/p2p/<relayPeerID>/p2p-circuit/p2p/<destPeerID>
//
// so the relay ID is the p2p component immediately preceding "/p2p-circuit".
// Returns "" if the address is not a circuit-relay address or the relay ID
// cannot be located. Used for diagnostics so the WebUI/logs can name WHICH
// relay a peer is being auto-relayed through (the cause of hidden high latency).
func relayPeerIDOf(addrStr string) string {
	const probe = "/p2p-circuit"
	idx := strings.Index(addrStr, probe)
	if idx < 0 {
		return ""
	}
	prefix := addrStr[:idx]
	const p2pTag = "/p2p/"
	j := strings.LastIndex(prefix, p2pTag)
	if j < 0 {
		return ""
	}
	relayID := prefix[j+len(p2pTag):]
	// Trim a trailing slash just in case the relay addr had no destination peer.
	return strings.TrimSuffix(relayID, "/")
}

// peerHasCircuitRelayConn reports whether the given peer currently has at least
// one live connection via a circuit-relay path. This is used to shorten retry
// intervals for SeqSync handshakes on relay paths, which are typically more
// unstable (frequent connection resets) and need faster re-key convergence.
func (n *Node) peerHasCircuitRelayConn(p peer.ID) bool {
	for _, conn := range n.Host.Network().ConnsToPeer(p) {
		if strings.Contains(conn.RemoteMultiaddr().String(), "/p2p-circuit") {
			return true
		}
	}
	return false
}

// isResyncLeader reports whether THIS node is the designated initiator of the
// SeqSync (re)key handshake for peer p. Exactly one side of a peer pair is the
// leader (the one whose PeerID string is lexicographically greater), so only
// that side ever opens a handshake stream; the other side only RESPONDS.
//
// Why this matters: when a key desynchronises (or a proactive re-key fires)
// BOTH nodes would otherwise call ForceSyncSeq simultaneously, each opening its
// own stream and minting a fresh one-shot ephemeral key. The two concurrent
// handshake rounds combine into FOUR different ECDH shared-secrets — the
// initiator round uses (L1, M1) while the responder round uses (L2, M2) — so
// each side can end up storing a cipher derived from a DIFFERENT ephemeral pair
// than the peer. The result is a permanent decrypt-fail loop: every frame is
// dropped, which triggers yet another re-key, forever. Leadership guarantees a
// single handshake round and therefore a single shared secret, so both sides
// always converge to matching keys. This is THE mechanism that prevents the
// crossed-handshake divergence — the rekeyPeers single-flight guard only
// serialises rounds WITHIN one node, it does NOT stop two nodes from crossing
// rounds, so leadership (deterministic by PeerID, agreed on both ends) is what
// actually forbids the second stream.
//
// Reachability note: the follower does NOT open its own re-key stream (that
// would cross with the leader's round). Instead the follower nudges the leader
// with a rekeyReq signal (see triggerPeerRekey / sendRekeyRequest); the leader
// answers by opening the single authoritative handshake stream and the follower
// responds. This breaks the old follower-deadlock (a follower seeing dropped
// frames whose leader does not would otherwise never re-handshake) without
// ever running two concurrent rounds. A follower behind a NAT the leader cannot
// dial escalates to a self-initiated handshake after a 30s grace window — a
// rare, ring-absorbed blip, not a permanent loop.
func (n *Node) isResyncLeader(p peer.ID) bool {
	return n.Host.ID().String() > p.String()
}

// markPeerReady records that the mutual readiness handshake completed with the
// given peer, unblocking TAP data transmission to it.
func (n *Node) markPeerReady(p peer.ID) {
	v, _ := n.peerReady.LoadOrStore(p, &atomic.Bool{})
	v.(*atomic.Bool).Store(true)
	// Record handshake convergence latency: time from first SyncSeqToPeer to
	// readiness. Only meaningful for peers we actively tried to handshake with.
	if t, ok := n.seqsyncHandshakeStart.Load(p); ok {
		ms := uint64(time.Since(t.(time.Time)).Milliseconds())
		cv, _ := n.seqsyncConvergeMs.LoadOrStore(p, &atomic.Uint64{})
		cv.(*atomic.Uint64).Store(ms)
		n.seqsyncHandshakeStart.Delete(p)
	}
}

// maybeMarkReadyOnDecrypt is a self-healing readiness shortcut: the very first
// time we successfully AEAD-decrypt a frame from a peer, we know our RX cipher
// is correct and the peer is transmitting real data — so the link is usable even
// if the "ready" acknowledgement handshake was lost (e.g. a dropped reciprocal
// frame over a relay). This lets traffic flow as soon as one direction actually
// works instead of waiting for an (unreliable) bidirectional ready exchange.
func (n *Node) maybeMarkReadyOnDecrypt(remotePeer peer.ID, ok bool) {
	if !ok {
		return
	}
	if n.isPeerReady(remotePeer) {
		return
	}
	// Only mark ready if we have actually negotiated a cipher for this peer
	// (otherwise a plaintext frame would wrongly flip the bit).
	if n.obfDecryptCipherForPeer(remotePeer) == nil {
		return
	}
	log.Debug("SeqSync: marking %s ready via successful frame decrypt (ready handshake may have been lost)", remotePeer.String())
	n.markPeerReady(remotePeer)
}

// rxGraceKey is the short-lived retention of a peer's full RX cipher set across
// a disconnect, used to absorb frames that arrive late on a lingering old
// connection. It holds the most-recent cipher (primary) AND the entire bounded
// fallback ring so a reconnect can open frames the peer sealed with ANY recent
// generation (see rxKeyGrace on Node).
type rxGraceKey struct {
	primary    obfuscate.ObfCipher // most-recent RX cipher retained across a disconnect
	primaryKey []byte
	ring       []rxRingSlot // ALL recent RX ciphers (DIRECT + CIRCUIT-RELAY generations)
	expires    time.Time
}

// rxKeyGraceTTL bounds how long a cleared RX key is retained as a decryption
// fallback. Long enough to cover a peer that keeps its previous session open
// for a few seconds after we reset (so a re-handshake immediately after a
// disconnect absorbs the stragglers), short enough to preserve forward secrecy.
const rxKeyGraceTTL = 90 * time.Second

// captureRxKeyGrace retains the current RX cipher for peer p briefly after a
// clear (see rxKeyGrace on Node) so a post-clear re-handshake can seed it as a
// decryption fallback for lingering old-connection frames. Host-free: it only
// reads the atomic perPeerObf table, so it is safe to call on a partially-built
// Node (e.g. from removePeerObf, or from tests).
func (n *Node) captureRxKeyGrace(p peer.ID) {
	if cur := n.perPeerObf.Load(); cur != nil {
		if po := (*cur)[p]; po != nil && po.negotiated && po.rxCipher != nil {
			gk := &rxGraceKey{
				primary:    po.rxCipher,
				primaryKey: append([]byte(nil), po.rxKey...),
				expires:    time.Now().Add(rxKeyGraceTTL),
			}
			// Retain the ENTIRE RX fallback ring, not just the last cipher: a
			// peer with several live connections holds one generation per
			// connection and may still be sealing with any of them on a lingering
			// old stream after we reset. Capturing only the last cipher left the
			// others unopenable — the persistent decrypt-fail loop.
			for _, s := range po.rxRing {
				gk.ring = append(gk.ring, rxRingSlot{cipher: s.cipher, key: append([]byte(nil), s.key...)})
			}
			n.rxKeyGrace.Store(p, gk)
		}
	}
}

// seedPrevRxFromGrace carries the just-cleared RX cipher (if any, and still
// within its TTL) forward as the decryption fallback for a freshly-negotiated
// cipher. Called from negotiateObfWithPeer when a (re)connection negotiates
// after a prior clear, so frames still arriving on a lingering old connection
// can be opened instead of dropped. Returns true if a grace key was seeded.
func (n *Node) seedPrevRxFromGrace(p peer.ID, po *PeerObf) bool {
	g, ok := n.rxKeyGrace.Load(p)
	if !ok {
		return false
	}
	gk := g.(*rxGraceKey)
	if !time.Now().Before(gk.expires) {
		return false
	}
	// Seed the whole retained ring (dedup handled by pushRxRing) plus the
	// primary cipher, so a post-clear handshake can open frames the peer sealed
	// with ANY recent generation — not just the single last one.
	po.pushRxRing(gk.primary, gk.primaryKey)
	for _, s := range gk.ring {
		po.pushRxRing(s.cipher, s.key)
	}
	log.Debug("SeqSync: seeded RX ring (N=%d, primaryFP=%s) from post-clear grace window for %s — will absorb lingering old-connection frames",
		len(gk.ring)+1, obfuscate.KeyFingerprint(gk.primaryKey), p.String())
	return true
}

// removePeerObf is called when a peer's last transport is lost. Historically it
// wiped the negotiated cipher + RX fallback ring so a reconnect would
// re-negotiate a fresh ECDH key. That wipe was the root cause of the persistent
// "decrypt FAILED … (no fallback — …)" loops seen in production: the peer
// almost always reconnects (DIRECT↔RELAY churn, dial-race flaps) and keeps
// sealing with its CURRENT key for a short window before the opportunistic
// re-handshake converges, but a fresh PeerObf (ring=0) could not open ANY of
// those in-flight / other-connection frames.
//
// We now RETAIN the cipher + ring across the disconnect and only reset the
// per-peer "ready" flag. decryptPeerFrame can therefore open frames the peer
// sealed with ANY recent generation, so a reconnect is seamless and the
// re-handshake merely rotates to a fresh key. The retained cipher is also
// snapshotted into the grace window (below) as a belt-and-suspenders fallback for
// any code path that rebuilds the table without this peer. Forward-secrecy
// impact is negligible: peers are pre-authenticated and the ring is bounded; the
// key is dropped only when rotated out by the ring cap or when the entry is
// garbage-collected.
func (n *Node) removePeerObf(p peer.ID) {
	n.captureRxKeyGrace(p)       // belt-and-suspenders: snapshot the full RX ring
	n.peerReady.Delete(p)        // force TX + handshake to re-confirm readiness on reconnect
	n.clearCachedHandshakeEph(p) // drop the round's ephemeral so the next session mints fresh (PFS)
	n.pushPeerEncryption()
}

// ObfFingerprint returns a short fingerprint of the most recent ephemeral ECDH
// public key actually used in a completed handshake. It changes after every
// (re)connection, which is by design: it is the visible proof that each session
// negotiates a FRESH key (per-handshake forward secrecy). Before any handshake
// has completed it falls back to the node's long-lived key fingerprint. Empty if
// encryption is disabled.
func (n *Node) ObfFingerprint() string {
	if fp := n.handshakeFingerprint.Load(); fp != nil && *fp != "" {
		return *fp
	}
	if n.obfKeyPair == nil {
		return ""
	}
	return n.obfKeyPair.Fingerprint()
}

// setHandshakeFingerprint records the fingerprint of the ephemeral key used in
// the latest completed handshake. Empty values are ignored.
func (n *Node) setHandshakeFingerprint(fp string) {
	if fp == "" {
		return
	}
	n.handshakeFingerprint.Store(&fp)
}

// mintObfHandshakeKey mints a ONE-SHOT ephemeral ECDH key pair for the current
// handshake with peer p and returns it directly to the caller. The caller is
// responsible for passing the SAME pair into negotiateObfWithPeer so the public
// key embedded in the outgoing SeqSync message and the private key used to derive
// the shared secret are guaranteed to match.
//
// The key is NEVER stored in a shared per-peer slot. The previous design stashed
// it in pendingObfKeys (one slot per peer), which was a handshake-timing bug:
// when two handshakes for the same peer ran concurrently (e.g. both sides re-key
// at once, or libp2p opened two streams to the same peer), the second handshake
// overwrote the first's ephemeral key, so one side derived its cipher from the
// wrong private key — a permanently mismatched rxKey/txKey pair that no
// re-handshake could heal (the "Rx decrypt 100% fail, rxKeyFP constant" symptom).
// Carrying the key in the handshake's local scope eliminates that class of bug.
// The returned *ObfKeyPair is nil if key generation fails (callers fall back to
// plaintext or the long-lived node key per StrictKeyNegotiation).
func (n *Node) mintObfHandshakeKey(p peer.ID) *obfuscate.ObfKeyPair {
	if n.obfKeyPair == nil {
		return nil
	}
	kp, err := obfuscate.GenerateObfKeyPair()
	if err != nil {
		log.Warn("SeqSync: failed to mint ephemeral handshake key for %s: %v", p.String(), err)
		return nil
	}
	log.Debug("SeqSync: minted ephemeral handshake key for %s (fp=%s) — used locally for this handshake only", p.String(), kp.Fingerprint())
	return kp
}

// useCachedHandshakeEph returns the ephemeral ECDH key pair to use for the
// CURRENT handshake round with peer p. The FIRST call mints a fresh one-shot key
// and caches it; every SUBSEQUENT call within the same round returns the SAME
// cached pair. Reusing one ephemeral across all sync retries and self-heal
// re-syncs is what makes the negotiated cipher deterministic: because both the
// initiator and the responder hold their cached pair fixed for the whole round,
// the generation derived from (initiator_eph, responder_eph) is identical on
// every attempt — so whichever ack/ready actually traverses a lossy relay, both
// ends converge onto the SAME key instead of racing into divergent generations.
// A nil result (encryption disabled or mint failed) is propagated as-is so both
// sides correctly fall back to plaintext symmetrically.
func (n *Node) useCachedHandshakeEph(p peer.ID) *obfuscate.ObfKeyPair {
	n.cachedHandshakeEphMu.Lock()
	defer n.cachedHandshakeEphMu.Unlock()
	if n.cachedHandshakeEph == nil {
		n.cachedHandshakeEph = make(map[peer.ID]*obfuscate.ObfKeyPair)
	}
	if kp, ok := n.cachedHandshakeEph[p]; ok {
		return kp
	}
	kp := n.mintObfHandshakeKey(p)
	n.cachedHandshakeEph[p] = kp
	return kp
}

// clearCachedHandshakeEph drops the cached handshake ephemeral for p so the NEXT
// round mints a FRESH one-shot key (restoring forward secrecy for the new
// session / rotation). It is called once a round fully completes (both sides have
// exchanged ready) and on peer disconnect. It is intentionally a no-op when
// nothing is cached, and must NOT be called on a lost-ready branch — leaving the
// cache intact there lets the self-heal re-sync reuse the same generation instead
// of re-flipping the peer onto a divergent one.
func (n *Node) clearCachedHandshakeEph(p peer.ID) {
	n.cachedHandshakeEphMu.Lock()
	defer n.cachedHandshakeEphMu.Unlock()
	if n.cachedHandshakeEph != nil {
		delete(n.cachedHandshakeEph, p)
	}
}

// acquireHandshakeLock returns a per-peer mutex that serialises ALL SeqSync
// handshakes (initiator and responder) for the given peer. The caller must call
// the returned release function when the handshake completes. This is what
// prevents two concurrent libp2p connections (DIRECT + CIRCUIT-RELAY) from
// each driving an independent handshake that overwrites the per-peer cipher slot
// with a different ECDH generation — the root cause of "ring=N fundamentally
// divergent key" where neither side's txKey matches the other's rxKey.
func (n *Node) acquireHandshakeLock(p peer.ID) (release func()) {
	mu, _ := n.handshakeMu.LoadOrStore(p, &sync.Mutex{})
	mu.(*sync.Mutex).Lock()
	return func() { mu.(*sync.Mutex).Unlock() }
}

// obfPubFromPair returns the wire public-key bytes for an ephemeral handshake key
// pair, or nil if the pair is nil or cannot be serialised. A nil result means
// "no encryption negotiated" — the peer will fall back to plaintext obfuscation.
func (n *Node) obfPubFromPair(kp *obfuscate.ObfKeyPair) []byte {
	if kp == nil {
		return nil
	}
	b, err := kp.PublicKeyBytes()
	if err != nil {
		log.Warn("SeqSync: failed to serialise ephemeral handshake pubkey: %v", err)
		return nil
	}
	return b
}

// TopologyNode is one node in the mesh topology tree returned by GetTopology.
type TopologyNode struct {
	PeerID   string `json:"peer_id"`
	NodeName string `json:"node_name"`
	TapIP    string `json:"tap_ip"`
	TapIPv6  string `json:"tap_ipv6"`
	TapMAC   string `json:"tap_mac"`
	OSArch   string `json:"os_arch"`
	Version  string `json:"version"`
	Self     bool   `json:"self"`
	Direct   bool   `json:"direct"` // directly connected to self (no relay)
	Parent   string `json:"parent"` // parent node id in the shortest-path tree ("" for self)
	Depth    int    `json:"depth"`  // hops from self in the SPT (0 = self)
	Relay    bool   `json:"relay"`  // this node is a transit relay for others
	RTT      int64  `json:"rtt"`    // link RTT to parent (ms), 0 for self

	// --- Complex-topology annotations ---------------------------------------
	// The fields above describe a single flat mesh. The ones below describe WHERE
	// a node sits in a multi-cluster deployment (several boots federated over the
	// peek-map backbone, plus static-peer entry points) and HOW its traffic
	// actually travels, which a plain parent/depth tree cannot express.

	// IsBoot marks a bootstrap/relay node: configured in BootstrapPeers,
	// attached after backbone discovery, or self-declared over the peek-map.
	IsBoot bool `json:"is_boot"`
	// Static marks a node configured as a static peer — a dial-direct entry
	// point that works with no boot at all.
	Static bool `json:"static"`
	// Cluster is the peer ID of the boot this node is grouped under (its
	// announcement anchor). Empty when the node is not attached to any boot,
	// which is the normal case for a pure static-peer mesh.
	Cluster string `json:"cluster"`
	// BootHops is how many boot-to-boot backbone hops this node's announcement
	// crossed before reaching us. 0 = same cluster as the boot it was heard
	// from; 1+ = federated in from a remote cluster.
	BootHops int `json:"boot_hops"`
	// TransportPath is the ACTUAL transport currently carrying traffic to this
	// node: "direct", "circuit-relay", "overlay-relay", or "" when we hold no
	// connection at all (node known only from the link-state graph / peek-map).
	TransportPath string `json:"transport_path"`
	// RelayHop is the peer ID of the overlay relay hop in use, when
	// TransportPath is "overlay-relay". Empty otherwise.
	RelayHop string `json:"relay_hop"`
}

// TopologyCluster summarises one boot cluster in the mesh. Computed server-side
// so the WebUI does not have to re-derive membership from the node list (and so
// both stay in agreement about what a "cluster" is).
type TopologyCluster struct {
	BootID   string `json:"boot_id"`
	BootName string `json:"boot_name"`
	Members  int    `json:"members"` // nodes grouped under this boot (boot excluded)
	Local    bool   `json:"local"`   // true for the cluster this node itself is in
}

// TopologyEdge is a single undirected link in the link-state graph (populated by
// LSA flooding). Exposed so the WebUI can compute transit relationships: e.g. two
// peers that are both directly connected to self but NOT directly linked to each
// other must have their traffic L2-switched through self.
type TopologyEdge struct {
	From string `json:"from"`
	To   string `json:"to"`
	RTT  int64  `json:"rtt"`
	// Class is the transport quality of the link: "direct" for a real
	// QUIC/TCP connection, "circuit" for a circuit-relayed (or peek-map
	// backfilled) one. Without it the WebUI cannot tell a genuine peer-to-peer
	// edge from a link that only exists through a shared relay.
	Class string `json:"class"`
}

// TopologyResponse is the full mesh topology, rooted at this node, suitable for
// rendering a hierarchical tree where relay nodes appear above the peers they
// transit. Data comes from the link-state graph (populated by LSA flooding) plus
// the per-peer identity table, so it includes nodes not directly connected.
type TopologyResponse struct {
	LocalPeerID string         `json:"local_peer_id"`
	Nodes       []TopologyNode `json:"nodes"`
	Edges       []TopologyEdge `json:"edges"`
	// LocalCluster is the boot this node itself is attached to ("" when running
	// boot-less, e.g. a pure static-peer mesh).
	LocalCluster string `json:"local_cluster"`
	// Clusters lists every boot cluster visible in the mesh, so the WebUI can
	// draw cluster groupings without re-deriving membership.
	Clusters []TopologyCluster `json:"clusters"`
}

// GetTopology builds the full mesh topology rooted at this node. A Dijkstra
// shortest-path tree (weights = link RTT) is computed from self over the
// link-state graph; every node's `parent` is the previous hop on its shortest
// path, which naturally places transit relays above the peers they carry — a
// relayed node hangs under the relay it is reached through.
func (n *Node) GetTopology() TopologyResponse {
	self := n.Host.ID()
	snap := n.Router.GetGraph()

	// Build adjacency (undirected) for Dijkstra + relay detection.
	adj := make(map[peer.ID]map[peer.ID]int64)
	addEdge := func(a, b peer.ID, w int64) {
		if adj[a] == nil {
			adj[a] = make(map[peer.ID]int64)
		}
		adj[a][b] = w
	}
	for _, e := range snap.Edges {
		addEdge(e.From, e.To, e.RTT)
		addEdge(e.To, e.From, e.RTT)
	}

	// Dijkstra from self.
	dist := map[peer.ID]int64{self: 0}
	parent := map[peer.ID]peer.ID{}
	visited := map[peer.ID]bool{}
	pq := &topoPQ{}
	pq.push(self, 0)
	for pq.Len() > 0 {
		u := pq.pop()
		if visited[u] {
			continue
		}
		visited[u] = true
		for v, w := range adj[u] {
			nd := dist[u] + w
			if cur, ok := dist[v]; !ok || nd < cur {
				dist[v] = nd
				parent[v] = u
				pq.push(v, nd)
			}
		}
	}

	// Assemble identity for every known node (self + learned via LSA/meta).
	meta := map[peer.ID]PeerMeta{}
	n.peerMeta.Range(func(k, v any) bool {
		meta[k.(peer.ID)] = v.(PeerMeta)
		return true
	})

	directSet := adj[self] // nodes one hop from self

	// Cluster/role classification inputs. Built once per call: a node may be a
	// boot because it is configured, because we attached to it after backbone
	// discovery, or because it declared itself over the peek-map.
	staticSet := peerIDSetFromMultiaddrs(n.Config.StaticPeers)
	localCluster := n.localBootCluster()

	resp := TopologyResponse{LocalPeerID: self.String(), LocalCluster: localCluster}
	// Self first. We are, by definition, in our own local cluster and reached
	// over no transport at all.
	resp.Nodes = append(resp.Nodes, TopologyNode{
		PeerID:   self.String(),
		NodeName: n.nodeName,
		TapIP:    stripCIDR(n.Config.TapIP),
		TapIPv6:  stripCIDR(n.Config.TapIPv6),
		TapMAC:   n.Config.TapMAC,
		OSArch:   fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
		Self:     true,
		Depth:    0,
		Cluster:  localCluster,
	})
	// Other nodes.
	for _, pid := range snap.Nodes {
		if pid == self {
			continue
		}
		tn := TopologyNode{PeerID: pid.String()}
		if m, ok := meta[pid]; ok {
			tn.NodeName = m.NodeName
			tn.TapIP = m.TapIP
			tn.TapIPv6 = m.TapIPv6
			tn.TapMAC = m.TapMAC
			tn.OSArch = m.OSArch
			tn.Version = m.Version
		}
		_, tn.Direct = directSet[pid]
		if p, ok := parent[pid]; ok {
			tn.Parent = p.String()
			tn.Depth = int(dist[pid]) // depth proxy = cumulative RTT; replaced below
		}
		// Compute true hop depth via parent chain.
		if tn.Parent != "" {
			d := 0
			cur := pid
			for cur != self {
				pp, ok := parent[cur]
				if !ok {
					break
				}
				d++
				cur = pp
				if d > 64 {
					break
				}
			}
			tn.Depth = d
		}
		if p, ok := parent[pid]; ok {
			if w, ok := adj[p][pid]; ok {
				tn.RTT = w
			}
		}
		// --- Complex-topology annotations ---
		tn.Static = staticSet[pid]
		origin, haveOrigin := n.lookupPeekMapOrigin(pid)
		_, discoveredBoot := n.discoveredBoots.Load(pid)
		tn.IsBoot = n.isBootstrapPeer(pid) || discoveredBoot || (haveOrigin && origin.IsBoot)
		switch {
		case tn.IsBoot:
			// A boot anchors its own cluster; grouping it under another boot
			// would make a federated backbone look like a hierarchy.
			tn.Cluster = pid.String()
		case haveOrigin:
			tn.Cluster = origin.Via.String()
			tn.BootHops = origin.Hops
		default:
			// Learned directly or via LSA flooding, i.e. it shares our anchor.
			tn.Cluster = localCluster
		}
		tn.TransportPath, tn.RelayHop = n.describeTransportPath(pid)
		resp.Nodes = append(resp.Nodes, tn)
	}
	// Mark relay nodes: those that are a parent of some other node (transit).
	relaySet := map[string]bool{}
	for _, tn := range resp.Nodes {
		if tn.Parent != "" {
			relaySet[tn.Parent] = true
		}
	}
	for i := range resp.Nodes {
		if resp.Nodes[i].Parent != "" { // only non-root can be a relay parent
			resp.Nodes[i].Relay = relaySet[resp.Nodes[i].PeerID]
		}
	}
	// Expose the raw link-state edges so the WebUI can derive transit/L2-switch
	// relationships (e.g. self forwarding between two direct-but-not-linked peers).
	for _, e := range snap.Edges {
		resp.Edges = append(resp.Edges, TopologyEdge{
			From:  e.From.String(),
			To:    e.To.String(),
			RTT:   e.RTT,
			Class: linkClassName(e.Class),
		})
	}
	resp.Clusters = summariseClusters(resp.Nodes, localCluster)
	return resp
}

// linkClassName renders a routing link class for the topology API.
func linkClassName(c routing.LinkClass) string {
	if c == routing.LinkCircuit {
		return "circuit"
	}
	return "direct"
}

// peerIDSetFromMultiaddrs extracts the peer IDs out of a list of /p2p/ suffixed
// multiaddrs (config entries), tolerating malformed or suffix-less values.
func peerIDSetFromMultiaddrs(specs []string) map[peer.ID]bool {
	out := make(map[peer.ID]bool, len(specs))
	for _, s := range specs {
		ma, err := multiaddr.NewMultiaddr(s)
		if err != nil {
			continue
		}
		info, err := peer.AddrInfoFromP2pAddr(ma)
		if err != nil {
			continue
		}
		out[info.ID] = true
	}
	return out
}

// localBootCluster reports which boot this node is anchored to, i.e. the cluster
// it belongs to in a multi-boot deployment.
//
// A CONNECTED boot always wins over a merely configured one: a node listing
// several boots is only actually a member of the cluster(s) it reached, and the
// topology view must not claim membership of a cluster whose boot is down.
// Configured boots are preferred over backbone-discovered ones, because
// discovered boots are joined to gain reachability, not to change our home
// cluster. Returns "" when the node runs boot-less (pure static-peer mesh).
func (n *Node) localBootCluster() string {
	var firstConfigured peer.ID
	for _, bStr := range n.Config.BootstrapPeers {
		ma, err := multiaddr.NewMultiaddr(bStr)
		if err != nil {
			continue
		}
		info, err := peer.AddrInfoFromP2pAddr(ma)
		if err != nil {
			continue
		}
		if firstConfigured == "" {
			firstConfigured = info.ID
		}
		if n.Host.Network().Connectedness(info.ID) == network.Connected {
			return info.ID.String()
		}
	}
	if firstConfigured != "" {
		return firstConfigured.String()
	}
	// No configured boot at all: fall back to a discovered one we did attach to,
	// so a node bootstrapped purely off a backbone announcement still reports a
	// cluster instead of looking unanchored.
	var discovered string
	n.discoveredBoots.Range(func(k, _ any) bool {
		pid := k.(peer.ID)
		if n.Host.Network().Connectedness(pid) == network.Connected {
			discovered = pid.String()
			return false
		}
		return true
	})
	return discovered
}

// describeTransportPath reports how traffic to pID actually travels right now,
// and (for overlay-relayed peers) through which hop.
//
// Order matters: an overlay relay hop is checked FIRST because a relay-only peer
// can simultaneously have a circuit-relay libp2p connection registered as a
// "direct" link — reporting that would hide the overlay hop actually carrying
// the data frames.
func (n *Node) describeTransportPath(pID peer.ID) (path string, relayHop string) {
	if hop := n.relayHopForTarget(pID); hop != "" {
		return "overlay-relay", hop.String()
	}
	if n.Host.Network().Connectedness(pID) != network.Connected {
		return "", ""
	}
	if n.peerHasCircuitRelayConn(pID) {
		return "circuit-relay", ""
	}
	return "direct", ""
}

// summariseClusters counts membership per boot cluster. Members exclude the boot
// itself so the number reads as "clients in this cluster".
func summariseClusters(nodes []TopologyNode, localCluster string) []TopologyCluster {
	names := map[string]string{}
	members := map[string]int{}
	order := []string{}
	for _, tn := range nodes {
		if tn.IsBoot {
			names[tn.PeerID] = tn.NodeName
		}
	}
	for _, tn := range nodes {
		if tn.Cluster == "" {
			continue
		}
		if _, seen := members[tn.Cluster]; !seen {
			order = append(order, tn.Cluster)
			members[tn.Cluster] = 0
		}
		if tn.PeerID == tn.Cluster {
			continue // the boot itself is the anchor, not a member
		}
		members[tn.Cluster]++
	}
	out := make([]TopologyCluster, 0, len(order))
	for _, id := range order {
		out = append(out, TopologyCluster{
			BootID:   id,
			BootName: names[id],
			Members:  members[id],
			Local:    id == localCluster,
		})
	}
	return out
}

// stripCIDR returns the bare address without its /mask suffix.
func stripCIDR(cidr string) string {
	if i := indexByte(cidr, '/'); i >= 0 {
		return cidr[:i]
	}
	return cidr
}

func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

// topoPQ is a tiny integer-weight priority queue for Dijkstra.
type topoPQ struct {
	items []topoPQItem
}
type topoPQItem struct {
	id   peer.ID
	dist int64
}

func (q *topoPQ) Len() int { return len(q.items) }
func (q *topoPQ) push(id peer.ID, d int64) {
	q.items = append(q.items, topoPQItem{id, d})
	// simple bubble-up (graph is tiny: a few hundred nodes at most)
	i := len(q.items) - 1
	for i > 0 {
		p := (i - 1) / 2
		if q.items[p].dist <= q.items[i].dist {
			break
		}
		q.items[p], q.items[i] = q.items[i], q.items[p]
		i = p
	}
}
func (q *topoPQ) pop() peer.ID {
	if len(q.items) == 0 {
		return ""
	}
	top := q.items[0]
	last := len(q.items) - 1
	q.items[0] = q.items[last]
	q.items = q.items[:last]
	// bubble-down
	i := 0
	for {
		l, r := 2*i+1, 2*i+2
		small := i
		if l < len(q.items) && q.items[l].dist < q.items[small].dist {
			small = l
		}
		if r < len(q.items) && q.items[r].dist < q.items[small].dist {
			small = r
		}
		if small == i {
			break
		}
		q.items[small], q.items[i] = q.items[i], q.items[small]
		i = small
	}
	return top.id
}

// obfStateForPeer returns the negotiated obfuscation state for a single peer,
// suitable for embedding in the per-peer WebUI payload.
func (n *Node) obfStateForPeer(p peer.ID) (negotiated bool, algo string, encrypted bool) {
	po := n.peerObf(p)
	if po == nil {
		return false, "none", false
	}
	return po.negotiated, obfuscate.AlgoName(po.algo), po.algo != obfuscate.ObfAlgoNone
}

// keyFingerprint returns a short, human-comparable fingerprint of a raw AEAD key
// (or any public key bytes): the first 8 hex characters of its SHA-256. Empty
// input yields an empty string. Used by the WebUI "negotiated key" panel so an
// operator can confirm each peer pair got a distinct cipher.
func keyFingerprint(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])[:8]
}

// pushPeerEncryption publishes a snapshot of every connected peer's
// encryption/obfuscation state to the WebUI collector. Peers with no negotiated
// cipher are reported as "none" (plaintext obfuscation). Cheap: called only
// on handshake changes, not per packet.
func (n *Node) pushPeerEncryption() {
	tbl := n.perPeerObf.Load()
	negotiated := make(map[peer.ID]*PeerObf, lenOpt(tbl))
	if tbl != nil {
		for p, po := range *tbl {
			negotiated[p] = po
		}
	}

	seen := make(map[peer.ID]struct{}, len(negotiated))
	snapshot := make([]observer.PeerObfInfoDTO, 0, len(negotiated))
	for p, po := range negotiated {
		seen[p] = struct{}{}
		snapshot = append(snapshot, observer.PeerObfInfoDTO{
			PeerID:      p.String(),
			Negotiated:  po.negotiated,
			Algo:        obfuscate.AlgoName(po.algo),
			Encrypted:   po.algo != obfuscate.ObfAlgoNone,
			TxKeyFP:     keyFingerprint(po.txKey),
			RxKeyFP:     keyFingerprint(po.rxKey),
			ConnEpoch:   po.peerEpoch,
			LocalEpoch:  po.localEpoch,
			PFS:         len(po.pfsPubKey) > 0,
			PFSPubKeyFP: keyFingerprint(po.pfsPubKey),
		})
	}
	// Also surface connected peers that never negotiated (unencrypted).
	// Guard the Host access: a partially-built Node (e.g. in unit tests) may
	// have no Host yet, and we must not panic pushing encryption state.
	if n.Host != nil && n.Host.Network() != nil {
		for _, c := range n.Host.Network().Conns() {
			p := c.RemotePeer()
			if _, ok := seen[p]; ok {
				continue
			}
			seen[p] = struct{}{}
			snapshot = append(snapshot, observer.PeerObfInfoDTO{
				PeerID:     p.String(),
				Negotiated: false,
				Algo:       "none",
				Encrypted:  false,
			})
		}
	}
	if n.Collector != nil {
		n.Collector.SetPeerEncryption(snapshot)
	}
}

func (n *Node) Close() error {
	// Close may be reached from several paths (signal handler, tray exit, web
	// shutdown). Guard so the underlying TAP/Host closers run exactly once.
	alreadyClosed := true
	n.closeOnce.Do(func() { alreadyClosed = false })
	if alreadyClosed {
		return nil
	}
	log.Info("Shutting down node...")
	if n.Gateway != nil {
		_ = n.Gateway.ClearExitNode()
	}
	n.cancel()

	// Wake any blocked boot-relay control-stream readers (SeqSync/Meta/Echo
	// handlers, or a metaPool client awaiting a reply) BEFORE the pool
	// invalidations below. Those readers hold the pool's per-peer lock while
	// blocked in Read, and metaPool.InvalidateAll takes that same lock — if we
	// did not close the streams first, Close would deadlock on its own shutdown.
	// Snapshot first, then Close (which re-takes bootRelayCtrlMu), so we never
	// hold the lock re-entrantly.
	n.bootRelayCtrlMu.Lock()
	ctrlStreams := make([]*bootRelayCtrlStream, 0, len(n.bootRelayCtrlStreams))
	for _, st := range n.bootRelayCtrlStreams {
		ctrlStreams = append(ctrlStreams, st)
	}
	n.bootRelayCtrlMu.Unlock()
	for _, st := range ctrlStreams {
		_ = st.Close()
	}

	n.stopRoamWatcher()

	// Each teardown step is bounded by a timeout so a blocking Close (notably
	// libp2p's Host.Close, which can hang on Windows while QUIC connections
	// are still draining) cannot keep the process alive after the user exits
	// the tray. Without this guard the main UI goroutine stalls in Close() and
	// never reaches PostQuitMessage, leaving p2ptap-tray.exe running.
	closeWithTimeout := func(name string, fn func() error) {
		done := make(chan struct{})
		go func() { _ = fn(); close(done) }()
		select {
		case <-done:
		case <-time.After(8 * time.Second):
			log.Warn("Close step %q timed out after 8s, forcing shutdown", name)
		}
	}
	if n.WebSrv != nil {
		closeWithTimeout("web", n.WebSrv.Close)
	}
	if n.TAP != nil {
		closeWithTimeout("tap", n.TAP.Close)
	}
	closeWithTimeout("host", n.Host.Close)
	n.relayPool.shutdown()
	n.lsaPool.InvalidateAll() // close all cached control streams
	n.metaPool.InvalidateAll()
	n.echoPool.InvalidateAll()
	// Wait for all worker goroutines (stream readers, dispatch loops, etc.) to
	// exit. Bound it with a timeout: if a stream reader is stuck in ReadFrame
	// after the host was force-closed, we must not block shutdown forever.
	// An unbounded Wait() here previously caused repeated test invocations
	// (e.g. `go test -count=N`) to hang for tens of seconds and overlap,
	// corrupting subsequent overlay setup.
	wgDone := make(chan struct{})
	go func() { n.wg.Wait(); close(wgDone) }()
	select {
	case <-wgDone:
	case <-time.After(8 * time.Second):
		log.Warn("Waiting for worker goroutines timed out after 8s, forcing shutdown")
	}
	log.Info("Node stopped")
	return nil
}
