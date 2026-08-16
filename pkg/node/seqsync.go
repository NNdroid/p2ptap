package node

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	mrand "math/rand/v2"
	"strings"
	"sync/atomic"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"

	"p2ptap/pkg/obfuscate"
)

// algoListString renders a list of ObfType bytes as a readable, comma-separated
// list of algorithm names for debug logging (e.g. "chacha20,aes-gcm,none").
func algoListString(algos []byte) string {
	parts := make([]string, 0, len(algos))
	for _, a := range algos {
		parts = append(parts, obfuscate.AlgoName(a))
	}
	return strings.Join(parts, ",")
}

// SeqSyncProtocolID is a lightweight control protocol used to synchronise
// deduplication sequence windows between two peers right after a connection
// is established (and on demand via ForceSyncSeq). Without it, a freshly
// connected peer starts its dedup window at maxSeq=0 while the sender's
// structured SeqIDs already carry a large counter, causing either a blind
// 64k-wide accept window or a spurious "stale" drop. SeqSync lets each side
// tell the other the SeqID it will issue next, so the receiver can anchor its
// window precisely. This also supports forced re-sync when a link is found to
// be desynchronised.
const SeqSyncProtocolID protocol.ID = "/p2ptap/seqsync/1.0.0"

// rxRingSlot is one previously-negotiated RX cipher retained as a decryption
// fallback. See rxRingCap / PeerObf.rxRing for why a *set* of fallbacks is
// needed rather than the single prevRxCipher slot.
type rxRingSlot struct {
	cipher obfuscate.ObfCipher
	key    []byte
}

// rxRingCap bounds how many recent RX ciphers decryptPeerFrame will try on an
// AEAD failure. The realistic upper bound is the number of simultaneous live
// connections to one peer (DIRECT + CIRCUIT-RELAY each negotiate their own
// cipher and may round-robin traffic), plus a couple of generations of key
// rotation — well under 8. Old slots age out so forward secrecy is preserved.
const rxRingCap = 8

// PeerObf records the per-peer obfuscation/encryption state negotiated during
// the SeqSync handshake. ECDH yields the SAME shared secret (hence the same
// keyA/keyB) on both sides, but each side assigns them to directions by PeerID
// ordering so that TX and RX use DISTINCT keys — this prevents two directions
// from ever producing the same (key, nonce) pair. txCipher seals frames we send
// to the peer; rxCipher opens frames we receive from it. negotiated==false means
// no encryption was negotiated (plaintext mode).
type PeerObf struct {
	algo       byte // negotiated algorithm (ObfAlgo*)
	txCipher   obfuscate.ObfCipher
	rxCipher   obfuscate.ObfCipher
	negotiated bool

	// prevRxCipher is the RX cipher from the PREVIOUS (one generation back)
	// negotiation, kept as a decryption fallback during a key rotation. When we
	// flip to a fresh key but the peer has not yet flipped (it has not received
	// our reciprocal "ready", or that "ready" was dropped over a lossy
	// circuit-relay), the peer is still sealing frames with its OLD key. Trying
	// prevRxCipher on a current-key AEAD failure lets us open those frames
	// instead of dropping the whole link into a permanent decrypt-fail loop.
	// Retained across disconnects (removePeerObf no longer wipes it) so a
	// reconnect can still open the peer's lingering old-connection frames.
	prevRxCipher obfuscate.ObfCipher
	prevRxKey    []byte

	// rxRing is a bounded set of RECENT RX ciphers retained as decryption
	// fallbacks. A single prevRxCipher slot cannot represent more than one extra
	// key, yet a peer commonly holds SEVERAL live ciphers at once: every live
	// connection (DIRECT and CIRCUIT-RELAY) runs its own SeqSync handshake and
	// therefore carries its own cipher, and the peer may round-robin outbound
	// traffic across them; plus key rotations add generations. decryptPeerFrame
	// tries each ring slot (newest-first) after the current key fails, so frames
	// the peer sealed with ANY recent key still open instead of being dropped.
	rxRing []rxRingSlot

	// --- WebUI observability: details of the negotiated per-pair key ---
	// txKey/rxKey are the raw 32-byte AEAD keys (derived by ECDH). They are kept
	// only so the WebUI can show a short fingerprint; they are never transmitted.
	txKey       []byte
	rxKey       []byte
	localEpoch  uint64 // our instance connEpoch (sent to this peer)
	peerEpoch   uint64 // the peer's instance connEpoch (received at handshake)
	pfsPubKey   []byte // peer's ephemeral ECDH(P256) public key (nil ⇒ no PFS / plaintext)

	// negotiatedAtSeq is the raw FramePacker counter value at the moment this
	// cipher was negotiated. It backs the GLOBAL safety-net re-key: the AEAD
	// nonce is derived from the frame header's 32-bit structured-counter field
	// (shared node-wide, only the 12-bit per-peer epoch differs), so a peer that
	// has sent few frames of its own still needs a rotation once THIS node has
	// shipped ~2^32 frames total — otherwise the global counter recycles and
	// reuses a (key, nonce) pair for it. See obfCipherForPeer's re-key check.
	negotiatedAtSeq uint64

	// framesSinceRekey is the number of AEAD-encrypted frames actually sealed
	// TO this peer under the CURRENT key (incremented in sealPeerFrame, once per
	// physical frame incl. fragments). It drives the PER-PEER proactive re-key:
	// a chatty peer rotates promptly even when the node as a whole is quiet,
	// independent of how many frames every other peer has shipped. It is a
	// distinct, safer signal than negotiatedAtSeq for the "one busy peer among
	// many idle ones" case. The nonce space under this key is exactly the
	// per-peer frame count (each frame gets a fresh 32-bit counter), so rotating
	// well before this approaches 2^32 is what prevents a nonce reuse. Zeroed on
	// every (re)negotiation because a fresh PeerObf is allocated each time.
	framesSinceRekey atomic.Uint64
}

// pushRxRing appends a recently-used RX cipher to the bounded fallback ring
// (newest last). It is a no-op if the key is already present (current or in the
// ring), so repeated commits of the same key never bloat the ring. decryptPeerFrame
// tries every slot after the current key fails, so frames the peer sealed with any
// of its recently-negotiated ciphers — e.g. a separate DIRECT vs CIRCUIT-RELAY
// connection key, or a key-rotation generation — still open.
func (po *PeerObf) pushRxRing(cipher obfuscate.ObfCipher, key []byte) {
	fp := obfuscate.KeyFingerprint(key)
	if obfuscate.KeyFingerprint(po.rxKey) == fp {
		return
	}
	for _, s := range po.rxRing {
		if obfuscate.KeyFingerprint(s.key) == fp {
			return
		}
	}
	po.rxRing = append(po.rxRing, rxRingSlot{cipher: cipher, key: append([]byte(nil), key...)})
	if len(po.rxRing) > rxRingCap {
		po.rxRing = po.rxRing[len(po.rxRing)-rxRingCap:]
	}
}

// SeqSyncMsg is the JSON payload exchanged over the seqsync control stream.
type SeqSyncMsg struct {
	Type      string `json:"t"` // "sync" | "request" | "ack" | "rekeyReq" | "epochSync"
	NodeID    string `json:"n"` // sender PeerID (string)
	MySeq     uint64 `json:"s"` // next structured SeqID the sender will issue
	ConnEpoch uint64 `json:"e"` // per-instance epoch (12-bit, masked) for anti-replay
	Timestamp int64  `json:"ts"`

	// Obfuscation/encryption negotiation (v2). These let two peers use
	// DIFFERENT local padding modes yet still interoperate, and establish a
	// per-peer AEAD key via ephemeral ECDH without ever sending the key.
	ObfEnabled bool   `json:"oe"`  // whether this node performs per-peer encryption
	ObfAlgos   []byte `json:"oas"` // supported algorithm bytes (preference order)
	ObfMode    string `json:"ob"`  // my outbound padding mode (informational)
	ObfPub     []byte `json:"opk"` // my ephemeral ECDH(P256) public key; empty ⇒ encryption disabled
}

// generateConnEpoch returns a fresh random 12-bit epoch for this node instance.
// The epoch is fixed for the node's lifetime; a restart yields a new epoch, so
// frames captured from a previous run fail the receiver's epoch check.
func generateConnEpoch() uint64 {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return uint64(binary.BigEndian.Uint32(b[:])) & 0xFFF
}

// ensureLocalEpoch returns this node's PER-PEER anti-replay epoch for peer p,
// generating and remembering a fresh random 12-bit value on first contact. The
// epoch identifies THIS node to THAT peer only; rotating it for one reconnecting
// peer leaves every other peer's dedup window untouched. It is independent of the
// negotiated cipher — a reconnect rotates the epoch (via refreshEpochOnReconnect)
// while retaining the same in-memory cipher, so the peer re-anchors its dedup
// window to the new epoch WITHOUT re-deriving the key.
func (n *Node) ensureLocalEpoch(p peer.ID) uint64 {
	if v, ok := n.peerLocalEpochs.Load(p); ok {
		return v.(uint64)
	}
	ep := generateConnEpoch()
	n.peerLocalEpochs.Store(p, ep)
	return ep
}

// txEpochForPeer returns the per-peer anti-replay epoch stamped into frames sent
// to peer p. It returns 0 (a valid epoch) when no cipher has been negotiated yet,
// so the SeqID stays well-formed and the receiver's dedup accepts it on a
// not-yet-epochSet window.
func (n *Node) txEpochForPeer(p peer.ID) uint64 {
	if po := n.peerObf(p); po != nil {
		return po.localEpoch
	}
	return 0
}

// buildSeqSyncMsg constructs a SeqSyncMsg of the given type for peer p,
// populating the obfuscation/encryption negotiation fields from the local config.
// myPub is the wire public key of the ONE-SHOT ephemeral ECDH key pair minted for
// THIS handshake (see mintObfHandshakeKey) — the caller passes the same pair into
// negotiateObfWithPeer so the public key embedded here and the private key used to
// derive the shared secret are guaranteed to match. "ready" passes myPub=nil
// because the key exchange already happened in the preceding sync/ack pair.
// m.ObfPub is empty when encryption is disabled (or key generation failed).
func (n *Node) buildSeqSyncMsg(msgType string, p peer.ID, myPub []byte) SeqSyncMsg {
	m := SeqSyncMsg{
		Type:      msgType,
		NodeID:    n.Host.ID().String(),
		MySeq:     n.Packer.NextSeqID(n.ensureLocalEpoch(p)),
		ConnEpoch: n.ensureLocalEpoch(p),
		Timestamp: time.Now().UnixMilli(),
	}
	// Advertise encryption support only when we actually have a key pair AND a
	// fresh ephemeral public key to offer. If myPub is empty (ephemeral mint
	// failed), we advertise ObfEnabled=false so the peer also negotiates plaintext
	// — keeping both sides symmetric instead of one side using a long-lived key
	// while the other goes plaintext (which would silently mismatch).
	m.ObfEnabled = n.obfKeyPair != nil && len(myPub) > 0
	m.ObfMode = n.Config.Obfuscation.Mode
	// Embed the handshake's ephemeral public key exactly when a fresh key was
	// minted for this message type (everything except "ready").
	if m.ObfEnabled && len(myPub) > 0 {
		m.ObfPub = myPub
		m.ObfAlgos = n.mySupportedAlgos()
	}
	return m
}

// registerSeqSyncHandler wires the seqsync control stream handler.
func (n *Node) registerSeqSyncHandler() {
	n.Host.SetStreamHandler(SeqSyncProtocolID, n.handleSeqSync)
}

// handleSeqSync processes an incoming seqsync request. It anchors this node's
// dedup window for the remote peer, and replies with our own next SeqID so the
// peer can anchor theirs.
func (n *Node) handleSeqSync(s network.Stream) {
	defer s.Close()
	_ = s.SetDeadline(time.Now().Add(5 * time.Second))

	remotePeer := s.Conn().RemotePeer()
	// Serialise per-peer: if two connections (DIRECT + CIRCUIT-RELAY) exist,
	// only one handshake runs at a time. Without this, each connection's
	// responder commits a different ECDH generation, overwriting the shared
	// per-peer cipher slot — producing "ring=N fundamentally divergent key".
	release := n.acquireHandshakeLock(remotePeer)
	defer release()
	// Responder-side provenance: who is allowed to drive the handshake, and over
	// what transport. Mirrors the initiator log so both ends of a debug trace
	// agree on leadership/path without external context.
	log.Debug("SeqSync: [RESPONDER] control stream from %s path=%s iAmResyncLeader=%v",
		remotePeer.String(), connPathLabel(s), n.isResyncLeader(remotePeer))
	msg, err := readSeqSyncMsg(s)
	if err != nil {
		log.Debug("SeqSync: read error from %s: %v", remotePeer.String(), err)
		return
	}

	switch msg.Type {
	case "sync", "request":
		// Ensure we ourselves have a (per-peer) epoch before replying.
		n.ensureLocalEpoch(remotePeer)
		// Anchor our dedup window to what the peer says it will send next,
		// including the epoch expected from that peer.
		n.anchorDedupForPeer(remotePeer, msg.MySeq, msg.ConnEpoch)
		// Mint THIS handshake's one-shot ephemeral key locally and keep it in
		// scope: buildSeqSyncMsg embeds its public key in the "ack", and we pass
		// the same pair into negotiateObfWithPeer below. Because the key lives in
		// this call's local frame (never a shared per-peer slot), two concurrent
		// handshakes for the same peer can no longer clobber each other — each
		// derives its cipher from its own ephemeral private key, so rxKey always
		// ends up matching the peer's txKey.
		// Reuse the ROUND's cached ephemeral (not a fresh mint) so every retry /
		// self-heal within this handshake round negotiates the SAME generation —
		// this is what stops a lossy relay from stranding the two ends on divergent
		// cipher generations (the "100% decrypt fail, rxKeyFP constant" outage).
		kp := n.useCachedHandshakeEph(remotePeer)
		reply := n.buildSeqSyncMsg("ack", remotePeer, n.obfPubFromPair(kp))
		_ = writeSeqSyncMsg(s, reply)
		log.Debug("SeqSync: anchored peer %s at seq=%d epoch=%d (type=%s)", remotePeer.String(), msg.MySeq, msg.ConnEpoch, msg.Type)
		// Commit the new cipher NOW — we already hold BOTH ephemeral public keys
		// (ours in kp, the initiator's in msg.ObfPub), so the ECDH shared secret
		// is fully determined and byte-identical on both sides. The previous
		// design gated this commit on the initiator's reciprocal "ready"; a
		// "ready" dropped over a circuit-relay then left the responder stranded on
		// the OLD key while the initiator (which commits right after its own ack)
		// had already flipped — every frame the initiator sent failed AEAD-open on
		// the responder, i.e. a permanent 100% decrypt-fail loop (the exact
		// "sustained failures → ForceSyncSeq" outage) that only a second,
		// independent re-handshake happened to rescue. Committing here closes that
		// window. The reciprocal "ready" is now purely an application-level
		// readiness / anti-replay ping, NOT a key-commit gate. TAP data stays
		// gated on markPeerReady (set below once "ready" arrives), so no ciphertext
		// is ever transmitted before the peer has also committed its cipher.
		if kp != nil {
			log.Debug("SeqSync: [RESPONDER] committing cipher for %s after ack — localEphemeralFP=%s", remotePeer.String(), kp.Fingerprint())
			n.negotiateObfWithPeer(remotePeer, msg.ObfPub, msg.ObfAlgos, msg.ConnEpoch, kp)
		} else {
			log.Warn("SeqSync: [as responder] could not mint ephemeral key for %s; proceeding with plaintext obfuscation", remotePeer.String())
		}
		// Await the initiator's reciprocal "ready" ONLY to flip readiness and echo
		// it back. We have ALREADY committed the cipher above, so a lost "ready"
		// (older build / relay loss) no longer strands the link in a decrypt-fail
		// loop — both sides are already on the same new key.
		readyMsg, rerr := readSeqSyncMsg(s)
		if rerr == nil && readyMsg.Type == "ready" {
			n.markPeerReady(remotePeer)
			_ = writeSeqSyncMsg(s, n.buildSeqSyncMsg("ready", remotePeer, nil))
			// Round complete (both ready exchanged): drop the cached ephemeral so
			// the next rotation mints a FRESH key (PFS). Do NOT clear on the
			// lost-ready branch below — there we keep the cache so the self-heal
			// re-sync reuses the same generation instead of re-flipping.
			n.clearCachedHandshakeEph(remotePeer)
		} else {
			// The reciprocal "ready" was lost (older build / relay loss), but
			// BOTH sides have ALREADY committed the same new cipher (we did above;
			// the initiator commits right after its own ack). We deliberately do
			// NOT mark the peer ready here: marking ready would start transmitting
			// TAP data, and a lost "ready" in the OTHER direction (or a lost "ack"
			// on a prior round) could still have the peer on its OLD key — which
			// would re-introduce the permanent 100% decrypt-fail loop. Instead we
			// re-run a clean handshake so readiness is reconfirmed symmetrically.
			// The link simply stays idle (no TAP) until that converges, which is
			// strictly safer than dropping every frame. Guarded by rekeyPeers.
			log.Debug("SeqSync: peer %s reciprocal ready lost (older build?/relay loss) — cipher flipped on both sides but NOT marking ready; re-running clean handshake to reconfirm readiness", remotePeer.String())
			n.maybeSelfHeal(remotePeer)
		}
	case "ack":
		// An "ack" arriving on a fresh stream means the peer's handshake reply did
		// not ride the original stream we opened (e.g. it was re-sent out-of-band).
		// We no longer hold the ephemeral private key from the original "sync", so
		// we cannot derive the shared secret here. The original syncSeqToPeerAttempt
		// will still negotiate on its own stream; to be safe we simply re-anchor the
		// dedup window and trigger one self-heal re-sync, which performs a clean
		// handshake with a brand-new local ephemeral key and converges the ciphers.
		n.anchorDedupForPeer(remotePeer, msg.MySeq, msg.ConnEpoch)
		log.Debug("SeqSync: [as ack-handler] anchoring peer %s at seq=%d epoch=%d (unsolicited ack; re-syncing keys via self-heal)", remotePeer.String(), msg.MySeq, msg.ConnEpoch)
		n.markPeerReady(remotePeer)
		n.maybeSelfHeal(remotePeer)
	case "rekeyReq":
		// A follower that sees sustained decryption failures cannot open its own
		// re-key stream (that would cross with our leader-initiated round and
		// produce four divergent ECDH secrets — the permanent decrypt-fail loop).
		// Instead it sends this lightweight nudge; ONLY the leader owns the single
		// handshake round, so on receiving it we drive the re-key ourselves. The
		// follower simply answers our handshake as the responder and converges onto
		// the exact same key we negotiate.
		if n.isResyncLeader(remotePeer) {
			log.Debug("SeqSync: [RESPONDER] received rekeyReq from follower %s — initiating re-key as leader", remotePeer.String())
			n.triggerPeerRekey(remotePeer)
		} else {
			log.Debug("SeqSync: [RESPONDER] received rekeyReq from %s but we are not the leader; ignoring (the leader owns the round)", remotePeer.String())
		}
	case "epochSync":
		// Lightweight RECONNECT sync: refresh the dedup window + expected
		// anti-replay epoch for this peer WITHOUT re-deriving the cipher. Used
		// when the peer reconnects but we still hold a valid (retained) in-memory
		// key, so a full ECDH handshake would be needless churn. No ObfPub is
		// exchanged and negotiateObfWithPeer is NEVER called here — the per-peer
		// cipher is left exactly as-is. The reciprocal epochSync we send back lets
		// the initiator learn OUR new epoch too, so both ends' dedup windows stay
		// consistent. Because the epoch is PER-PEER (not a node-wide value), this
		// reconnect touches ONLY the two participating peers — every other peer's
		// dedup window is left completely undisturbed.
		n.anchorDedupForPeer(remotePeer, msg.MySeq, msg.ConnEpoch)
		n.markPeerReady(remotePeer)
		reply := n.buildEpochSyncMsg(remotePeer)
		_ = writeSeqSyncMsg(s, reply)
		log.Debug("SeqSync: [epochSync] re-anchored dedup for %s at seq=%d epoch=%d (retained key, cipher NOT re-derived)", remotePeer.String(), msg.MySeq, msg.ConnEpoch)
	}
}

// maybeSelfHeal triggers a passive-side handshake re-sync when a reciprocal
// "ready" is lost (or an unsolicited ack arrives). It does NOT re-run the
// handshake directly — it delegates to triggerPeerRekey, which owns the single
// rekeyPeers guard AND the persistent retry loop. Delegating here guarantees
// exactly one re-key round is ever in flight per peer (never two concurrent
// rounds that would produce mismatched keys), and unifies the proactive
// rotation, the reactive decrypt-fail self-heal, and the lost-ready self-heal
// onto one code path.
func (n *Node) maybeSelfHeal(p peer.ID) {
	// A lost reciprocal-ready means we deliberately did NOT flip our cipher, so
	// the link is still usable on the current key. To converge both sides onto a
	// fresh key we run a clean re-handshake. The leader owns the actual handshake
	// round (triggerPeerRekey opens the stream only when iAmResyncLeader); a
	// follower routes through triggerPeerRekey too, which nudges the leader via
	// rekeyReq instead of opening its own stream — so this self-heal works
	// regardless of which end we are, and never crosses generations with the
	// peer's own round.
	n.triggerPeerRekey(p)
}

// anchorDedupForPeer lazily creates (if needed) and syncs the dedup window for
// a given remote peer, recording the epoch expected from that peer so stale
// (cross-session) frames are rejected.
func (n *Node) anchorDedupForPeer(p peer.ID, remoteSeq uint64, connEpoch uint64) {
	n.dedupPeersMu.RLock()
	d, ok := n.dedupPeers[p]
	n.dedupPeersMu.RUnlock()
	if !ok {
		n.dedupPeersMu.Lock()
		d = n.dedupPeers[p]
		if d == nil {
			d = obfuscate.NewDeduplicator()
			n.dedupPeers[p] = d
		}
		n.dedupPeersMu.Unlock()
	}
	d.SyncFrom(remoteSeq)
	d.SetConnEpoch(connEpoch)
}

// buildEpochSyncMsg constructs a lightweight "epochSync" message used on a
// retained-key reconnect. It carries our CURRENT (just-refreshed) node-wide
// conn epoch and next SeqID so the peer can re-anchor its dedup window and
// adopt the new anti-replay epoch — but it carries NO ephemeral ECDH public
// key, so receiving it never triggers a cipher re-negotiation.
func (n *Node) buildEpochSyncMsg(p peer.ID) SeqSyncMsg {
	return SeqSyncMsg{
		Type:      "epochSync",
		NodeID:    n.Host.ID().String(),
		MySeq:     n.Packer.NextSeqID(n.ensureLocalEpoch(p)),
		ConnEpoch: n.ensureLocalEpoch(p),
		Timestamp: time.Now().UnixMilli(),
	}
}

// SyncSeqToPeer initiates a seqsync exchange with a connected peer: it sends
// our next SeqID (so the peer can anchor us) and, in return, learns the peer's
// next SeqID to anchor our own window for it. The handshake (anchor + ECDH +
// mutual ready) is retried with exponential backoff if an attempt fails, because
// the window-anchor / mutual-ready exchange can transiently race with the peer's
// own handshake (especially under connect storms). Retries stop early once the
// peer is genuinely gone (Connectedness == NotConnected) — Limited/transient
// states are NOT treated as offline, so a NAT-restricted but reachable peer is
// still retried instead of being abandoned prematurely.
func (n *Node) SyncSeqToPeer(p peer.ID) error {
	const (
		maxAttempts = 8
		baseDelay   = 1 * time.Second
		maxDelay    = 15 * time.Second
	)
	// Serialise ALL handshakes (initiator + responder) per peer. Without this,
	// a concurrent responder on a second connection can overwrite the per-peer
	// cipher slot while this initiator is mid-handshake — producing divergent
	// ECDH generations and permanent decrypt failure.
	release := n.acquireHandshakeLock(p)
	defer release()
	// Begin tracking handshake convergence latency. Only seed the start time if
	// this peer is not already converged (so a later re-handshake does not reset
	// a healthy measurement) and we have no pending measurement for it.
	if !n.isPeerReady(p) {
		if _, exists := n.seqsyncHandshakeStart.Load(p); !exists {
			n.seqsyncHandshakeStart.Store(p, time.Now())
		}
	}
	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if attempt > 0 {
			// Stop retrying only when the peer is genuinely unreachable. A
			// relay-only peer is never "directly connected" yet is still
			// reachable through an overlay-relay hop or a boot circuit, so we
			// must keep retrying (it will converge once a route exists) instead
			// of bailing on the NotConnected state.
			if n.Host.Network().Connectedness(p) == network.NotConnected &&
				n.relayHopForTarget(p) == "" {
				log.Debug("SeqSync: peer %s not connected and no relay hop; stop retrying", p.String())
				if lastErr == nil {
					lastErr = fmt.Errorf("peer %s offline", p.String())
				}
				return lastErr
			}
			// Exponential backoff with full jitter: base * 2^(attempt-1), capped
			// at maxDelay; the jitter spreads retries so a connect storm does not
			// re-synchronise into a new thundering herd.
			delay := baseDelay * time.Duration(1<<uint(attempt-1))
			if delay > maxDelay {
				delay = maxDelay
			}
			delay += time.Duration(mrand.Uint64N(uint64(delay) / 2))
			log.Debug("SeqSync: retry %d/%d with %s in %v", attempt+1, maxAttempts, p.String(), delay)
			time.Sleep(delay)
		}
		err := n.syncSeqToPeerAttempt(p)
		if err == nil {
			return nil
		}
		lastErr = err
		log.Debug("SeqSync: attempt %d with %s failed: %v", attempt+1, p.String(), err)
	}
	return fmt.Errorf("SeqSync: gave up after %d attempts with %s: %w", maxAttempts, p.String(), lastErr)
}

// syncSeqToPeerAttempt performs ONE SeqSync handshake attempt (anchor + ECDH +
// mutual ready). It is wrapped by SyncSeqToPeer, which retries with exponential
// backoff if the attempt fails and the peer is still connected.
func (n *Node) syncSeqToPeerAttempt(p peer.ID) error {
	n.ensureLocalEpoch(p)
	// Open the control stream with a generous, dedicated timeout. The default
	// libp2p stream-open deadline is too tight when the peer is only reachable
	// via a congested circuit-relay (high throughput saturates the relayed QUIC
	// connection), which previously surfaced as "failed to open stream: context
	// deadline exceeded" and aborted the re-handshake. 30s gives the relay time
	// to drain and the handshake to complete.
	ctx, cancel := context.WithTimeout(n.ctx, 30*time.Second)
	defer cancel()
	// Open the control stream through the unified opener: direct if p is
	// directly connected, else tunnelled through an overlay-relay hop
	// (relay-ctrl), else the boot circuit relay. The handshake bytes written
	// below are carried verbatim to p, which runs this handler with its logical
	// peer set to the true origin — so the cipher is anchored on p either way.
	s, err := n.openControlStream(ctx, p, SeqSyncProtocolID)
	if err != nil {
		return err
	}
	defer s.Close()
	_ = s.SetDeadline(time.Now().Add(5 * time.Second))
	// Path + leadership are the two facts that decide whether a re-key can even
	// start: a relayed path can drop the reciprocal "ready", and only the
	// resync leader may initiate. Logging both up front means a stuck link is
	// explained by the log itself rather than by cross-referencing source.
	log.Debug("SeqSync: opened control stream to %s protocol=%s path=%s iAmResyncLeader=%v",
		p.String(), SeqSyncProtocolID, connPathLabel(s), n.isResyncLeader(p))

	// Mint THIS handshake's one-shot ephemeral key locally and keep it in scope.
	// The same pair is embedded (public) in the "sync" message and used (private)
	// to derive the shared secret in negotiateObfWithPeer below — so rxKey will
	// match the peer's txKey even if another handshake for p runs concurrently.
	// Reuse the ROUND's cached ephemeral (not a fresh mint) so every retry within
	// this handshake round negotiates the SAME generation — this is what stops a
	// lossy relay from stranding the two ends on divergent cipher generations.
	kp := n.useCachedHandshakeEph(p)
	msg := n.buildSeqSyncMsg("sync", p, n.obfPubFromPair(kp))
	if err := writeSeqSyncMsg(s, msg); err != nil {
		return err
	}
	// Read the peer's reply (ack with its own SeqID).
	reply, err := readSeqSyncMsg(s)
	if err != nil {
		// CRITICAL: do NOT treat a missing ack as success. For a
		// version-matched peer, a failed ack-read means THIS side never
		// received the peer's ephemeral public key, so we must NOT commit
		// our cipher (negotiateObfWithPeer at the bottom runs only after a
		// successful read) — yet the RESPONDER already committed when it
		// wrote its ack (handleSeqSync commits on ack, before reading
		// "ready"). Returning nil here would (a) leave this side on the OLD
		// key while the peer flipped → exactly one cipher generation of
		// divergence, and (b) make SyncSeqToPeer report SUCCESS, which
		// releases the rekeyPeers single-flight guard prematurely and lets
		// the next re-key round start immediately — a self-sustaining
		// cross-generation re-key storm (the "ring=N, flipping keys"
		// signature seen in production). Return the error instead so
		// SyncSeqToPeer retries the round (up to 8× with backoff) and only
		// reports success once the ack is genuinely read and the cipher is
		// committed. (Against a genuinely older peer with no seqsync
		// handler, this now retries on a 20s cadence; this is bounded and
		// strictly safer than silently desyncing the keys.)
		log.Debug("SeqSync: no ack from %s — round NOT converged, reporting failure for retry: %v", p.String(), err)
		return fmt.Errorf("SeqSync: initiator did not receive ack from %s: %w", p.String(), err)
	}
	n.anchorDedupForPeer(p, reply.MySeq, reply.ConnEpoch)
	// Negotiate per-peer encryption from the peer's ECDH public key, using our
	// freshly-minted ephemeral private key. Skip if we could not mint one
	// (kp == nil) so we stay symmetric with the peer (plaintext on both sides).
	if kp != nil {
		log.Debug("SeqSync: [INITIATOR] committing cipher for %s after ack — localEphemeralFP=%s (peer's pubkey arrives in ack)",
			p.String(), kp.Fingerprint())
		n.negotiateObfWithPeer(p, reply.ObfPub, reply.ObfAlgos, reply.ConnEpoch, kp)
	} else {
		log.Warn("SeqSync: [as initiator] could not mint ephemeral key for %s; proceeding with plaintext obfuscation", p.String())
	}
	// Announce readiness and await the peer's reciprocal "ready" so neither
	// side transmits encrypted TAP data before the other has negotiated its
	// cipher. This closes the handshake-window race (a peer sending to its
	// neighbor before the neighbor derived the shared key). Fall back to ready
	// on a failed/empty reciprocal to stay compatible with older peers.
	if err := writeSeqSyncMsg(s, n.buildSeqSyncMsg("ready", p, nil)); err != nil {
		n.markPeerReady(p) // fallback: still usable
		n.clearCachedHandshakeEph(p) // handshake considered done via fallback
		return nil
	}
	readyReply, rerr := readSeqSyncMsg(s)
	if rerr == nil && readyReply.Type == "ready" {
		n.markPeerReady(p)
		// Round complete (both ready exchanged): drop the cached ephemeral so the
		// next rotation mints a FRESH key (PFS).
		n.clearCachedHandshakeEph(p)
	} else {
		log.Debug("SeqSync: peer %s did not confirm ready (older build? / lost over relay): marking usable anyway", p.String())
		n.markPeerReady(p)
		// The reciprocal ready was lost, so the responder may still be waiting
		// for our "ready" and thus not sending. Re-run the handshake once in the
		// background (self-heal) so both sides converge; the real traffic will
		// start as soon as one side decrypts the other's first frame.
		n.maybeSelfHeal(p)
	}
	return nil
}

// ForceSyncSeq forces a seqsync exchange with a peer (used by WebUI "resync"
// action or when desynchronisation is detected). It delegates to
// triggerPeerRekey rather than calling SyncSeqToPeer directly.
//
// WHY this matters: triggerPeerRekey owns the single rekeyPeers single-flight
// guard, the leader check, AND the persistent retry loop. Calling SyncSeqToPeer
// directly here (the previous behaviour) let a burst of decrypt-fail events —
// each undecryptable frame currently spawns a ForceSyncSeq — open many
// *concurrent* handshakes for the same peer. Each mints an independent
// one-shot ephemeral and flips the cipher in its own generation; when the two
// ends' last-completed generations differ, their derived keyA/keyB diverge and
// every frame fails to decrypt forever. That is exactly the
// "refreshing identical cipher" + permanent decrypt-fail loop seen in
// production: the re-handshake "succeeds" yet frames still fail, because this
// node flipped to generation N while the peer flipped to generation M (a
// crossed-ephemeral mismatch the single-flight guard exists to prevent).
// Routing through triggerPeerRekey guarantees at most ONE handshake generation
// is ever in flight per peer (the rekeyPeers single-flight guard), so the two
// ends can never cross generations into a decrypt-fail loop.
//
// Either side may initiate now: the old leader-only rule made a follower that
// saw sustained decrypt failures deadlock forever (the leader, receiving the
// follower's frames fine, never re-handshaked). The single-flight guard — not
// the leader rule — is what prevents concurrent-round storms, so lifting the
// restriction is safe and lets a follower self-heal.
func (n *Node) ForceSyncSeq(p peer.ID) {
	// Leadership decides who opens the handshake stream: only the leader (larger
	// PeerID) ever does, which guarantees exactly one handshake round per re-key
	// event and thereby eliminates the crossed-handshake divergence. A follower
	// routes its reactive re-key through triggerPeerRekey, which nudges the
	// leader via a rekeyReq signal instead of opening its own stream — so the
	// follower still recovers from sustained decrypt failures (it forces the
	// leader to act) without ever crossing generations with the leader's round.
	log.Debug("SeqSync: ForceSyncSeq to %s (iAmResyncLeader=%v) — driving re-handshake", p.String(), n.isResyncLeader(p))
	n.triggerPeerRekey(p)
}

// mySupportedAlgos returns the list of obfuscation algorithms this node
// advertises, derived from the local config. "auto" expands to the full
// preference order; a concrete algo is advertised alongside "none" so we can
// interoperate with peers configured for plaintext obfuscation.
func (n *Node) mySupportedAlgos() []byte {
	switch n.Config.Obfuscation.Algorithm {
	case "aes-gcm", "aes":
		// Prefer AES-GCM, but support ChaCha20 and None for maximum cross-node compatibility
		return []byte{obfuscate.ObfAlgoAESGCM, obfuscate.ObfAlgoChaCha20, obfuscate.ObfAlgoNone}
	case "chacha20", "chacha20poly1305", "chacha":
		// Prefer ChaCha20, but support AES-GCM and None for maximum cross-node compatibility
		return []byte{obfuscate.ObfAlgoChaCha20, obfuscate.ObfAlgoAESGCM, obfuscate.ObfAlgoNone}
	case "none":
		return []byte{obfuscate.ObfAlgoNone}
	default: // "auto" or empty ⇒ full preference order
		return append([]byte(nil), obfuscate.DefaultAlgoPreference...)
	}
}

// negotiateObfWithPeer performs the ECDH handshake given the peer's public key
// bytes and advertised algorithm list, derives the per-peer AEAD cipher, and
// stores it in n.perPeerObf. If the peer sends no public key (encryption
// disabled) or advertises no common algorithm, the entry is left nil so frames
// fall back to plaintext obfuscation.
//
// Forward secrecy: the private key used for ECDH is the ONE-SHOT ephemeral key
// passed in via myEphemeral — minted locally for THIS handshake by the caller
// (mintObfHandshakeKey) and never stored in a shared per-peer slot. Passing the
// key by value (instead of reading a global pendingObfKeys[peer]) is what makes
// two concurrent handshakes for the same peer safe: each derives its cipher from
// its own ephemeral private key, so rxKey always matches the peer's txKey. If
// myEphemeral is nil (no ephemeral key available), the long-lived node key is used
// as a backward-compatible fallback. The derived keyA/keyB are wiped from memory
// once the ciphers are constructed.
func (n *Node) negotiateObfWithPeer(p peer.ID, peerPub []byte, peerAlgos []byte, peerEpoch uint64, myEphemeral *obfuscate.ObfKeyPair) {
	log.Debug("SeqSync: negotiateObfWithPeer(peer=%s, hasPub=%v pubLen=%d, peerAlgos=[%s], peerEpoch=%d)",
		p.String(), len(peerPub) > 0, len(peerPub), algoListString(peerAlgos), peerEpoch)
	if len(peerPub) == 0 || n.obfKeyPair == nil || len(peerAlgos) == 0 {
		// Disabled peer: no encryption negotiation.
		log.Debug("SeqSync: peer %s does not negotiate encryption (disabled), falling back to plaintext obfuscation", p.String())
		return
	}
	// The ephemeral key is now passed in by the caller (minted locally for THIS
	// handshake), NOT read from a shared per-peer slot. This removes the previous
	// race where two concurrent handshakes for the same peer could overwrite each
	// other's one-shot key in pendingObfKeys, leaving one side with a cipher
	// derived from the wrong private key — a permanently mismatched rxKey/txKey
	// pair that no re-handshake could heal.
	useFallback := myEphemeral == nil
	var priv *ecdh.PrivateKey
	var fp string
	if useFallback {
		// With StrictKeyNegotiation enabled, refuse to degrade to the long-lived
		// node key: that would reuse one static identity key across all peers and
		// sacrifice PFS. Leave the peer pair at plaintext obfuscation instead. The
		// next fresh SeqSync handshake (with a one-shot ephemeral key) will restore
		// proper per-pair encryption.
		if n.Config.Obfuscation.StrictKeyNegotiation {
			log.Warn("SeqSync: peer %s has no ephemeral handshake key and StrictKeyNegotiation is on; refusing long-lived-key fallback, leaving peer at plaintext", p.String())
			return
		}
		priv = n.obfKeyPair.Priv()
		fp = n.obfKeyPair.Fingerprint()
		log.Debug("SeqSync: handshake key state for %s: forward-secret one-shot key unavailable → negotiating via long-lived node key (fallback, PFS NOT preserved)", p.String())
	} else {
		priv = myEphemeral.Priv()
		fp = myEphemeral.Fingerprint()
		log.Debug("SeqSync: handshake key state for %s: forward-secret (one-shot ECDH) → negotiating via %s", p.String(), fp)
	}
	keyA, keyB, err := obfuscate.DeriveKeys(priv, peerPub)
	if err != nil {
		log.Warn("SeqSync: ECDH derive with %s failed: %v", p.String(), err)
		return
	}
	if keyA == nil || keyB == nil {
		// Disabled peer: no encryption negotiation.
		log.Debug("SeqSync: peer %s does not negotiate encryption (disabled), falling back to plaintext obfuscation", p.String())
		return
	}
	// Guard against a degenerate key (all-zero), which would make the AEAD a
	// fixed, publicly-known key and void all confidentiality/authentication.
	// A valid ECDH shared secret can be all-zero only with negligible
	// probability, so treat it as a failed negotiation rather than encrypting
	// with a known key.
	if obfuscate.IsZeroKey(keyA) || obfuscate.IsZeroKey(keyB) {
		log.Warn("SeqSync: derived all-zero AEAD key with %s; refusing to encrypt with a degenerate key", p.String())
		return
	}
	// The derived symmetric keys are copied into the AEAD ciphers below; wipe
	// them from this stack frame immediately afterward so key material does not
	// linger in memory.
	defer func() {
		for i := range keyA {
			keyA[i] = 0
		}
		for i := range keyB {
			keyB[i] = 0
		}
	}()
	algo := obfuscate.SelectAlgo(n.mySupportedAlgos(), peerAlgos)
	if algo == obfuscate.ObfAlgoNone {
		log.Debug("SeqSync: no common algorithm with %s, falling back to plaintext", p.String())
		return
	}
	txKey, rxKey := keyA, keyB
	// Direction assignment: the side with the smaller PeerID sends with keyA /
	// receives with keyB; the other side reverses. Because keyA/keyB are identical
	// on both nodes, the sender's txKey always equals the receiver's rxKey.
	// Log the pre-swap key fingerprints and which side we are so a mismatch
	// (sender's txKey != receiver's rxKey) is immediately visible in the logs.
	dirLabel := "send=keyA/recv=keyB"
	if n.Host.ID() > p {
		txKey, rxKey = keyB, keyA
		dirLabel = "send=keyB/recv=keyA"
	}
	log.Debug("SeqSync: derived keys for %s: algo=%s keyAFP=%s keyBFP=%s peerOrder(self>peer=%v) → %s",
		p.String(), obfuscate.AlgoName(algo),
		obfuscate.KeyFingerprint(keyA), obfuscate.KeyFingerprint(keyB),
		n.Host.ID() > p, dirLabel)
	txCipher, err := obfuscate.NewObfCipher(algo, txKey)
	if err != nil {
		log.Warn("SeqSync: TX cipher build for %s failed: %v", p.String(), err)
		return
	}
	rxCipher, err := obfuscate.NewObfCipher(algo, rxKey)
	if err != nil {
		log.Warn("SeqSync: RX cipher build for %s failed: %v", p.String(), err)
		return
	}
	// Detect an OVERWRITE of an already-negotiated cipher. The handshake can
	// drive negotiateObfWithPeer more than once for the same peer (initial
	// sync/ack pair plus any self-heal re-sync). If a forward-secret cipher is
	// being replaced by a long-lived-key fallback — or the algorithm changes —
	// that is the signature of the key-exchange ordering bug: both sides may end
	// up on mismatched ciphers and every frame fails to decrypt. Log it loudly so
	// the condition is unmistakable during debugging.
	if existing := n.peerObf(p); existing != nil && existing.negotiated {
		modeBefore := "forward-secret"
		if existing.pfsPubKey == nil {
			modeBefore = "long-lived-fallback"
		}
		modeAfter := "forward-secret"
		if useFallback {
			modeAfter = "long-lived-fallback"
		}
		if modeBefore != modeAfter || existing.algo != algo {
			log.Warn("SeqSync: RE-NEGOTIATING cipher for %s: %s(%s) → %s(%s) (existing txKeyFP=%s rxKeyFP=%s)",
				p.String(), modeBefore, obfuscate.AlgoName(existing.algo),
				modeAfter, obfuscate.AlgoName(algo),
				obfuscate.KeyFingerprint(existing.txKey), obfuscate.KeyFingerprint(existing.rxKey))
		} else {
			log.Debug("SeqSync: refreshing identical cipher for %s: %s(%s)",
				p.String(), modeAfter, obfuscate.AlgoName(algo))
		}
	}
	// Guard: never let a long-lived-key FALLBACK downgrade an already-negotiated
	// FORWARD-SECRET cipher. The fallback reuses one static identity key across
	// all peers (no PFS) and — critically — can be mismatched with the peer's
	// forward-secret cipher, which makes EVERY frame fail to decrypt (the
	// deterministic "100% decrypt fail" seen in production). If we already hold
	// a forward-secret cipher for this peer, keep it and refuse the downgrade;
	// the next fresh SeqSync handshake (which always mints a one-shot ephemeral
	// key) will converge both sides onto a new forward-secret cipher.
	if useFallback {
		if existing := n.peerObf(p); existing != nil && existing.negotiated && existing.pfsPubKey != nil {
			log.Warn("SeqSync: refusing long-lived-key fallback for %s — would clobber an existing forward-secret cipher; keeping current (txKeyFP=%s rxKeyFP=%s)",
				p.String(), obfuscate.KeyFingerprint(existing.txKey), obfuscate.KeyFingerprint(existing.rxKey))
			return
		}
	}
	po := &PeerObf{
		algo:       algo,
		txCipher:   txCipher,
		rxCipher:   rxCipher,
		negotiated: true,
		// Observability for the WebUI "negotiated key" panel. These are NOT
		// transmitted; they let an operator confirm that every peer pair got a
		// distinct, forward-secret cipher.
		txKey:      append([]byte(nil), txKey...),
		rxKey:      append([]byte(nil), rxKey...),
		localEpoch: n.ensureLocalEpoch(p),
		peerEpoch:  peerEpoch,
		pfsPubKey:  append([]byte(nil), peerPub...),
		// Snapshot the raw frame counter so the TX path can schedule a key
		// rotation before the structured 32-bit counter wraps under this key.
		negotiatedAtSeq: n.Packer.CurrentCounter(),
	}
	// Roll-over tolerance: carry the previous RX cipher forward as a decryption
	// fallback. If the new rxKey differs from the currently-stored one we are
	// replacing, the peer may briefly still be sealing with that old key (it has
	// not yet flipped to our new key — the reciprocal "ready" can be lost over a
	// lossy circuit-relay). Keeping prevRxCipher lets decryptPeerFrame open those
	// in-flight/old-key frames so a key rotation never strands the link in a
	// permanent decrypt-fail loop. When refreshing an identical cipher we preserve
	// any fallback we already held.
	if existing := n.peerObf(p); existing != nil && existing.negotiated {
		if obfuscate.KeyFingerprint(existing.rxKey) != obfuscate.KeyFingerprint(rxKey) {
			// New key generation: keep the just-replaced RX cipher as the
			// single-generation prevRxCipher (for diagnostics / the common
			// rotation case) AND accumulate the full history of recent RX
			// ciphers into the bounded ring. A peer with multiple live
			// connections (DIRECT + CIRCUIT-RELAY) holds a DIFFERENT cipher per
			// connection and may round-robin traffic across them, so only the
			// single prev slot would strand every other connection's frames.
			po.prevRxCipher = existing.rxCipher
			po.prevRxKey = append([]byte(nil), existing.rxKey...)
			po.rxRing = append(append([]rxRingSlot(nil), existing.rxRing...), rxRingSlot{
				cipher: existing.rxCipher,
				key:    append([]byte(nil), existing.rxKey...),
			})
			if len(po.rxRing) > rxRingCap {
				po.rxRing = po.rxRing[len(po.rxRing)-rxRingCap:]
			}
		} else {
			// Identical key: preserve whatever fallback/ring we already held.
			po.prevRxCipher = existing.prevRxCipher
			po.prevRxKey = append([]byte(nil), existing.prevRxKey...)
			po.rxRing = append([]rxRingSlot(nil), existing.rxRing...)
		}
	} else {
		// Fresh (re)connection immediately after a cipher clear: seed the
		// previous generation's RX cipher (retained briefly in rxKeyGrace) so
		// frames still arriving on a lingering old connection — the peer is
		// still sealing with its pre-reconnect key — decrypt instead of being
		// dropped. This is the exact situation that produced a single
		// AEAD-failed frame right after a DIRECT re-handshake: the peer kept its
		// old session open and a straggler frame slipped in with the old key
		// after we had already flipped to the new one.
		n.seedPrevRxFromGrace(p, po)
	}
	n.storePeerObf(p, po)
	// Reflect the freshly-used handshake key in ObfFingerprint so the WebUI can
	// confirm forward secrecy is active for this (re)connection.
	n.setHandshakeFingerprint(fp)
	if useFallback {
		log.Info("SeqSync: negotiated obfuscation with %s: algo=%s (encrypted, LONG-LIVED KEY FALLBACK) txKeyFP=%s rxKeyFP=%s",
			p.String(), obfuscate.AlgoName(algo),
			obfuscate.KeyFingerprint(txKey), obfuscate.KeyFingerprint(rxKey))
	} else {
		log.Info("SeqSync: negotiated obfuscation with %s: algo=%s (encrypted, forward-secret, fp=%s) txKeyFP=%s rxKeyFP=%s",
			p.String(), obfuscate.AlgoName(algo), fp,
			obfuscate.KeyFingerprint(txKey), obfuscate.KeyFingerprint(rxKey))
	}
	n.pushPeerEncryption()
}

// connPathLabel describes how the seqsync control stream is physically carried:
// directly, or hopped through a circuit relay. A relayed handshake is the
// classic place a "ready" frame gets dropped — surfacing the path in the logs
// lets us correlate a decrypt-fail storm with relay loss without extra probes.
func connPathLabel(s network.Stream) string {
	c := s.Conn()
	ma := ""
	if c != nil {
		if rma := c.RemoteMultiaddr(); rma != nil {
			ma = rma.String()
		}
	}
	if c != nil && strings.Contains(ma, "/p2p-circuit") {
		return "CIRCUIT-RELAY " + ma
	}
	return "DIRECT " + ma
}

// shortPeerID keeps a peer-ID readable in a one-line log (full IDs are ~52 chars).
func shortPeerID(s string) string {
	if len(s) <= 12 {
		return s
	}
	return "..." + s[len(s)-10:]
}

// seqSyncMsgSummary renders the wire-relevant fields of a SeqSyncMsg for debug
// logs. The ephemeral ECDH public-key fingerprint (obfPubFP) is the per-round
// correlation token: it is minted fresh every handshake and exchanged in the
// message, so matching obfPubFP values across the two sides prove both ends
// derived their cipher from the SAME ephemeral pair (i.e. the same key
// generation). A mismatch is the smoking gun for the cross-generation bug.
func seqSyncMsgSummary(m SeqSyncMsg) string {
	pubFP := "(none)"
	if len(m.ObfPub) > 0 {
		pubFP = obfuscate.KeyFingerprint(m.ObfPub)
	}
	return fmt.Sprintf("type=%s node=%s mySeq=%d epoch=%d obf=%v algos=[%s] obfPubFP=%s",
		m.Type, shortPeerID(m.NodeID), m.MySeq, m.ConnEpoch, m.ObfEnabled,
		algoListString(m.ObfAlgos), pubFP)
}

// readSeqSyncMsg decodes one SeqSyncMsg off the control stream and traces it on
// the wire (DEBUG) so a full handshake is reconstructable from logs alone:
// direction, transport path, message type, and the exchanged ephemeral pubkey.
func readSeqSyncMsg(s network.Stream) (SeqSyncMsg, error) {
	var msg SeqSyncMsg
	dec := json.NewDecoder(io.LimitReader(s, 4096))
	err := dec.Decode(&msg)
	if err != nil {
		log.Debug("SeqSync[wire] RECV %s %s | READ ERROR: %v", s.Conn().RemotePeer().String(), connPathLabel(s), err)
		return msg, err
	}
	log.Debug("SeqSync[wire] RECV %s %s | %s", s.Conn().RemotePeer().String(), connPathLabel(s), seqSyncMsgSummary(msg))
	return msg, err
}

// writeSeqSyncMsg encodes one SeqSyncMsg onto the control stream and traces it.
func writeSeqSyncMsg(s network.Stream, msg SeqSyncMsg) error {
	log.Debug("SeqSync[wire] SEND %s %s | %s", s.Conn().RemotePeer().String(), connPathLabel(s), seqSyncMsgSummary(msg))
	enc := json.NewEncoder(s)
	return enc.Encode(msg)
}
