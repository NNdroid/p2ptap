package node

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"p2ptap/pkg/obfuscate"
	"p2ptap/pkg/routing"
)

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

// pskRequired reports whether this node belongs to a PSK-private network. When
// true, the PSK is folded into every per-peer key schedule (see
// obfuscate.DeriveKeysPSK) AND mesh traffic is fail-closed: a peer that has not
// negotiated an ENCRYPTED cipher with us is neither sent plaintext frames nor
// allowed to inject them. A party that completes the identity-only libp2p
// handshake but lacks the PSK therefore cannot read, forge, or covert-channel
// frames — it is isolated on the DIRECT data path, not just at the
// relay/peek-map boundary that PSK gated before.
func (n *Node) pskRequired() bool {
	c := n.config()
	return c != nil && c.PSK != ""
}

// pskSaltBytes returns the PSK bytes mixed into the per-peer KDF salt (nil for a
// PSK-less deployment, which keeps the pre-binding key schedule byte-for-byte
// compatible with older builds).
//
// The canonical form from routing.PSKKeyBytes is used, not the raw config
// string: hex is case-insensitive, so "ABCD" and "abcd" must yield the same
// salt. Both ends of a link route through the same canonicalizer, which is what
// makes per-peer key agreement possible.
func pskSaltBytes(n *Node) []byte {
	c := n.config()
	if c == nil || c.PSK == "" {
		return nil
	}
	return routing.PSKKeyBytes(c.PSK)
}

// hasNegotiatedCipher reports whether an encrypted per-peer cipher has been
// established with p. In a PSK-required network it is the membership proof:
// only a peer holding the same PSK derives matching keys (see
// obfuscate.DeriveKeysPSK), so "cipher negotiated" ⇔ "peer knows the PSK".
// Peers without one must never exchange plaintext mesh frames.
func (n *Node) hasNegotiatedCipher(p peer.ID) bool {
	po := n.peerObf(p)
	return po != nil && po.negotiated && po.txCipher != nil
}

// obfRekeyFrameThreshold is the number of frames a single negotiated key may
// protect before we proactively rotate it. It bounds BOTH the per-peer
// logical-frame counter and the per-peer fragment counter (framesSinceRekey).
//
// It is deliberately kept below txFragSeqBase (2^31): the 32-bit nonce counter
// is now split into two per-peer halves — logical frames in [1, 2^31) and
// tunnel fragment envelopes in [2^31, 2^32) — so the *real* per-key nonce space
// of each half is 2^31 values, not 2^32. Rotating at ~2^30 leaves a wide margin
// on both halves and keeps a (key, nonce) pair from ever repeating, which is the
// one catastrophic failure mode of AES-GCM / ChaCha20.
const obfRekeyFrameThreshold = txFragSeqBase - (1 << 27)

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
	return n.sealPeerFrameInto(p, cipher, data, nil)
}

// sealPeerFrameInto is the pooled-destination form used by data dispatch. The
// re-key frame counter remains centralized here so allocation strategy never
// changes nonce/accounting semantics.
func (n *Node) sealPeerFrameInto(p peer.ID, cipher obfuscate.ObfCipher, data, dst []byte) ([]byte, error) {
	if cipher == nil {
		return nil, fmt.Errorf("sealPeerFrame: nil cipher for peer %s — refusing to ship frame unsealed", p.String())
	}
	enc, err := obfuscate.EncryptPayloadRegionInto(dst, data, cipher)
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
		// PERF: per-frame path. p.String() is a base58 encode plus allocations
		// and Go evaluates the arguments at the CALL SITE regardless of level,
		// so an unguarded log.Debug costs that on every frame even at info.
		// This branch is hit for every frame sent to a peer whose crypto has
		// not completed negotiation (and forever in plaintext mode).
		if log.IsDebug() {
			log.Debug("Tx: NO negotiated cipher for %s (po=%v) — sending payload in PLAINTEXT (obfuscation only, NOT encrypted)",
				p.String(), po != nil)
		}
		return nil
	}
	// Proactively rotate the per-peer key before a nonce could be reused under
	// this key. Two independent triggers, each a single atomic load; the actual
	// re-handshake is fire-and-forget and guarded per-peer so it cannot spam.
	//
	//  1. LOGICAL-FRAME budget: the AEAD nonce is derived from the frame
	//     header's 32-bit structured counter field, which is now PER-PEER (see
	//     tx_seq.go) and split into two halves — logical frames in [1, 2^31),
	//     fragment envelopes in [2^31, 2^32). negotiatedAtSeq anchors this
	//     delta, so the key rotates before either half could wrap and reuse a
	//     (key, nonce) pair.
	//  2. PER-PEER wire-frame count: counts every physical frame sealed to this
	//     peer (fragments included), which is the exact number of nonces spent
	//     under this key and therefore the tighter of the two signals.
	var nonceBudgetDelta uint64
	if n.Packer != nil {
		if delta := n.txFrameCounter(p) - po.negotiatedAtSeq; delta > obfRekeyFrameThreshold {
			log.Debug("Tx: proactive re-key (logical-frame counter) triggered for %s (counter delta=%d > threshold=%d); re-handshaking in background",
				p.String(), delta, obfRekeyFrameThreshold)
			nonceBudgetDelta = delta
			n.triggerPeerRekey(p)
		}
	}
	perPeerBudget := po.framesSinceRekey.Load()
	if perPeerBudget > obfRekeyFrameThreshold {
		log.Debug("Tx: proactive re-key (per-peer frame count) triggered for %s (framesSinceRekey=%d > threshold=%d); re-handshaking in background",
			p.String(), perPeerBudget, obfRekeyFrameThreshold)
		n.triggerPeerRekey(p)
	}
	// R10: Hard stop when the nonce budget is exhausted and a re-key is
	// in flight. Returning nil causes the caller to send the frame in
	// plaintext rather than reusing a (key, nonce) pair under the
	// current key. The re-key completes asynchronously and the next
	// frame will be encrypted with a fresh key/nonce.
	//
	// The gate must mirror BOTH triggers above: the structured counter field is
	// per-peer but split into two halves (logical frames / fragments), so each
	// half can wrap independently of framesSinceRekey.
	if nonceBudgetDelta > obfRekeyFrameThreshold || perPeerBudget > obfRekeyFrameThreshold {
		if _, rekeying := n.rekeyPeers.Load(p); rekeying {
			log.Debug("Tx: nonce budget exhausted for %s; re-key in flight — dropping encryption for this frame", p.String())
			return nil
		}
	}
	// PERF: guarded by IsDebug() on purpose. Go evaluates arguments at the CALL
	// SITE, so without this guard every frame pays peer.String() (base58, ~930ns)
	// + KeyFingerprint() (SHA-256+hex) even when debug logging is suppressed —
	// ~2.9us and 8 allocations per frame purely for diagnostics. Do NOT "simplify"
	// this back to a bare log.Debug call.
	if log.IsDebug() {
		log.Debug("Tx: encrypting to %s with algo=%s forward-secret=%v txKeyFP=%s",
			p.String(), obfuscate.AlgoName(po.algo), po.pfsPubKey != nil, obfuscate.KeyFingerprint(po.txKey))
	}
	return po.txCipher
}

// triggerPeerRekey schedules a background SeqSync re-handshake for peer p to
// rotate its per-peer AEAD key before the structured nonce counter wraps under
// the current key. It is a no-op if a re-key is already in flight for that
// peer, and silently does nothing if the peer is disconnected.
func (n *Node) triggerPeerRekey(p peer.ID) {
	if !n.hasPeerConnection(p) && n.relayHopForTarget(p) == "" {
		return
	}
	if n.isResyncLeader(p) {
		// LEADER: own the single handshake round for this peer pair.
		if _, busy := n.rekeyPeers.LoadOrStore(p, struct{}{}); busy {
			return
		}
		go func() {
			defer n.rekeyPeers.Delete(p)
			log.Debug("SeqSync: starting re-key loop for %s (iAmResyncLeader=%v) — driving handshake to break any decrypt-fail deadlock", p.String(), n.isResyncLeader(p))
			consecutiveFailures := 0
			for {
				if !n.hasPeerConnection(p) &&
					n.relayHopForTarget(p) == "" {
					return
				}
				attemptStarted := time.Now()
				err := n.SyncSeqToPeer(p)
				if err == nil {
					log.Info("SeqSync: rotated/anchored encryption key with %s (re-key converged)", p.String())
					n.lastRekeySuccess.Store(p, time.Now())
					n.clearRelayControlFailure(p)
					return
				}
				consecutiveFailures++
				n.recordRelayControlFailure(p, err)
				retryDelay := 5 * time.Second
				if n.peerHasCircuitRelayConn(p) || n.relayHopForTarget(p) != "" {
					retryDelay = 3 * time.Second * time.Duration(1<<min(consecutiveFailures-1, 5))
					if retryDelay > 2*time.Minute {
						retryDelay = 2 * time.Minute
					}
				}
				pathState := "transport connection present"
				if n.Host.Network().Connectedness(p) == network.NotConnected {
					pathState = "relay route known but not verified"
				}
				if cooldown := n.relayPermissionCooldownRemaining(p); cooldown > retryDelay {
					retryDelay = cooldown
					pathState = "relay permission-denial cooldown active"
				}
				log.Warn("SeqSync: re-key to %s failed after %v: %v; next attempt in %v (%s)",
					p.String(), time.Since(attemptStarted).Round(time.Millisecond), err, retryDelay, pathState)
				select {
				case <-n.ctx.Done():
					return
				case <-time.After(retryDelay):
				}
			}
		}()
		return
	}
	// FOLLOWER: nudge leader to initiate. rekeyPeers is still registered here,
	// because R10 above keys off it to stop encrypting past the nonce budget:
	// a re-key IS in flight from this node's point of view (the nudge plus the
	// escalation below), so without the flag a follower could keep sealing
	// frames under an exhausted nonce budget indefinitely — only the leader's
	// branch used to set it. Whoever owns the escalation deletes the flag when
	// the round resolves, so the nudge owner and the flag owner may differ.
	n.sendRekeyRequest(p)
	n.rekeyPeers.Store(p, struct{}{})
	if _, pending := n.rekeyEscalation.LoadOrStore(p, struct{}{}); !pending {
		go func() {
			defer n.rekeyEscalation.Delete(p)
			defer n.rekeyPeers.Delete(p)
			select {
			case <-n.ctx.Done():
				return
			case <-time.After(10 * time.Second):
			}
			if !n.hasPeerConnection(p) {
				return
			}
			if n.isPeerReady(p) {
				return
			}
			log.Warn("SeqSync: follower rekeyReq to leader for %s did not converge in 10s; escalating to self-initiated handshake (NAT fallback)", p.String())
			if err := n.SyncSeqToPeer(p); err != nil {
				n.recordRelayControlFailure(p, err)
			} else {
				n.clearRelayControlFailure(p)
			}
		}()
	}
}

// sendRekeyRequest sends a lightweight rekeyReq nudge to the leader for peer p.
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
		s, err := n.openControlStream(ctx, p, SeqSyncProtocolID)
		if err != nil {
			return
		}
		defer s.Close()
		_ = s.SetDeadline(time.Now().Add(5 * time.Second))
		// rekeyReq is a control nudge with no ObfPub, so buildSeqSyncMsg leaves
		// it unsigned (HandshakeVer=0). It drives a full re-key round on the
		// leader, so sign it here to bind the nudge to the follower's identity —
		// the leader then rejects a forged nudge from any peer that can open a
		// stream instead of burning an ECDH round.
		req := n.buildSeqSyncMsg("rekeyReq", p, nil)
		if err := n.signSeqSyncMsg(&req); err != nil {
			log.Warn("SeqSync: cannot sign rekeyReq for %s, not sending: %v", p.String(), err)
			return
		}
		if err := writeSeqSyncMsg(s, req); err != nil {
			return
		}
		_, _ = readSeqSyncMsg(s)
	}()
}

// obfDecryptCipherForPeer returns the per-peer cipher used to DECRYPT frames
// received FROM the given peer (the RX direction).
func (n *Node) obfDecryptCipherForPeer(p peer.ID) obfuscate.ObfCipher {
	po := n.peerObf(p)
	if po == nil || !po.negotiated {
		log.Debug("Rx: NO negotiated cipher for %s — frame will be treated as PLAINTEXT", p.String())
		return nil
	}
	// PERF: see the IsDebug() note in obfCipherForPeer — this is the RX twin on
	// the per-frame path and must stay guarded.
	if log.IsDebug() {
		log.Debug("Rx: will decrypt from %s with algo=%s forward-secret=%v rxKeyFP=%s",
			p.String(), obfuscate.AlgoName(po.algo), po.pfsPubKey != nil, obfuscate.KeyFingerprint(po.rxKey))
	}
	return po.rxCipher
}

// decryptPeerFrame attempts per-peer payload decryption.
//
// scratch is an optional caller-owned reusable buffer for the decrypted
// plaintext (per-frame hot paths pass one so steady-state frames cost zero
// allocations; nil restores the allocating behaviour). The returned slice may
// alias a grown scratch — hot-path callers re-base their scratch on the return
// value and must not let it outlive the current frame-processing iteration
// without copying (fragment reassembly copies internally, so it is safe).
func (n *Node) decryptPeerFrame(scratch []byte, data []byte, remotePeer peer.ID) (out []byte, decrypted bool, garbage bool) {
	cipher := n.obfDecryptCipherForPeer(remotePeer)
	if cipher == nil {
		log.Debug("Rx: decrypt skipped for %s (no cipher); assuming frame is plaintext", remotePeer.String())
		return data, false, false
	}
	dec, derr := obfuscate.DecryptPayloadRegionInto(scratch[:0], data, cipher)
	if derr != nil {
		if errors.Is(derr, obfuscate.ErrFrameCorrupted) {
			log.Debug("Rx: frame from %s is not a well-formed obfuscate frame (%v) — structural, not a key failure; skipping resync",
				remotePeer.String(), derr)
			return data, false, false
		}
		if po := n.peerObf(remotePeer); po != nil {
			for i := len(po.rxRing) - 1; i >= 0; i-- {
				slot := po.rxRing[i]
				if dec2, derr2 := obfuscate.DecryptPayloadRegion(data, slot.cipher); derr2 == nil {
					// PERF: during a rollover EVERY frame can land on the ring
					// fallback, so this is a per-frame path — keep it guarded.
					if log.IsDebug() {
						log.Debug("Rx: decrypted from %s with RING rxKeyFP=%s (currentRxKeyFP=%s) — peer still sealing with a prior-gen / other-connection key; link tolerated",
							remotePeer.String(), obfuscate.KeyFingerprint(slot.key), obfuscate.KeyFingerprint(po.rxKey))
					}
					n.recordPeerRxDecrypt(remotePeer, true)
					n.maybeMarkReadyOnDecrypt(remotePeer, true)
					return dec2, true, false
				}
			}
			if po.prevRxCipher != nil {
				if dec2, derr2 := obfuscate.DecryptPayloadRegion(data, po.prevRxCipher); derr2 == nil {
					// PERF: rollover path, per-frame while the peer still seals
					// with the old generation — keep guarded.
					if log.IsDebug() {
						log.Debug("Rx: decrypted from %s with PREVIOUS rxKeyFP=%s (currentRxKeyFP=%s) — peer still sealing with old gen during rollover; link tolerated",
							remotePeer.String(), obfuscate.KeyFingerprint(po.prevRxKey), obfuscate.KeyFingerprint(po.rxKey))
					}
					n.recordPeerRxDecrypt(remotePeer, true)
					n.maybeMarkReadyOnDecrypt(remotePeer, true)
					return dec2, true, false
				}
			}
		}
		// PERF: guarded because this is the decrypt-FAILURE storm path — during a
		// key divergence every frame lands here, and it costs a fmt.Sprintf plus
		// NonceHex + peer.String on top of the AEAD open.
		if log.IsDebug() {
			fallbackNote := ""
			if po := n.peerObf(remotePeer); po != nil && (po.prevRxCipher != nil || len(po.rxRing) > 0) {
				fallbackNote = fmt.Sprintf(" (ring=%d prevRxCipher staged but did not open — fundamentally divergent key)", len(po.rxRing))
			} else {
				fallbackNote = " (no fallback — lingering old-connection frame or divergent key)"
			}
			log.Debug("Rx: decrypt FAILED for %s algo=%s nonce=%s (ciphertext ⇒ DROP, never forwarded as plaintext)%s",
				remotePeer.String(), obfuscate.AlgoName(cipher.Algo()), obfuscate.NonceHex(data), fallbackNote)
		}
		return data, false, true
	}
	n.recordPeerRxDecrypt(remotePeer, true)
	n.maybeMarkReadyOnDecrypt(remotePeer, true)
	// PERF: per-frame RX success path — must stay guarded (see obfCipherForPeer).
	if log.IsDebug() {
		log.Debug("Rx: decrypted frame from %s algo=%s nonce=%s", remotePeer.String(), obfuscate.AlgoName(cipher.Algo()), obfuscate.NonceHex(data))
	}
	return dec, true, false
}

// maybeResyncPeer arms the SeqSync re-handshake once a per-peer failure counter
// crosses its threshold. It returns false when it deliberately did NOT fire, so
// a caller can stay quiet; true when it scheduled the re-handshake.
//
// Decrypt failures and dedup-desync failures are counted separately because they
// are different failure modes, but both are healed by the same action — a fresh
// SeqSync re-anchors ciphers AND dedup epochs on both ends — so they share this
// threshold state machine instead of each growing one.
func (n *Node) maybeResyncPeer(errs *sync.Map, remotePeer peer.ID) bool {
	const (
		threshold     = 16
		cooldown      = 30 * time.Second
		settleWindow  = 90 * time.Second
		escalationCap = 64
	)
	rv, ok := errs.Load(remotePeer)
	if !ok {
		return false
	}
	cnt := rv.(*atomic.Uint64)
	if cnt.Load() < threshold {
		return false
	}
	if t, ok := n.lastRekeySuccess.Load(remotePeer); ok {
		if since := time.Since(t.(time.Time)); since < settleWindow && cnt.Load() < escalationCap {
			return false
		}
	}
	if t, loaded := n.decryptResyncCooldown.LoadOrStore(remotePeer, time.Now()); loaded {
		if time.Since(t.(time.Time)) < cooldown {
			return false
		}
		n.decryptResyncCooldown.Store(remotePeer, time.Now())
	}
	return true
}

// maybeResyncOnDecryptFail triggers a background SeqSync re-handshake when a
// peer's decryption failures accumulate.
func (n *Node) maybeResyncOnDecryptFail(remotePeer peer.ID) {
	rv, ok := n.peerRxDecryptRecentErrs.Load(remotePeer)
	if !ok || !n.maybeResyncPeer(&n.peerRxDecryptRecentErrs, remotePeer) {
		return
	}
	log.Info("Rx: %s has %d sustained decryption failures — triggering SeqSync re-handshake to re-anchor keys",
		remotePeer.String(), rv.(*atomic.Uint64).Load())
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

// maybeResyncOnDedupDesync is the dedup-side twin of maybeResyncOnDecryptFail.
//
// A frame rejected by the dedup window for a STALE EPOCH looks healthy to every
// other subsystem: it decrypted cleanly (so recordPeerRxDecrypt recorded a
// success and may even have reset the decrypt-fail counter), it arrived on a
// live stream (so notePeerRx marked the peer reachable), and the ping/pong
// liveness probe rides a plaintext echo that bypasses the encrypted data plane
// entirely. Until now the ONLY observer of a dedup desync was this counter, and
// nothing read it — so a sender whose epoch drifted from the window we anchored
// was silently dropping every one of our frames, in one direction only, with no
// error anywhere and no recovery. This makes that signal actionable.
func (n *Node) maybeResyncOnDedupDesync(remotePeer peer.ID) {
	rv, ok := n.peerDedupDesyncErrs.Load(remotePeer)
	if !ok || !n.maybeResyncPeer(&n.peerDedupDesyncErrs, remotePeer) {
		return
	}
	log.Info("Rx: %s has %d sustained dedup desyncs (frames we can decrypt but must drop) — triggering SeqSync re-handshake to re-anchor epochs",
		remotePeer.String(), rv.(*atomic.Uint64).Load())
	go n.ForceSyncSeq(remotePeer)
}

// storePeerObf upserts a peer's obfuscation state via copy-on-write.
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
