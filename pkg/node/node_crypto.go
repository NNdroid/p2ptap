package node

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"p2ptap/pkg/obfuscate"
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
	if n.Host.Network().Connectedness(p) != network.Connected && n.relayHopForTarget(p) == "" {
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
			for {
				if n.Host.Network().Connectedness(p) != network.Connected &&
					n.relayHopForTarget(p) == "" {
					return
				}
				if err := n.SyncSeqToPeer(p); err == nil {
					log.Info("SeqSync: rotated/anchored encryption key with %s (re-key converged)", p.String())
					n.lastRekeySuccess.Store(p, time.Now())
					return
				}
				retryDelay := 5 * time.Second
				if n.peerHasCircuitRelayConn(p) || n.relayHopForTarget(p) != "" {
					retryDelay = 3 * time.Second
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
	// FOLLOWER: nudge leader to initiate
	n.sendRekeyRequest(p)
	if _, pending := n.rekeyEscalation.LoadOrStore(p, struct{}{}); !pending {
		go func() {
			defer n.rekeyEscalation.Delete(p)
			select {
			case <-n.ctx.Done():
				return
			case <-time.After(10 * time.Second):
			}
			if n.Host.Network().Connectedness(p) != network.Connected {
				return
			}
			if n.isPeerReady(p) {
				return
			}
			log.Warn("SeqSync: follower rekeyReq to leader for %s did not converge in 10s; escalating to self-initiated handshake (NAT fallback)", p.String())
			_ = n.SyncSeqToPeer(p)
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
		if err := writeSeqSyncMsg(s, n.buildSeqSyncMsg("rekeyReq", p, nil)); err != nil {
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
func (n *Node) decryptPeerFrame(data []byte, remotePeer peer.ID) (out []byte, decrypted bool, garbage bool) {
	cipher := n.obfDecryptCipherForPeer(remotePeer)
	if cipher == nil {
		log.Debug("Rx: decrypt skipped for %s (no cipher); assuming frame is plaintext", remotePeer.String())
		return data, false, false
	}
	dec, derr := obfuscate.DecryptPayloadRegion(data, cipher)
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

// maybeResyncOnDecryptFail triggers a background SeqSync re-handshake when a
// peer's decryption failures accumulate.
func (n *Node) maybeResyncOnDecryptFail(remotePeer peer.ID) {
	const (
		threshold     = 16
		cooldown      = 30 * time.Second
		settleWindow  = 90 * time.Second
		escalationCap = 64
	)
	rv, ok := n.peerRxDecryptRecentErrs.Load(remotePeer)
	if !ok {
		return
	}
	if v := rv.(*atomic.Uint64).Load(); v < threshold {
		return
	}
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
