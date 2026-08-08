package node

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
)

const ProtocolID protocol.ID = "/p2ptap/1.0.0"

// PeerStreams manages all active P2P streams to a single remote peer
type PeerStreams struct {
	mu      sync.RWMutex
	writeMu sync.Mutex   // serializes WriteFrame calls to prevent interleaving across concurrent goroutines
	peerID  peer.ID
	streams map[string]network.Stream // TransportName -> Stream
}

func NewPeerStreams(pID peer.ID) *PeerStreams {
	return &PeerStreams{
		peerID:  pID,
		streams: make(map[string]network.Stream),
	}
}

func (ps *PeerStreams) AddStream(transportName string, s network.Stream) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	ps.streams[transportName] = s
	log.Debug("Stream registered for peer %s via %s (total: %d streams)", ps.peerID.String(), transportName, len(ps.streams))
}

func (ps *PeerStreams) RemoveStream(transportName string, stream network.Stream) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	if current, ok := ps.streams[transportName]; ok && current == stream {
		delete(ps.streams, transportName)
	}
}

func (ps *PeerStreams) GetAllStreams() []network.Stream {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	res := make([]network.Stream, 0, len(ps.streams))
	for _, s := range ps.streams {
		res = append(res, s)
	}
	return res
}

// StrategyDispatcher implements 'best_path', 'redundant', and 'fallback' transport strategies
type StrategyDispatcher struct {
	h                     host.Host
	mode                  string // "best_path", "redundant", "fallback"
	peersMu               sync.RWMutex
	peerMap               map[peer.ID]*PeerStreams
	outgoingStreamHandler func(network.Stream)
}

// SetOutgoingStreamHandler installs the reader used for locally opened
// streams. libp2p only calls the host stream handler for streams opened by a
// remote peer, so locally opened streams need this explicit reader as well.
func (sd *StrategyDispatcher) SetOutgoingStreamHandler(handler func(network.Stream)) {
	sd.outgoingStreamHandler = handler
}

func NewStrategyDispatcher(h host.Host, mode string) *StrategyDispatcher {
	return &StrategyDispatcher{
		h:       h,
		mode:    mode,
		peerMap: make(map[peer.ID]*PeerStreams),
	}
}

func (sd *StrategyDispatcher) GetOrCreatePeerStreams(pID peer.ID) *PeerStreams {
	sd.peersMu.Lock()
	defer sd.peersMu.Unlock()

	ps, exists := sd.peerMap[pID]
	if !exists {
		ps = NewPeerStreams(pID)
		sd.peerMap[pID] = ps
	}
	return ps
}

func (sd *StrategyDispatcher) RegisterStream(pID peer.ID, transportName string, s network.Stream) {
	ps := sd.GetOrCreatePeerStreams(pID)
	ps.AddStream(transportName, s)
}

func (sd *StrategyDispatcher) UnregisterStream(pID peer.ID, transportName string, s network.Stream) {
	sd.peersMu.RLock()
	ps := sd.peerMap[pID]
	sd.peersMu.RUnlock()
	if ps != nil {
		ps.RemoveStream(transportName, s)
	}
}

func (sd *StrategyDispatcher) RemovePeer(pID peer.ID) {
	sd.peersMu.Lock()
	defer sd.peersMu.Unlock()
	delete(sd.peerMap, pID)
	log.Debug("Removed peer %s from strategy dispatcher map", pID.String())
}

func (sd *StrategyDispatcher) openStream(parentCtx context.Context, targetPeer peer.ID) (*PeerStreams, network.Stream, error) {
	// Double-check if stream was opened while caller was waiting
	sd.peersMu.RLock()
	ps, exists := sd.peerMap[targetPeer]
	sd.peersMu.RUnlock()
	if exists && ps != nil {
		streams := ps.GetAllStreams()
		if len(streams) > 0 {
			return ps, streams[0], nil
		}
	}

	log.Debug("No active streams to peer %s, opening new stream...", targetPeer.String())
	ctx, cancel := context.WithTimeout(parentCtx, 8*time.Second)
	defer cancel()

	// Allow stream creation over transient / relayed connections
	streamCtx := network.WithAllowLimitedConn(ctx, "p2ptap-data")
	s, err := sd.h.NewStream(streamCtx, targetPeer, ProtocolID)
	if err != nil {
		return nil, nil, fmt.Errorf("open stream to peer %s: %w", targetPeer, err)
	}

	// Best-effort: disable Nagle/delay on the underlying connection for low-latency forwarding.
	if conn := s.Conn(); conn != nil {
		if tcpConn, ok := extractUnderlyingTCPConn(conn); ok {
			_ = tcpConn.SetNoDelay(true)
		}
	}

	transportName := s.Conn().RemoteMultiaddr().String()
	ps = sd.GetOrCreatePeerStreams(targetPeer)
	ps.AddStream(transportName, s)
	log.Debug("Opened new outgoing stream to peer %s via %s", targetPeer.String(), transportName)

	if sd.outgoingStreamHandler != nil {
		go sd.outgoingStreamHandler(s)
	}

	return ps, s, nil
}

// extractUnderlyingTCPConn unwraps libp2p transport layers to find a *net.TCPConn for NoDelay tuning.
func extractUnderlyingTCPConn(conn interface{}) (interface{ SetNoDelay(bool) error }, bool) {
	// Direct match (fast path, rare in libp2p).
	if tc, ok := conn.(interface{ SetNoDelay(bool) error }); ok {
		return tc, true
	}
	// Walk common libp2p wrapper chains via reflection-free interface probing.
	type connAccessor interface{ Conn() interface{} }
	type rawAccessor interface{ RawConn() interface{} }
	if accessor, ok := conn.(connAccessor); ok {
		inner := accessor.Conn()
		if tc, ok := inner.(interface{ SetNoDelay(bool) error }); ok {
			return tc, true
		}
		if ra, ok := inner.(rawAccessor); ok {
			if tc, ok := ra.RawConn().(interface{ SetNoDelay(bool) error }); ok {
				return tc, true
			}
		}
	}
	if accessor, ok := conn.(rawAccessor); ok {
		if tc, ok := accessor.RawConn().(interface{ SetNoDelay(bool) error }); ok {
			return tc, true
		}
	}
	return nil, false
}

// SendToPeer dispatches packed frame bytes according to the configured strategy.
// On write failure, dead streams are removed, a new stream is opened, and the write is retried once.
func (sd *StrategyDispatcher) SendToPeer(ctx context.Context, targetPeer peer.ID, packedData []byte) error {
	sd.peersMu.RLock()
	ps, exists := sd.peerMap[targetPeer]
	sd.peersMu.RUnlock()

	if !exists {
		var err error
		ps, _, err = sd.openStream(ctx, targetPeer)
		if err != nil {
			log.Debug("Failed to open stream to peer %s: %v", targetPeer.String(), err)
			return err
		}
	}

	// Serialize writes per-peer to prevent frame interleaving when multiple
	// async dispatch goroutines write to the same stream concurrently.
	ps.writeMu.Lock()
	defer ps.writeMu.Unlock()

	streams := ps.GetAllStreams()

	// Try to send with deadline and dead-stream cleanup
	writeWithDeadline := func(s network.Stream) error {
		_ = s.SetWriteDeadline(time.Now().Add(5 * time.Second))
		return WriteFrame(s, packedData)
	}

	// sendOverStreams tries each stream and returns the first success.
	// If all fail, it removes dead streams and returns the last error.
	sendOverStreams := func(streams []network.Stream, removeOnFail bool) error {
		var lastErr error
		var deadStreams []struct {
			transportName string
			stream        network.Stream
		}
		for _, s := range streams {
			if s == nil {
				continue
			}
			err := writeWithDeadline(s)
			if err == nil {
				return nil
			}
			lastErr = err
			if removeOnFail {
				var tName string
				if conn := s.Conn(); conn != nil {
					tName = conn.RemoteMultiaddr().String()
				} else {
					tName = "(disconnected)"
				}
				deadStreams = append(deadStreams, struct {
					transportName string
					stream        network.Stream
				}{tName, s})
			}
		}
		// Clean up dead streams
		for _, ds := range deadStreams {
			ps.RemoveStream(ds.transportName, ds.stream)
			log.Debug("Removed dead stream for peer %s via %s", targetPeer.String(), ds.transportName)
		}
		return lastErr
	}

	switch sd.mode {
	case "redundant":
		// Send duplicate copies over ALL active transport streams
		return sendOverStreams(streams, false) // Don't remove in redundant mode

	case "fallback":
		// Try streams sequentially until one succeeds
		fallbackErr := sendOverStreams(streams, true)
		if fallbackErr == nil {
			return nil
		}
		// After removal, try to open a fresh stream and retry
		remaining := ps.GetAllStreams()
		if len(remaining) == 0 {
			var openErr error
			ps, _, openErr = sd.openStream(ctx, targetPeer)
			if openErr != nil {
				return fmt.Errorf("fallback: %w (after %d failures, open failed)", openErr, len(streams))
			}
			remaining = ps.GetAllStreams()
		}
		if len(remaining) > 0 {
			return writeWithDeadline(remaining[0])
		}
		return fmt.Errorf("fallback: no streams available for peer %s", targetPeer.String())

	case "best_path":
		fallthrough
	default:
		// Default: best_path — send over first stream, cleanup + retry on failure
		if len(streams) == 0 {
			var err error
			ps, _, err = sd.openStream(ctx, targetPeer)
			if err != nil {
				return err
			}
			streams = ps.GetAllStreams()
		}
		if len(streams) > 0 {
			err := writeWithDeadline(streams[0])
			if err == nil {
				return nil
			}
			// Dead stream detected: remove it, open a new one, retry once
			tName := streams[0].Conn().RemoteMultiaddr().String()
			ps.RemoveStream(tName, streams[0])
			log.Debug("Removed dead best_path stream for peer %s (%v), retrying with fresh stream", targetPeer.String(), err)

			ps2, _, openErr := sd.openStream(ctx, targetPeer)
			if openErr != nil {
				return fmt.Errorf("best_path retry failed: %w (original: %v)", openErr, err)
			}
			newStreams := ps2.GetAllStreams()
			if len(newStreams) > 0 {
				return writeWithDeadline(newStreams[0])
			}
			return fmt.Errorf("best_path: no streams after retry for peer %s", targetPeer.String())
		}
		return fmt.Errorf("no streams available for peer %s", targetPeer.String())
	}
}

// SendBatchToPeer sends multiple obfuscated frames to the same target peer over a single
// stream open/close cycle, avoiding per-frame stream negotiation overhead.
// The caller has already grouped frames by target, so we only need one stream.
func (sd *StrategyDispatcher) SendBatchToPeer(ctx context.Context, targetPeer peer.ID, packedFrames [][]byte) error {
	if len(packedFrames) == 0 {
		return nil
	}
	// Open one stream for the whole batch.
	_, s, err := sd.openStream(ctx, targetPeer)
	if err != nil {
		return fmt.Errorf("open batch stream to peer %s: %w", targetPeer, err)
	}
	defer s.Close()

	for i, data := range packedFrames {
		if err := WriteFrame(s, data); err != nil {
			return fmt.Errorf("batch write frame %d/%d to %s: %w", i+1, len(packedFrames), targetPeer, err)
		}
	}
	return nil
}

// BroadcastToAllPeers floods packed frame bytes to all connected VPN peers
// (ignores Bootstrap nodes) using parallel fan-out.  Each peer gets its own
// goroutine with a per-peer deadline so one slow/stuck peer never blocks the
// entire broadcast wave.
func (sd *StrategyDispatcher) BroadcastToAllPeers(ctx context.Context, packedData []byte) {
	peerIDs := collectBroadcastPeers(sd)

	if len(peerIDs) == 0 {
		return
	}

	log.Debug("Broadcasting to %d active P2P peers (parallel fan-out)", len(peerIDs))

	// Per-peer deadline: broadcast frames are time-sensitive; if a peer can't
	// accept the frame within 5s the frame is stale anyway.
	perPeerCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	for pID := range peerIDs {
		wg.Add(1)
		go func(p peer.ID) {
			defer wg.Done()
			if err := sd.sendToPeerFast(perPeerCtx, p, packedData); err != nil {
				log.Debug("P2P broadcast write to peer %s failed: %v", p.String(), err)
			}
		}(pID)
	}
	wg.Wait()
}

// BroadcastBatchToAllPeers floods multiple packed frames to all connected
// VPN peers in a single fan-out pass.  Peer list is collected once (unlike
// calling BroadcastToAllPeers N times).  Each peer gets all frames on its
// active stream; if a write fails the remaining frames for that peer are
// skipped.
func (sd *StrategyDispatcher) BroadcastBatchToAllPeers(ctx context.Context, packedFrames [][]byte) {
	if len(packedFrames) == 0 {
		return
	}
	peerIDs := collectBroadcastPeers(sd)
	if len(peerIDs) == 0 {
		return
	}

	log.Debug("Broadcasting batch (%d frames) to %d active P2P peers", len(packedFrames), len(peerIDs))

	perPeerCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	for pID := range peerIDs {
		wg.Add(1)
		go func(p peer.ID) {
			defer wg.Done()
			for _, data := range packedFrames {
				if err := sd.sendToPeerFast(perPeerCtx, p, data); err != nil {
					log.Debug("P2P broadcast batch write to peer %s failed: %v", p.String(), err)
					return // stop sending to this peer on first error
				}
			}
		}(pID)
	}
	wg.Wait()
}

// collectBroadcastPeers returns the set of peers to which broadcast frames
// should be delivered.  Peers that are not currently connected (or do not
// advertise the P2P TAP protocol) are excluded.
func collectBroadcastPeers(sd *StrategyDispatcher) map[peer.ID]bool {
	peerIDs := make(map[peer.ID]bool)

	// Phase 1: peers that already have active P2P streams.
	sd.peersMu.Lock()
	for pID := range sd.peerMap {
		if sd.h.Network().Connectedness(pID) == network.Connected {
			peerIDs[pID] = true
		} else {
			delete(sd.peerMap, pID)
		}
	}
	sd.peersMu.Unlock()

	// Phase 2: peers that are connected but haven't opened a stream yet,
	// provided they support the P2P TAP protocol (excludes bootstrap/crawlers).
	for _, pID := range sd.h.Network().Peers() {
		if peerIDs[pID] {
			continue
		}
		if sd.h.Network().Connectedness(pID) != network.Connected {
			continue
		}
		protocols, err := sd.h.Peerstore().GetProtocols(pID)
		if err != nil {
			continue
		}
		for _, p := range protocols {
			if p == ProtocolID {
				peerIDs[pID] = true
				break
			}
		}
	}
	return peerIDs
}

// sendToPeerFast writes a frame to the best available stream for the given
// peer.  If no stream exists it falls back to SendToPeer which lazily opens a
// stream.  Broadcast fan-out runs each peer in its own goroutine so one slow
// peer never stalls the entire wave.
func (sd *StrategyDispatcher) sendToPeerFast(ctx context.Context, targetPeer peer.ID, packedData []byte) error {
	sd.peersMu.RLock()
	ps, exists := sd.peerMap[targetPeer]
	sd.peersMu.RUnlock()

	if exists && ps != nil {
		streams := ps.GetAllStreams()
		if len(streams) > 0 {
			_ = streams[0].SetWriteDeadline(time.Now().Add(5 * time.Second))
			return WriteFrame(streams[0], packedData)
		}
	}

	// No existing stream for this peer (Phase-2 broadcast target).
	// Open a stream lazily with a tight deadline so the broadcast wave
	// isn't held up.  Direct connections complete within 2-3 s; relay
	// peers that haven't opened a stream yet are unlikely to receive
	// time-sensitive broadcast frames in time anyway.
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	return sd.SendToPeer(ctx, targetPeer, packedData)
}