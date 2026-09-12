package node

import (
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"p2ptap/pkg/config"
	"p2ptap/pkg/obfuscate"
	vswitch "p2ptap/pkg/switch"
)

// TestRelayPSKFailClosedGate locks the P1 security fix: in a PSK network, a
// relayed frame from an origin we have NOT negotiated an end-to-end cipher with
// must be dropped at the deliverRelayedFrameToTAP choke point (never recorded as
// return-path liveness, never sunk to the TAP) — otherwise a non-PSK peer could
// inject plaintext via a relay hop even though the direct path is gated.
func TestRelayPSKFailClosedGate(t *testing.T) {
	origin := peer.ID("psk-origin-peer")
	boot := peer.ID("boot-hop")

	newNode := func(psk string) *Node {
		n := &Node{
			Config:             &config.Config{PSK: psk},
			MACTable:           vswitch.NewMACTable(),
			Collector:          noopCollector{},
			bootRelayConns:     make(map[peer.ID]*bootRelayConn),
			bootRelayBlacklist: make(map[peer.ID]time.Time),
			dedupPeers:         make(map[peer.ID]*obfuscate.Deduplicator),
			arpIndex:           &arpIndex{v4: make(map[uint32]arpIndexEntry), v6: make(map[[16]byte]arpIndexEntry)},
		}
		// config() reads the atomic snapshot, not the Config field — publish PSK
		// the way the runtime does so pskRequired() sees it.
		n.SetConfig(&config.Config{PSK: psk})
		return n
	}

	payload := make([]byte, 64)
	payload[12] = 0x08
	payload[13] = 0x00
	copy(payload[26:30], []byte{10, 0, 0, 88})

	// 1. PSK network, origin has NO cipher → frame must be dropped (no liveness
	//    recorded, i.e. the gate returned before notePeerRx).
	n := newNode("shared-secret")
	n.deliverRelayedFrameToTAP(payload, origin, boot, 100)
	if n.peerRxWithin(origin, 2*time.Second) {
		t.Fatal("PSK network: relayed frame from cipher-less origin must be dropped, but liveness was recorded")
	}

	// 2. Same node, now WITH a negotiated cipher for the origin → the gate opens
	//    and the frame is processed (liveness recorded).
	c, err := obfuscate.NewObfCipher(obfuscate.ObfAlgoChaCha20, make([]byte, 32))
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	tbl := map[peer.ID]*PeerObf{
		origin: {negotiated: true, txCipher: c, rxCipher: c},
	}
	n.perPeerObf.Store(&tbl)
	n.deliverRelayedFrameToTAP(payload, origin, boot, 101)
	if !n.peerRxWithin(origin, 2*time.Second) {
		t.Fatal("PSK network: relayed frame from a cipher-negotiated origin must pass the gate")
	}

	// 3. No PSK configured → gate is inert (legacy behaviour preserved).
	n2 := newNode("")
	n2.deliverRelayedFrameToTAP(payload, peer.ID("plain-origin"), boot, 200)
	if !n2.peerRxWithin(peer.ID("plain-origin"), 2*time.Second) {
		t.Fatal("PSK-less network must not drop relayed frames (gate must be inert)")
	}
}
