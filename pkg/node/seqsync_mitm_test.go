package node

import (
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/network"

	"p2ptap/pkg/obfuscate"
	"p2ptap/pkg/tap"
)

// TestSeqSyncRefusesMitmKeySubstitution is the end-to-end regression for the
// relay-ctrl key-exchange MITM: a transit hop that authenticates cleanly to both
// sides (libp2p transports it, and the origin stamp covers the header claim)
// substitutes ITS OWN ephemeral ECDH key for each side's ObfPub, stripping the
// signature and the HandshakeVer marker so the reply looks like an older peer's
// unsigned exchange. Without authenticated key exchange that hop ends up on two
// separate sessions it can both decrypt.
//
// The guard is the identity signature on ObfPub: the hop holds neither side's
// libp2p identity private key, so it cannot produce an accepted signature, and
// the cipher must therefore never be committed.
//
// The assertion is deliberately transport-independent — the guard sits inside
// SeqSync, not in the relay layer — so driving it against a directly-connected
// malicious responder exercises the identical code path a relay hop would reach.
func TestSeqSyncRefusesMitmKeySubstitution(t *testing.T) {
	// The hop's own ephemeral key, substituted for the victim's.
	attackerKp, err := obfuscate.GenerateObfKeyPair()
	if err != nil {
		t.Fatalf("generate attacker ephemeral: %v", err)
	}
	attackerPub, err := attackerKp.PublicKeyBytes()
	if err != nil || len(attackerPub) == 0 {
		t.Fatalf("serialise attacker ephemeral pubkey")
	}

	// Malicious responder: it answers the handshake, offers its own key, and
	// completes the round so the victim cannot tell the substitution apart from
	// a merely lossy relay.
	mHost, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatalf("create malicious responder: %v", err)
	}
	defer func() { _ = mHost.Close() }()
	mHost.SetStreamHandler(SeqSyncProtocolID, func(s network.Stream) {
		defer s.Close()
		_ = s.SetDeadline(time.Now().Add(10 * time.Second))
		// Consume the victim's (correctly signed) sync.
		_, _ = readSeqSyncMsg(s)
		// The substitution: our key, no signature, no version advertised.
		ack := SeqSyncMsg{
			Type:       "ack",
			NodeID:     mHost.ID().String(),
			MySeq:      1,
			ConnEpoch:  7,
			Timestamp:  time.Now().UnixMilli(),
			ObfEnabled: true,
			ObfAlgos:   []byte{obfuscate.ObfAlgoChaCha20},
			ObfPub:     attackerPub,
			// HandshakeVer: 0 — the downgrade that makes this look legacy.
			// ObfPubSig / ObfPubSignerPub deliberately absent.
		}
		if err := writeSeqSyncMsg(s, ack); err != nil {
			return
		}
		_, _ = readSeqSyncMsg(s) // the victim's "ready"
		_ = writeSeqSyncMsg(s, SeqSyncMsg{Type: "ready", NodeID: mHost.ID().String()})
	})

	// The victim, with the strict flag on so a non-signing peer is refused
	// rather than silently accepted as legacy.
	tapA, _ := tap.NewMemTAPPair("tapA", "pipeA")
	cfgA := createTestNodeConfig("10.0.0.1/24", "fd00::1/64", "best_path")
	cfgA.Obfuscation.RequireAuthKeyExchange = true
	aNode, err := NewNodeWithTAP(cfgA, tapA, nil)
	if err != nil {
		t.Fatalf("create victim node: %v", err)
	}
	defer aNode.Close()
	aNode.Start()

	ti := mHost.Peerstore().PeerInfo(mHost.ID())
	ti.Addrs = mHost.Addrs()
	if err := aNode.Host.Connect(aNode.ctx, ti); err != nil {
		t.Fatalf("connect victim -> malicious responder: %v", err)
	}

	// One handshake attempt: it must fail, and must leave no cipher behind.
	if err := aNode.syncSeqToPeerAttempt(mHost.ID()); err == nil {
		t.Fatal("a key-substituting responder must not complete the handshake")
	}
	if po := aNode.peerObf(mHost.ID()); po != nil && po.negotiated {
		t.Fatal("a cipher must NOT be committed from a substituted ObfPub")
	}

	// No key material derived from the attacker's substituted key.
	if po := aNode.peerObf(mHost.ID()); po != nil {
		if len(po.txKey) > 0 || len(po.rxKey) > 0 {
			t.Fatalf("the victim derived key material from the attacker's substituted key (tx=%s rx=%s)",
				obfuscate.KeyFingerprint(po.txKey), obfuscate.KeyFingerprint(po.rxKey))
		}
	}
	t.Log("✓ key-substituting (unsigned, downgraded) responder refused; no cipher committed")
}

// TestSeqSyncAcceptsLegitimatelySignedKeyExchange is the positive control for
// the same harness: a responder that signs its offered key with its own libp2p
// identity key completes the handshake and the cipher is committed. Together
// with TestSeqSyncRefusesMitmKeySubstitution this pins the exact boundary:
// the deciding factor is the signature, not the transport.
func TestSeqSyncAcceptsLegitimatelySignedKeyExchange(t *testing.T) {
	hKp, err := obfuscate.GenerateObfKeyPair()
	if err != nil {
		t.Fatalf("generate responder ephemeral: %v", err)
	}
	hPub, err := hKp.PublicKeyBytes()
	if err != nil || len(hPub) == 0 {
		t.Fatalf("serialise responder ephemeral pubkey")
	}

	hHost, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatalf("create honest responder: %v", err)
	}
	defer func() { _ = hHost.Close() }()
	hHost.SetStreamHandler(SeqSyncProtocolID, func(s network.Stream) {
		defer s.Close()
		_ = s.SetDeadline(time.Now().Add(10 * time.Second))
		_, _ = readSeqSyncMsg(s)
		// Sign the offered key with this host's own identity key.
		sig, signerPub, serr := signObfPubWith(hHost.Peerstore().PrivKey(hHost.ID()), hPub)
		if serr != nil {
			t.Errorf("honest responder could not sign: %v", serr)
			return
		}
		ack := SeqSyncMsg{
			Type:            "ack",
			NodeID:          hHost.ID().String(),
			MySeq:           1,
			ConnEpoch:       7,
			Timestamp:       time.Now().UnixMilli(),
			ObfEnabled:      true,
			ObfAlgos:        []byte{obfuscate.ObfAlgoChaCha20},
			ObfPub:          hPub,
			HandshakeVer:    seqSyncAuthVersion,
			ObfPubSig:       sig,
			ObfPubSignerPub: signerPub,
		}
		if err := writeSeqSyncMsg(s, ack); err != nil {
			return
		}
		_, _ = readSeqSyncMsg(s)
		_ = writeSeqSyncMsg(s, SeqSyncMsg{Type: "ready", NodeID: hHost.ID().String()})
	})

	tapA, _ := tap.NewMemTAPPair("tapA", "pipeA")
	cfgA := createTestNodeConfig("10.0.0.1/24", "fd00::1/64", "best_path")
	cfgA.Obfuscation.RequireAuthKeyExchange = true
	aNode, err := NewNodeWithTAP(cfgA, tapA, nil)
	if err != nil {
		t.Fatalf("create node: %v", err)
	}
	defer aNode.Close()
	aNode.Start()

	ti := hHost.Peerstore().PeerInfo(hHost.ID())
	ti.Addrs = hHost.Addrs()
	if err := aNode.Host.Connect(aNode.ctx, ti); err != nil {
		t.Fatalf("connect: %v", err)
	}

	if err := aNode.syncSeqToPeerAttempt(hHost.ID()); err != nil {
		t.Fatalf("a legitimately signed key exchange must complete: %v", err)
	}
	if po := aNode.peerObf(hHost.ID()); po == nil || !po.negotiated {
		t.Fatal("the cipher must be committed from a validly signed key exchange")
	}
	t.Log("✓ legitimately signed key exchange accepted and cipher committed")
}

// TestSeqSyncLegacyPeerStillAcceptedWithAuthRequiredOff pins the mixed-fleet
// rollout contract: with the flag off (the default), a peer that cannot sign is
// still accepted, so upgrading a mesh peer-by-peer never strands the peers that
// have not been upgraded yet.
func TestSeqSyncLegacyPeerStillAcceptedWithAuthRequiredOff(t *testing.T) {
	lKp, err := obfuscate.GenerateObfKeyPair()
	if err != nil {
		t.Fatalf("generate ephemeral: %v", err)
	}
	lPub, err := lKp.PublicKeyBytes()
	if err != nil || len(lPub) == 0 {
		t.Fatalf("serialise ephemeral pubkey")
	}

	lHost, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatalf("create legacy responder: %v", err)
	}
	defer func() { _ = lHost.Close() }()
	lHost.SetStreamHandler(SeqSyncProtocolID, func(s network.Stream) {
		defer s.Close()
		_ = s.SetDeadline(time.Now().Add(10 * time.Second))
		_, _ = readSeqSyncMsg(s)
		// An older build: offers a key, has no auth fields at all.
		if err := writeSeqSyncMsg(s, SeqSyncMsg{
			Type: "ack", NodeID: lHost.ID().String(), MySeq: 1, ConnEpoch: 7,
			Timestamp: time.Now().UnixMilli(), ObfEnabled: true,
			ObfAlgos: []byte{obfuscate.ObfAlgoChaCha20}, ObfPub: lPub,
		}); err != nil {
			return
		}
		_, _ = readSeqSyncMsg(s)
		_ = writeSeqSyncMsg(s, SeqSyncMsg{Type: "ready", NodeID: lHost.ID().String()})
	})

	tapA, _ := tap.NewMemTAPPair("tapA", "pipeA")
	cfgA := createTestNodeConfig("10.0.0.1/24", "fd00::1/64", "best_path")
	// RequireAuthKeyExchange stays false (the default).
	aNode, err := NewNodeWithTAP(cfgA, tapA, nil)
	if err != nil {
		t.Fatalf("create node: %v", err)
	}
	defer aNode.Close()
	aNode.Start()

	ti := lHost.Peerstore().PeerInfo(lHost.ID())
	ti.Addrs = lHost.Addrs()
	if err := aNode.Host.Connect(aNode.ctx, ti); err != nil {
		t.Fatalf("connect: %v", err)
	}

	if err := aNode.syncSeqToPeerAttempt(lHost.ID()); err != nil {
		t.Fatalf("a legacy peer must still be accepted with the flag off: %v", err)
	}
	if po := aNode.peerObf(lHost.ID()); po == nil || !po.negotiated {
		t.Fatal("a legacy peer must still negotiate a cipher with the flag off")
	}
	// And the peer must NOT be pinned to the sticky requirement it can never meet.
	if _, ok := aNode.obfAuthSticky.Load(lHost.ID()); ok {
		t.Fatal("accepting a legacy peer must not set the sticky requirement")
	}
	t.Log("✓ legacy peer accepted with the flag off, and not pinned to the requirement")
}
