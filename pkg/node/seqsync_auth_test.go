package node

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"testing"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"

	"p2ptap/pkg/config"
)

// genIdentity mints an Ed25519 identity key pair and returns it with the peer
// ID it implies (libp2p PeerIDs ARE the public keys).
func genIdentity(t *testing.T) (crypto.PrivKey, peer.ID) {
	t.Helper()
	priv, _, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 identity: %v", err)
	}
	id, err := peer.IDFromPublicKey(priv.GetPublic())
	if err != nil {
		t.Fatalf("derive peer id: %v", err)
	}
	return priv, id
}

// peerIDOf returns the peer ID implied by an identity key.
func peerIDOf(t *testing.T, priv crypto.PrivKey) peer.ID {
	t.Helper()
	id, err := peer.IDFromPublicKey(priv.GetPublic())
	if err != nil {
		t.Fatalf("derive peer id: %v", err)
	}
	return id
}

// signedMsg builds a SeqSyncMsg carrying an identity-signed ObfPub from signer.
func signedMsg(t *testing.T, signer crypto.PrivKey, obfPub []byte) SeqSyncMsg {
	t.Helper()
	sig, signerPub, err := signObfPubWith(signer, obfPub)
	if err != nil {
		t.Fatalf("signObfPubWith: %v", err)
	}
	return SeqSyncMsg{
		Type:            "sync",
		NodeID:          peerIDOf(t, signer).String(),
		ObfEnabled:      true,
		ObfPub:          obfPub,
		HandshakeVer:    seqSyncAuthVersion,
		ObfPubSig:       sig,
		ObfPubSignerPub: signerPub,
	}
}

// minimalAuthNode builds the smallest Node the auth policy touches: a config
// snapshot (config() falls back to the exported Config field while the atomic
// pointer is unset) plus the zero-value sticky map. Host is nil, which skips
// the peerstore diagnostic.
func minimalAuthNode(requireAuth bool) *Node {
	cfg := config.DefaultConfig()
	cfg.Obfuscation.RequireAuthKeyExchange = requireAuth
	return &Node{Config: cfg}
}

func TestObfPubAuthRoundTrip(t *testing.T) {
	origin, originID := genIdentity(t)
	msg := signedMsg(t, origin, []byte{0x04, 0x01, 0x02, 0x03})

	if err := (&Node{}).verifyObfPubAuth(originID, msg); err != nil {
		t.Fatalf("a correctly signed key exchange must verify: %v", err)
	}
}

func TestObfPubAuthRejectsTamperedKey(t *testing.T) {
	origin, originID := genIdentity(t)
	msg := signedMsg(t, origin, []byte{0x04, 0x01, 0x02, 0x03})

	// An active transit hop substitutes its own ephemeral key for the origin's.
	msg.ObfPub = append(msg.ObfPub, 0xFF)
	if err := (&Node{}).verifyObfPubAuth(originID, msg); err == nil {
		t.Fatal("a substituted (tampered) ObfPub must not verify")
	}
}

func TestObfPubAuthRejectsWrongIdentity(t *testing.T) {
	_, originID := genIdentity(t)
	attacker, _ := genIdentity(t)

	// The hop signs with its OWN identity key and offers it as the origin's.
	msg := signedMsg(t, attacker, []byte{0x04, 0x01, 0x02})
	if err := (&Node{}).verifyObfPubAuth(originID, msg); err == nil {
		t.Fatal("a key signed by a different identity must be rejected")
	}
}

func TestObfPubAuthRejectsStrippedSignature(t *testing.T) {
	origin, originID := genIdentity(t)
	msg := signedMsg(t, origin, []byte{0x04, 0x01})

	// Downgrade attempt: keep ObfPub, strip the auth fields.
	msg.ObfPubSig = nil
	msg.ObfPubSignerPub = nil
	if err := (&Node{}).verifyObfPubAuth(originID, msg); err == nil {
		t.Fatal("a signature-stripped key exchange must not verify")
	}
}

func TestObfPubAuthDomainSeparation(t *testing.T) {
	origin, originID := genIdentity(t)
	sig, signerPub, err := signObfPubWith(origin, []byte("pub-A"))
	if err != nil {
		t.Fatalf("sign pub-A: %v", err)
	}

	// A signature minted for one offered key must not validate another.
	msg := SeqSyncMsg{ObfPub: []byte("pub-B"), ObfPubSig: sig, ObfPubSignerPub: signerPub}
	if err := (&Node{}).verifyObfPubAuth(originID, msg); err == nil {
		t.Fatal("a signature over a different key must not verify (domain separation)")
	}
}

func TestObfPubAuthRequiresIdentityKeyWhenSigning(t *testing.T) {
	if _, _, err := signObfPubWith(nil, []byte{0x01}); err == nil {
		t.Fatal("signing with no identity key must fail, not silently succeed")
	}
}

func TestCheckObfPubAuthAcceptsEmptyObfPub(t *testing.T) {
	_, id := genIdentity(t)
	// "ready" and "epochSync" carry no key: nothing to authenticate.
	if err := minimalAuthNode(true).checkObfPubAuth(id, SeqSyncMsg{Type: "ready"}); err != nil {
		t.Fatalf("an empty ObfPub must not require authentication: %v", err)
	}
}

// TestCheckObfPubAuthAcceptsLegacyPeerForInterop locks the mixed-fleet
// behaviour: a peer that predates the feature offers an unsigned key with no
// version advertised, and a capable node must still accept it rather than drop
// the encrypted link.
func TestCheckObfPubAuthAcceptsLegacyPeerForInterop(t *testing.T) {
	_, id := genIdentity(t)
	n := minimalAuthNode(false)

	legacy := SeqSyncMsg{Type: "sync", ObfEnabled: true, ObfPub: []byte{0x04, 0x02}, HandshakeVer: 0}
	if err := n.checkObfPubAuth(id, legacy); err != nil {
		t.Fatalf("a legacy (unsigned, unversioned) peer must be accepted for interop: %v", err)
	}
	// Accepting a legacy peer must NOT set the sticky bit — otherwise the peer
	// would be pinned to a requirement it can never satisfy and the link would
	// die on the next handshake.
	if _, ok := n.obfAuthSticky.Load(id); ok {
		t.Fatal("accepting a legacy peer must not set the sticky requirement")
	}
	if err := n.checkObfPubAuth(id, legacy); err != nil {
		t.Fatalf("a legacy peer must keep being accepted on later handshakes: %v", err)
	}
}

// TestCheckObfPubAuthStickyClosesDowngradeWindow proves the sticky bit does its
// job: once a peer has demonstrated it can sign, it can no longer drop
// HandshakeVer and fall back to an unauthenticated key exchange on a later
// connection.
func TestCheckObfPubAuthStickyClosesDowngradeWindow(t *testing.T) {
	origin, originID := genIdentity(t)
	n := minimalAuthNode(false)

	if err := n.checkObfPubAuth(originID, signedMsg(t, origin, []byte{0x04, 0x02})); err != nil {
		t.Fatalf("a signed exchange must verify on first contact: %v", err)
	}
	if _, ok := n.obfAuthSticky.Load(originID); !ok {
		t.Fatal("a verified signature must set the sticky requirement")
	}

	downgraded := signedMsg(t, origin, []byte{0x04, 0x02})
	downgraded.HandshakeVer = 0
	downgraded.ObfPubSig = nil
	downgraded.ObfPubSignerPub = nil
	if err := n.checkObfPubAuth(originID, downgraded); err == nil {
		t.Fatal("a peer that has already signed must not be allowed to downgrade")
	}
}

// TestCheckObfPubAuthStickySurvivesConfigOff: stickiness is a property of the
// relationship with a peer, not of the current config, so it must hold even
// when the operator turns the flag off.
func TestCheckObfPubAuthStickySurvivesConfigOff(t *testing.T) {
	origin, originID := genIdentity(t)
	n := minimalAuthNode(false)

	n.markObfAuth(originID)
	downgraded := signedMsg(t, origin, []byte{0x04, 0x02})
	downgraded.ObfPubSig = nil
	downgraded.ObfPubSignerPub = nil
	if err := n.checkObfPubAuth(originID, downgraded); err == nil {
		t.Fatal("the sticky requirement must hold even with the config flag off")
	}
}

// TestCheckObfPubAuthRequireConfigForcesRequirement: with the flag on, even a
// peer that has never signed and advertises no version is refused. This is the
// only setting that closes the downgrade window on a FIRST-EVER contact.
func TestCheckObfPubAuthRequireConfigForcesRequirement(t *testing.T) {
	_, id := genIdentity(t)
	n := minimalAuthNode(true)

	legacy := SeqSyncMsg{Type: "sync", ObfEnabled: true, ObfPub: []byte{0x04, 0x02}, HandshakeVer: 0}
	if err := n.checkObfPubAuth(id, legacy); err == nil {
		t.Fatal("with RequireAuthKeyExchange, an unsigned key exchange must be refused")
	}
}

// TestCheckObfPubAuthVerifiesThenMarksSticky proves the happy path sets the
// sticky bit, so a subsequent handshake is held to the requirement.
func TestCheckObfPubAuthVerifiesThenMarksSticky(t *testing.T) {
	origin, originID := genIdentity(t)
	n := minimalAuthNode(false)

	if err := n.checkObfPubAuth(originID, signedMsg(t, origin, []byte{0x04, 0x02})); err != nil {
		t.Fatalf("signed exchange should verify: %v", err)
	}
	if _, ok := n.obfAuthSticky.Load(originID); !ok {
		t.Fatal("a successful verification must mark the peer as authenticated")
	}
	// And the same peer still verifies immediately afterwards.
	if err := n.checkObfPubAuth(originID, signedMsg(t, origin, []byte{0x04, 0x03})); err != nil {
		t.Fatalf("a second signed exchange from the same peer must verify: %v", err)
	}
}

// TestSeqSyncMsgWireCompat pins the interop contract at the serialisation
// level: a legacy payload must decode as HandshakeVer=0 with no signature (so a
// new peer takes the legacy path), and the new fields must round-trip intact.
func TestSeqSyncMsgWireCompat(t *testing.T) {
	type legacySeqSyncMsg struct {
		Type       string `json:"t"`
		NodeID     string `json:"n"`
		MySeq      uint64 `json:"s"`
		ConnEpoch  uint64 `json:"e"`
		Timestamp  int64  `json:"ts"`
		ObfEnabled bool   `json:"oe"`
		ObfAlgos   []byte `json:"oas"`
		ObfMode    string `json:"ob"`
		ObfPub     []byte `json:"opk"`
	}

	legacy := legacySeqSyncMsg{
		Type: "sync", NodeID: "peer-a", MySeq: 7, ConnEpoch: 42, Timestamp: 1,
		ObfEnabled: true, ObfAlgos: []byte{0x01}, ObfMode: "random", ObfPub: []byte{0x04, 0x02},
	}
	wire, err := json.Marshal(legacy)
	if err != nil {
		t.Fatalf("marshal legacy: %v", err)
	}

	var decoded SeqSyncMsg
	if err := json.Unmarshal(wire, &decoded); err != nil {
		t.Fatalf("unmarshal legacy payload into the new struct: %v", err)
	}
	if decoded.HandshakeVer != 0 {
		t.Errorf("legacy payload must decode to HandshakeVer=0, got %d", decoded.HandshakeVer)
	}
	if len(decoded.ObfPubSig) != 0 || len(decoded.ObfPubSignerPub) != 0 {
		t.Error("legacy payload must decode with no signature and no identity key")
	}
	if !bytes.Equal(decoded.ObfPub, legacy.ObfPub) {
		t.Errorf("ObfPub mismatch: got %x want %x", decoded.ObfPub, legacy.ObfPub)
	}

	origin, _ := genIdentity(t)
	fresh := signedMsg(t, origin, []byte{0x04, 0x02})
	out, err := json.Marshal(fresh)
	if err != nil {
		t.Fatalf("marshal new payload: %v", err)
	}
	var back SeqSyncMsg
	if err := json.Unmarshal(out, &back); err != nil {
		t.Fatalf("unmarshal new payload: %v", err)
	}
	if back.HandshakeVer != seqSyncAuthVersion || len(back.ObfPubSig) == 0 || len(back.ObfPubSignerPub) == 0 {
		t.Error("the new auth fields did not round-trip")
	}
	if !bytes.Equal(back.ObfPub, fresh.ObfPub) {
		t.Error("ObfPub did not round-trip")
	}
}

// TestSignObfPubUsesHostIdentityKey proves the production signing path — the
// identity private key pulled out of the libp2p peerstore — yields signatures
// that verify against that host's own peer ID.
func TestSignObfPubUsesHostIdentityKey(t *testing.T) {
	h, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatalf("create libp2p host: %v", err)
	}
	defer func() { _ = h.Close() }()

	n := &Node{Host: h}
	msg := signedMsgFor(t, n, []byte{0x04, 0x01, 0x02, 0x03})
	if err := n.verifyObfPubAuth(h.ID(), msg); err != nil {
		t.Fatalf("a host identity signature must verify against its own peer id: %v", err)
	}
	// And it must be rejected as any other peer — the identity is bound.
	_, otherID := genIdentity(t)
	if err := n.verifyObfPubAuth(otherID, msg); err == nil {
		t.Fatal("a host identity signature must not verify as a different peer")
	}
}

// signedMsgFor signs obfPub using the NODE's own identity key (the production
// path) rather than an injected one.
func signedMsgFor(t *testing.T, n *Node, obfPub []byte) SeqSyncMsg {
	t.Helper()
	sig, signerPub, err := n.signObfPub(obfPub)
	if err != nil {
		t.Fatalf("signObfPub: %v", err)
	}
	return SeqSyncMsg{
		Type:            "sync",
		NodeID:          n.Host.ID().String(),
		ObfEnabled:      true,
		ObfPub:          obfPub,
		HandshakeVer:    seqSyncAuthVersion,
		ObfPubSig:       sig,
		ObfPubSignerPub: signerPub,
	}
}
