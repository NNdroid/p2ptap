package node

import (
	"fmt"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
)

// AUTHENTICATED KEY EXCHANGE for the SeqSync obfuscation handshake.
//
// Threat model. SeqSync derives the per-peer AEAD key from an ECDH over each
// side's offered ObfPub, and ObfPub travels as plaintext JSON. Over a relay-ctrl
// tunnel the libp2p transport authenticates the RELAY HOP, not the ORIGIN: the
// hop is authenticated, the "Origin: A" header claim is an application-level
// assertion. So a transit hop sitting between A and C can substitute its OWN
// ephemeral key for A's ObfPub in one direction and for C's in the other, finish
// two independent ECDHs, and end up on two separate sessions it can both
// decrypt — a full man-in-the-middle of the encrypted TAP link.
//
// A PSK-keyed MAC over ObfPub cannot close this: the PSK is shared with every
// mesh member, relays included, so a PSK-holding hop forges it. The only
// per-side secret a hop does NOT hold is the origin's libp2p IDENTITY private
// key, so that is what binds the key exchange to the origin:
//
//	sig = identity_priv_A( obfPubSigDomain || ObfPub )
//
// A hop without A's identity key cannot sign, so it cannot substitute a key and
// get it accepted. Origin spoofing (who is speaking) is a different claim and is
// already closed by the PSK-HMAC stamp in relay_ctrl_attest.go; this closes the
// key-exchange MITM (what key the speaker is offering). Together the two make
// the tunnel carry an authentic key exchange: the stamp authenticates the
// identity claim, the signature authenticates the offered key against it.
//
// The signature is verified against the peer's claimed identity by deriving the
// PeerID from the offered identity public key and comparing it with the
// transport/logical origin (which the relay-ctrl stamp has already
// authenticated). libp2p PeerIDs ARE their public keys, so no peerstore lookup
// is required and a first-ever contact verifies cleanly.
//
// The long-lived-key fallback is covered by the same mechanism: whether ObfPub is
// a per-handshake ephemeral or the node key, the offered key must be signed by
// the origin's identity key.
//
// Interop. seqSyncAuthVersion is carried in SeqSyncMsg.HandshakeVer and the
// fields are ADDITIVE — an older peer simply ignores them and keeps working
// (unauthenticated, as before). A capable node therefore signs every key it
// offers, but only REQUIRES a signature when it has reason to believe the
// counterpart is capable: the counterpart advertised HandshakeVer >= 1, we have
// previously seen a valid signature from it (obfAuthSticky, so a peer cannot
// retroactively downgrade once upgraded), or the operator has opted into
// Obfuscation.RequireAuthKeyExchange. Against a legacy peer we accept
// unauthenticated and log it, because breaking connectivity is worse than the
// pre-existing exposure. A signature that is required but invalid fails CLOSED —
// the cipher is never committed — so the attack outcome is a lost link that is
// loudly logged, not a silently MITM'd one.
const seqSyncAuthVersion = uint32(1)

// obfPubSigDomain is prepended to the offered handshake public key before
// signing, domain-separating these signatures from every other use of the
// identity key so a signature cannot be repurposed across message types.
var obfPubSigDomain = []byte("p2ptap-obfpub-sig\x00")

// obfPubSigInput is the exact byte string signed and verified for an offered
// handshake public key.
func obfPubSigInput(obfPub []byte) []byte {
	buf := make([]byte, 0, len(obfPubSigDomain)+len(obfPub))
	buf = append(buf, obfPubSigDomain...)
	buf = append(buf, obfPub...)
	return buf
}

// identityPrivKey returns this node's libp2p identity private key, or nil if the
// host has not exposed one. Signing the key exchange is what makes substitution
// impossible, so a nil key means "cannot authenticate".
func (n *Node) identityPrivKey() crypto.PrivKey {
	if n == nil || n.Host == nil || n.Host.Peerstore() == nil {
		return nil
	}
	return n.Host.Peerstore().PrivKey(n.Host.ID())
}

// signObfPubWith signs an offered handshake public key with the given identity
// private key and returns the signature together with the marshalled identity
// public key the signature must be verified against. Kept free of Node state so
// the crypto round trip can be unit-tested in isolation.
func signObfPubWith(priv crypto.PrivKey, obfPub []byte) (sig, signerPub []byte, err error) {
	if priv == nil {
		return nil, nil, fmt.Errorf("no identity key available to sign the key exchange")
	}
	sig, err = priv.Sign(obfPubSigInput(obfPub))
	if err != nil {
		return nil, nil, fmt.Errorf("signing handshake key: %w", err)
	}
	signerPub, err = crypto.MarshalPublicKey(priv.GetPublic())
	if err != nil {
		return nil, nil, fmt.Errorf("marshalling identity public key: %w", err)
	}
	return sig, signerPub, nil
}

// signObfPub signs with this node's libp2p identity key.
func (n *Node) signObfPub(obfPub []byte) ([]byte, []byte, error) {
	return signObfPubWith(n.identityPrivKey(), obfPub)
}

// verifyObfPubAuth checks that msg.ObfPub was signed by the identity key of
// remotePeer (the origin the relay-ctrl stamp has already authenticated) and
// returns nil on success. An empty ObfPub is nothing to authenticate.
func (n *Node) verifyObfPubAuth(remotePeer peer.ID, msg SeqSyncMsg) error {
	if len(msg.ObfPub) == 0 {
		return nil
	}
	if len(msg.ObfPubSignerPub) == 0 {
		return fmt.Errorf("no identity public key offered with the handshake key")
	}
	if len(msg.ObfPubSig) == 0 {
		return fmt.Errorf("handshake key offered without a signature")
	}

	signerPub, err := crypto.UnmarshalPublicKey(msg.ObfPubSignerPub)
	if err != nil {
		return fmt.Errorf("unmarshalling offered identity key: %w", err)
	}

	// Bind the signing key to the CLAIMED identity. A hop that substitutes its
	// own ephemeral key must also produce a signature under the origin's
	// identity key, which it cannot do — this comparison is what rejects it.
	// Deriving the ID from the key (rather than trusting msg.NodeID) is what
	// makes the binding self-verifying: no peerstore entry is needed, so a
	// first-ever contact verifies cleanly.
	if signerID, err := peer.IDFromPublicKey(signerPub); err != nil {
		return fmt.Errorf("deriving peer id from offered identity key: %w", err)
	} else if signerID != remotePeer {
		return fmt.Errorf("offered identity key belongs to %s, not the claimed origin %s", signerID, remotePeer)
	}

	if ok, verr := signerPub.Verify(obfPubSigInput(msg.ObfPub), msg.ObfPubSig); verr != nil {
		return fmt.Errorf("verifying handshake key signature: %w", verr)
	} else if !ok {
		return fmt.Errorf("handshake key signature from %s does not verify", remotePeer)
	}
	return nil
}

// requireObfAuth reports whether a signature is MANDATORY for an ObfPub coming
// from peer, given what peer has advertised in this message.
func (n *Node) requireObfAuth(peer peer.ID, msg SeqSyncMsg) bool {
	if n.config().Obfuscation.RequireAuthKeyExchange {
		return true
	}
	if v, ok := n.obfAuthSticky.Load(peer); ok && v.(bool) {
		return true
	}
	return msg.HandshakeVer >= seqSyncAuthVersion
}

// markObfAuth records that peer demonstrated an authenticated key exchange. The
// bit is intentionally sticky for the node's lifetime: once a peer has proven it
// can sign, a later connection from the same peer must not be able to drop
// HandshakeVer and silently fall back to an unauthenticated key exchange. It is
// never deleted on disconnect (unlike the per-connection per-peer state), which
// is exactly what keeps the downgrade window closed across reconnects.
func (n *Node) markObfAuth(peer peer.ID) {
	n.obfAuthSticky.Store(peer, true)
}

// checkObfPubAuth gates the offered ObfPub before any cipher is derived from
// it. It returns nil when ObfPub may be used, and an error when it must not be.
// Legacy peers (no signature, no version advertised, never seen signed) are
// accepted for interop and logged, so mixed fleets keep working.
func (n *Node) checkObfPubAuth(remotePeer peer.ID, msg SeqSyncMsg) error {
	if len(msg.ObfPub) == 0 {
		return nil
	}
	if !n.requireObfAuth(remotePeer, msg) {
		log.Debug("SeqSync: %s offered an unauthenticated key exchange (legacy peer); accepting for interop", remotePeer)
		return nil
	}
	if err := n.verifyObfPubAuth(remotePeer, msg); err != nil {
		return err
	}
	n.markObfAuth(remotePeer)
	log.Debug("SeqSync: %s key exchange authenticated (HandshakeVer=%d)", remotePeer, msg.HandshakeVer)
	return nil
}
