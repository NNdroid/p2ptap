package node

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"

	"p2ptap/pkg/obfuscate"
)

// PSK-keyed ORIGIN ATTESTATION for the overlay relay-ctrl tunnel.
//
// The tunnel header carries hdr.Origin — the peer whose inner control protocol
// (SeqSync/Meta/LSA/Echo) the FINAL hop must bind its per-peer state to
// (cipher slot, dedup anchor, meta identity, MAC learning). Without an
// integrity guard on that claim, ANY node able to open a relay-ctrl stream to
// a victim — a direct identity-only dial, or an unverified transit request —
// could set Origin = some legitimate mesh peer V and run the handshake
// "as V", overwriting V's cipher slot (V's real traffic then fails AEAD at the
// victim while the reconciler believes the pair converged), anchoring V's
// dedup window, or injecting fake identity/gratuitous-ARP entries for V. The
// transport authenticates the DIRECT dialer only — the logical origin is an
// application-level claim, and ready/cipher state for the transport peer is
// NOT a proof: the SeqSync ack exchange rides plaintext JSON, so even a
// PSK-mismatched one-sided handshake sets those flags.
//
// The guard therefore binds the claim to the PSK itself: the FIRST relay that
// accepts a tunnel where Origin == transport peer (a claim it verified
// directly) endorses the header with
//
//	stamp = HMAC-SHA256(key = SHA256(PSK || "|p2ptap-relayctrl-attest"),
//	                     msg = "v1" || origin || target || proto)
//
// and every downstream hop — including the final node — accepts an
// Origin != transport peer only with a valid stamp. An attacker without the
// PSK cannot mint stamps; a self-origin claim needs no stamp. In PSK-less
// meshes stamps are neither minted nor required (behaviour identical to
// pre-attestation). Hops is deliberately NOT in the MAC (rewritten per hop);
// origin+target+proto keep the stamp from being replayable across different
// tunnels. Residual trust: a PSK-holding insider that acts as first relay can
// endorse a false origin — but it already holds the network key and can
// inject frames as itself, i.e. this closes the outside-the-mesh attack
// class, which is the one the claim was vulnerable to without ANY credential.
const relayCtrlStampVersion = "v1"

// relayCtrlStampKey derives the HMAC key from the PSK (nil-safe: empty PSK
// callers never reach stamping/verification, guarded by pskRequired()).
func relayCtrlStampKey(psk []byte) []byte {
	h := sha256.New()
	h.Write(psk)
	h.Write([]byte(obfuscate.D([]byte{0x34, 0x38, 0x7a, 0x38, 0x3c, 0x29, 0x38, 0x65, 0x3a, 0x2d, 0x24, 0x29, 0x31, 0x2b, 0x3c, 0x3a, 0x24, 0x65, 0x29, 0x3c, 0x3c, 0x2d, 0x3b, 0x3c})))
	return h.Sum(nil)
}

// mintRelayCtrlStamp mints the endorsement for an origin claim the caller just
// verified directly (Origin == transport peer). psk is the SHA-256 PSK key
// bytes as a mesh node derives them (routing.PSKKeyBytes). Returns "" when psk
// is empty — no stamps exist in PSK-less meshes, by design.
//
// psk is a parameter, not a method receiver, because the custom boot node is a
// FIRST relay for clients that never share a Node's config plumbing: it holds
// the PSKs as a configured list and must mint stamps byte-identical to a mesh
// node's. Keeping one implementation here is what guarantees that parity — a
// second copy in cmd/p2ptap-boot would drift.
func mintRelayCtrlStamp(psk []byte, origin, target peer.ID, proto protocol.ID) string {
	if len(psk) == 0 {
		return ""
	}
	mac := hmac.New(sha256.New, relayCtrlStampKey(psk))
	mac.Write([]byte(relayCtrlStampVersion))
	mac.Write([]byte{0})
	mac.Write([]byte(origin.String()))
	mac.Write([]byte{0})
	mac.Write([]byte(target.String()))
	mac.Write([]byte{0})
	mac.Write([]byte(proto))
	return hex.EncodeToString(mac.Sum(nil))
}

// checkRelayCtrlStamp validates an endorsement received in a tunnel header. In
// PSK-less meshes there are no stamps and none is required; in PSK meshes an
// EMPTY stamp never verifies (old unstamped tunnels from a pre-upgrade
// first-hop cannot attest — consistent with the documented PSK full-upgrade
// requirement: those peers cannot derive matching keys either).
func checkRelayCtrlStamp(psk []byte, origin, target peer.ID, proto protocol.ID, stamp string) bool {
	if len(psk) == 0 {
		return true
	}
	if stamp == "" {
		return false
	}
	return hmac.Equal([]byte(stamp), []byte(mintRelayCtrlStamp(psk, origin, target, proto)))
}

// stampRelayCtrlOrigin mints the endorsement for an origin claim this node
// just verified directly (Origin == transport peer). Returns "" in PSK-less
// meshes (no stamps exist there, by design).
func (n *Node) stampRelayCtrlOrigin(origin, target peer.ID, proto protocol.ID) string {
	return mintRelayCtrlStamp(pskSaltBytes(n), origin, target, proto)
}

// verifyRelayCtrlStamp validates an endorsement received in a tunnel header.
// See checkRelayCtrlStamp for the PSK-less / empty-stamp rules.
func (n *Node) verifyRelayCtrlStamp(origin, target peer.ID, proto protocol.ID, stamp string) bool {
	return checkRelayCtrlStamp(pskSaltBytes(n), origin, target, proto, stamp)
}

// StampRelayCtrlOrigin is the exported mint for first relays outside this
// package — the custom boot node in particular, which terminates client
// relay-ctrl tunnels and dials the target itself, so it is the first relay for
// every target it serves. psk must be routing.PSKKeyBytes(the client's PSK).
// Returns "" for an empty psk.
func StampRelayCtrlOrigin(psk []byte, origin, target peer.ID, proto protocol.ID) string {
	return mintRelayCtrlStamp(psk, origin, target, proto)
}

// VerifyRelayCtrlStamp is the exported check, mirroring stampRelayCtrlOrigin:
// a first relay that mints with this package's StampRelayCtrlOrigin must verify
// with this one so a boot cannot accept a stamp another boot minted under a
// drifted derivation.
func VerifyRelayCtrlStamp(psk []byte, origin, target peer.ID, proto protocol.ID, stamp string) bool {
	return checkRelayCtrlStamp(psk, origin, target, proto, stamp)
}

// relayCtrlOriginSigDomain separates the origin signature from any other
// signature the identity key may produce (SeqSync, etc.), so a signature minted
// for one protocol cannot be replayed as another.
const relayCtrlOriginSigDomain = "p2ptap-relay-ctrl-origin-v1"

// relayCtrlOriginSigInput builds the exact byte string signed over. It binds
// the claim to (Origin, Target, Proto) — the same fields the stamp covers —
// and NOT to Hops, which is rewritten per hop. peer.ID and protocol IDs are
// base58 / ASCII so the 0x00 separators cannot collide with the fields.
func relayCtrlOriginSigInput(origin, target peer.ID, proto protocol.ID) []byte {
	buf := make([]byte, 0, 32+len(origin.String())+len(target.String())+len(proto))
	buf = append(buf, relayCtrlOriginSigDomain...)
	buf = append(buf, 0)
	buf = append(buf, origin.String()...)
	buf = append(buf, 0)
	buf = append(buf, target.String()...)
	buf = append(buf, 0)
	buf = append(buf, proto...)
	return buf
}

// signRelayCtrlOriginSig signs an origin claim with this node's identity key.
// Returns "" when origin is not self (only the true origin may sign its own
// claim) or when the identity key is unavailable — callers then simply leave
// the header unsigned, which the PSK-stamp fallback covers in PSK meshes and
// which is rejected outright in PSK-less meshes.
func (n *Node) signRelayCtrlOriginSig(origin, target peer.ID, proto protocol.ID) string {
	if origin != n.Host.ID() {
		return ""
	}
	key := n.Host.Peerstore().PrivKey(origin)
	if key == nil {
		return ""
	}
	sig, err := key.Sign(relayCtrlOriginSigInput(origin, target, proto))
	if err != nil {
		return ""
	}
	return hex.EncodeToString(sig)
}

// verifyRelayCtrlOriginSig validates an origin signature received in a tunnel
// header against the origin's public key from the peerstore. A missing or
// malformed signature, or an unknown origin key, fails closed — the caller
// must not bind per-peer state to an unauthenticated origin.
func (n *Node) verifyRelayCtrlOriginSig(hdr RelayCtrlHeader) bool {
	if hdr.OriginSig == "" {
		return false
	}
	pub := n.Host.Peerstore().PubKey(peer.ID(hdr.Origin))
	if pub == nil {
		return false
	}
	sig, err := hex.DecodeString(hdr.OriginSig)
	if err != nil {
		return false
	}
	ok, err := pub.Verify(relayCtrlOriginSigInput(peer.ID(hdr.Origin), hdr.Target, protocol.ID(hdr.Proto)), sig)
	return err == nil && ok
}

// originClaimTrusted decides whether a tunnel header's Origin claim is
// authenticated at this hop:
//
//   - a self-origin claim (Origin == transport peer) is always trusted — the
//     libp2p transport already authenticated the dialer;
//   - a valid origin identity signature is always trusted (the strongest
//     credential: the origin key is unique and non-shareable);
//   - otherwise, in a PSK mesh, a valid PSK stamp is accepted as the legacy
//     pre-signature fallback (old nodes sign nothing but carry a stamp);
//   - in a PSK-less mesh nothing else can vouch for a foreign origin, so the
//     claim is rejected — this closes the hole where any relay could forge an
//     arbitrary Origin against a downstream victim.
func (n *Node) originClaimTrusted(hdr RelayCtrlHeader, remotePeer peer.ID) bool {
	if hdr.Origin == remotePeer {
		return true
	}
	if n.verifyRelayCtrlOriginSig(hdr) {
		return true
	}
	if len(pskSaltBytes(n)) > 0 {
		return n.verifyRelayCtrlStamp(peer.ID(hdr.Origin), hdr.Target, protocol.ID(hdr.Proto), hdr.Stamp)
	}
	return false
}

// RelayCtrlOriginSigInput is the exported domain-separated byte string signed
// by an origin identity key. Exported for the custom boot node, which verifies
// origin signatures on backbone-transited tunnels and must agree byte-for-byte
// with the mesh node's signing input.
func RelayCtrlOriginSigInput(origin, target peer.ID, proto protocol.ID) []byte {
	return relayCtrlOriginSigInput(origin, target, proto)
}

// SignRelayCtrlOriginSig signs an origin claim with an explicit identity key.
// Exported for the boot node (and any external first relay) so a signature
// minted by a mesh node's signRelayCtrlOriginSig verifies here.
func SignRelayCtrlOriginSig(key crypto.PrivKey, origin, target peer.ID, proto protocol.ID) string {
	if key == nil {
		return ""
	}
	sig, err := key.Sign(relayCtrlOriginSigInput(origin, target, proto))
	if err != nil {
		return ""
	}
	return hex.EncodeToString(sig)
}

// VerifyRelayCtrlOriginSig verifies an origin signature against an explicit
// public key. Exported for the boot node, which holds origin keys in its own
// peerstore and must verify a tunnel it did not originate before forwarding.
func VerifyRelayCtrlOriginSig(pub crypto.PubKey, origin, target peer.ID, proto protocol.ID, sigHex string) bool {
	if pub == nil || sigHex == "" {
		return false
	}
	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		return false
	}
	ok, err := pub.Verify(relayCtrlOriginSigInput(origin, target, proto), sig)
	return err == nil && ok
}
