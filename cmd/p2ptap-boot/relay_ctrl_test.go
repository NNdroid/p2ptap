package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"

	"p2ptap/pkg/meta"
	"p2ptap/pkg/node"
	"p2ptap/pkg/routing"
)

// TestRelayCtrlBootMintsOriginStamp reproduces the dead relay-ctrl tunnel
// through the boot and locks its fix.
//
// Three independent bugs made every relay-ctrl tunnel that passed through the
// boot useless:
//
//  1. Wire dialect. The boot's RelayCtrlHeader used json tags
//     origin/target/proto/hops while the mesh node uses o/t/p/h. encoding/json
//     drops unknown keys, so each side parsed the other's header as Origin ==
//     "" and rejected it as malformed. Tunnels were dead in BOTH directions,
//     PSK or not.
//
//  2. Missing endorsement. Once the header parsed, the boot rebuilt it with no
//     Stamp. The target saw Origin != transport peer with an empty stamp,
//     node.verifyRelayCtrlStamp refused it, and every seqsync / meta / echo
//     handshake tunnelled through the boot was dropped at the last hop. The
//     boot IS the first relay here — it verified Origin == transport peer
//     directly through the libp2p transport — so it is exactly the party
//     authorised to mint the endorsement.
//
//  3. Open-mode ACL gate. The handler required IsAuthenticated unconditionally,
//     but in open mode no peer ever authenticates, so it blocked everyone.
//
// Regression contract: the header the target receives carries the compact
// dialect, an incremented hop count, and a stamp that verifies under the
// client's network PSK. That last assertion is what makes boot-minted tunnels
// reachable at all: a boot and a node that derived their HMAC keys differently
// would produce a stamp the node cannot verify.
func TestRelayCtrlBootMintsOriginStamp(t *testing.T) {
	const psk = "0123456789abcdef"
	h := newRelayCtrlHarness(t, psk)
	defer h.close()
	h.targetH.SetStreamHandler(RelayCtrlProtocolID, h.recordHeader())

	client := h.attachClient()
	hdr, ok := h.openClientTunnel(client, node.SeqSyncProtocolID)
	if !ok {
		t.Fatal("client could not open a relay-ctrl tunnel through the boot")
	}
	assertRelayedHeader(t, hdr, client.ID(), h.targetH.ID())
	if hdr.Stamp == "" {
		t.Fatal("boot minted no stamp — the target will refuse this tunnel in a PSK network")
	}
	if !node.VerifyRelayCtrlStamp(routing.PSKKeyBytes(psk), hdr.Origin, hdr.Target, protocol.ID(hdr.Proto), hdr.Stamp) {
		t.Fatalf("boot-minted stamp does not verify with the client's network PSK (%q)", hdr.Stamp)
	}
}

// TestRelayCtrlBootOpenModeMintsNoStamp locks the open-mode half of the same
// contract: with no PSK configured there is nothing to stamp with, and the
// target's verifier treats an absent stamp as "not applicable" rather than as a
// rejection. A boot that minted a garbage stamp here would break PSK-less
// meshes, and one that failed to let the tunnel through would break open-mode
// control-plane handshakes outright (bug 3).
func TestRelayCtrlBootOpenModeMintsNoStamp(t *testing.T) {
	h := newRelayCtrlHarness(t, "")
	defer h.close()
	h.targetH.SetStreamHandler(RelayCtrlProtocolID, h.recordHeader())

	client := h.attachClient()
	hdr, ok := h.openClientTunnel(client, node.EchoProtocolID)
	if !ok {
		t.Fatal("open-mode client could not open a relay-ctrl tunnel through the boot")
	}
	assertRelayedHeader(t, hdr, client.ID(), h.targetH.ID())
	if hdr.Stamp != "" {
		t.Fatalf("open mode must mint no stamp, got %q", hdr.Stamp)
	}
	if !node.VerifyRelayCtrlStamp(nil, hdr.Origin, hdr.Target, protocol.ID(hdr.Proto), hdr.Stamp) {
		t.Fatal("an open-mode target must accept an absent stamp")
	}
}

// TestRelayCtrlBootRejectsLegacyLongTags records the dialect decision: a header
// written by a pre-upgrade boot (origin/target/proto/hops) no longer parses.
// The new boot DROPS it as malformed rather than guessing at a mapping, because
// Go binds a struct field to its FIRST json tag only, so
// `json:"o" json:"origin"` does not read either spelling. This is not a live
// regression path — the only writer of the long dialect was a pre-upgrade boot,
// and no live boot writes it because the handler dials hdr.Target directly
// rather than choosing a peer boot as the next hop.
func TestRelayCtrlBootRejectsLegacyLongTags(t *testing.T) {
	origin, target := mustPeerID(t), mustPeerID(t)

	raw, err := json.Marshal(map[string]any{
		"origin": origin.String(),
		"target": target.String(),
		"proto":  node.SeqSyncProtocolID,
		"hops":   1,
	})
	if err != nil {
		t.Fatalf("marshal legacy: %v", err)
	}
	var got RelayCtrlHeader
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("legacy header should parse (not error), got: %v", err)
	}
	if got.Origin != "" || got.Target != "" || got.Proto != "" || got.Hops != 0 || got.Stamp != "" {
		t.Fatalf("legacy long tags must not populate the compact fields, got %+v", got)
	}

	// And the compact dialect round-trips cleanly.
	compact := RelayCtrlHeader{
		Origin: origin,
		Target: target,
		Proto:  string(node.SeqSyncProtocolID),
		Hops:   1,
		Stamp:  "stamp-1",
	}
	b, err := json.Marshal(compact)
	if err != nil {
		t.Fatalf("marshal compact: %v", err)
	}
	var rt RelayCtrlHeader
	if err := json.Unmarshal(b, &rt); err != nil {
		t.Fatalf("unmarshal compact: %v", err)
	}
	if rt != compact {
		t.Fatalf("compact header did not round-trip: got %+v want %+v", rt, compact)
	}
	// Marshal must emit the node dialect only — no legacy keys alongside.
	for _, legacyKey := range []string{`"origin"`, `"target"`, `"proto"`, `"hops"`, `"stamp"`} {
		if strings.Contains(string(b), legacyKey) {
			t.Fatalf("marshal emitted legacy key %s: %s", legacyKey, b)
		}
	}
}

// TestRelayCtrlBootRefusesUnendorsedTransit locks the transit gate: a backbone
// boot that relays a claim it did not verify itself must present a valid
// endorsement, or the tunnel is dropped. Without this the boot is an open relay
// for origin forgery against the targets it dials directly.
func TestRelayCtrlBootRefusesUnendorsedTransit(t *testing.T) {
	h := newRelayCtrlHarness(t, "shared-secret")
	defer h.close()
	h.targetH.SetStreamHandler(RelayCtrlProtocolID, h.recordHeader())

	if hdr, ok := h.openPeerTunnel(h.meshPeerH, h.claimantH.ID(), h.targetH.ID(), meta.MetaProtocolID, "", 5*time.Second); ok {
		t.Fatalf("target received a tunnel claiming origin %s from mesh peer %s with no valid endorsement (hops=%d, stamp=%q)",
			hdr.Origin, h.meshPeerH.ID(), hdr.Hops, hdr.Stamp)
	}
}

// TestRelayCtrlBootCarriesUpstreamStamp locks the mirror case of the transit
// gate: an endorsement minted upstream is trusted and forwarded unchanged, so a
// node that relayed through another PSK holder still reaches this boot's
// targets. Asserting byte-equality of the stamp is what catches a boot that
// re-stamps transit traffic and thereby overwrites a legitimate endorsement.
func TestRelayCtrlBootCarriesUpstreamStamp(t *testing.T) {
	const psk = "shared-secret"
	h := newRelayCtrlHarness(t, psk)
	defer h.close()
	h.targetH.SetStreamHandler(RelayCtrlProtocolID, h.recordHeader())

	proto := protocol.ID(meta.MetaProtocolID)
	upstream := node.StampRelayCtrlOrigin(routing.PSKKeyBytes(psk), h.claimantH.ID(), h.targetH.ID(), proto)

	hdr, ok := h.openPeerTunnel(h.meshPeerH, h.claimantH.ID(), h.targetH.ID(), proto, upstream, 8*time.Second)
	if !ok {
		t.Fatal("an endorsed transit tunnel was refused — the boot is not carrying upstream stamps")
	}
	assertRelayedHeader(t, hdr, h.claimantH.ID(), h.targetH.ID())
	if hdr.Stamp != upstream {
		t.Fatalf("boot rewrote the upstream endorsement: got %q want %q", hdr.Stamp, upstream)
	}
}

// --- helpers ---

// assertRelayedHeader checks the fields that must survive the boot unchanged,
// plus the hop count, which the boot must bump exactly once.
func assertRelayedHeader(t *testing.T, got RelayCtrlHeader, wantOrigin, wantTarget peer.ID) {
	t.Helper()
	if got.Origin != wantOrigin {
		t.Fatalf("target saw origin %s, want %s — the header dialect is still wrong", got.Origin, wantOrigin)
	}
	if got.Target != wantTarget {
		t.Fatalf("target saw target %s, want %s", got.Target, wantTarget)
	}
	if got.Hops != 2 {
		t.Fatalf("target saw hops=%d, want 2 (client + boot)", got.Hops)
	}
}

// mustPeerID returns a real, CID-valid peer ID for JSON round-trip tests. A
// bare peer.ID("o1") would not unmarshal: peer.ID implements UnmarshalText over
// the CID, so the ID must be a genuine key-derived identity.
func mustPeerID(t *testing.T) peer.ID {
	t.Helper()
	k, _, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	id, err := peer.IDFromPublicKey(k.GetPublic())
	if err != nil {
		t.Fatalf("derive peer id: %v", err)
	}
	return id
}

// --- harness ---

// relayCtrlHarness wires four real libp2p hosts: the boot running
// makeRelayCtrlHandler, a target that records the header the boot forwards, a
// backbone boot peer (hub.isMesh == true) for the transit cases, and an
// authenticated mesh peer used as a claimed Origin. In a real deployment the
// target runs node.handleRelayCtrl; a recording handler is enough here because
// the assertions are about the header on the wire.
type relayCtrlHarness struct {
	bootH     host.Host
	targetH   host.Host
	meshPeerH host.Host
	claimantH host.Host
	acl       *pskACLFilter
	hub       *peekMapHub
	got       chan RelayCtrlHeader
	psk       string
	clients   []host.Host
}

func newRelayCtrlHarness(t *testing.T, psk string) *relayCtrlHarness {
	t.Helper()

	newHost := func() host.Host {
		h, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
		if err != nil {
			t.Fatalf("libp2p.New: %v", err)
		}
		t.Cleanup(func() { _ = h.Close() })
		return h
	}

	bootH := newHost()
	targetH := newHost()
	meshPeerH := newHost()
	claimantH := newHost()

	enable := psk != ""
	netID := networkIDFromPSK(psk)
	entries := []pskEntry{}
	if enable {
		entries = append(entries, pskEntry{hash: computePSKHash(psk), netID: netID, psk: psk})
	}

	acl := newPSKACLFilter(enable)
	acl.SetHost(bootH)
	hub := newPeekMapHub()
	hub.markMesh(meshPeerH.ID())

	bootH.SetStreamHandler(RelayCtrlProtocolID, makeRelayCtrlHandler(bootH, acl, hub, entries))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, p := range []host.Host{targetH, meshPeerH, claimantH} {
		if err := bootH.Connect(ctx, peer.AddrInfo{ID: p.ID(), Addrs: p.Addrs()}); err != nil {
			t.Fatalf("boot connect %s: %v", p.ID(), err)
		}
		if enable {
			acl.AddAuthenticated(p.ID(), netID)
		}
	}

	return &relayCtrlHarness{
		bootH:     bootH,
		targetH:   targetH,
		meshPeerH: meshPeerH,
		claimantH: claimantH,
		acl:       acl,
		hub:       hub,
		got:       make(chan RelayCtrlHeader, 8),
		psk:       psk,
	}
}

func (h *relayCtrlHarness) close() {
	for _, c := range h.clients {
		_ = c.Close()
	}
	_ = h.bootH.Close()
	_ = h.targetH.Close()
	_ = h.meshPeerH.Close()
	_ = h.claimantH.Close()
}

// attachClient dials the boot and, in PSK mode, marks the client as having
// completed its handshake. The real path is /p2ptap/auth/1.0.0; the handler only
// consults the ACL table, which is what these assertions depend on.
func (h *relayCtrlHarness) attachClient() host.Host {
	c, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		panic(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := c.Connect(ctx, peer.AddrInfo{ID: h.bootH.ID(), Addrs: h.bootH.Addrs()}); err != nil {
		panic(err)
	}
	if h.acl.pskEnabled {
		h.acl.AddAuthenticated(c.ID(), networkIDFromPSK(h.psk))
	}
	h.clients = append(h.clients, c)
	return c
}

// openClientTunnel opens a relay-ctrl stream from client to the boot claiming
// Origin == client, and returns the header the target received.
func (h *relayCtrlHarness) openClientTunnel(client host.Host, proto protocol.ID) (RelayCtrlHeader, bool) {
	return h.openTunnel(client, client.ID(), h.targetH.ID(), proto, "", 8*time.Second)
}

// openPeerTunnel is the backbone-boot variant: meshPeerH presents a claim for
// claimant, optionally carrying an upstream endorsement. wait bounds how long
// the test is willing to sit proving nothing arrived.
func (h *relayCtrlHarness) openPeerTunnel(from host.Host, claimant, target peer.ID, proto protocol.ID, stamp string, wait time.Duration) (RelayCtrlHeader, bool) {
	return h.openTunnel(from, claimant, target, proto, stamp, wait)
}

func (h *relayCtrlHarness) openTunnel(from host.Host, origin, target peer.ID, proto protocol.ID, stamp string, wait time.Duration) (RelayCtrlHeader, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s, err := from.NewStream(ctx, h.bootH.ID(), RelayCtrlProtocolID)
	if err != nil {
		return RelayCtrlHeader{}, false
	}
	hdr := RelayCtrlHeader{Origin: origin, Target: target, Proto: string(proto), Hops: 1, Stamp: stamp}
	b, err := json.Marshal(hdr)
	if err != nil {
		return RelayCtrlHeader{}, false
	}
	if err := writeFrame(s, b); err != nil {
		return RelayCtrlHeader{}, false
	}
	select {
	case got := <-h.got:
		return got, true
	case <-time.After(wait):
		return RelayCtrlHeader{}, false
	}
}

// recordHeader installs a RelayCtrlProtocolID handler on the target that
// forwards whatever header it receives onto h.got.
func (h *relayCtrlHarness) recordHeader() func(network.Stream) {
	return func(s network.Stream) {
		defer s.Close()
		buf := make([]byte, 4096)
		n0, err := readFrame(s, buf)
		if err != nil || n0 == 0 {
			h.got <- RelayCtrlHeader{}
			return
		}
		var got RelayCtrlHeader
		if err := json.Unmarshal(buf[:n0], &got); err != nil {
			h.got <- RelayCtrlHeader{}
			return
		}
		h.got <- got
	}
}
