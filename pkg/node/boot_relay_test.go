package node

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
	relayClient "github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/client"

	"p2ptap/pkg/tap"
)

// TestBootRelayCircuitReservationAndDial exercises the BOOT-relay path (libp2p
// Circuit Relay v2 via a static bootstrap relay) end to end, using an
// IN-PROCESS relay host so the test needs no external server, no git secret and
// no public relay (which would be flaky in CI). The peer relay (p2ptap's own
// overlay relay) is covered separately in overlay_relay_forward_test.go.
//
// Topology:
//
//	NodeA ──(circuit v2)── [in-process BOOT relay] ──(circuit v2)── NodeC
//
// Neither A nor C is directly connected; the only path between them is the
// boot relay. This mirrors the production "two NAT'd peers reach each other
// through the shared BOOT" scenario.
//
// Regression contracts:
//   - Both p2ptap nodes MUST successfully reserve a Circuit Relay v2 slot on
//     the boot relay (the client.Reserve API exercised here directly; in
//     production p2ptap relies on libp2p AutoRelay for this, since p2ptap
//     nodes do not themselves mount the relay service).
//   - NodeA MUST be able to establish a connection to NodeC THROUGH the boot
//     relay (Circuit Relay v2). We assert this with a network notifee capturing
//     the Connected event whose transport is /p2p-circuit — a race-free proof
//     the relay actually forwarded the connection. (p2ptap's own control plane
//     may subsequently drop the link when no peer metadata / overlay cipher is
//     present, which is why we lock the *establishment* event, not a sustained
//     Connectedness.)
//   - SynthesizeRelayCircuitAddrs now FALLS BACK to a peer-ID-only circuit addr
//     for loopback relays (matching dialInParallel) instead of returning empty,
//     so the relay-priority control path can reuse a live circuit link even when
//     the relay is same-host. Locked here: the fallback MUST be the bare
//     "/p2p/<relay>/p2p-circuit/p2p/<target>" form (no loopback transport prefix)
func TestBootRelayCircuitReservationAndDial(t *testing.T) {
	// --- 1. Spin up an in-process Circuit Relay v2 server (BOOT-equivalent) ---
	relayHost, err := libp2p.New(
		libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"),
		libp2p.EnableRelayService(),
		// The relay service only mounts the /libp2p/circuit/relay/0.2.0/hop
		// handler when the host is "publicly reachable". A loopback in-process
		// relay reads as private, so force public reachability to activate it.
		libp2p.ForceReachabilityPublic(),
	)
	if err != nil {
		t.Fatalf("create in-process boot relay: %v", err)
	}
	defer relayHost.Close()
	if len(relayHost.Addrs()) == 0 {
		t.Fatal("in-process boot relay has no listen addresses")
	}
	relayMa := relayHost.Addrs()[0] // /ip4/127.0.0.1/tcp/<port> (no /p2p suffix in this build)
	relayIDStr := relayHost.ID().String()
	// Bootstrap peers must carry the relay's /p2p/<id> so p2ptap can parse them.
	relayBootstrap := relayMa.String() + "/p2p/" + relayIDStr
	relayInfo := &peer.AddrInfo{ID: relayHost.ID(), Addrs: []multiaddr.Multiaddr{relayMa}}
	t.Logf("in-process boot relay listening at %s", relayBootstrap)

	// --- 2. Two p2ptap nodes that both use the relay as their bootstrap/static relay ---
	cfgA := createTestNodeConfig("10.0.0.1/24", "fd00::1/64", "best_path")
	cfgA.BootstrapPeers = []string{relayBootstrap}
	cfgC := createTestNodeConfig("10.0.0.3/24", "fd00::3/64", "best_path")
	cfgC.BootstrapPeers = []string{relayBootstrap}

	tapA, _ := tap.NewMemTAPPair("tapA", "pipeA")
	tapC, _ := tap.NewMemTAPPair("tapC", "pipeC")

	aNode, err := NewNodeWithTAP(cfgA, tapA, nil)
	if err != nil {
		t.Fatalf("create NodeA: %v", err)
	}
	defer aNode.Close()
	cNode, err := NewNodeWithTAP(cfgC, tapC, nil)
	if err != nil {
		t.Fatalf("create NodeC: %v", err)
	}
	defer cNode.Close()

	aNode.Start()
	cNode.Start()

	// --- 3. Wait for both nodes to be CONNECTED to the boot relay ---
	waitConnectedTo(t, aNode.Host, relayHost.ID(), "A->boot-relay")
	waitConnectedTo(t, cNode.Host, relayHost.ID(), "C->boot-relay")

	// --- 4. Verify the libp2p Circuit Relay v2 service on the boot relay is
	// actually usable (the boot relay mounts the /hop handler because it runs
	// EnableRelayService + ForceReachabilityPublic). p2ptap's production nodes
	// do NOT mount the relay service (ForceReachabilityPrivate), so the explicit
	// client-side reservation is handled solely by libp2p AutoRelay; here we
	// assert the underlying circuit relay works when the service IS present.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if _, err := relayClient.Reserve(ctx, aNode.Host, *relayInfo); err != nil {
		t.Fatalf("NodeA failed to reserve circuit slot on boot relay: %v", err)
	}
	if _, err := relayClient.Reserve(ctx, cNode.Host, *relayInfo); err != nil {
		t.Fatalf("NodeC failed to reserve circuit slot on boot relay: %v", err)
	}
	t.Log("✓ both nodes reserved Circuit Relay v2 slots on the boot relay")

	// --- 6. Behavioral lock: loopback relays now fall back to the peer-ID-only
	// circuit form (matching dialInParallel) instead of being skipped.
	// Previously the function returned empty for loopback relays, which made the
	// relay-priority control path unable to reuse a live circuit link. The
	// returned address MUST be a bare "/p2p/<relay>/p2p-circuit/p2p/<target>"
	// (no loopback transport prefix), proving the fallback path is taken.
	loopbackAddrs := aNode.SynthesizeRelayCircuitAddrs(cNode.Host.ID())
	if len(loopbackAddrs) == 0 {
		t.Fatalf("SynthesizeRelayCircuitAddrs must fall back to a peer-ID-only circuit addr for loopback relays, got empty")
	}
	for _, a := range loopbackAddrs {
		s := a.String()
		if !strings.Contains(s, "/p2p-circuit/") {
			t.Fatalf("SynthesizeRelayCircuitAddrs loopback fallback must contain /p2p-circuit/: %s", s)
		}
		if strings.HasPrefix(s, "/ip4/127.0.0.1") || strings.HasPrefix(s, "/ip6/::1") {
			t.Fatalf("SynthesizeRelayCircuitAddrs loopback fallback must NOT carry a loopback transport prefix: %s", s)
		}
	}

	// --- 7. Dial C THROUGH the boot relay and prove the relay forwarded it ---
	// relayMa is the bare transport prefix (/ip4/.../tcp/port); encapsulate the
	// <relayID>/p2p-circuit/<targetID> components onto it.
	circuitComp, _ := multiaddr.NewMultiaddr(
		"/p2p/" + relayIDStr + "/p2p-circuit/p2p/" + cNode.Host.ID().String())
	targetCircuit := relayMa.Encapsulate(circuitComp)

	// Capture the Connected event to assert the transport was the circuit relay
	// (race-free: the event fires even if p2ptap's control plane drops it after).
	nf := &relayConnectedNotifee{ch: make(chan struct{}, 1), cID: cNode.Host.ID()}
	aNode.Host.Network().Notify(nf)
	defer aNode.Host.Network().StopNotify(nf)

	connCtx, connCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer connCancel()
	if err := aNode.Host.Connect(connCtx, peer.AddrInfo{
		ID:    cNode.Host.ID(),
		Addrs: []multiaddr.Multiaddr{targetCircuit},
	}); err != nil {
		t.Fatalf("NodeA failed to dial NodeC through boot relay: %v", err)
	}
	t.Log("✓ NodeA's Host.Connect through the boot relay returned (circuit v2 handshake completed)")

	select {
	case <-nf.ch:
		t.Log("✓ NodeA established a connection to NodeC whose transport is /p2p-circuit — the boot relay forwarded it")
	case <-time.After(15 * time.Second):
		t.Fatal("NodeA connected to C but NOT via the boot relay circuit transport")
	}
}

// relayConnectedNotifee records the first time a connection to cID is
// established over a /p2p-circuit (relay) transport.
type relayConnectedNotifee struct {
	ch  chan struct{}
	cID peer.ID
}

func (n *relayConnectedNotifee) Connected(_ network.Network, c network.Conn) {
	if c.RemotePeer() == n.cID && strings.Contains(c.RemoteMultiaddr().String(), "p2p-circuit") {
		select {
		case n.ch <- struct{}{}:
		default:
		}
	}
}
func (n *relayConnectedNotifee) Disconnected(network.Network, network.Conn)      {}
func (n *relayConnectedNotifee) OpenedStream(network.Network, network.Stream)     {}
func (n *relayConnectedNotifee) ClosedStream(network.Network, network.Stream)     {}
func (n *relayConnectedNotifee) Listen(network.Network, multiaddr.Multiaddr)      {}
func (n *relayConnectedNotifee) ListenClose(network.Network, multiaddr.Multiaddr) {}

// waitConnectedTo blocks until host h is Connected to peer id, or fails the test
// after a timeout. Used to ensure the boot relay is reachable before we try to
// reserve/dial through it.
func waitConnectedTo(t *testing.T, h interface {
	Network() network.Network
}, id peer.ID, label string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		if h.Network().Connectedness(id) == network.Connected {
			t.Logf("✓ %s connected", label)
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s to connect", label)
		}
		time.Sleep(200 * time.Millisecond)
	}
}
