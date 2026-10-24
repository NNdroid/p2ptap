package main

import (
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/relay"
)

// TestRelayResourcesNoCircuitLimit locks the one relay value that must not
// change: Limit stays nil.
//
// A non-nil Limit makes the relay SetDeadline(now+Duration) on both directions
// of every relayed connection and wrap each direction in
// io.LimitReader(..., Data), and relay v2 has no circuit-renewal message, so a
// circuit simply dies. This was 5 minutes / 512 MiB, which capped every p2ptap
// peer-to-peer session riding on a circuit at 5 minutes and filled the data
// quota in seconds on a gigabit link. The envelope below is the rest of the
// same table; the Limit assertion is the one that catches a regression no one
// notices from the relay's advertised capacity.
func TestRelayResourcesNoCircuitLimit(t *testing.T) {
	if got := relayResources().Limit; got != nil {
		t.Fatalf("relayResources().Limit = %+v, want nil (an unlimited circuit relay)", got)
	}
}

// TestRelayResourcesEnvelope records the reservation-side envelope, so a change
// to any of these values has to be a deliberate one. The value a regression
// here is hardest to spot is MaxReservationsPerPeer: it is dead code in
// libp2p, so setting it looks like it takes effect.
func TestRelayResourcesEnvelope(t *testing.T) {
	res := relayResources()

	cases := []struct {
		name string
		got  int
		want int
	}{
		{"MaxReservations", res.MaxReservations, relayMaxReservations},
		{"MaxCircuits", res.MaxCircuits, relayMaxCircuits},
		{"BufferSize", res.BufferSize, relayBufferSize},
		{"MaxReservationsPerIP", res.MaxReservationsPerIP, 64},
		{"MaxReservationsPerASN", res.MaxReservationsPerASN, 256},
		{"MaxReservationsPerPeer", res.MaxReservationsPerPeer, relay.DefaultResources().MaxReservationsPerPeer},
	}
	for _, tc := range cases {
		if tc.got != tc.want {
			t.Errorf("%s = %d, want %d", tc.name, tc.got, tc.want)
		}
	}

	if got := res.ReservationTTL; got != time.Hour {
		t.Errorf("ReservationTTL = %v, want 1h", got)
	}
	// The reservation TTL must not be mistaken for a circuit lifetime: it bounds
	// how long a reservation is offered, and it is deliberately far longer than
	// any circuit is likely to live.
}

// TestRelayResourceDerivations checks the resource-manager inputs derived from
// the relay envelope, which relayResourceManager reads. They are derived rather
// than hard-coded so the relay cannot advertise a circuit budget its resource
// manager silently refuses.
func TestRelayResourceDerivations(t *testing.T) {
	if relayStreamPerDir != 2*relayMaxCircuits {
		t.Errorf("relayStreamPerDir = %d, want 2*relayMaxCircuits = %d", relayStreamPerDir, 2*relayMaxCircuits)
	}
	if relayCircuitMemory != 4*relayMaxCircuits*relayBufferSize {
		t.Errorf("relayCircuitMemory = %d, want 4*relayMaxCircuits*relayBufferSize = %d",
			relayCircuitMemory, 4*relayMaxCircuits*relayBufferSize)
	}
	// Each circuit holds one stream per direction, so the per-direction ceiling
	// must clear MaxCircuits before auth, boot-relay tunnel and control streams
	// are counted.
	if relayStreamPerDir < relayMaxCircuits {
		t.Errorf("relayStreamPerDir = %d does not clear MaxCircuits = %d", relayStreamPerDir, relayMaxCircuits)
	}
}
