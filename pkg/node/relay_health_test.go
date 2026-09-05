package node

import (
	"errors"
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
)

func TestRelayPermissionDeniedClassification(t *testing.T) {
	for _, msg := range []string{
		"error opening relay circuit: PERMISSION_DENIED (202)",
		"relay permission denied by ACL",
	} {
		if !isRelayPermissionDenied(errors.New(msg)) {
			t.Fatalf("%q was not classified as permission denied", msg)
		}
	}
	for _, msg := range []string{
		"CONNECTION_FAILED (203)",
		"dial backoff",
		"context deadline exceeded",
	} {
		if isRelayPermissionDenied(errors.New(msg)) {
			t.Fatalf("%q was incorrectly classified as permission denied", msg)
		}
	}
}

func TestRelayPermissionDeniedTripsTargetCooldown(t *testing.T) {
	n := &Node{relayControlHealth: make(map[peer.ID]relayControlFailureState)}
	target := peer.ID("relay-denied-target")

	for i := 1; i <= relayPermissionDenyThreshold; i++ {
		n.recordRelayControlFailure(target, errors.New("PERMISSION_DENIED (202), attempt "+string(rune('0'+i))))
	}
	if remaining := n.relayPermissionCooldownRemaining(target); remaining <= 0 {
		t.Fatal("repeated permission denials did not trip the target cooldown")
	}
	if err := n.relayPermissionCooldownError(target); err == nil {
		t.Fatal("cooling target was allowed to dial immediately")
	}
	if detail, ok := n.recentRelayControlFailure(target, relayFailureResetWindow); !ok || detail == "" {
		t.Fatalf("recent failure not exposed for diagnostics: ok=%v detail=%q", ok, detail)
	}

	n.clearRelayControlFailure(target)
	if remaining := n.relayPermissionCooldownRemaining(target); remaining != 0 {
		t.Fatalf("successful recovery did not clear cooldown: %v", remaining)
	}
}
