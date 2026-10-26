package node

import (
	"testing"

	"p2ptap/pkg/config"
	"p2ptap/pkg/routing"
)

// TestPackRelayFrameHeaderVersion selects the relay header version from the
// running config and honours a live config save without rebuilding the Node.
func TestPackRelayFrameHeaderVersion(t *testing.T) {
	dst := mustPeerID(t)
	src := mustPeerID(t)
	payload := []byte("end-to-end encrypted inner frame")

	for _, tc := range []struct {
		name string
		flag bool
		want byte
	}{
		{name: "default v2", flag: false, want: routing.RelayHeaderVersion},
		{name: "compact v3", flag: true, want: routing.RelayHeaderVersionV3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n := &Node{Config: &config.Config{RelayHeaderMultihash: tc.flag}}
			buf, err := n.packRelayFrame(dst, src, 2, payload)
			if err != nil {
				t.Fatalf("packRelayFrame: %v", err)
			}
			if buf[0] != tc.want {
				t.Fatalf("header version = 0x%02x, want 0x%02x", buf[0], tc.want)
			}
			gotDst, gotSrc, gotTTL, gotPayload, err := routing.UnpackRelayFrame(buf)
			if err != nil {
				t.Fatalf("UnpackRelayFrame: %v", err)
			}
			if gotDst != dst || gotSrc != src || gotTTL != 2 || string(gotPayload) != string(payload) {
				t.Fatalf("round trip mismatch: %s/%s/%d/%q", gotDst, gotSrc, gotTTL, gotPayload)
			}
		})
	}
}

// TestPackRelayFrameHeaderVersionHotReload pins the reload semantics: the flag
// is read per frame through the atomic snapshot, so flipping it must change the
// emitted header without a restart.
func TestPackRelayFrameHeaderVersionHotReload(t *testing.T) {
	dst := mustPeerID(t)
	src := mustPeerID(t)
	n := &Node{Config: &config.Config{}}

	versionOf := func(label string, want byte) {
		t.Helper()
		buf, err := n.packRelayFrame(dst, src, 1, []byte("x"))
		if err != nil {
			t.Fatalf("%s: packRelayFrame: %v", label, err)
		}
		if buf[0] != want {
			t.Fatalf("%s: header version = 0x%02x, want 0x%02x", label, buf[0], want)
		}
	}

	versionOf("before reload", routing.RelayHeaderVersion)

	n.SetConfig(&config.Config{RelayHeaderMultihash: true})
	versionOf("after reload", routing.RelayHeaderVersionV3)

	// And back again, so the reload is a genuine toggle and not a latch.
	n.SetConfig(&config.Config{})
	versionOf("after toggle back", routing.RelayHeaderVersion)
}

// TestPackRelayFrameHeaderVersionNilConfig keeps a bare test Node from panicking
// in the per-frame TX path; it must fall back to the default header.
func TestPackRelayFrameHeaderVersionNilConfig(t *testing.T) {
	n := &Node{}
	buf, err := n.packRelayFrame(mustPeerID(t), mustPeerID(t), 1, []byte("x"))
	if err != nil {
		t.Fatalf("packRelayFrame: %v", err)
	}
	if buf[0] != routing.RelayHeaderVersion {
		t.Fatalf("header version = 0x%02x, want 0x%02x", buf[0], routing.RelayHeaderVersion)
	}
}
