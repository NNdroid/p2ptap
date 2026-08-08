package tap

import (
	"bytes"
	"testing"
)

func TestMemTAPPairCommunication(t *testing.T) {
	tapA, tapB := NewMemTAPPair("tapA", "tapB")
	defer tapA.Close()
	defer tapB.Close()

	if err := tapA.ConfigureIP("10.0.0.1/24", "fd00::1/64"); err != nil {
		t.Fatalf("ConfigureIP on tapA failed: %v", err)
	}

	payload := []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x02, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x08, 0x00, 'P', 'I', 'N', 'G'}

	// Write from tapA to tapB
	n, err := tapA.Write(payload)
	if err != nil || n != len(payload) {
		t.Fatalf("tapA Write failed: n=%d, err=%v", n, err)
	}

	readBuf := make([]byte, 1500)
	rn, err := tapB.Read(readBuf)
	if err != nil {
		t.Fatalf("tapB Read failed: %v", err)
	}

	if !bytes.Equal(readBuf[:rn], payload) {
		t.Errorf("Data read on tapB does not match written data! Got %v", readBuf[:rn])
	}
}

func TestMemTAPSetMAC(t *testing.T) {
	dev, peer := NewMemTAPPair("test_p2ptap", "test_p2ptap_peer")
	defer dev.Close()
	defer peer.Close()

	if err := dev.SetMAC("02:00:00:00:00:01"); err != nil {
		t.Fatalf("SetMAC failed: %v", err)
	}
	if err := dev.SetMAC("not-a-mac"); err == nil {
		t.Fatal("SetMAC accepted an invalid MAC address")
	}
}
