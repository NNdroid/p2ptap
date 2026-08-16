package observer

import (
	"net"
	"testing"
)

func TestInterceptorMAC(t *testing.T) {
	t.Log("[observer] InterceptorMAC constant value")
	want := net.HardwareAddr{0x02, 0xca, 0xfe, 0x00, 0x02, 0x54}
	if !interceptorMACEqual(InterceptorMAC, want) {
		t.Errorf("InterceptorMAC = %v, want %v", InterceptorMAC, want)
	} else {
		t.Logf("[observer] ✓ InterceptorMAC=%s", InterceptorMAC)
	}
}

func interceptorMACEqual(a, b net.HardwareAddr) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestPeerInfoDTOZeroValue(t *testing.T) {
	t.Log("[observer] PeerInfoDTO zero value")
	var dto PeerInfoDTO
	if dto.PeerID != "" || dto.NodeName != "" || dto.Role != "" {
		t.Errorf("zero PeerInfoDTO should be empty, got %+v", dto)
	}
	if dto.RTTMs != 0 || dto.TxSpeed != 0 {
		t.Errorf("zero PeerInfoDTO numeric fields should be zero, got %+v", dto)
	}
	t.Log("[observer] ✓ PeerInfoDTO zero value as expected")
}

func TestSpeedTestResultDTO(t *testing.T) {
	t.Log("[observer] SpeedTestResultDTO zero value")
	var r SpeedTestResultDTO
	if r.Mbps != 0 || r.RTTAvg != 0 || r.Jitter != 0 || r.PacketLoss != 0 {
		t.Errorf("zero SpeedTestResultDTO numeric fields should be zero, got %+v", r)
	}
	if r.PeerID != "" || r.NodeName != "" || r.QualityGrade != "" {
		t.Errorf("zero SpeedTestResultDTO string fields should be empty, got %+v", r)
	}
	t.Log("[observer] ✓ SpeedTestResultDTO zero value as expected")
}

func TestPeerMetaDTOFields(t *testing.T) {
	t.Log("[observer] PeerMetaDTO zero value")
	var m PeerMetaDTO
	if m.NodeName != "" || len(m.AdvertisedSubnets) != 0 {
		t.Errorf("zero PeerMetaDTO should be empty, got %+v", m)
	}
	t.Log("[observer] ✓ PeerMetaDTO zero value as expected")
}
