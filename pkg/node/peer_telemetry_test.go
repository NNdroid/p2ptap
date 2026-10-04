package node

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"p2ptap/pkg/observer"
)

func TestPeerTelemetrySamplesLocalPayloadWithoutMetadata(t *testing.T) {
	n := &Node{
		perPeerLastTx: make(map[peer.ID]uint64), perPeerLastRx: make(map[peer.ID]uint64),
		perPeerTxSpeed: make(map[peer.ID]uint64), perPeerRxSpeed: make(map[peer.ID]uint64),
	}
	id := peer.ID("test")
	now := time.Now()
	n.recordPeerTxBytes(id, 54)
	n.samplePeerSpeeds([]peer.ID{id}, now)
	if n.peerSpeedMeasured(id) {
		t.Fatal("first baseline is not a measured rate")
	}
	n.recordPeerTxBytes(id, 1500)
	n.recordPeerRxBytes(id, 1000)
	n.samplePeerSpeeds([]peer.ID{id}, now.Add(time.Second))
	tx, rx := n.getPeerSpeed(id)
	if tx != 1500 || rx != 1000 {
		t.Fatalf("rates = %d/%d", tx, rx)
	}
	n.recordPeerTxBytes(id, 100)
	n.samplePeerSpeeds([]peer.ID{id}, now.Add(time.Second+time.Millisecond))
	tx, _ = n.getPeerSpeed(id)
	if tx != 1500 {
		t.Fatalf("tiny read consumed the sampling window: %d", tx)
	}
	n.samplePeerSpeeds([]peer.ID{id}, now.Add(2*time.Second))
	tx, rx = n.getPeerSpeed(id)
	if tx != 100 || rx != 0 {
		t.Fatalf("next interval rates = %d/%d", tx, rx)
	}
	if !n.peerSpeedMeasured(id) {
		t.Fatal("completed sample should be valid")
	}
	dto := observer.PeerInfoDTO{TotalTx: 999999, LinkTotalTx: loadPeerPayloadBytes(&n.peerTxBytes, id),
		LinkTotalRx: loadPeerPayloadBytes(&n.peerRxBytes, id), LinkSpeedMeasured: n.peerSpeedMeasured(id)}
	data, err := json.Marshal(dto)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]interface{}
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got["link_total_tx"] != float64(1654) || got["link_total_rx"] != float64(1000) || got["total_tx"] != float64(999999) {
		t.Fatalf("local/remote totals mixed: %s", data)
	}
}
