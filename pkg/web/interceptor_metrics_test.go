package web

import (
	"bytes"
	"encoding/json"
	"math"
	"testing"

	"p2ptap/pkg/config"
)

func tapHTTPBody(t *testing.T, response []byte) []byte {
	t.Helper()
	parts := bytes.SplitN(response, []byte("\r\n\r\n"), 2)
	if len(parts) != 2 {
		t.Fatalf("malformed HTTP response: %q", response)
	}
	return parts[1]
}

func TestTAPInterceptorMetricsUseProbeResultsWithoutFabrication(t *testing.T) {
	collector := NewStatsCollector()
	collector.ProbePeerSpeedTest = func(peerID string) *SpeedTestResultDTO {
		return &SpeedTestResultDTO{
			PeerID: peerID, Mbps: 7.25, RTTMin: 321.1, RTTAvg: 654.2,
			RTTMax: 987.3, Jitter: 111.4, PacketLoss: 0.2,
			QualityGrade: "MEASURED", MeasurementNote: "fixture probe",
		}
	}

	rtts := []float64{10, 20, 0, 50}
	probeIndex := 0
	collector.ProbePeerEcho = func(peerID string) *PeerEchoResultDTO {
		rtt := rtts[probeIndex]
		probeIndex++
		return &PeerEchoResultDTO{PeerID: peerID, Success: rtt > 0, RTTMs: rtt}
	}

	collector.ProbeTapForward = func(peerID string) *TapProbeResultDTO {
		return &TapProbeResultDTO{PeerID: peerID, Success: true, RTTMills: 432, SentBytes: 64}
	}

	it := NewTAPInterceptor("10.0.0.254", "", 80, collector, config.DefaultConfig(), "")

	speedResp := it.processHTTP([]byte("GET /api/speedtest?peer_id=peer-a HTTP/1.1\r\nHost: tap\r\n\r\n"))
	if !bytes.Contains(speedResp, []byte("HTTP/1.1 200 OK")) {
		t.Fatalf("speedtest status: %q", speedResp)
	}
	var speed SpeedTestResultDTO
	if err := json.Unmarshal(tapHTTPBody(t, speedResp), &speed); err != nil {
		t.Fatal(err)
	}
	if speed.Mbps != 7.25 || speed.RTTAvg != 654.2 || speed.Jitter != 111.4 || speed.MeasurementNote != "fixture probe" {
		t.Fatalf("speedtest result was altered/fabricated: %+v", speed)
	}

	pingResp := it.processHTTP([]byte("GET /api/ping?peer_id=peer-a HTTP/1.1\r\nHost: tap\r\n\r\n"))
	var ping PingResultDTO
	if err := json.Unmarshal(tapHTTPBody(t, pingResp), &ping); err != nil {
		t.Fatal(err)
	}
	if !ping.Success || ping.Probes != 4 || ping.Replies != 3 || ping.PacketLoss != 0.25 {
		t.Fatalf("unexpected live ping counts: %+v", ping)
	}
	if math.Abs(ping.RTTAvgMs-80.0/3.0) > 0.001 || math.Abs(ping.JitterMs-20) > 0.001 {
		t.Fatalf("unexpected live ping timing: %+v", ping)
	}

	tapResp := it.processHTTP([]byte("POST /api/tap/forward-test HTTP/1.1\r\nContent-Length: 20\r\n\r\n{\"peer_id\":\"peer-a\"}"))
	var tapResult TapProbeResultDTO
	if err := json.Unmarshal(tapHTTPBody(t, tapResp), &tapResult); err != nil {
		t.Fatal(err)
	}
	if !tapResult.Success || tapResult.RTTMills != 432 || tapResult.SentBytes != 64 {
		t.Fatalf("TAP probe result was altered: %+v", tapResult)
	}

	notFound := it.processHTTP([]byte("GET /api/not-real HTTP/1.1\r\nHost: tap\r\n\r\n"))
	if !bytes.Contains(notFound, []byte("HTTP/1.1 404 Not Found")) || bytes.Contains(notFound, []byte("<!DOCTYPE html>")) {
		t.Fatalf("unsupported API must be a JSON 404, got %q", notFound)
	}
}
