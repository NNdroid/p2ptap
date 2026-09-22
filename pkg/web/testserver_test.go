package web

import (
	"fmt"
	"net"
	"testing"
)

// startTestServerOnFreePort boots a WebUI server on a port the OS picks and
// returns it together with the "host:port" to address it by.
//
// Tests must not hard-code a port here. StartServer retries the SAME address
// (listenTCPWithRetry has no fallback to a different port) and then gives up, so
// anything already holding 18080-18099 — a stale process left behind by an
// earlier run, or a developer's own p2ptap instance — turns the whole package
// red for reasons that have nothing to do with the code under test.
//
// Probing for a free port and then binding it leaves a small race window; a
// lost race just retries against the next candidate.
func startTestServerOnFreePort(t *testing.T, collector *StatsCollector) (*Server, string) {
	t.Helper()
	var lastErr error
	for attempt := 0; attempt < 10; attempt++ {
		probe, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("probe for a free TCP port: %v", err)
		}
		port := probe.Addr().(*net.TCPAddr).Port
		_ = probe.Close()

		srv, err := StartServer(collector, "127.0.0.1", "", port, nil, "", nil)
		if err == nil {
			return srv, fmt.Sprintf("127.0.0.1:%d", port)
		}
		lastErr = err
	}
	t.Fatalf("could not start the test WebUI server on any free port: %v", lastErr)
	return nil, ""
}
