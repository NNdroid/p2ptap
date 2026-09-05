package web

import (
	"net"
	"testing"
)

func TestListenAllSpecificIPv4FailureFallsBackToLoopbackOnly(t *testing.T) {
	s := &Server{
		listenIP:   "192.0.2.254", // TEST-NET-1: must not be assigned locally.
		listenIPv6: "",
		port:       0,
	}

	listeners, err := s.listenAll()
	if err != nil {
		t.Fatalf("listenAll: %v", err)
	}
	defer func() {
		for _, ln := range listeners {
			_ = ln.Close()
		}
	}()
	if len(listeners) != 1 {
		t.Fatalf("listener count = %d, want 1", len(listeners))
	}
	tcp, ok := listeners[0].Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("listener address type = %T, want *net.TCPAddr", listeners[0].Addr())
	}
	if !tcp.IP.IsLoopback() {
		t.Fatalf("specific-IP bind failure broadened listener to %s; want loopback only", tcp.IP)
	}
}

func TestListenAllExplicitWildcardRemainsWildcard(t *testing.T) {
	s := &Server{listenIP: "0.0.0.0", listenIPv6: "", port: 0}
	listeners, err := s.listenAll()
	if err != nil {
		t.Fatalf("listenAll: %v", err)
	}
	defer func() {
		for _, ln := range listeners {
			_ = ln.Close()
		}
	}()
	if len(listeners) != 1 {
		t.Fatalf("listener count = %d, want 1", len(listeners))
	}
	tcp := listeners[0].Addr().(*net.TCPAddr)
	if !tcp.IP.IsUnspecified() {
		t.Fatalf("explicit wildcard bound to %s, want unspecified address", tcp.IP)
	}
}
