package node

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/pion/transport/v3"
)

// TestProtectNetListenTCPReturnsUsableListener is the regression guard for the
// ICE TCP listen path. Before protectNet.ListenTCP did its own
// net.ListenConfig, it delegated to pion's stdnet, which calls net.ListenTCP
// with no control hook — so an ICE TCP listener would follow the OS routing
// table and, once the TAP is the default gateway, bind onto the tunnel.
//
// The wrapper must therefore satisfy pion's transport.TCPListener *and* be able
// to hand back connections that still read and write. If *net.TCPConn ever stops
// implementing pion's TCPConn, the AcceptTCP shadow below stops compiling, so
// this test also pins the type-adapter premise.
func TestProtectNetListenTCPReturnsUsableListener(t *testing.T) {
	nt, err := NewProtectNet()
	if err != nil {
		t.Fatalf("NewProtectNet: %v", err)
	}

	listener, err := nt.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	defer listener.Close()

	if listener.Addr().Network() == "" {
		t.Fatalf("listener has no address")
	}
	if p, ok := listener.Addr().(*net.TCPAddr); !ok || p.Port == 0 {
		t.Fatalf("listener bound to %v, want an ephemeral port", listener.Addr())
	}

	// Exercise AcceptTCP end to end: pion gathers TCP host candidates by
	// listening and accepting, so a listener that cannot return a usable
	// transport.TCPConn breaks the whole TCP candidate path.
	conn, err := net.DialTimeout("tcp", listener.Addr().String(), 3*time.Second)
	if err != nil {
		t.Fatalf("dial listener: %v", err)
	}
	defer conn.Close()

	listener.SetDeadline(time.Now().Add(3 * time.Second))
	accepted, err := listener.AcceptTCP()
	if err != nil {
		t.Fatalf("AcceptTCP: %v", err)
	}
	defer accepted.Close()

	// Round-trip bytes through the pion-interface connection to prove it is a
	// live socket, not a stale or half-constructed handle.
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 4)
	accepted.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := io.ReadFull(accepted, buf)
	if err != nil {
		t.Fatalf("read %d/%d bytes: %v", n, len(buf), err)
	}
	if string(buf) != "ping" {
		t.Fatalf("got %q, want %q", buf, "ping")
	}

	// Write back through the pion TCPConn interface.
	if err := accepted.SetWriteDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
	if _, err := accepted.Write([]byte("pong")); err != nil {
		t.Fatalf("accepted.Write: %v", err)
	}
	if _, err := conn.Read(buf[:4]); err != nil {
		t.Fatalf("read reply: %v", err)
	}
}

// TestProtectNetTCPInterfacesAreSatisfied is a compile-time check that both the
// wrapper and its listener adapter really implement pion's interfaces. It also
// pins the premise behind ListenTCP: pion's TCPListener.AcceptTCP returns its
// own TCPConn interface, which net.TCPListener's *net.TCPConn does not match
// positionally, so an AcceptTCP shadow is required rather than a bare
// delegation to stdnet.
func TestProtectNetTCPInterfacesAreSatisfied(t *testing.T) {
	var _ transport.Net = (*protectNet)(nil)
	var _ transport.TCPListener = protectTCPListener{}
	var _ transport.TCPListener = (*protectTCPListener)(nil)
}

// TestProtectNetDialTCPHonnorsRemoteAddress pins the ICE dial path, which
// relies on DialTCP to reach remote TCP candidates (host, server reflexive and
// relayed).
func TestProtectNetDialTCPHonnorsRemoteAddress(t *testing.T) {
	nt, err := NewProtectNet()
	if err != nil {
		t.Fatalf("NewProtectNet: %v", err)
	}

	listener, err := nt.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	defer listener.Close()

	go func() {
		if _, err := listener.Accept(); err != nil {
			return
		}
	}()

	conn, err := nt.DialTCP("tcp4", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatalf("DialTCP: %v", err)
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
	if _, err := conn.Write([]byte("ok")); err != nil {
		t.Fatalf("write over DialTCP connection: %v", err)
	}
}
