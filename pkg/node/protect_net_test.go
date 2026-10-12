package node

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/pion/transport/v3"
)

// startProtectedTCPListener starts a protected TCP listener on an ephemeral
// port and returns it together with the address a dialer must use to reach it.
//
// The bind address stays 0.0.0.0 so the listener really exercises
// listenerProtectControl's unspecified-address branch — the branch an ICE TCP
// listener hits — instead of the concrete-IP shortcut. But 0.0.0.0 is a bind
// wildcard, not a routable destination: a connect() to it is refused outright
// on macOS ("can't assign requested address") and refused or timed out on
// Linux. Only Windows happens to route 0.0.0.0 to localhost, which is exactly
// why this test passed on the dev box and broke on every unix CI runner.
//
// The pinned NIC's own address is reachable whether or not the
// SO_BINDTODEVICE / IP_BOUND_IF pin actually took effect, so it is the correct
// dial target in both cases. Candidates are ordered most-likely first, with
// loopback as the last resort.
func startProtectedTCPListener(t *testing.T) (transport.TCPListener, []*net.TCPAddr) {
	t.Helper()

	nt, err := NewProtectNet()
	if err != nil {
		t.Fatalf("NewProtectNet: %v", err)
	}

	listener, err := nt.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}

	addr := listener.Addr()
	if addr.Network() == "" {
		t.Fatalf("listener has no address")
	}
	bound, ok := addr.(*net.TCPAddr)
	if !ok || bound.Port == 0 {
		t.Fatalf("listener bound to %v, want an ephemeral port", addr)
	}

	port := bound.Port

	// Build an ordered candidate list: the pinned NIC's own addresses first
	// (that is the address a pinned socket is actually reachable on), then the
	// rest of the machine, then loopback. Trying them in order rather than
	// guessing keeps the test honest on hosts whose default-egress interface
	// resolution and the kernel pin disagree.
	var remotes []*net.TCPAddr
	seen := map[string]bool{}
	addAddr := func(ifName string) {
		addrs := []net.Addr{}
		if ifc, err := net.InterfaceByName(ifName); err == nil {
			addrs, _ = ifc.Addrs()
		}
		for _, a := range addrs {
			ipNet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			// v4 only: the listener was opened as tcp4, and a v4 bind is not
			// reachable via a v6 address. IsGlobalUnicast is deliberately not
			// used — it rejects RFC1918, which is exactly what CI runners use.
			ip4 := ipNet.IP.To4()
			if ip4 == nil || ip4[0] == 0 ||
				ip4.IsLoopback() || ip4.IsLinkLocalUnicast() || ip4.IsMulticast() {
				continue
			}
			if seen[ip4.String()] {
				continue
			}
			seen[ip4.String()] = true
			remotes = append(remotes, &net.TCPAddr{IP: ip4, Port: port})
		}
	}

	if ifName := listenerInterfaceForAddress(addr.String()); ifName != "" {
		addAddr(ifName)
	}
	ifaces, _ := net.Interfaces()
	for _, ifc := range ifaces {
		addAddr(ifc.Name)
	}
	// Loopback last: a listener bound to the egress NIC is unreachable via
	// loopback, but this is the right target when the pin took no effect.
	remotes = append(remotes, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: port})

	return listener, remotes
}

// dialFirst returns the first address in remotes that accepts a connection,
// dialing with the ordinary stdlib listener path. Only one connection is ever
// established, so the caller's AcceptTCP picks it up cleanly.
func dialFirst(t *testing.T, remotes []*net.TCPAddr) net.Conn {
	t.Helper()
	var lastErr error
	for _, remote := range remotes {
		conn, err := net.DialTimeout("tcp4", remote.String(), 3*time.Second)
		if err == nil {
			return conn
		}
		lastErr = err
	}
	if lastErr == nil {
		t.Fatalf("no candidate addresses available to dial")
	}
	t.Fatalf("dial listener via %v: %v", remotes, lastErr)
	return nil
}

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
	listener, remotes := startProtectedTCPListener(t)
	defer listener.Close()

	// Exercise AcceptTCP end to end: pion gathers TCP host candidates by
	// listening and accepting, so a listener that cannot return a usable
	// transport.TCPConn breaks the whole TCP candidate path.
	conn := dialFirst(t, remotes)
	defer conn.Close()

	listener.SetDeadline(time.Now().Add(5 * time.Second))
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
	accepted.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := io.ReadFull(accepted, buf)
	if err != nil {
		t.Fatalf("read %d/%d bytes: %v", n, len(buf), err)
	}
	if string(buf) != "ping" {
		t.Fatalf("got %q, want %q", buf, "ping")
	}

	// Write back through the pion TCPConn interface.
	if err := accepted.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
	if _, err := accepted.Write([]byte("pong")); err != nil {
		t.Fatalf("accepted.Write: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
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
	listener, remotes := startProtectedTCPListener(t)
	defer listener.Close()

	go func() {
		if _, err := listener.Accept(); err == nil {
			return
		}
	}()

	nt, err := NewProtectNet()
	if err != nil {
		t.Fatalf("NewProtectNet: %v", err)
	}

	var conn transport.TCPConn
	var lastErr error
	for _, remote := range remotes {
		conn, lastErr = nt.DialTCP("tcp4", nil, remote)
		if conn != nil {
			break
		}
	}
	if conn == nil {
		t.Fatalf("DialTCP via %v: %v", remotes, lastErr)
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
	if _, err := conn.Write([]byte("ok")); err != nil {
		t.Fatalf("write over DialTCP connection: %v", err)
	}
}
