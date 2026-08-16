package node

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/pion/transport/v3"
	"github.com/pion/transport/v3/stdnet"
)

// protectNet is a pion transport.Net implementation that pins every socket it
// creates to the physical network interface, exactly like the TCP/QUIC dial
// protection used elsewhere in the node. This is required for the WebRTC ICE
// agent: by default pion's stdnet follows the OS routing table, which — once an
// Exit Node installs a /1 default route pointing at the TAP tunnel — would send
// all WebRTC ICE candidate sockets into the tunnel and break NAT traversal.
//
// Listen sockets (host-candidate gathering + the libp2p WebRTC listener) are
// pinned via listenerProtectControl: a concrete listen IP binds to the NIC that
// owns it, while 0.0.0.0 / :: falls back to the cached default egress
// interface. Dial sockets are pinned via GetSocketControlHook, which binds to
// the default egress (or the owning NIC for a concrete peer IP) and skips
// loopback / link-local / overlay addresses.
//
// All non-socket methods are delegated to the embedded pion stdnet
// implementation so the wrapper is a complete transport.Net.
type protectNet struct {
	base transport.Net
}

// NewProtectNet returns a transport.Net that binds all created sockets to the
// physical interface. It wraps pion's default stdnet implementation and only
// overrides the socket-creation methods.
func NewProtectNet() (transport.Net, error) {
	base, err := stdnet.NewNet()
	if err != nil {
		return nil, fmt.Errorf("create stdnet: %w", err)
	}
	return &protectNet{base: base}, nil
}

func (p *protectNet) ListenPacket(network, address string) (net.PacketConn, error) {
	lc := net.ListenConfig{Control: listenerProtectControl}
	return lc.ListenPacket(context.Background(), network, address)
}

func (p *protectNet) ListenUDP(network string, locAddr *net.UDPAddr) (transport.UDPConn, error) {
	pc, err := ProtectedListenUDP(network, locAddr)
	if err != nil {
		return nil, err
	}
	udp, ok := pc.(*net.UDPConn)
	if !ok {
		pc.Close()
		return nil, fmt.Errorf("ProtectedListenUDP returned %T, expected *net.UDPConn", pc)
	}
	return udp, nil
}

func (p *protectNet) ListenTCP(network string, laddr *net.TCPAddr) (transport.TCPListener, error) {
	return p.base.ListenTCP(network, laddr)
}

func (p *protectNet) Dial(network, address string) (net.Conn, error) {
	return p.base.Dial(network, address)
}

func (p *protectNet) DialUDP(network string, laddr, raddr *net.UDPAddr) (transport.UDPConn, error) {
	// NOTE: we intentionally avoid net.Dialer.DialUDP here because its
	// netip.AddrPort-based signature is a Go 1.26 addition; the string-based
	// Dial keeps this wrapper buildable on Go 1.25+. The ICE agent always dials
	// with a nil laddr, so only the remote address matters.
	if raddr == nil {
		return nil, fmt.Errorf("webrtc dial requires a remote UDP address")
	}
	d := &net.Dialer{Control: GetSocketControlHook("")}
	conn, err := d.Dial(network, raddr.String())
	if err != nil {
		return nil, err
	}
	udp, ok := conn.(*net.UDPConn)
	if !ok {
		conn.Close()
		return nil, fmt.Errorf("net.Dial returned %T, expected *net.UDPConn", conn)
	}
	return udp, nil
}

func (p *protectNet) DialTCP(network string, laddr, raddr *net.TCPAddr) (transport.TCPConn, error) {
	if raddr == nil {
		return nil, fmt.Errorf("webrtc dial requires a remote TCP address")
	}
	d := &net.Dialer{Control: GetSocketControlHook(""), Timeout: 30 * time.Second}
	conn, err := d.Dial(network, raddr.String())
	if err != nil {
		return nil, err
	}
	tcp, ok := conn.(*net.TCPConn)
	if !ok {
		conn.Close()
		return nil, fmt.Errorf("net.Dial returned %T, expected *net.TCPConn", conn)
	}
	return tcp, nil
}

func (p *protectNet) ResolveIPAddr(network, address string) (*net.IPAddr, error) {
	return p.base.ResolveIPAddr(network, address)
}

func (p *protectNet) ResolveUDPAddr(network, address string) (*net.UDPAddr, error) {
	return p.base.ResolveUDPAddr(network, address)
}

func (p *protectNet) ResolveTCPAddr(network, address string) (*net.TCPAddr, error) {
	return p.base.ResolveTCPAddr(network, address)
}

func (p *protectNet) Interfaces() ([]*transport.Interface, error) {
	return p.base.Interfaces()
}

func (p *protectNet) InterfaceByIndex(index int) (*transport.Interface, error) {
	return p.base.InterfaceByIndex(index)
}

func (p *protectNet) InterfaceByName(name string) (*transport.Interface, error) {
	return p.base.InterfaceByName(name)
}

func (p *protectNet) CreateDialer(dialer *net.Dialer) transport.Dialer {
	return p.base.CreateDialer(dialer)
}
