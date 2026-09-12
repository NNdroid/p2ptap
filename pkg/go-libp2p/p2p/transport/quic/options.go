package libp2pquic

import p2ptls "github.com/libp2p/go-libp2p/p2p/security/tls"

// Option is a function that configures the QUIC transport.
type Option func(o *transportConfig) error

type transportConfig struct {
	tlsIdentityOpts []p2ptls.IdentityOption
}

// WithTLSIdentityOption passes the given p2ptls.IdentityOption through to the
// TLS identity used by the QUIC transport.
func WithTLSIdentityOption(opt ...p2ptls.IdentityOption) Option {
	return func(c *transportConfig) error {
		c.tlsIdentityOpts = append(c.tlsIdentityOpts, opt...)
		return nil
	}
}

// NOTE (p2ptap): outgoing QUIC ClientHello SNI is configured centrally in the
// p2ptls identity (see p2p/security/tls SetDialServerName + ConfigForPeer), NOT
// here — so TLS-over-TCP and QUIC dials share ONE server_name setting, matching
// how both transports obtain their tls.Config from the same Identity. See
// pkg/go-libp2p/LOCAL_PATCHES.md.
