package node

import (
	"time"

	libp2pconnmgr "github.com/libp2p/go-libp2p/core/connmgr"
	"github.com/libp2p/go-libp2p/core/peer"
	connmgr "github.com/libp2p/go-libp2p/p2p/net/connmgr"
	"github.com/multiformats/go-multiaddr"
)

// ConnManager sizing. libp2p's built-in default (160/192 connections, a 1 min
// grace period and a trim pass every 10 s) is tuned for public networks of
// strangers, not for a p2ptap mesh where every link is intentional. Under load
// the default silently closes the lowest-value peer's connections on every trim
// pass, so the watermarks are raised to a scale the mesh actually needs. The
// boot node runs the same numbers for the same reason.
const (
	connMgrLowWater      = 2048
	connMgrHighWater     = 8192
	connMgrGracePeriod   = 30 * time.Second
	connMgrSilencePeriod = time.Hour
)

// bootstrapConnProtectTag exempts a peer from ConnManager trimming. Protect()
// is keyed by peer ID and persists across connection churn, so a link that
// drops and is re-established later stays protected; trim skips any peer
// carrying a protection tag.
const bootstrapConnProtectTag = "p2ptap-keep"

// buildConnManager constructs the node's ConnManager and protects every peer
// whose link must never be trimmed: bootstrap peers and statically configured
// peers.
//
// Bootstrap peers are the worst possible victims of trimming. Their links carry
// the relay/data-plane and the SeqSync control plane, so they look exactly like
// idle low-value connections — peerPingPongLoop deliberately skips them, so
// nothing else marks them as recently active. A trimmed bootstrap link then
// presents as "the peer is intermittently unreachable", and it is only noticed
// by bootstrapKeepAliveLoop after Connectedness has already flipped.
//
// Unparseable or peer-less static peer strings are skipped rather than
// fatal: a typo must not prevent the node from coming up.
//
// Returns the number of distinct peers that ended up protected.
func buildConnManager(bootstrapPeers []peer.AddrInfo, staticPeers []string) (libp2pconnmgr.ConnManager, int, error) {
	cm, err := connmgr.NewConnManager(connMgrLowWater, connMgrHighWater,
		connmgr.WithGracePeriod(connMgrGracePeriod),
		connmgr.WithSilencePeriod(connMgrSilencePeriod),
	)
	if err != nil {
		return nil, 0, err
	}

	protected := map[peer.ID]struct{}{}
	for i := range bootstrapPeers {
		if bootstrapPeers[i].ID == "" {
			continue
		}
		cm.Protect(bootstrapPeers[i].ID, bootstrapConnProtectTag)
		protected[bootstrapPeers[i].ID] = struct{}{}
	}
	for _, sStr := range staticPeers {
		ma, err := multiaddr.NewMultiaddr(sStr)
		if err != nil {
			continue
		}
		info, err := peer.AddrInfoFromP2pAddr(ma)
		if err != nil {
			continue
		}
		if info.ID == "" {
			continue
		}
		cm.Protect(info.ID, bootstrapConnProtectTag)
		protected[info.ID] = struct{}{}
	}

	return cm, len(protected), nil
}
