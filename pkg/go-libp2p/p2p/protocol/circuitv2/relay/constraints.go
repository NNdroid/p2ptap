package relay

import (
	"errors"
	"slices"
	"sync"
	"time"

	asnutil "github.com/libp2p/go-libp2p-asn-util"
	"github.com/libp2p/go-libp2p/core/peer"

	ma "github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr/net"
)

var (
	errTooManyReservations       = errors.New("too many reservations")
	errTooManyReservationsForIP  = errors.New("too many peers for IP address")
	errTooManyReservationsForASN = errors.New("too many peers for ASN")
)

type peerWithExpiry struct {
	Expiry time.Time
	Peer   peer.ID
}

// constraints implements various reservation constraints
type constraints struct {
	rc *Resources

	mutex sync.Mutex
	total []peerWithExpiry
	ips   map[string][]peerWithExpiry
	asns  map[uint32][]peerWithExpiry
}

// newConstraints creates a new constraints object.
// The methods are *not* thread-safe; an external lock must be held if synchronization
// is required.
func newConstraints(rc *Resources) *constraints {
	return &constraints{
		rc:   rc,
		ips:  make(map[string][]peerWithExpiry),
		asns: make(map[uint32][]peerWithExpiry),
	}
}

// Reserve adds a reservation for a given peer with a given multiaddr.
// If adding this reservation violates IP, ASN, or total reservation constraints, an error is returned.
//
// Validation order matters: cleanupPeer (which drops the peer's previous
// reservation from total/ips/asns) MUST run only after every cap check has
// passed. Removing it before the checks means a refresh that violates a cap
// (peer's IP/ASN/total reservation is over quota) desyncs the peer's
// reservation state — the peer loses its existing constraint footprint while
// r.rsvp still considers it eligible to CONNECT, so the peer becomes
// reservation-eligible without a constraints entry. Reorder the cleanupPeer
// call to AFTER the caps pass and the desync cannot happen: a rejected
// refresh leaves the peer's previous reservation intact.
func (c *constraints) Reserve(p peer.ID, a ma.Multiaddr, expiry time.Time) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	now := time.Now()
	c.cleanup(now)

	// Check caps WITHOUT dropping the peer's existing reservation yet. This
	// means a refresh that would go over quota sees the pre-refresh total,
	// which is the intended semantics (the caller is only allowed to add one
	// fresh reservation at a time; the previous one is replaced at the end of
	// this function, not dropped mid-way).
	//
	// Use countExcluding for the total cap too — a peer refreshing an existing
	// reservation must not be denied just because the pool is at capacity,
	// since the refresh replaces the old entry and adds no net new slot.
	if c.countExcluding(c.total, p) >= c.rc.MaxReservations {
		return errTooManyReservations
	}

	ip, err := manet.ToIP(a)
	if err != nil {
		return errors.New("no IP address associated with peer")
	}

	// Subtract the peer's existing reservation from the effective count for
	// this IP/ASN before comparing: a refresh must not be denied just because
	// the peer already holds one slot against the same cap.
	ipReservations := c.ips[ip.String()]
	if c.countExcluding(ipReservations, p) >= c.rc.MaxReservationsPerIP {
		return errTooManyReservationsForIP
	}

	var asnReservations []peerWithExpiry
	var asn uint32
	if ip.To4() == nil {
		asn = asnutil.AsnForIPv6(ip)
		if asn != 0 {
			asnReservations = c.asns[asn]
			if c.countExcluding(asnReservations, p) >= c.rc.MaxReservationsPerASN {
				return errTooManyReservationsForASN
			}
		}
	}

	// All caps passed. Now swap in the refreshed reservation: drop the
	// peer's previous entry (if any) and commit the new one.
	c.cleanupPeer(p)
	ipReservations = c.ips[ip.String()]

	c.total = append(c.total, peerWithExpiry{Expiry: expiry, Peer: p})
	ipReservations = append(ipReservations, peerWithExpiry{Expiry: expiry, Peer: p})
	c.ips[ip.String()] = ipReservations

	if asn != 0 {
		asnReservations = c.asns[asn]
		asnReservations = append(asnReservations, peerWithExpiry{Expiry: expiry, Peer: p})
		c.asns[asn] = asnReservations
	}
	return nil
}

// countExcluding counts entries in list whose Peer is not p. Used to decide
// whether a peer refreshing an existing reservation is still within the
// per-IP / per-ASN cap, without double-counting the slot it is about to
// replace.
func (c *constraints) countExcluding(list []peerWithExpiry, p peer.ID) int {
	n := 0
	for _, pe := range list {
		if pe.Peer != p {
			n++
		}
	}
	return n
}

func (c *constraints) cleanup(now time.Time) {
	expireFunc := func(pe peerWithExpiry) bool {
		return pe.Expiry.Before(now)
	}
	c.total = slices.DeleteFunc(c.total, expireFunc)
	for k, ipReservations := range c.ips {
		c.ips[k] = slices.DeleteFunc(ipReservations, expireFunc)
		if len(c.ips[k]) == 0 {
			delete(c.ips, k)
		}
	}
	for k, asnReservations := range c.asns {
		c.asns[k] = slices.DeleteFunc(asnReservations, expireFunc)
		if len(c.asns[k]) == 0 {
			delete(c.asns, k)
		}
	}
}

func (c *constraints) cleanupPeer(p peer.ID) {
	removeFunc := func(pe peerWithExpiry) bool {
		return pe.Peer == p
	}
	c.total = slices.DeleteFunc(c.total, removeFunc)
	for k, ipReservations := range c.ips {
		c.ips[k] = slices.DeleteFunc(ipReservations, removeFunc)
		if len(c.ips[k]) == 0 {
			delete(c.ips, k)
		}
	}
	for k, asnReservations := range c.asns {
		c.asns[k] = slices.DeleteFunc(asnReservations, removeFunc)
		if len(c.asns[k]) == 0 {
			delete(c.asns, k)
		}
	}
}
