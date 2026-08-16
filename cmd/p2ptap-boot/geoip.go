package main

import (
	"net"
	"sync"

	"github.com/oschwald/geoip2-golang"
)

// GeoIPResolver wraps a MaxMind GeoLite2-City database for offline IP geolocation.
// It is optional: if the database file is not found on startup the resolver is nil
// and all geographic features are silently disabled (no error to the caller).
type GeoIPResolver struct {
	mu sync.RWMutex
	db *geoip2.Reader
}

// newGeoIPResolver opens the GeoLite2-City.mmdb file at dbPath. Returns a non-nil
// error only when the file exists but cannot be opened; a missing file returns
// (nil, nil) so callers can treat absence as "disabled" without a fatal error.
func newGeoIPResolver(dbPath string) (*GeoIPResolver, error) {
	db, err := geoip2.Open(dbPath)
	if err != nil {
		return nil, err
	}
	return &GeoIPResolver{db: db}, nil
}

// Lookup resolves an IP string to geographic coordinates and place names.
// Returns zero values for private / loopback / invalid / unresolvable addresses.
func (r *GeoIPResolver) Lookup(ipStr string) (lat, lon float64, country, city string) {
	if r == nil {
		return
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return
	}
	// Skip private/loopback/link-local addresses — they have no meaningful geolocation.
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
		return
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.db == nil {
		return
	}
	record, err := r.db.City(ip)
	if err != nil {
		return
	}
	lat = record.Location.Latitude
	lon = record.Location.Longitude
	if name, ok := record.Country.Names["en"]; ok {
		country = name
	}
	if name, ok := record.City.Names["en"]; ok {
		city = name
	}
	return
}

// Available reports whether the GeoIP database is loaded and ready.
func (r *GeoIPResolver) Available() bool {
	return r != nil && r.db != nil
}

// Close releases the database file handle.
func (r *GeoIPResolver) Close() {
	if r == nil || r.db == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	_ = r.db.Close()
	r.db = nil
}
