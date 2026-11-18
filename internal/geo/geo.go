// Package geo resolves IPv4 addresses to countries through a chain of
// caches (in-process memory, then Redis) in front of a rate-limited HTTP API.
package geo

import (
	"context"
	"errors"
	"net/netip"
)

// Location is the subset of geolocation data the program needs.
type Location struct {
	CountryCode string `json:"countryCode"`
	Country     string `json:"country"`
}

// ErrNotFound is returned by a Cache when it has no entry for an address.
var ErrNotFound = errors.New("not in cache")

// Locator resolves an address to a Location, typically over the network.
type Locator interface {
	Locate(ctx context.Context, address netip.Addr) (Location, error)
}

// Cache stores resolved locations. Get returns ErrNotFound on a miss.
type Cache interface {
	Get(ctx context.Context, address netip.Addr) (Location, error)
	Set(ctx context.Context, address netip.Addr, location Location) error
}
