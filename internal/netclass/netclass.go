// Package netclass decides which side of a packet is the remote peer and
// whether that peer is a public address worth geolocating.
package netclass

import (
	"net/netip"
)

// Direction of a packet relative to this host.
type Direction string

// Directions, used as metric label values.
const (
	Inbound  Direction = "in"
	Outbound Direction = "out"
)

// Flow is the result of classifying a packet.
type Flow struct {
	Remote    netip.Addr
	Direction Direction
}

// specialPurposePrefixes are IPv4 ranges that are not covered by the netip
// helpers but are never globally routable (RFC 6890 and friends).
var specialPurposePrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
}

// IsPublic reports whether address is a globally routable IPv4 unicast
// address. Private, loopback, link-local, multicast, broadcast, unspecified
// and documentation ranges all return false.
func IsPublic(address netip.Addr) bool {
	address = address.Unmap()
	if !address.Is4() {
		return false
	}
	if address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() ||
		address.IsMulticast() || address.IsUnspecified() || address == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		return false
	}
	for _, prefix := range specialPurposePrefixes {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

// Classifier knows the addresses that belong to this host.
type Classifier struct {
	localAddresses map[netip.Addr]struct{}
}

// NewClassifier returns a Classifier for a host owning localAddresses.
func NewClassifier(localAddresses []netip.Addr) *Classifier {
	addressSet := make(map[netip.Addr]struct{}, len(localAddresses))
	for _, address := range localAddresses {
		addressSet[address.Unmap()] = struct{}{}
	}
	return &Classifier{localAddresses: addressSet}
}

func (classifier *Classifier) isLocal(address netip.Addr) bool {
	_, found := classifier.localAddresses[address]
	return found
}

// Classify returns the remote peer of a packet and the direction of travel.
// ok is false when the packet should be ignored: the remote side is not a
// public address, or neither side belongs to this host (forwarded traffic,
// which the INPUT/OUTPUT chains would not affect anyway).
func (classifier *Classifier) Classify(source, destination netip.Addr) (flow Flow, ok bool) {
	source, destination = source.Unmap(), destination.Unmap()
	switch {
	case classifier.isLocal(source):
		flow = Flow{Remote: destination, Direction: Outbound}
	case classifier.isLocal(destination):
		flow = Flow{Remote: source, Direction: Inbound}
	case IsPublic(destination) && !IsPublic(source):
		// Host behind NAT whose address list we do not know.
		flow = Flow{Remote: destination, Direction: Outbound}
	case IsPublic(source) && !IsPublic(destination):
		flow = Flow{Remote: source, Direction: Inbound}
	default:
		return Flow{}, false
	}
	if !IsPublic(flow.Remote) {
		return Flow{}, false
	}
	return flow, true
}
