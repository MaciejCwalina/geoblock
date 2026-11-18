package capture

import (
	"fmt"
	"net/netip"
	"strings"
)

// Endpoint is a TCP/UDP service whose traffic must not be captured.
type Endpoint struct {
	Address netip.Addr
	Port    uint16
}

// BuildFilter returns a BPF expression that keeps IPv4 traffic but drops
// loopback addresses and every excluded endpoint. Excluding the program's own
// Redis and lookup API traffic prevents a feedback loop where each lookup
// generates packets that trigger more lookups.
func BuildFilter(excluded []Endpoint) string {
	parts := []string{"ip", "not net 127.0.0.0/8"}
	seen := make(map[Endpoint]struct{}, len(excluded))
	for _, endpoint := range excluded {
		endpoint.Address = endpoint.Address.Unmap()
		if !endpoint.Address.Is4() {
			continue
		}
		if _, duplicate := seen[endpoint]; duplicate {
			continue
		}
		seen[endpoint] = struct{}{}
		parts = append(parts, fmt.Sprintf("not (host %s and port %d)", endpoint.Address, endpoint.Port))
	}
	return strings.Join(parts, " and ")
}
