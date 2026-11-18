// Package metrics defines the Prometheus metrics exported by geoblock. Label
// values are bounded: direction is "in" or "out", country is an ISO code or
// "unknown", so the series count stays small regardless of traffic.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

// UnknownCountry labels traffic whose remote address is not resolved yet.
const UnknownCountry = "unknown"

// Metrics groups every collector so it can be passed around explicitly.
type Metrics struct {
	Bytes          *prometheus.CounterVec
	Packets        *prometheus.CounterVec
	BlockedIPs     prometheus.Counter
	Lookups        *prometheus.CounterVec
	LookupsDropped prometheus.Counter
}

// New creates the collectors and registers them with registerer.
func New(registerer prometheus.Registerer) *Metrics {
	collectors := &Metrics{
		Bytes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "geoblock_bytes_total",
			Help: "Bytes seen on the wire to or from public addresses, by direction and remote country.",
		}, []string{"direction", "country"}),
		Packets: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "geoblock_packets_total",
			Help: "Packets seen to or from public addresses, by direction and remote country.",
		}, []string{"direction", "country"}),
		BlockedIPs: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "geoblock_blocked_ips_total",
			Help: "Remote addresses for which firewall rules were added.",
		}),
		Lookups: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "geoblock_lookups_total",
			Help: "Country lookups by layer (memory, redis, api) and result (ok, miss, error).",
		}, []string{"source", "result"}),
		LookupsDropped: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "geoblock_lookup_queue_dropped_total",
			Help: "Addresses not queued for lookup because the queue was full.",
		}),
	}
	registerer.MustRegister(
		collectors.Bytes,
		collectors.Packets,
		collectors.BlockedIPs,
		collectors.Lookups,
		collectors.LookupsDropped,
	)
	return collectors
}

// ObservePacket counts one packet of size bytes.
func (collectors *Metrics) ObservePacket(direction, country string, size int) {
	if country == "" {
		country = UnknownCountry
	}
	collectors.Packets.WithLabelValues(direction, country).Inc()
	collectors.Bytes.WithLabelValues(direction, country).Add(float64(size))
}

// ObserveLookup counts one lookup step.
func (collectors *Metrics) ObserveLookup(source, result string) {
	collectors.Lookups.WithLabelValues(source, result).Inc()
}

// BlockedAddress counts one newly blocked remote address.
func (collectors *Metrics) BlockedAddress() {
	collectors.BlockedIPs.Inc()
}

// QueueFull counts one address that could not be queued for lookup.
func (collectors *Metrics) QueueFull() {
	collectors.LookupsDropped.Inc()
}
