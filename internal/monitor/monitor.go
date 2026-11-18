// Package monitor ties packet classification, country lookup, metrics and
// blocking together. The capture path (HandlePacket) only touches in-memory
// state; anything that needs network I/O is handed to a deduplicated queue
// served by background workers.
package monitor

import (
	"context"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/MaciejCwalina/go_prometheus_packet_monitoring/internal/firewall"
	"github.com/MaciejCwalina/go_prometheus_packet_monitoring/internal/geo"
	"github.com/MaciejCwalina/go_prometheus_packet_monitoring/internal/netclass"
)

// Resolver is the lookup chain used by the monitor.
type Resolver interface {
	// Cached must not block on I/O.
	Cached(address netip.Addr) (geo.Location, bool)
	Resolve(ctx context.Context, address netip.Addr) (geo.Location, geo.Source, error)
}

// Recorder receives traffic and queue statistics.
type Recorder interface {
	ObservePacket(direction, country string, size int)
	BlockedAddress()
	QueueFull()
}

// Policy decides which countries are blocked.
type Policy struct {
	blockedCountries map[string]struct{}
}

// NewPolicy returns a Policy blocking the given ISO country codes.
func NewPolicy(countryCodes []string) Policy {
	blockedCountries := make(map[string]struct{}, len(countryCodes))
	for _, countryCode := range countryCodes {
		blockedCountries[strings.ToUpper(countryCode)] = struct{}{}
	}
	return Policy{blockedCountries: blockedCountries}
}

// ShouldBlock reports whether traffic from location must be dropped.
func (policy Policy) ShouldBlock(location geo.Location) bool {
	if location.CountryCode == "" {
		return false
	}
	_, found := policy.blockedCountries[strings.ToUpper(location.CountryCode)]
	return found
}

// Options tunes the background lookup machinery.
type Options struct {
	Workers    int
	QueueSize  int
	RetryAfter time.Duration
}

// DefaultOptions are used for any zero field in Options.
var DefaultOptions = Options{Workers: 4, QueueSize: 1024, RetryAfter: 5 * time.Minute}

// Monitor processes captured packets.
type Monitor struct {
	classifier *netclass.Classifier
	resolver   Resolver
	firewall   firewall.Firewall
	policy     Policy
	recorder   Recorder
	logger     *slog.Logger
	options    Options
	now        func() time.Time

	queue chan netip.Addr

	pendingMutex sync.Mutex
	pending      map[netip.Addr]struct{}
	retryAfter   map[netip.Addr]time.Time
}

// New creates a Monitor. Call Run to start its workers.
func New(
	classifier *netclass.Classifier,
	resolver Resolver,
	blocker firewall.Firewall,
	policy Policy,
	recorder Recorder,
	logger *slog.Logger,
	options Options,
) *Monitor {
	if options.Workers <= 0 {
		options.Workers = DefaultOptions.Workers
	}
	if options.QueueSize <= 0 {
		options.QueueSize = DefaultOptions.QueueSize
	}
	if options.RetryAfter <= 0 {
		options.RetryAfter = DefaultOptions.RetryAfter
	}
	return &Monitor{
		classifier: classifier,
		resolver:   resolver,
		firewall:   blocker,
		policy:     policy,
		recorder:   recorder,
		logger:     logger,
		options:    options,
		now:        time.Now,
		queue:      make(chan netip.Addr, options.QueueSize),
		pending:    make(map[netip.Addr]struct{}),
		retryAfter: make(map[netip.Addr]time.Time),
	}
}

// HandlePacket records one captured IPv4 packet. It never blocks on network
// I/O: unknown addresses are queued for the background workers.
func (monitor *Monitor) HandlePacket(source, destination netip.Addr, size int) {
	flow, ok := monitor.classifier.Classify(source, destination)
	if !ok {
		return
	}

	location, found := monitor.resolver.Cached(flow.Remote)
	monitor.recorder.ObservePacket(string(flow.Direction), location.CountryCode, size)

	switch {
	case !found:
		monitor.enqueue(flow.Remote)
	case monitor.policy.ShouldBlock(location) && !monitor.firewall.IsBlocked(flow.Remote):
		// Known blocked country but no rule yet (e.g. an earlier attempt
		// failed): let a worker retry.
		monitor.enqueue(flow.Remote)
	}
}

// enqueue schedules address for lookup unless it is already queued or
// recently failed. It never blocks.
func (monitor *Monitor) enqueue(address netip.Addr) {
	monitor.pendingMutex.Lock()
	defer monitor.pendingMutex.Unlock()

	if _, queued := monitor.pending[address]; queued {
		return
	}
	if retryAt, failed := monitor.retryAfter[address]; failed {
		if monitor.now().Before(retryAt) {
			return
		}
		delete(monitor.retryAfter, address)
	}

	select {
	case monitor.queue <- address:
		monitor.pending[address] = struct{}{}
	default:
		monitor.recorder.QueueFull()
	}
}

// Run starts the workers and blocks until ctx is cancelled and every worker
// has returned.
func (monitor *Monitor) Run(ctx context.Context) {
	var workers sync.WaitGroup
	for range monitor.options.Workers {
		workers.Go(func() {
			for {
				select {
				case <-ctx.Done():
					return
				case address := <-monitor.queue:
					monitor.process(ctx, address)
				}
			}
		})
	}
	workers.Wait()
}

func (monitor *Monitor) process(ctx context.Context, address netip.Addr) {
	succeeded := monitor.resolveAndBlock(ctx, address)

	monitor.pendingMutex.Lock()
	defer monitor.pendingMutex.Unlock()
	delete(monitor.pending, address)
	if !succeeded && ctx.Err() == nil {
		monitor.retryAfter[address] = monitor.now().Add(monitor.options.RetryAfter)
		monitor.pruneRetries()
	}
}

// maxRetryEntries bounds memory used by addresses whose lookup failed.
const maxRetryEntries = 10000

// pruneRetries drops expired retry entries once the map grows large. The
// caller must hold pendingMutex.
func (monitor *Monitor) pruneRetries() {
	if len(monitor.retryAfter) < maxRetryEntries {
		return
	}
	now := monitor.now()
	for address, retryAt := range monitor.retryAfter {
		if now.After(retryAt) {
			delete(monitor.retryAfter, address)
		}
	}
}

func (monitor *Monitor) resolveAndBlock(ctx context.Context, address netip.Addr) bool {
	location, source, err := monitor.resolver.Resolve(ctx, address)
	if err != nil {
		if ctx.Err() == nil {
			monitor.logger.Warn("country lookup failed", "address", address, "error", err)
		}
		return false
	}
	monitor.logger.Debug("resolved address", "address", address, "country", location.CountryCode, "source", source)

	if !monitor.policy.ShouldBlock(location) {
		return true
	}
	added, err := monitor.firewall.Block(address)
	if err != nil {
		monitor.logger.Error("blocking address failed", "address", address, "country", location.CountryCode, "error", err)
		return false
	}
	if added {
		monitor.recorder.BlockedAddress()
		monitor.logger.Info("blocked address", "address", address, "country", location.CountryCode)
	}
	return true
}
