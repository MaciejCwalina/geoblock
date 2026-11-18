package monitor

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/MaciejCwalina/go_prometheus_packet_monitoring/internal/geo"
	"github.com/MaciejCwalina/go_prometheus_packet_monitoring/internal/netclass"
)

var (
	localAddress = netip.MustParseAddr("192.168.1.10")
	chinaAddress = netip.MustParseAddr("1.1.1.1")
	usAddress    = netip.MustParseAddr("8.8.8.8")
)

// fakeResolver answers from a fixed table. Resolve blocks until gate is
// closed (if set) so tests can observe deduplication.
type fakeResolver struct {
	mutex     sync.Mutex
	locations map[netip.Addr]geo.Location
	cached    map[netip.Addr]geo.Location
	err       error
	gate      chan struct{}
	calls     map[netip.Addr]int
}

func newFakeResolver() *fakeResolver {
	return &fakeResolver{
		locations: map[netip.Addr]geo.Location{
			chinaAddress: {CountryCode: "CN"},
			usAddress:    {CountryCode: "US"},
		},
		cached: map[netip.Addr]geo.Location{},
		calls:  map[netip.Addr]int{},
	}
}

func (resolver *fakeResolver) Cached(address netip.Addr) (geo.Location, bool) {
	resolver.mutex.Lock()
	defer resolver.mutex.Unlock()
	location, found := resolver.cached[address]
	return location, found
}

func (resolver *fakeResolver) Resolve(ctx context.Context, address netip.Addr) (geo.Location, geo.Source, error) {
	if resolver.gate != nil {
		select {
		case <-resolver.gate:
		case <-ctx.Done():
			return geo.Location{}, geo.SourceAPI, ctx.Err()
		}
	}
	resolver.mutex.Lock()
	defer resolver.mutex.Unlock()
	resolver.calls[address]++
	if resolver.err != nil {
		return geo.Location{}, geo.SourceAPI, resolver.err
	}
	location := resolver.locations[address]
	resolver.cached[address] = location
	return location, geo.SourceAPI, nil
}

func (resolver *fakeResolver) callCount(address netip.Addr) int {
	resolver.mutex.Lock()
	defer resolver.mutex.Unlock()
	return resolver.calls[address]
}

type fakeFirewall struct {
	mutex   sync.Mutex
	blocked map[netip.Addr]int
	err     error
}

func (blocker *fakeFirewall) Block(address netip.Addr) (bool, error) {
	blocker.mutex.Lock()
	defer blocker.mutex.Unlock()
	if blocker.err != nil {
		return false, blocker.err
	}
	blocker.blocked[address]++
	return blocker.blocked[address] == 1, nil
}

func (blocker *fakeFirewall) IsBlocked(address netip.Addr) bool {
	blocker.mutex.Lock()
	defer blocker.mutex.Unlock()
	return blocker.blocked[address] > 0
}

func (blocker *fakeFirewall) blockCount(address netip.Addr) int {
	blocker.mutex.Lock()
	defer blocker.mutex.Unlock()
	return blocker.blocked[address]
}

type packetKey struct{ direction, country string }

type fakeRecorder struct {
	mutex     sync.Mutex
	packets   map[packetKey]int
	bytes     map[packetKey]int
	blocked   int
	queueFull int
}

func newFakeRecorder() *fakeRecorder {
	return &fakeRecorder{packets: map[packetKey]int{}, bytes: map[packetKey]int{}}
}

func (recorder *fakeRecorder) ObservePacket(direction, country string, size int) {
	recorder.mutex.Lock()
	defer recorder.mutex.Unlock()
	if country == "" {
		country = "unknown"
	}
	recorder.packets[packetKey{direction, country}]++
	recorder.bytes[packetKey{direction, country}] += size
}

func (recorder *fakeRecorder) BlockedAddress() {
	recorder.mutex.Lock()
	defer recorder.mutex.Unlock()
	recorder.blocked++
}

func (recorder *fakeRecorder) QueueFull() {
	recorder.mutex.Lock()
	defer recorder.mutex.Unlock()
	recorder.queueFull++
}

type fixture struct {
	monitor  *Monitor
	resolver *fakeResolver
	firewall *fakeFirewall
	recorder *fakeRecorder
}

func newFixture(options Options) fixture {
	resolver := newFakeResolver()
	blocker := &fakeFirewall{blocked: map[netip.Addr]int{}}
	recorder := newFakeRecorder()
	packetMonitor := New(
		netclass.NewClassifier([]netip.Addr{localAddress}),
		resolver,
		blocker,
		NewPolicy([]string{"cn"}),
		recorder,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		options,
	)
	return fixture{monitor: packetMonitor, resolver: resolver, firewall: blocker, recorder: recorder}
}

// drain processes everything currently queued, synchronously.
func (fixture fixture) drain(t *testing.T) {
	t.Helper()
	for {
		select {
		case address := <-fixture.monitor.queue:
			fixture.monitor.process(context.Background(), address)
		default:
			return
		}
	}
}

func TestPolicyShouldBlock(t *testing.T) {
	policy := NewPolicy([]string{"CN", "ru"})
	tests := []struct {
		countryCode string
		want        bool
	}{
		{"CN", true},
		{"cn", true},
		{"RU", true},
		{"US", false},
		{"", false},
	}
	for _, test := range tests {
		t.Run(test.countryCode, func(t *testing.T) {
			if got := policy.ShouldBlock(geo.Location{CountryCode: test.countryCode}); got != test.want {
				t.Errorf("ShouldBlock(%q) = %v, want %v", test.countryCode, got, test.want)
			}
		})
	}
}

func TestHandlePacketBlocksOnlyBlockedCountries(t *testing.T) {
	tests := []struct {
		name        string
		source      netip.Addr
		destination netip.Addr
		wantBlocked netip.Addr
		wantLookups int
	}{
		{"outbound to blocked country", localAddress, chinaAddress, chinaAddress, 1},
		{"unsolicited inbound from blocked country", chinaAddress, localAddress, chinaAddress, 1},
		{"outbound to allowed country", localAddress, usAddress, netip.Addr{}, 1},
		{"private traffic is ignored", localAddress, netip.MustParseAddr("192.168.1.1"), netip.Addr{}, 0},
		{"multicast is ignored", localAddress, netip.MustParseAddr("224.0.0.251"), netip.Addr{}, 0},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newFixture(Options{})
			for range 3 {
				fixture.monitor.HandlePacket(test.source, test.destination, 100)
				fixture.drain(t)
			}

			totalLookups := fixture.resolver.callCount(chinaAddress) + fixture.resolver.callCount(usAddress)
			if totalLookups != test.wantLookups {
				t.Errorf("lookups = %d, want %d", totalLookups, test.wantLookups)
			}
			for _, address := range []netip.Addr{chinaAddress, usAddress} {
				wantCount := 0
				if address == test.wantBlocked {
					wantCount = 1
				}
				if got := fixture.firewall.blockCount(address); got != wantCount {
					t.Errorf("Block(%s) called %d times, want %d", address, got, wantCount)
				}
			}
		})
	}
}

func TestHandlePacketRecordsMetrics(t *testing.T) {
	fixture := newFixture(Options{})
	fixture.monitor.HandlePacket(localAddress, usAddress, 60) // unresolved yet
	fixture.drain(t)
	fixture.monitor.HandlePacket(usAddress, localAddress, 1500) // now cached
	fixture.monitor.HandlePacket(localAddress, chinaAddress, 40)
	fixture.drain(t)
	fixture.monitor.HandlePacket(localAddress, netip.MustParseAddr("10.0.0.1"), 999) // ignored

	want := map[packetKey]int{
		{"out", "unknown"}: 60 + 40, // both first seen before resolution
		{"in", "US"}:       1500,
	}
	if len(fixture.recorder.bytes) != len(want) {
		t.Fatalf("bytes = %v, want %v", fixture.recorder.bytes, want)
	}
	for key, wantBytes := range want {
		if got := fixture.recorder.bytes[key]; got != wantBytes {
			t.Errorf("bytes[%v] = %d, want %d", key, got, wantBytes)
		}
	}
	if fixture.recorder.blocked != 1 {
		t.Errorf("blocked = %d, want 1", fixture.recorder.blocked)
	}
}

func TestLookupsAreDeduplicated(t *testing.T) {
	fixture := newFixture(Options{Workers: 4})
	fixture.resolver.gate = make(chan struct{})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		fixture.monitor.Run(ctx)
		close(done)
	}()

	// A burst of packets for the same address while the lookup is in flight.
	for range 1000 {
		fixture.monitor.HandlePacket(chinaAddress, localAddress, 64)
	}
	close(fixture.resolver.gate)

	deadline := time.Now().Add(2 * time.Second)
	for fixture.firewall.blockCount(chinaAddress) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	// More packets after resolution are served from the cache.
	for range 1000 {
		fixture.monitor.HandlePacket(chinaAddress, localAddress, 64)
	}
	cancel()
	<-done

	if calls := fixture.resolver.callCount(chinaAddress); calls != 1 {
		t.Errorf("Resolve called %d times, want 1", calls)
	}
	if blocks := fixture.firewall.blockCount(chinaAddress); blocks != 1 {
		t.Errorf("Block called %d times, want 1", blocks)
	}
}

func TestHandlePacketNeverBlocksWhenQueueIsFull(t *testing.T) {
	fixture := newFixture(Options{QueueSize: 2})
	// No workers running: the queue fills up and further addresses are
	// dropped instead of blocking the capture path.
	finished := make(chan struct{})
	go func() {
		for index := range 10 {
			remote := netip.AddrFrom4([4]byte{1, 1, 1, byte(index + 10)})
			fixture.monitor.HandlePacket(remote, localAddress, 64)
		}
		close(finished)
	}()
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("HandlePacket blocked on a full queue")
	}
	if fixture.recorder.queueFull != 8 {
		t.Errorf("queueFull = %d, want 8", fixture.recorder.queueFull)
	}
}

func TestFailedLookupIsRetriedAfterBackoff(t *testing.T) {
	fixture := newFixture(Options{RetryAfter: time.Minute})
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	fixture.monitor.now = func() time.Time { return now }
	fixture.resolver.err = errors.New("rate limited")

	fixture.monitor.HandlePacket(chinaAddress, localAddress, 64)
	fixture.drain(t)
	fixture.monitor.HandlePacket(chinaAddress, localAddress, 64)
	fixture.drain(t)
	if calls := fixture.resolver.callCount(chinaAddress); calls != 1 {
		t.Fatalf("calls during backoff = %d, want 1", calls)
	}

	now = now.Add(2 * time.Minute)
	fixture.resolver.err = nil
	fixture.monitor.HandlePacket(chinaAddress, localAddress, 64)
	fixture.drain(t)
	if calls := fixture.resolver.callCount(chinaAddress); calls != 2 {
		t.Errorf("calls after backoff = %d, want 2", calls)
	}
	if fixture.firewall.blockCount(chinaAddress) != 1 {
		t.Error("address should be blocked after a successful retry")
	}
}

func TestFailedBlockIsRetried(t *testing.T) {
	fixture := newFixture(Options{RetryAfter: time.Minute})
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	fixture.monitor.now = func() time.Time { return now }
	fixture.firewall.err = errors.New("iptables: permission denied")

	fixture.monitor.HandlePacket(localAddress, chinaAddress, 64)
	fixture.drain(t)
	if fixture.firewall.IsBlocked(chinaAddress) {
		t.Fatal("block should have failed")
	}

	now = now.Add(2 * time.Minute)
	fixture.firewall.err = nil
	// The country is cached now, but the missing rule still triggers a retry.
	fixture.monitor.HandlePacket(localAddress, chinaAddress, 64)
	fixture.drain(t)
	if !fixture.firewall.IsBlocked(chinaAddress) {
		t.Error("block should have been retried")
	}
}
