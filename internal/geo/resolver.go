package geo

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
)

// Source identifies which layer of the chain answered a lookup.
type Source string

// Lookup sources, used as metric label values.
const (
	SourceMemory Source = "memory"
	SourceRedis  Source = "redis"
	SourceAPI    Source = "api"
)

// Result is the outcome of one layer of the chain.
type Result string

// Lookup results, used as metric label values.
const (
	ResultOK    Result = "ok"
	ResultMiss  Result = "miss"
	ResultError Result = "error"
)

// ObserveFunc is called once for every layer consulted during a lookup.
type ObserveFunc func(source Source, result Result)

// Resolver looks an address up in memory, then in the shared cache, then via
// the Locator, filling the faster layers on the way back.
type Resolver struct {
	memory  *MemoryCache
	shared  Cache
	locator Locator
	observe ObserveFunc
	logger  *slog.Logger
}

// NewResolver builds the lookup chain. observe may be nil.
func NewResolver(memory *MemoryCache, shared Cache, locator Locator, observe ObserveFunc, logger *slog.Logger) *Resolver {
	if observe == nil {
		observe = func(Source, Result) {}
	}
	return &Resolver{memory: memory, shared: shared, locator: locator, observe: observe, logger: logger}
}

// Cached returns a location from the in-process cache only. It never blocks
// on I/O and is safe to call on the packet capture path.
func (resolver *Resolver) Cached(address netip.Addr) (Location, bool) {
	location, found := resolver.memory.Peek(address)
	if found {
		resolver.observe(SourceMemory, ResultOK)
	}
	return location, found
}

// Resolve walks the full chain. A failing shared cache is logged and skipped
// so a Redis outage degrades to API lookups instead of stopping everything.
// Failed API lookups are not cached.
func (resolver *Resolver) Resolve(ctx context.Context, address netip.Addr) (Location, Source, error) {
	if location, found := resolver.Cached(address); found {
		return location, SourceMemory, nil
	}

	location, err := resolver.shared.Get(ctx, address)
	switch {
	case err == nil:
		resolver.observe(SourceRedis, ResultOK)
		resolver.memory.Store(address, location)
		return location, SourceRedis, nil
	case errors.Is(err, ErrNotFound):
		resolver.observe(SourceRedis, ResultMiss)
	default:
		resolver.observe(SourceRedis, ResultError)
		resolver.logger.Warn("shared cache read failed", "address", address, "error", err)
	}

	location, err = resolver.locator.Locate(ctx, address)
	if err != nil {
		resolver.observe(SourceAPI, ResultError)
		return Location{}, SourceAPI, err
	}
	resolver.observe(SourceAPI, ResultOK)
	resolver.memory.Store(address, location)
	if err := resolver.shared.Set(ctx, address, location); err != nil {
		resolver.logger.Warn("shared cache write failed", "address", address, "error", err)
	}
	return location, SourceAPI, nil
}
