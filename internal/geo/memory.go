package geo

import (
	"net/netip"
	"sync"
	"time"
)

type memoryEntry struct {
	location  Location
	expiresAt time.Time
}

// MemoryCache is a small, bounded, concurrency-safe in-process cache. When it
// is full, an arbitrary entry is evicted; the Redis layer behind it keeps the
// long-term data so precision is not important here.
type MemoryCache struct {
	mutex      sync.RWMutex
	entries    map[netip.Addr]memoryEntry
	maxEntries int
	ttl        time.Duration
	now        func() time.Time
}

// NewMemoryCache returns a cache holding at most maxEntries for ttl each.
func NewMemoryCache(maxEntries int, ttl time.Duration) *MemoryCache {
	return &MemoryCache{
		entries:    make(map[netip.Addr]memoryEntry),
		maxEntries: maxEntries,
		ttl:        ttl,
		now:        time.Now,
	}
}

// Peek returns the cached location for address without any I/O.
func (cache *MemoryCache) Peek(address netip.Addr) (Location, bool) {
	cache.mutex.RLock()
	entry, found := cache.entries[address]
	cache.mutex.RUnlock()
	if !found || cache.now().After(entry.expiresAt) {
		return Location{}, false
	}
	return entry.location, true
}

// Store saves location for address.
func (cache *MemoryCache) Store(address netip.Addr, location Location) {
	cache.mutex.Lock()
	defer cache.mutex.Unlock()
	if _, exists := cache.entries[address]; !exists && len(cache.entries) >= cache.maxEntries {
		for evicted := range cache.entries {
			delete(cache.entries, evicted)
			break
		}
	}
	cache.entries[address] = memoryEntry{location: location, expiresAt: cache.now().Add(cache.ttl)}
}

// Len returns the number of entries, including expired ones not yet evicted.
func (cache *MemoryCache) Len() int {
	cache.mutex.RLock()
	defer cache.mutex.RUnlock()
	return len(cache.entries)
}
