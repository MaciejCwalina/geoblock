package geo

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"
)

type fakeCache struct {
	mutex   sync.Mutex
	entries map[netip.Addr]Location
	getErr  error
	sets    int
}

func (cache *fakeCache) Get(_ context.Context, address netip.Addr) (Location, error) {
	cache.mutex.Lock()
	defer cache.mutex.Unlock()
	if cache.getErr != nil {
		return Location{}, cache.getErr
	}
	location, found := cache.entries[address]
	if !found {
		return Location{}, ErrNotFound
	}
	return location, nil
}

func (cache *fakeCache) Set(_ context.Context, address netip.Addr, location Location) error {
	cache.mutex.Lock()
	defer cache.mutex.Unlock()
	if cache.entries == nil {
		cache.entries = make(map[netip.Addr]Location)
	}
	cache.entries[address] = location
	cache.sets++
	return nil
}

type fakeLocator struct {
	location Location
	err      error
	calls    int
}

func (locator *fakeLocator) Locate(context.Context, netip.Addr) (Location, error) {
	locator.calls++
	return locator.location, locator.err
}

type observation struct {
	source Source
	result Result
}

func TestResolverChain(t *testing.T) {
	address := netip.MustParseAddr("1.1.1.1")
	china := Location{CountryCode: "CN", Country: "China"}

	tests := []struct {
		name             string
		inMemory         bool
		inShared         bool
		sharedErr        error
		locatorErr       error
		wantSource       Source
		wantErr          bool
		wantLocatorCalls int
		wantSharedSets   int
		wantMemoryAfter  bool
		wantObservations []observation
	}{
		{
			name:             "memory hit",
			inMemory:         true,
			wantSource:       SourceMemory,
			wantMemoryAfter:  true,
			wantObservations: []observation{{SourceMemory, ResultOK}},
		},
		{
			name:             "redis hit fills memory",
			inShared:         true,
			wantSource:       SourceRedis,
			wantMemoryAfter:  true,
			wantObservations: []observation{{SourceRedis, ResultOK}},
		},
		{
			name:             "api hit fills both caches",
			wantSource:       SourceAPI,
			wantLocatorCalls: 1,
			wantSharedSets:   1,
			wantMemoryAfter:  true,
			wantObservations: []observation{{SourceRedis, ResultMiss}, {SourceAPI, ResultOK}},
		},
		{
			name:             "redis down falls through to api",
			sharedErr:        errors.New("connection refused"),
			wantSource:       SourceAPI,
			wantLocatorCalls: 1,
			wantSharedSets:   1,
			wantMemoryAfter:  true,
			wantObservations: []observation{{SourceRedis, ResultError}, {SourceAPI, ResultOK}},
		},
		{
			name:             "api failure is not cached",
			locatorErr:       errors.New("status fail"),
			wantSource:       SourceAPI,
			wantErr:          true,
			wantLocatorCalls: 1,
			wantObservations: []observation{{SourceRedis, ResultMiss}, {SourceAPI, ResultError}},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			memory := NewMemoryCache(10, time.Hour)
			if test.inMemory {
				memory.Store(address, china)
			}
			shared := &fakeCache{getErr: test.sharedErr}
			if test.inShared {
				shared.entries = map[netip.Addr]Location{address: china}
			}
			locator := &fakeLocator{location: china, err: test.locatorErr}
			var observations []observation
			resolver := NewResolver(memory, shared, locator, func(source Source, result Result) {
				observations = append(observations, observation{source, result})
			}, slog.New(slog.NewTextHandler(io.Discard, nil)))

			location, source, err := resolver.Resolve(context.Background(), address)
			if (err != nil) != test.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, test.wantErr)
			}
			if !test.wantErr && location != china {
				t.Errorf("location = %+v", location)
			}
			if source != test.wantSource {
				t.Errorf("source = %s, want %s", source, test.wantSource)
			}
			if locator.calls != test.wantLocatorCalls {
				t.Errorf("locator calls = %d, want %d", locator.calls, test.wantLocatorCalls)
			}
			if shared.sets != test.wantSharedSets {
				t.Errorf("shared sets = %d, want %d", shared.sets, test.wantSharedSets)
			}
			if _, found := memory.Peek(address); found != test.wantMemoryAfter {
				t.Errorf("memory populated = %v, want %v", found, test.wantMemoryAfter)
			}
			if !slices.Equal(observations, test.wantObservations) {
				t.Errorf("observations = %v, want %v", observations, test.wantObservations)
			}
		})
	}
}

func TestMemoryCache(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cache := NewMemoryCache(2, time.Minute)
	cache.now = func() time.Time { return now }

	first, second, third := netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("9.9.9.9")
	cache.Store(first, Location{CountryCode: "AU"})
	cache.Store(second, Location{CountryCode: "US"})
	cache.Store(third, Location{CountryCode: "CH"})

	if cache.Len() != 2 {
		t.Errorf("Len = %d, want 2 (bounded)", cache.Len())
	}
	if location, found := cache.Peek(third); !found || location.CountryCode != "CH" {
		t.Errorf("latest entry missing: %+v %v", location, found)
	}

	now = now.Add(2 * time.Minute)
	if _, found := cache.Peek(third); found {
		t.Error("entry should have expired")
	}
}
