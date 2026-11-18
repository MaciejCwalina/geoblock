package geo

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func TestRedisCache(t *testing.T) {
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	ctx := context.Background()
	cache := NewRedisCache(client, 7*24*time.Hour)
	address := netip.MustParseAddr("1.1.1.1")

	if _, err := cache.Get(ctx, address); !errors.Is(err, ErrNotFound) {
		t.Fatalf("miss err = %v, want ErrNotFound", err)
	}

	china := Location{CountryCode: "CN", Country: "China"}
	if err := cache.Set(ctx, address, china); err != nil {
		t.Fatal(err)
	}
	if ttl := server.TTL(RedisKeyPrefix + "1.1.1.1"); ttl != 7*24*time.Hour {
		t.Errorf("TTL = %v, want 168h", ttl)
	}
	location, err := cache.Get(ctx, address)
	if err != nil {
		t.Fatal(err)
	}
	if location != china {
		t.Errorf("location = %+v", location)
	}

	server.FastForward(8 * 24 * time.Hour)
	if _, err := cache.Get(ctx, address); !errors.Is(err, ErrNotFound) {
		t.Errorf("after expiry err = %v, want ErrNotFound", err)
	}

	server.Close()
	if _, err := cache.Get(ctx, address); err == nil || errors.Is(err, ErrNotFound) {
		t.Errorf("unreachable redis err = %v, want a connection error", err)
	}
}
