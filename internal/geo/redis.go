package geo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisKeyPrefix namespaces cache keys so they do not collide with other data.
const RedisKeyPrefix = "geoblock:location:"

// RedisCache stores locations as JSON with a TTL.
type RedisCache struct {
	client redis.Cmdable
	ttl    time.Duration
}

// NewRedisCache returns a Cache backed by client whose entries expire after ttl.
func NewRedisCache(client redis.Cmdable, ttl time.Duration) *RedisCache {
	return &RedisCache{client: client, ttl: ttl}
}

// Get implements Cache.
func (cache *RedisCache) Get(ctx context.Context, address netip.Addr) (Location, error) {
	content, err := cache.client.Get(ctx, RedisKeyPrefix+address.String()).Bytes()
	if errors.Is(err, redis.Nil) {
		return Location{}, ErrNotFound
	}
	if err != nil {
		return Location{}, fmt.Errorf("redis get: %w", err)
	}
	var location Location
	if err := json.Unmarshal(content, &location); err != nil {
		return Location{}, fmt.Errorf("decode cached location: %w", err)
	}
	return location, nil
}

// Set implements Cache.
func (cache *RedisCache) Set(ctx context.Context, address netip.Addr, location Location) error {
	content, err := json.Marshal(location)
	if err != nil {
		return err
	}
	if err := cache.client.Set(ctx, RedisKeyPrefix+address.String(), content, cache.ttl).Err(); err != nil {
		return fmt.Errorf("redis set: %w", err)
	}
	return nil
}
