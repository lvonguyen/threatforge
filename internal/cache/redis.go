package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	DefaultTTL    = 1 * time.Hour
	keyPrefix     = "threatforge:ioc:"
	negativeValue = "__CLEAN__"
)

type CacheEntry struct {
	Value      string    `json:"value"`
	IOCType    string    `json:"ioc_type"`
	IsNegative bool      `json:"is_negative"`
	Data       []byte    `json:"data,omitempty"`
	CachedAt   time.Time `json:"cached_at"`
}

type Option func(*Cache)

type Cache struct {
	client *redis.Client
	ttl    time.Duration
}

func WithTTL(ttl time.Duration) Option {
	return func(c *Cache) {
		c.ttl = ttl
	}
}

func WithClient(client *redis.Client) Option {
	return func(c *Cache) {
		c.client = client
	}
}

func NewRedisCache(addr string, opts ...Option) *Cache {
	c := &Cache{
		ttl: DefaultTTL,
	}
	for _, opt := range opts {
		opt(c)
	}
	if c.client == nil {
		c.client = redis.NewClient(&redis.Options{
			Addr: addr,
		})
	}
	return c
}

func (c *Cache) buildKey(key string) string {
	return keyPrefix + key
}

func (c *Cache) Get(ctx context.Context, key string) (*CacheEntry, error) {
	raw, err := c.client.Get(ctx, c.buildKey(key)).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, nil
		}
		return nil, fmt.Errorf("cache get %q: %w", key, err)
	}

	var entry CacheEntry
	if err := json.Unmarshal(raw, &entry); err != nil {
		return nil, fmt.Errorf("cache unmarshal %q: %w", key, err)
	}
	return &entry, nil
}

func (c *Cache) Set(ctx context.Context, key string, entry *CacheEntry, ttl time.Duration) error {
	if ttl == 0 {
		ttl = c.ttl
	}
	entry.CachedAt = time.Now().UTC()

	raw, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("cache marshal %q: %w", key, err)
	}
	if err := c.client.Set(ctx, c.buildKey(key), raw, ttl).Err(); err != nil {
		return fmt.Errorf("cache set %q: %w", key, err)
	}
	return nil
}

func (c *Cache) SetNegative(ctx context.Context, key string, iocType string, ttl time.Duration) error {
	entry := &CacheEntry{
		Value:      key,
		IOCType:    iocType,
		IsNegative: true,
		Data:       []byte(negativeValue),
	}
	return c.Set(ctx, key, entry, ttl)
}

func (c *Cache) Delete(ctx context.Context, key string) error {
	if err := c.client.Del(ctx, c.buildKey(key)).Err(); err != nil {
		return fmt.Errorf("cache delete %q: %w", key, err)
	}
	return nil
}

func (c *Cache) Has(ctx context.Context, key string) (bool, error) {
	n, err := c.client.Exists(ctx, c.buildKey(key)).Result()
	if err != nil {
		return false, fmt.Errorf("cache exists %q: %w", key, err)
	}
	return n > 0, nil
}

func (c *Cache) Ping(ctx context.Context) error {
	return c.client.Ping(ctx).Err()
}

func (c *Cache) Close() error {
	return c.client.Close()
}
