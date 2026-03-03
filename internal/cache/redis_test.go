package cache

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func newTestCache(t *testing.T) (*Cache, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	c := NewRedisCache(mr.Addr())
	return c, mr
}

func TestNewRedisCache(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		mr := miniredis.RunT(t)
		c := NewRedisCache(mr.Addr())
		if c.ttl != DefaultTTL {
			t.Errorf("ttl = %v, want %v", c.ttl, DefaultTTL)
		}
		if c.client == nil {
			t.Error("client is nil")
		}
	})

	t.Run("WithTTL", func(t *testing.T) {
		mr := miniredis.RunT(t)
		want := 5 * time.Minute
		c := NewRedisCache(mr.Addr(), WithTTL(want))
		if c.ttl != want {
			t.Errorf("ttl = %v, want %v", c.ttl, want)
		}
	})

	t.Run("WithClient", func(t *testing.T) {
		mr := miniredis.RunT(t)
		custom := redis.NewClient(&redis.Options{Addr: mr.Addr()})
		c := NewRedisCache("unused-addr", WithClient(custom))
		if c.client != custom {
			t.Error("client was not replaced by WithClient option")
		}
	})
}

func TestCacheGetSet(t *testing.T) {
	c, _ := newTestCache(t)
	ctx := context.Background()

	entry := &CacheEntry{
		Value:   "1.2.3.4",
		IOCType: "ip",
		Data:    []byte(`{"score":90}`),
	}

	before := time.Now().UTC()
	if err := c.Set(ctx, "1.2.3.4", entry, 0); err != nil {
		t.Fatalf("Set: %v", err)
	}
	after := time.Now().UTC()

	got, err := c.Get(ctx, "1.2.3.4")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got == nil {
		t.Fatal("Get returned nil, want entry")
	}
	if got.Value != "1.2.3.4" {
		t.Errorf("Value = %q, want %q", got.Value, "1.2.3.4")
	}
	if got.IOCType != "ip" {
		t.Errorf("IOCType = %q, want %q", got.IOCType, "ip")
	}
	if string(got.Data) != `{"score":90}` {
		t.Errorf("Data = %q, want %q", got.Data, `{"score":90}`)
	}
	if got.CachedAt.Before(before) || got.CachedAt.After(after) {
		t.Errorf("CachedAt %v not in [%v, %v]", got.CachedAt, before, after)
	}
}

func TestCacheGetMiss(t *testing.T) {
	c, _ := newTestCache(t)
	ctx := context.Background()

	got, err := c.Get(ctx, "nonexistent-key")
	if err != nil {
		t.Fatalf("Get miss: %v", err)
	}
	if got != nil {
		t.Errorf("Get miss = %+v, want nil", got)
	}
}

func TestCacheSetNegative(t *testing.T) {
	c, _ := newTestCache(t)
	ctx := context.Background()

	if err := c.SetNegative(ctx, "8.8.8.8", "ip", 0); err != nil {
		t.Fatalf("SetNegative: %v", err)
	}

	got, err := c.Get(ctx, "8.8.8.8")
	if err != nil {
		t.Fatalf("Get after SetNegative: %v", err)
	}
	if got == nil {
		t.Fatal("Get returned nil after SetNegative")
	}
	if !got.IsNegative {
		t.Error("IsNegative = false, want true")
	}
	if string(got.Data) != negativeValue {
		t.Errorf("Data = %q, want %q", got.Data, negativeValue)
	}
	if got.Value != "8.8.8.8" {
		t.Errorf("Value = %q, want %q", got.Value, "8.8.8.8")
	}
	if got.IOCType != "ip" {
		t.Errorf("IOCType = %q, want %q", got.IOCType, "ip")
	}
}

func TestCacheDelete(t *testing.T) {
	c, _ := newTestCache(t)
	ctx := context.Background()

	entry := &CacheEntry{Value: "evil.com", IOCType: "domain"}
	if err := c.Set(ctx, "evil.com", entry, 0); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := c.Delete(ctx, "evil.com"); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	got, err := c.Get(ctx, "evil.com")
	if err != nil {
		t.Fatalf("Get after Delete: %v", err)
	}
	if got != nil {
		t.Errorf("Get after Delete = %+v, want nil", got)
	}
}

func TestCacheHas(t *testing.T) {
	c, _ := newTestCache(t)
	ctx := context.Background()

	exists, err := c.Has(ctx, "missing-key")
	if err != nil {
		t.Fatalf("Has on missing key: %v", err)
	}
	if exists {
		t.Error("Has = true for missing key, want false")
	}

	entry := &CacheEntry{Value: "hash123", IOCType: "hash"}
	if err := c.Set(ctx, "hash123", entry, 0); err != nil {
		t.Fatalf("Set: %v", err)
	}

	exists, err = c.Has(ctx, "hash123")
	if err != nil {
		t.Fatalf("Has on existing key: %v", err)
	}
	if !exists {
		t.Error("Has = false for existing key, want true")
	}
}

func TestBuildKey(t *testing.T) {
	c := &Cache{}
	tests := []struct {
		input string
		want  string
	}{
		{"1.2.3.4", "threatforge:ioc:1.2.3.4"},
		{"evil.com", "threatforge:ioc:evil.com"},
		{"", "threatforge:ioc:"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := c.buildKey(tt.input)
			if got != tt.want {
				t.Errorf("buildKey(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestCachePing(t *testing.T) {
	c, _ := newTestCache(t)
	ctx := context.Background()

	if err := c.Ping(ctx); err != nil {
		t.Errorf("Ping: %v", err)
	}
}

func TestCacheClose(t *testing.T) {
	c, _ := newTestCache(t)

	if err := c.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

func TestSetTTLZeroUsesDefault(t *testing.T) {
	mr := miniredis.RunT(t)
	customTTL := 10 * time.Minute
	c := NewRedisCache(mr.Addr(), WithTTL(customTTL))
	ctx := context.Background()

	entry := &CacheEntry{Value: "1.1.1.1", IOCType: "ip"}
	if err := c.Set(ctx, "1.1.1.1", entry, 0); err != nil {
		t.Fatalf("Set: %v", err)
	}

	ttl := mr.TTL("threatforge:ioc:1.1.1.1")
	if ttl != customTTL {
		t.Errorf("TTL in redis = %v, want %v", ttl, customTTL)
	}
}
