// Package gateway provides API gateway functionality including rate limiting
package gateway

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

// RateLimiter provides configurable rate limiting for API endpoints
type RateLimiter struct {
	redis       *redis.Client
	logger      *zap.Logger
	config      RateLimitConfig
	localLimits sync.Map
}

// RateLimitConfig configures the rate limiter
type RateLimitConfig struct {
	DefaultRequestsPerSecond int                       `yaml:"default_requests_per_second"`
	DefaultRequestsPerMinute int                       `yaml:"default_requests_per_minute"`
	DefaultBurstSize         int                       `yaml:"default_burst_size"`
	Tiers                    map[string]TierLimits     `yaml:"tiers"`
	Endpoints                map[string]EndpointLimits `yaml:"endpoints"`
	IncludeHeaders           bool                      `yaml:"include_headers"`
}

// TierLimits defines rate limits per API tier
type TierLimits struct {
	RequestsPerSecond int `yaml:"requests_per_second"`
	RequestsPerMinute int `yaml:"requests_per_minute"`
	RequestsPerHour   int `yaml:"requests_per_hour"`
	BurstSize         int `yaml:"burst_size"`
}

// EndpointLimits defines rate limits for specific endpoints
type EndpointLimits struct {
	Path              string `yaml:"path"`
	Method            string `yaml:"method"`
	RequestsPerSecond int    `yaml:"requests_per_second"`
	RequestsPerMinute int    `yaml:"requests_per_minute"`
	CostMultiplier    int    `yaml:"cost_multiplier"`
}

// RateLimitResult contains the result of a rate limit check
type RateLimitResult struct {
	Allowed    bool
	Remaining  int
	Limit      int
	ResetAt    time.Time
	RetryAfter time.Duration
	Tier       string
	Reason     string
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(redisClient *redis.Client, cfg RateLimitConfig, logger *zap.Logger) *RateLimiter {
	if cfg.DefaultRequestsPerSecond == 0 {
		cfg.DefaultRequestsPerSecond = 10
	}
	if cfg.DefaultRequestsPerMinute == 0 {
		cfg.DefaultRequestsPerMinute = 100
	}
	if cfg.DefaultBurstSize == 0 {
		cfg.DefaultBurstSize = 20
	}

	if cfg.Tiers == nil {
		cfg.Tiers = DefaultTiers()
	}

	return &RateLimiter{
		redis:  redisClient,
		logger: logger,
		config: cfg,
	}
}

// DefaultTiers returns default tier configurations for threat intel
func DefaultTiers() map[string]TierLimits {
	return map[string]TierLimits{
		"free": {
			RequestsPerSecond: 2,
			RequestsPerMinute: 30,
			RequestsPerHour:   200,
			BurstSize:         5,
		},
		"basic": {
			RequestsPerSecond: 10,
			RequestsPerMinute: 100,
			RequestsPerHour:   1000,
			BurstSize:         20,
		},
		"professional": {
			RequestsPerSecond: 30,
			RequestsPerMinute: 300,
			RequestsPerHour:   3000,
			BurstSize:         60,
		},
		"enterprise": {
			RequestsPerSecond: 100,
			RequestsPerMinute: 1000,
			RequestsPerHour:   10000,
			BurstSize:         200,
		},
	}
}

// DefaultEndpointLimits returns default endpoint-specific limits for threat intel
func DefaultEndpointLimits() map[string]EndpointLimits {
	return map[string]EndpointLimits{
		// IOC enrichment
		"POST:/api/v1/iocs/enrich": {
			Path:              "/api/v1/iocs/enrich",
			Method:            "POST",
			RequestsPerSecond: 5,
			RequestsPerMinute: 50,
			CostMultiplier:    2,
		},
		// Bulk IOC lookup
		"POST:/api/v1/iocs/bulk": {
			Path:              "/api/v1/iocs/bulk",
			Method:            "POST",
			RequestsPerSecond: 2,
			RequestsPerMinute: 20,
			CostMultiplier:    5,
		},
		// MITRE ATT&CK mapping
		"POST:/api/v1/mitre/map": {
			Path:              "/api/v1/mitre/map",
			Method:            "POST",
			RequestsPerSecond: 10,
			RequestsPerMinute: 100,
			CostMultiplier:    1,
		},
		// Threat feed sync
		"POST:/api/v1/feeds/sync": {
			Path:              "/api/v1/feeds/sync",
			Method:            "POST",
			RequestsPerSecond: 1,
			RequestsPerMinute: 5,
			CostMultiplier:    10,
		},
	}
}

// Check performs a rate limit check
func (rl *RateLimiter) Check(ctx context.Context, tier, clientID, endpoint, method string) (*RateLimitResult, error) {
	tierLimits := rl.getTierLimits(tier)
	endpointLimits := rl.getEndpointLimits(endpoint, method)
	effectiveLimits := rl.calculateEffectiveLimits(tierLimits, endpointLimits)

	redisKey := fmt.Sprintf("threatforge:ratelimit:%s:%s:%s:minute", tier, clientID, endpoint)
	now := time.Now()

	script := redis.NewScript(`
		local current = redis.call('INCR', KEYS[1])
		if current == 1 then
			redis.call('PEXPIRE', KEYS[1], ARGV[1])
		end
		return current
	`)

	result, err := script.Run(ctx, rl.redis, []string{redisKey}, 60000).Int()
	if err != nil {
		rl.logger.Warn("Rate limit check failed, allowing request", zap.Error(err))
		return &RateLimitResult{Allowed: true, Tier: tier}, nil
	}

	allowed := result <= effectiveLimits.RequestsPerMinute
	remaining := effectiveLimits.RequestsPerMinute - result
	if remaining < 0 {
		remaining = 0
	}

	ttl, _ := rl.redis.TTL(ctx, redisKey).Result()
	resetAt := now.Add(ttl)

	var retryAfter time.Duration
	var reason string
	if !allowed {
		retryAfter = ttl
		reason = "Rate limit exceeded"
	}

	return &RateLimitResult{
		Allowed:    allowed,
		Remaining:  remaining,
		Limit:      effectiveLimits.RequestsPerMinute,
		ResetAt:    resetAt,
		RetryAfter: retryAfter,
		Tier:       tier,
		Reason:     reason,
	}, nil
}

func (rl *RateLimiter) getTierLimits(tier string) TierLimits {
	if limits, ok := rl.config.Tiers[tier]; ok {
		return limits
	}
	return rl.config.Tiers["free"]
}

func (rl *RateLimiter) getEndpointLimits(endpoint, method string) *EndpointLimits {
	key := method + ":" + endpoint
	if limits, ok := rl.config.Endpoints[key]; ok {
		return &limits
	}
	return nil
}

func (rl *RateLimiter) calculateEffectiveLimits(tier TierLimits, endpoint *EndpointLimits) TierLimits {
	if endpoint == nil {
		return tier
	}
	effective := tier
	if endpoint.RequestsPerSecond > 0 && endpoint.RequestsPerSecond < tier.RequestsPerSecond {
		effective.RequestsPerSecond = endpoint.RequestsPerSecond
	}
	if endpoint.RequestsPerMinute > 0 && endpoint.RequestsPerMinute < tier.RequestsPerMinute {
		effective.RequestsPerMinute = endpoint.RequestsPerMinute
	}
	if endpoint.CostMultiplier > 1 {
		effective.RequestsPerSecond /= endpoint.CostMultiplier
		effective.RequestsPerMinute /= endpoint.CostMultiplier
	}
	return effective
}

// Middleware returns an HTTP middleware for rate limiting
func (rl *RateLimiter) Middleware(getTier func(r *http.Request) string, getClientID func(r *http.Request) string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			tier := getTier(r)
			clientID := getClientID(r)
			if clientID == "" {
				clientID = getClientIP(r)
			}

			result, err := rl.Check(ctx, tier, clientID, r.URL.Path, r.Method)
			if err != nil {
				next.ServeHTTP(w, r)
				return
			}

			if rl.config.IncludeHeaders {
				w.Header().Set("X-RateLimit-Limit", strconv.Itoa(result.Limit))
				w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(result.Remaining))
				w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(result.ResetAt.Unix(), 10))
			}

			if !result.Allowed {
				w.Header().Set("Retry-After", strconv.Itoa(int(result.RetryAfter.Seconds())))
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusTooManyRequests)
				fmt.Fprintf(w, `{"error":"rate_limit_exceeded","message":"%s","retry_after":%d}`,
					result.Reason, int(result.RetryAfter.Seconds()))
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func getClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return xff
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	return r.RemoteAddr
}

