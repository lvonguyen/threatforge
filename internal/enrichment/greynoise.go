package enrichment

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

const (
	gnBaseURL     = "https://api.greynoise.io"
	gnDefaultRate = 100 // requests per minute (Community API)
)

// GreyNoiseProvider implements Provider for the GreyNoise Community API.
type GreyNoiseProvider struct {
	apiKey     string
	httpClient *http.Client
	rateLimit  RateLimitStatus
	limiter    *rate.Limiter
	mu         sync.RWMutex
}

type gnCommunityResponse struct {
	IP             string `json:"ip"`
	Noise          bool   `json:"noise"`
	Riot           bool   `json:"riot"`
	Classification string `json:"classification"` // benign, malicious, unknown
	Name           string `json:"name"`
	Link           string `json:"link"`
	LastSeen       string `json:"last_seen"`
	Message        string `json:"message,omitempty"`
}

// NewGreyNoiseProvider creates a GreyNoise provider. apiKeyEnv is the env var
// name holding the API key. timeout is the HTTP client timeout.
func NewGreyNoiseProvider(apiKeyEnv string, timeout time.Duration) (*GreyNoiseProvider, error) {
	apiKey := os.Getenv(apiKeyEnv)
	if apiKey == "" {
		return nil, fmt.Errorf("GreyNoise API key not set: env var %s is empty", apiKeyEnv)
	}
	// 100 req/min → 1 req per 600ms
	pollInterval := time.Minute / gnDefaultRate
	return &GreyNoiseProvider{
		apiKey: apiKey,
		httpClient: &http.Client{
			Timeout: timeout,
		},
		rateLimit: RateLimitStatus{
			Limit:     gnDefaultRate,
			Remaining: gnDefaultRate,
		},
		limiter: rate.NewLimiter(rate.Every(pollInterval), 1),
	}, nil
}

func (p *GreyNoiseProvider) Name() string { return "greynoise" }

// CheckIOC queries GreyNoise for IP types only. Non-IP types return nil, nil.
func (p *GreyNoiseProvider) CheckIOC(ctx context.Context, iocType IOCType, value string) (*Match, error) {
	if iocType != IOCTypeIP {
		return nil, nil
	}

	if err := p.limiter.Wait(ctx); err != nil {
		return nil, err
	}

	url := gnBaseURL + "/v3/community/" + value
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating GreyNoise request: %w", err)
	}
	req.Header.Set("key", p.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GreyNoise lookup failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("GreyNoise rate limit exceeded")
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("GreyNoise API error %d: %s", resp.StatusCode, string(body))
	}

	p.trackRate()

	var gnResp gnCommunityResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&gnResp); err != nil {
		return nil, fmt.Errorf("decoding GreyNoise response: %w", err)
	}

	return gnBuildMatch(iocType, value, &gnResp), nil
}

func (p *GreyNoiseProvider) CheckBatch(ctx context.Context, iocType IOCType, values []string) ([]Match, error) {
	var matches []Match
	var errs []error
	for _, v := range values {
		select {
		case <-ctx.Done():
			return matches, ctx.Err()
		default:
		}
		m, err := p.CheckIOC(ctx, iocType, v)
		if err != nil {
			errs = append(errs, fmt.Errorf("GreyNoise lookup for %q: %w", v, err))
			continue
		}
		if m != nil {
			matches = append(matches, *m)
		}
	}
	if len(matches) == 0 && len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return matches, nil
}

func (p *GreyNoiseProvider) GetIndicators(_ context.Context, _ IOCType, _ time.Time) ([]Indicator, error) {
	return nil, fmt.Errorf("GreyNoise Community API does not support bulk indicator feeds")
}

func (p *GreyNoiseProvider) HealthCheck(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, gnBaseURL+"/ping", nil)
	if err != nil {
		return fmt.Errorf("creating GreyNoise health check request: %w", err)
	}
	req.Header.Set("key", p.apiKey)

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("GreyNoise health check failed: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		return nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return fmt.Errorf("GreyNoise authentication failed: invalid API key")
	default:
		return fmt.Errorf("GreyNoise health check returned status %d", resp.StatusCode)
	}
}

func (p *GreyNoiseProvider) RateLimit() RateLimitStatus {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.rateLimit
}

func (p *GreyNoiseProvider) trackRate() {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	if now.After(p.rateLimit.ResetAt) {
		p.rateLimit.Remaining = p.rateLimit.Limit
	}
	if p.rateLimit.Remaining > 0 {
		p.rateLimit.Remaining--
	}
	if p.rateLimit.ResetAt.IsZero() || now.After(p.rateLimit.ResetAt) {
		p.rateLimit.ResetAt = now.Add(time.Minute)
	}
}

// gnBuildMatch maps a GreyNoise response to Match. Returns nil for benign/riot traffic.
func gnBuildMatch(iocType IOCType, value string, r *gnCommunityResponse) *Match {
	if r.Classification == "benign" || r.Riot {
		return nil
	}
	if r.Classification == "" || r.Classification == "unknown" {
		if !r.Noise {
			return nil
		}
	}

	threatType := gnInferThreatType(r.Classification)
	confidence := gnConfidence(r)
	severity := gnSeverity(confidence)

	var lastSeen time.Time
	if r.LastSeen != "" {
		lastSeen, _ = time.Parse("2006-01-02", r.LastSeen)
	}

	return &Match{
		Indicator: Indicator{
			Type:       iocType,
			Value:      value,
			ThreatType: threatType,
			Confidence: confidence,
			Severity:   severity,
			Source:     "greynoise",
			LastSeen:   lastSeen,
			Tags:       gnTags(r),
		},
		MatchedOn:    string(iocType),
		MatchedValue: value,
		Source:       "greynoise",
		Timestamp:    time.Now().UTC(),
	}
}

func gnInferThreatType(classification string) ThreatType {
	switch classification {
	case "malicious":
		return ThreatTypeMalware
	case "benign":
		return ThreatTypeUnknown
	default:
		return ThreatTypeScanner
	}
}

func gnConfidence(r *gnCommunityResponse) float64 {
	switch r.Classification {
	case "malicious":
		if r.Noise {
			return 0.9
		}
		return 0.75
	case "unknown":
		if r.Noise {
			return 0.5
		}
		return 0.3
	default:
		return 0.2
	}
}

func gnSeverity(confidence float64) string {
	switch {
	case confidence >= 0.8:
		return "high"
	case confidence >= 0.5:
		return "medium"
	default:
		return "low"
	}
}

func gnTags(r *gnCommunityResponse) []string {
	var tags []string
	if r.Noise {
		tags = append(tags, "noise")
	}
	if r.Riot {
		tags = append(tags, "riot")
	}
	if r.Name != "" {
		tags = append(tags, r.Name)
	}
	return tags
}
