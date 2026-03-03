package enrichment

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

const (
	abuseIPDBBaseURL     = "https://api.abuseipdb.com"
	abuseIPDBDefaultRate = 1000 // requests per day; use conservative per-minute limit
	abuseIPDBPollRate    = 60   // ~60 req/min safe default
)

// AbuseIPDBProvider implements Provider for the AbuseIPDB v2 API.
type AbuseIPDBProvider struct {
	apiKey     string
	httpClient *http.Client
	rateLimit  RateLimitStatus
	limiter    *rate.Limiter
	mu         sync.RWMutex
}

type abuseIPDBCheckResponse struct {
	Data abuseIPDBData `json:"data"`
}

type abuseIPDBData struct {
	IPAddress            string `json:"ipAddress"`
	IsPublic             bool   `json:"isPublic"`
	IPVersion            int    `json:"ipVersion"`
	IsWhitelisted        bool   `json:"isWhitelisted"`
	AbuseConfidenceScore int    `json:"abuseConfidenceScore"` // 0–100
	CountryCode          string `json:"countryCode"`
	UsageType            string `json:"usageType"`
	ISP                  string `json:"isp"`
	Domain               string `json:"domain"`
	TotalReports         int    `json:"totalReports"`
	NumDistinctUsers     int    `json:"numDistinctUsers"`
	LastReportedAt       string `json:"lastReportedAt,omitempty"`
}

// NewAbuseIPDBProvider creates an AbuseIPDB provider. apiKeyEnv is the env var
// name holding the API key. timeout is the HTTP client timeout.
func NewAbuseIPDBProvider(apiKeyEnv string, timeout time.Duration) (*AbuseIPDBProvider, error) {
	apiKey := os.Getenv(apiKeyEnv)
	if apiKey == "" {
		return nil, fmt.Errorf("AbuseIPDB API key not set: env var %s is empty", apiKeyEnv)
	}
	pollInterval := time.Minute / abuseIPDBPollRate
	return &AbuseIPDBProvider{
		apiKey: apiKey,
		httpClient: &http.Client{
			Timeout: timeout,
		},
		rateLimit: RateLimitStatus{
			Limit:     abuseIPDBPollRate,
			Remaining: abuseIPDBPollRate,
		},
		limiter: rate.NewLimiter(rate.Every(pollInterval), 1),
	}, nil
}

func (p *AbuseIPDBProvider) Name() string { return "abuseipdb" }

// CheckIOC queries AbuseIPDB for IP types only. Non-IP types return nil, nil.
func (p *AbuseIPDBProvider) CheckIOC(ctx context.Context, iocType IOCType, value string) (*Match, error) {
	if iocType != IOCTypeIP {
		return nil, nil
	}

	if err := p.limiter.Wait(ctx); err != nil {
		return nil, err
	}

	params := url.Values{}
	params.Set("ipAddress", value)
	params.Set("maxAgeInDays", "90")
	reqURL := abuseIPDBBaseURL + "/api/v2/check?" + params.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating AbuseIPDB request: %w", err)
	}
	req.Header.Set("Key", p.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("AbuseIPDB lookup failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("AbuseIPDB rate limit exceeded")
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("AbuseIPDB API error %d: %s", resp.StatusCode, string(body))
	}

	p.trackRate()

	var checkResp abuseIPDBCheckResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&checkResp); err != nil {
		return nil, fmt.Errorf("decoding AbuseIPDB response: %w", err)
	}

	return abuseIPDBBuildMatch(iocType, value, &checkResp.Data), nil
}

func (p *AbuseIPDBProvider) CheckBatch(ctx context.Context, iocType IOCType, values []string) ([]Match, error) {
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
			errs = append(errs, fmt.Errorf("AbuseIPDB lookup for %q: %w", v, err))
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

func (p *AbuseIPDBProvider) GetIndicators(_ context.Context, _ IOCType, _ time.Time) ([]Indicator, error) {
	return nil, fmt.Errorf("AbuseIPDB does not support bulk indicator feeds")
}

func (p *AbuseIPDBProvider) HealthCheck(ctx context.Context) error {
	// Use a known-safe IP for health check probe
	params := url.Values{}
	params.Set("ipAddress", "8.8.8.8")
	reqURL := abuseIPDBBaseURL + "/api/v2/check?" + params.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return fmt.Errorf("creating AbuseIPDB health check request: %w", err)
	}
	req.Header.Set("Key", p.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("AbuseIPDB health check failed: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		return nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return fmt.Errorf("AbuseIPDB authentication failed: invalid API key")
	default:
		return fmt.Errorf("AbuseIPDB health check returned status %d", resp.StatusCode)
	}
}

func (p *AbuseIPDBProvider) RateLimit() RateLimitStatus {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.rateLimit
}

func (p *AbuseIPDBProvider) trackRate() {
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

// abuseIPDBBuildMatch maps AbuseIPDB data to Match. Returns nil when score is 0.
func abuseIPDBBuildMatch(iocType IOCType, value string, data *abuseIPDBData) *Match {
	if data.AbuseConfidenceScore == 0 {
		return nil
	}

	confidence := float64(data.AbuseConfidenceScore) / 100.0
	severity := abuseIPDBSeverity(confidence)

	var lastSeen time.Time
	if data.LastReportedAt != "" {
		lastSeen, _ = time.Parse(time.RFC3339, data.LastReportedAt)
	}

	tags := []string{}
	if data.UsageType != "" {
		tags = append(tags, data.UsageType)
	}
	if data.ISP != "" {
		tags = append(tags, data.ISP)
	}

	return &Match{
		Indicator: Indicator{
			Type:       iocType,
			Value:      value,
			ThreatType: ThreatTypeUnknown,
			Confidence: confidence,
			Severity:   severity,
			Source:     "abuseipdb",
			LastSeen:   lastSeen,
			Tags:       tags,
		},
		MatchedOn:    string(iocType),
		MatchedValue: value,
		Source:       "abuseipdb",
		Timestamp:    time.Now().UTC(),
	}
}

func abuseIPDBSeverity(confidence float64) string {
	switch {
	case confidence >= 0.75:
		return "critical"
	case confidence >= 0.5:
		return "high"
	case confidence >= 0.25:
		return "medium"
	default:
		return "low"
	}
}
