package enrichment

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

const (
	vtBaseURL         = "https://www.virustotal.com/api/v3"
	vtFreeRateLimit   = 4
	vtMinPollInterval = 15 * time.Second // 60s / 4 req
)

// VirusTotalProvider implements Provider for the VirusTotal API v3.
type VirusTotalProvider struct {
	apiKey     string
	httpClient *http.Client
	rateLimit  RateLimitStatus
	limiter    *rate.Limiter
	mu         sync.RWMutex
}

type vtResponse struct {
	Data vtData `json:"data"`
}

type vtData struct {
	ID         string       `json:"id"`
	Attributes vtAttributes `json:"attributes"`
}

type vtAttributes struct {
	LastAnalysisStats   vtAnalysisStats        `json:"last_analysis_stats"`
	LastAnalysisDate    int64                  `json:"last_analysis_date"`
	FirstSubmissionDate int64                  `json:"first_submission_date"` // Unix timestamp; zero when absent
	Reputation          int                    `json:"reputation"`
	Tags                []string               `json:"tags"`
	TotalVotes          map[string]int         `json:"total_votes"`
	LastAnalysisResult  map[string]vtScanEntry `json:"last_analysis_results"`
}

type vtAnalysisStats struct {
	Malicious        int `json:"malicious"`
	Suspicious       int `json:"suspicious"`
	Undetected       int `json:"undetected"`
	Harmless         int `json:"harmless"`
	Timeout          int `json:"timeout"`
	ConfirmedTimeout int `json:"confirmed-timeout"`
	Failure          int `json:"failure"`
	TypeUnsupported  int `json:"type-unsupported"`
}

type vtScanEntry struct {
	Category string `json:"category"`
	Result   string `json:"result"`
	Method   string `json:"method"`
}

// NewVirusTotalProvider creates a VT provider. apiKeyEnv is the env var name
// holding the API key. rateLimit is requests per minute (0 defaults to 4).
func NewVirusTotalProvider(apiKeyEnv string, timeout time.Duration, rateLimit int) (*VirusTotalProvider, error) {
	apiKey := os.Getenv(apiKeyEnv)
	if apiKey == "" {
		return nil, fmt.Errorf("VirusTotal API key not set: env var %s is empty", apiKeyEnv)
	}
	if rateLimit <= 0 {
		rateLimit = vtFreeRateLimit
	}
	return &VirusTotalProvider{
		apiKey: apiKey,
		httpClient: &http.Client{
			Timeout: timeout,
		},
		rateLimit: RateLimitStatus{
			Limit:     rateLimit,
			Remaining: rateLimit,
		},
		limiter: rate.NewLimiter(rate.Every(vtMinPollInterval), 1),
	}, nil
}

func (p *VirusTotalProvider) Name() string { return "virustotal" }

func (p *VirusTotalProvider) CheckIOC(ctx context.Context, iocType IOCType, value string) (*Match, error) {
	endpoint, err := vtEndpoint(iocType, value)
	if err != nil {
		return nil, nil
	}

	if err := p.limiter.Wait(ctx); err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("creating VT request: %w", err)
	}
	req.Header.Set("x-apikey", p.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("VT lookup failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("VT rate limit exceeded")
	}

	p.trackRate()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("VT API error %d: %s", resp.StatusCode, string(body))
	}

	var vtResp vtResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 10<<20)).Decode(&vtResp); err != nil {
		return nil, fmt.Errorf("decoding VT response: %w", err)
	}

	return vtBuildMatch(iocType, value, &vtResp.Data.Attributes), nil
}

func (p *VirusTotalProvider) CheckBatch(ctx context.Context, iocType IOCType, values []string) ([]Match, error) {
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
			errs = append(errs, fmt.Errorf("VT lookup for %q: %w", v, err))
			continue
		}
		if m != nil {
			matches = append(matches, *m)
		}
	}
	// If every lookup failed and nothing succeeded, surface a joined error.
	if len(matches) == 0 && len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return matches, nil
}

func (p *VirusTotalProvider) GetIndicators(_ context.Context, _ IOCType, _ time.Time) ([]Indicator, error) {
	return nil, fmt.Errorf("VT free tier does not support bulk indicator feeds")
}

func (p *VirusTotalProvider) HealthCheck(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, vtBaseURL+"/users/me", nil)
	if err != nil {
		return fmt.Errorf("creating VT health check request: %w", err)
	}
	req.Header.Set("x-apikey", p.apiKey)

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("VT health check failed: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		return nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return fmt.Errorf("VT authentication failed: invalid API key")
	default:
		return fmt.Errorf("VT health check returned status %d", resp.StatusCode)
	}
}

func (p *VirusTotalProvider) RateLimit() RateLimitStatus {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.rateLimit
}

func (p *VirusTotalProvider) trackRate() {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	// Reset counter when the previous window has expired.
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

func vtEndpoint(iocType IOCType, value string) (string, error) {
	switch iocType {
	case IOCTypeIP:
		return vtBaseURL + "/ip_addresses/" + url.PathEscape(value), nil
	case IOCTypeDomain:
		return vtBaseURL + "/domains/" + url.PathEscape(value), nil
	case IOCTypeURL:
		id := base64.RawURLEncoding.EncodeToString([]byte(value))
		return vtBaseURL + "/urls/" + id, nil
	case IOCTypeHash:
		return vtBaseURL + "/files/" + url.PathEscape(value), nil
	case IOCTypeEmail, IOCTypeFile:
		return "", fmt.Errorf("unsupported IOC type for VT: %s", iocType)
	default:
		return "", fmt.Errorf("unsupported IOC type for VT: %s", iocType)
	}
}

// vtBuildMatch maps VT analysis results to our Match type. Returns nil for clean results.
func vtBuildMatch(iocType IOCType, value string, attrs *vtAttributes) *Match {
	stats := attrs.LastAnalysisStats
	total := stats.Malicious + stats.Suspicious + stats.Undetected + stats.Harmless
	if total == 0 {
		return nil
	}

	positives := stats.Malicious + stats.Suspicious
	if positives == 0 {
		return nil
	}

	malRatio := float64(positives) / float64(total)
	confidence := malRatio
	if total < 10 {
		confidence *= 0.5
	}
	if confidence > 1.0 {
		confidence = 1.0
	}

	var firstSeen time.Time
	if attrs.FirstSubmissionDate != 0 {
		firstSeen = time.Unix(attrs.FirstSubmissionDate, 0)
	}
	var lastSeen time.Time
	if attrs.LastAnalysisDate != 0 {
		lastSeen = time.Unix(attrs.LastAnalysisDate, 0)
	}

	return &Match{
		Indicator: Indicator{
			Type:       iocType,
			Value:      value,
			ThreatType: vtInferThreatType(attrs),
			Confidence: confidence,
			Severity:   vtSeverity(malRatio),
			Source:     "virustotal",
			FirstSeen:  firstSeen,
			LastSeen:   lastSeen,
			Tags:       attrs.Tags,
		},
		MatchedOn:    string(iocType),
		MatchedValue: value,
		Source:       "virustotal",
		Timestamp:    time.Now().UTC(),
	}
}

func vtSeverity(malRatio float64) string {
	switch {
	case malRatio >= 0.5:
		return "critical"
	case malRatio >= 0.25:
		return "high"
	case malRatio >= 0.1:
		return "medium"
	default:
		return "low"
	}
}

func vtInferThreatType(attrs *vtAttributes) ThreatType {
	for _, tag := range attrs.Tags {
		lower := strings.ToLower(tag)
		switch {
		case strings.Contains(lower, "malware"):
			return ThreatTypeMalware
		case strings.Contains(lower, "phish"):
			return ThreatTypePhishing
		case strings.Contains(lower, "ransomware"):
			return ThreatTypeRansomware
		case strings.Contains(lower, "botnet"):
			return ThreatTypeBotnet
		case strings.Contains(lower, "c2") || strings.Contains(lower, "command"):
			return ThreatTypeC2
		case strings.Contains(lower, "scanner"):
			return ThreatTypeScanner
		case strings.Contains(lower, "tor"):
			return ThreatTypeTOR
		case strings.Contains(lower, "spam"):
			return ThreatTypeSpam
		}
	}
	return ThreatTypeUnknown
}
