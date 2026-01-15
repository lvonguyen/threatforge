// Package enrichment provides a client for AlienVault OTX (Open Threat Exchange).
// OTX is a free threat intelligence community that provides indicators of compromise
// and threat data shared by security researchers worldwide.
package enrichment

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	otxDefaultBaseURL = "https://otx.alienvault.com"
	otxAPIPath        = "/api/v1"
)

// OTXProvider implements the Provider interface for AlienVault OTX.
type OTXProvider struct {
	config     OTXConfig
	httpClient *http.Client
	cache      *otxCache
	rateLimit  RateLimitStatus
	mu         sync.RWMutex
}

// OTXConfig holds OTX-specific configuration.
type OTXConfig struct {
	ProviderConfig `yaml:",inline"`
	PulseLimit     int      `yaml:"pulse_limit"`     // Max pulses to fetch per request
	MinPulseAge    int      `yaml:"min_pulse_age"`   // Min days old for pulses (0 = all)
	ThreatTypes    []string `yaml:"threat_types"`    // Filter by threat type
	IncludeExpired bool     `yaml:"include_expired"` // Include expired indicators
}

// DefaultOTXConfig returns sensible defaults for OTX.
func DefaultOTXConfig() OTXConfig {
	return OTXConfig{
		ProviderConfig: ProviderConfig{
			APIKey:     "OTX_API_KEY",
			BaseURL:    otxDefaultBaseURL,
			Timeout:    30 * time.Second,
			RetryCount: 3,
			CacheTTL:   1 * time.Hour,
			RateLimit:  60, // OTX allows ~60 requests/minute
		},
		PulseLimit:     50,
		MinPulseAge:    0,
		IncludeExpired: false,
	}
}

// otxCache provides thread-safe caching for OTX lookups.
type otxCache struct {
	mu      sync.RWMutex
	entries map[string]*otxCacheEntry
	ttl     time.Duration
}

type otxCacheEntry struct {
	match     *Match
	expiresAt time.Time
	notFound  bool // Cache negative results too
}

func newOTXCache(ttl time.Duration) *otxCache {
	return &otxCache{
		entries: make(map[string]*otxCacheEntry),
		ttl:     ttl,
	}
}

func (c *otxCache) get(key string) (*Match, bool, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, exists := c.entries[key]
	if !exists {
		return nil, false, false
	}

	if time.Now().After(entry.expiresAt) {
		return nil, false, false
	}

	return entry.match, entry.notFound, true
}

func (c *otxCache) set(key string, match *Match, notFound bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries[key] = &otxCacheEntry{
		match:     match,
		expiresAt: time.Now().Add(c.ttl),
		notFound:  notFound,
	}
}

func (c *otxCache) cacheKey(iocType IOCType, value string) string {
	return fmt.Sprintf("%s:%s", iocType, strings.ToLower(value))
}

// cleanup removes expired entries (call periodically).
func (c *otxCache) cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	for key, entry := range c.entries {
		if now.After(entry.expiresAt) {
			delete(c.entries, key)
		}
	}
}

// NewOTXProvider creates a new OTX provider.
func NewOTXProvider(config OTXConfig) (*OTXProvider, error) {
	apiKey := os.Getenv(config.APIKey)
	if apiKey == "" {
		return nil, fmt.Errorf("OTX API key not found in env var: %s", config.APIKey)
	}

	if config.BaseURL == "" {
		config.BaseURL = otxDefaultBaseURL
	}

	provider := &OTXProvider{
		config: config,
		httpClient: &http.Client{
			Timeout: config.Timeout,
		},
		cache: newOTXCache(config.CacheTTL),
		rateLimit: RateLimitStatus{
			Remaining: config.RateLimit,
			Limit:     config.RateLimit,
			ResetAt:   time.Now().Add(time.Minute),
		},
	}

	// Start background cache cleanup
	go provider.startCacheCleanup()

	return provider, nil
}

func (p *OTXProvider) startCacheCleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	for range ticker.C {
		p.cache.cleanup()
	}
}

// Name returns the provider identifier.
func (p *OTXProvider) Name() string {
	return "otx"
}

// HealthCheck verifies connectivity to OTX.
func (p *OTXProvider) HealthCheck(ctx context.Context) error {
	req, err := p.newRequest(ctx, "GET", "/user/me", nil)
	if err != nil {
		return fmt.Errorf("creating health check request: %w", err)
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("OTX health check failed: %w", err)
	}
	defer resp.Body.Close()

	p.updateRateLimit(resp)

	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("OTX authentication failed: invalid API key")
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("OTX returned status %d", resp.StatusCode)
	}

	return nil
}

// RateLimit returns current rate limit status.
func (p *OTXProvider) RateLimit() RateLimitStatus {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.rateLimit
}

// GetIndicators retrieves indicators from OTX subscribed pulses.
func (p *OTXProvider) GetIndicators(ctx context.Context, iocType IOCType, since time.Time) ([]Indicator, error) {
	// OTX uses pulses - fetch subscribed pulses and extract indicators
	path := fmt.Sprintf("/pulses/subscribed?modified_since=%s&limit=%d",
		url.QueryEscape(since.Format(time.RFC3339)),
		p.config.PulseLimit,
	)

	req, err := p.newRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("creating indicators request: %w", err)
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching OTX pulses: %w", err)
	}
	defer resp.Body.Close()

	p.updateRateLimit(resp)

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("OTX returned %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var pulseResp OTXPulseListResponse
	if err := json.NewDecoder(resp.Body).Decode(&pulseResp); err != nil {
		return nil, fmt.Errorf("decoding OTX response: %w", err)
	}

	// Extract indicators matching the requested type
	var indicators []Indicator
	for _, pulse := range pulseResp.Results {
		for _, ind := range pulse.Indicators {
			indType := otxTypeToIOCType(ind.Type)
			if indType == iocType {
				indicators = append(indicators, p.otxIndicatorToIndicator(ind, pulse))
			}
		}
	}

	return indicators, nil
}

// CheckIOC checks if a value exists in OTX.
func (p *OTXProvider) CheckIOC(ctx context.Context, iocType IOCType, value string) (*Match, error) {
	// Check cache first
	cacheKey := p.cache.cacheKey(iocType, value)
	if match, notFound, exists := p.cache.get(cacheKey); exists {
		if notFound {
			return nil, nil
		}
		return match, nil
	}

	// Build API path based on IOC type
	path, err := p.buildIndicatorPath(iocType, value)
	if err != nil {
		return nil, nil // Unsupported type
	}

	req, err := p.newRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("creating check request: %w", err)
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("OTX lookup failed: %w", err)
	}
	defer resp.Body.Close()

	p.updateRateLimit(resp)

	// 404 means not found in OTX
	if resp.StatusCode == http.StatusNotFound {
		p.cache.set(cacheKey, nil, true)
		return nil, nil
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OTX returned status %d", resp.StatusCode)
	}

	var generalResp OTXGeneralResponse
	if err := json.NewDecoder(resp.Body).Decode(&generalResp); err != nil {
		return nil, fmt.Errorf("decoding OTX response: %w", err)
	}

	// Check if there are any associated pulses (threats)
	if generalResp.PulseInfo.Count == 0 {
		p.cache.set(cacheKey, nil, true)
		return nil, nil
	}

	// Build match from first pulse
	match := p.buildMatchFromGeneral(iocType, value, generalResp)
	p.cache.set(cacheKey, match, false)

	return match, nil
}

// CheckBatch checks multiple IOCs against OTX.
func (p *OTXProvider) CheckBatch(ctx context.Context, iocType IOCType, values []string) ([]Match, error) {
	// OTX doesn't have a native batch API, so we check individually
	// but leverage caching to avoid redundant lookups
	var matches []Match

	for _, value := range values {
		select {
		case <-ctx.Done():
			return matches, ctx.Err()
		default:
		}

		match, err := p.CheckIOC(ctx, iocType, value)
		if err != nil {
			// Log but continue with other values
			continue
		}

		if match != nil {
			matches = append(matches, *match)
		}
	}

	return matches, nil
}

// buildIndicatorPath constructs the API path for IOC lookup.
func (p *OTXProvider) buildIndicatorPath(iocType IOCType, value string) (string, error) {
	encodedValue := url.PathEscape(value)

	switch iocType {
	case IOCTypeIP:
		// OTX auto-detects IPv4 vs IPv6
		return fmt.Sprintf("/indicators/IPv4/%s/general", encodedValue), nil
	case IOCTypeDomain:
		return fmt.Sprintf("/indicators/domain/%s/general", encodedValue), nil
	case IOCTypeURL:
		return fmt.Sprintf("/indicators/url/%s/general", encodedValue), nil
	case IOCTypeHash:
		// Detect hash type by length
		hashType := detectHashType(value)
		if hashType == "" {
			return "", fmt.Errorf("unknown hash type for value: %s", value)
		}
		return fmt.Sprintf("/indicators/file/%s/general", encodedValue), nil
	default:
		return "", fmt.Errorf("unsupported IOC type: %s", iocType)
	}
}

func detectHashType(hash string) string {
	switch len(hash) {
	case 32:
		return "MD5"
	case 40:
		return "SHA1"
	case 64:
		return "SHA256"
	default:
		return ""
	}
}

// newRequest creates an authenticated OTX API request.
func (p *OTXProvider) newRequest(ctx context.Context, method, path string, body io.Reader) (*http.Request, error) {
	fullURL := strings.TrimSuffix(p.config.BaseURL, "/") + otxAPIPath + path

	req, err := http.NewRequestWithContext(ctx, method, fullURL, body)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	apiKey := os.Getenv(p.config.APIKey)
	req.Header.Set("X-OTX-API-KEY", apiKey)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "ThreatForge/1.0")

	return req, nil
}

// updateRateLimit updates rate limit from response headers.
func (p *OTXProvider) updateRateLimit(resp *http.Response) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// OTX uses X-RateLimit-* headers
	if remaining := resp.Header.Get("X-RateLimit-Remaining"); remaining != "" {
		var r int
		fmt.Sscanf(remaining, "%d", &r)
		p.rateLimit.Remaining = r
	}

	if limit := resp.Header.Get("X-RateLimit-Limit"); limit != "" {
		var l int
		fmt.Sscanf(limit, "%d", &l)
		p.rateLimit.Limit = l
	}
}

// otxTypeToIOCType converts OTX indicator type to our IOCType.
func otxTypeToIOCType(otxType string) IOCType {
	switch otxType {
	case "IPv4", "IPv6":
		return IOCTypeIP
	case "domain", "hostname":
		return IOCTypeDomain
	case "URL", "URI":
		return IOCTypeURL
	case "FileHash-MD5", "FileHash-SHA1", "FileHash-SHA256":
		return IOCTypeHash
	case "email":
		return IOCTypeEmail
	case "filepath":
		return IOCTypeFile
	default:
		return ""
	}
}

// otxIndicatorToIndicator converts OTX indicator to our format.
func (p *OTXProvider) otxIndicatorToIndicator(ind OTXIndicator, pulse OTXPulse) Indicator {
	created, _ := time.Parse("2006-01-02T15:04:05", ind.Created)
	modified, _ := time.Parse("2006-01-02T15:04:05.000000", pulse.Modified)

	if modified.IsZero() {
		modified = created
	}

	return Indicator{
		ID:          ind.ID,
		Type:        otxTypeToIOCType(ind.Type),
		Value:       ind.Indicator,
		ThreatType:  p.determineThreatType(pulse),
		Confidence:  0.7, // Default moderate confidence
		Severity:    p.determineSeverity(pulse),
		Source:      "otx",
		FirstSeen:   created,
		LastSeen:    modified,
		Tags:        pulse.Tags,
		Description: ind.Description,
		Reference:   fmt.Sprintf("https://otx.alienvault.com/pulse/%s", pulse.ID),
		Raw:         ind,
	}
}

// buildMatchFromGeneral creates a Match from OTX general response.
func (p *OTXProvider) buildMatchFromGeneral(iocType IOCType, value string, resp OTXGeneralResponse) *Match {
	if len(resp.PulseInfo.Pulses) == 0 {
		return nil
	}

	// Use first pulse for primary match info
	pulse := resp.PulseInfo.Pulses[0]
	created, _ := time.Parse("2006-01-02T15:04:05.000000", pulse.Created)
	modified, _ := time.Parse("2006-01-02T15:04:05.000000", pulse.Modified)

	if modified.IsZero() {
		modified = created
	}

	indicator := Indicator{
		ID:          pulse.ID,
		Type:        iocType,
		Value:       value,
		ThreatType:  p.determineThreatType(pulse),
		Confidence:  p.calculateConfidence(resp.PulseInfo.Count),
		Severity:    p.determineSeverity(pulse),
		Source:      "otx",
		FirstSeen:   created,
		LastSeen:    modified,
		Tags:        pulse.Tags,
		Description: pulse.Description,
		Reference:   fmt.Sprintf("https://otx.alienvault.com/pulse/%s", pulse.ID),
		Raw:         resp,
	}

	return &Match{
		Indicator:    indicator,
		MatchedOn:    string(iocType),
		MatchedValue: value,
		Source:       "otx",
		Timestamp:    time.Now(),
	}
}

// determineThreatType maps OTX pulse data to our threat type.
func (p *OTXProvider) determineThreatType(pulse OTXPulse) ThreatType {
	// Check tags for threat indicators
	tagLower := strings.ToLower(strings.Join(pulse.Tags, " "))

	switch {
	case strings.Contains(tagLower, "malware"):
		return ThreatTypeMalware
	case strings.Contains(tagLower, "c2") || strings.Contains(tagLower, "command and control"):
		return ThreatTypeC2
	case strings.Contains(tagLower, "phishing"):
		return ThreatTypePhishing
	case strings.Contains(tagLower, "botnet"):
		return ThreatTypeBotnet
	case strings.Contains(tagLower, "scanner") || strings.Contains(tagLower, "scan"):
		return ThreatTypeScanner
	case strings.Contains(tagLower, "tor"):
		return ThreatTypeTOR
	case strings.Contains(tagLower, "vpn"):
		return ThreatTypeVPN
	case strings.Contains(tagLower, "proxy"):
		return ThreatTypeProxy
	case strings.Contains(tagLower, "spam"):
		return ThreatTypeSpam
	case strings.Contains(tagLower, "apt"):
		return ThreatTypeAPT
	case strings.Contains(tagLower, "ransomware"):
		return ThreatTypeRansomware
	default:
		return ThreatTypeUnknown
	}
}

// determineSeverity maps OTX pulse to severity level.
func (p *OTXProvider) determineSeverity(pulse OTXPulse) string {
	// Check tags for severity indicators first (highest priority)
	tagLower := strings.ToLower(strings.Join(pulse.Tags, " "))

	switch {
	case strings.Contains(tagLower, "apt") || strings.Contains(tagLower, "ransomware"):
		return "critical"
	case strings.Contains(tagLower, "malware") || strings.Contains(tagLower, "c2"):
		return "high"
	case strings.Contains(tagLower, "phishing") || strings.Contains(tagLower, "botnet"):
		return "medium"
	}

	// If adversary field is present, at least high severity
	if pulse.Adversary != "" {
		return "high"
	}

	return "low"
}

// calculateConfidence determines confidence based on pulse count.
func (p *OTXProvider) calculateConfidence(pulseCount int) float64 {
	switch {
	case pulseCount >= 10:
		return 0.95
	case pulseCount >= 5:
		return 0.85
	case pulseCount >= 3:
		return 0.75
	case pulseCount >= 1:
		return 0.65
	default:
		return 0.5
	}
}

// OTX API Response Types

// OTXPulseListResponse is the response from /pulses/subscribed.
type OTXPulseListResponse struct {
	Results []OTXPulse `json:"results"`
	Count   int        `json:"count"`
	Next    string     `json:"next,omitempty"`
}

// OTXPulse represents an OTX pulse (threat report).
type OTXPulse struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Author      OTXAuthor      `json:"author"`
	Created     string         `json:"created"`
	Modified    string         `json:"modified"`
	Tags        []string       `json:"tags"`
	Adversary   string         `json:"adversary,omitempty"`
	Industries  []string       `json:"industries,omitempty"`
	Countries   []string       `json:"targeted_countries,omitempty"`
	Indicators  []OTXIndicator `json:"indicators,omitempty"`
}

// OTXAuthor represents the pulse author.
type OTXAuthor struct {
	Username     string `json:"username"`
	ID           string `json:"id"`
	AvatarURL    string `json:"avatar_url,omitempty"`
	IsSubscribed bool   `json:"is_subscribed"`
	IsFollowing  bool   `json:"is_following"`
}

// OTXIndicator represents an indicator within a pulse.
type OTXIndicator struct {
	ID          string `json:"id"`
	Indicator   string `json:"indicator"`
	Type        string `json:"type"`
	Created     string `json:"created"`
	Description string `json:"description,omitempty"`
	Title       string `json:"title,omitempty"`
	Content     string `json:"content,omitempty"`
	IsActive    int    `json:"is_active"`
	Expiration  string `json:"expiration,omitempty"`
}

// OTXGeneralResponse is the response from /indicators/{type}/{value}/general.
type OTXGeneralResponse struct {
	Indicator   string       `json:"indicator"`
	Type        string       `json:"type"`
	TypeTitle   string       `json:"type_title"`
	Whois       string       `json:"whois,omitempty"`
	Reputation  int          `json:"reputation"`
	PulseInfo   OTXPulseInfo `json:"pulse_info"`
	BaseInfo    OTXBaseInfo  `json:"base_indicator,omitempty"`
	Validation  []OTXValid   `json:"validation,omitempty"`
	ASN         string       `json:"asn,omitempty"`
	CountryCode string       `json:"country_code,omitempty"`
	CountryName string       `json:"country_name,omitempty"`
	City        string       `json:"city,omitempty"`
}

// OTXPulseInfo contains pulse association info.
type OTXPulseInfo struct {
	Count      int        `json:"count"`
	Pulses     []OTXPulse `json:"pulses"`
	References []string   `json:"references,omitempty"`
}

// OTXBaseInfo contains base indicator info.
type OTXBaseInfo struct {
	ID          int    `json:"id"`
	Indicator   string `json:"indicator"`
	Type        string `json:"type"`
	AccessType  string `json:"access_type"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Content     string `json:"content"`
}

// OTXValid represents validation info.
type OTXValid struct {
	Source string `json:"source"`
	Name   string `json:"name"`
}
