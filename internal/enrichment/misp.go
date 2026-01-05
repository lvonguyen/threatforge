// Package enrichment provides a client for MISP (Malware Information Sharing Platform).
// MISP is an open-source threat intelligence platform for sharing, storing and
// correlating indicators of compromise.
package enrichment

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// MISPProvider implements the Provider interface for MISP.
type MISPProvider struct {
	config     MISPConfig
	httpClient *http.Client
	rateLimit  RateLimitStatus
	mu         sync.RWMutex
}

// MISPConfig holds MISP-specific configuration.
type MISPConfig struct {
	ProviderConfig `yaml:",inline"`
	VerifySSL      bool     `yaml:"verify_ssl"`
	OrgFilter      []string `yaml:"org_filter"`   // Filter by organization
	TagFilter      []string `yaml:"tag_filter"`   // Filter by tags
	ThreatLevel    []int    `yaml:"threat_level"` // 1=High, 2=Medium, 3=Low, 4=Undefined
	PublishedOnly  bool     `yaml:"published_only"`
}

// DefaultMISPConfig returns sensible defaults for MISP.
func DefaultMISPConfig() MISPConfig {
	return MISPConfig{
		ProviderConfig: DefaultProviderConfig(),
		VerifySSL:      true,
		PublishedOnly:  true,
		ThreatLevel:    []int{1, 2, 3}, // High, Medium, Low (exclude undefined)
	}
}

// NewMISPProvider creates a new MISP provider.
func NewMISPProvider(config MISPConfig) (*MISPProvider, error) {
	// Load API key from environment
	apiKey := os.Getenv(config.APIKey)
	if apiKey == "" {
		return nil, fmt.Errorf("MISP API key not found in env var: %s", config.APIKey)
	}

	if config.BaseURL == "" {
		return nil, fmt.Errorf("MISP base URL is required")
	}

	return &MISPProvider{
		config: config,
		httpClient: &http.Client{
			Timeout: config.Timeout,
		},
		rateLimit: RateLimitStatus{
			Remaining: config.RateLimit,
			Limit:     config.RateLimit,
			ResetAt:   time.Now().Add(time.Minute),
		},
	}, nil
}

// Name returns the provider identifier.
func (p *MISPProvider) Name() string {
	return "misp"
}

// HealthCheck verifies connectivity to MISP.
func (p *MISPProvider) HealthCheck(ctx context.Context) error {
	req, err := p.newRequest(ctx, "GET", "/servers/getVersion", nil)
	if err != nil {
		return err
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("MISP health check failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("MISP returned status %d", resp.StatusCode)
	}

	return nil
}

// RateLimit returns current rate limit status.
func (p *MISPProvider) RateLimit() RateLimitStatus {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.rateLimit
}

// GetIndicators retrieves indicators from MISP.
func (p *MISPProvider) GetIndicators(ctx context.Context, iocType IOCType, since time.Time) ([]Indicator, error) {
	mispType := toMISPType(iocType)
	if mispType == "" {
		return nil, fmt.Errorf("unsupported IOC type for MISP: %s", iocType)
	}

	// Build search request
	searchReq := MISPAttributeSearchRequest{
		Type:      mispType,
		Timestamp: since.Unix(),
		Published: p.config.PublishedOnly,
	}

	body, err := json.Marshal(searchReq)
	if err != nil {
		return nil, err
	}

	req, err := p.newRequest(ctx, "POST", "/attributes/restSearch", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("MISP search failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("MISP returned %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var searchResp MISPAttributeSearchResponse
	if err := json.NewDecoder(resp.Body).Decode(&searchResp); err != nil {
		return nil, fmt.Errorf("failed to decode MISP response: %w", err)
	}

	// Convert to common format
	indicators := make([]Indicator, 0, len(searchResp.Response.Attribute))
	for _, attr := range searchResp.Response.Attribute {
		indicators = append(indicators, p.attributeToIndicator(attr, iocType))
	}

	return indicators, nil
}

// CheckIOC checks if a value exists in MISP.
func (p *MISPProvider) CheckIOC(ctx context.Context, iocType IOCType, value string) (*Match, error) {
	mispType := toMISPType(iocType)
	if mispType == "" {
		return nil, nil // Unsupported type
	}

	// Search by value
	searchReq := MISPAttributeSearchRequest{
		Value:     value,
		Type:      mispType,
		Published: p.config.PublishedOnly,
	}

	body, err := json.Marshal(searchReq)
	if err != nil {
		return nil, err
	}

	req, err := p.newRequest(ctx, "POST", "/attributes/restSearch", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("MISP search failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("MISP returned status %d", resp.StatusCode)
	}

	var searchResp MISPAttributeSearchResponse
	if err := json.NewDecoder(resp.Body).Decode(&searchResp); err != nil {
		return nil, err
	}

	if len(searchResp.Response.Attribute) == 0 {
		return nil, nil // Not found
	}

	// Return first match (most relevant)
	attr := searchResp.Response.Attribute[0]
	indicator := p.attributeToIndicator(attr, iocType)

	return &Match{
		Indicator:    indicator,
		MatchedOn:    string(iocType),
		MatchedValue: value,
		Source:       "misp",
		Timestamp:    time.Now(),
	}, nil
}

// CheckBatch checks multiple IOCs against MISP.
func (p *MISPProvider) CheckBatch(ctx context.Context, iocType IOCType, values []string) ([]Match, error) {
	// MISP supports OR queries with multiple values
	mispType := toMISPType(iocType)
	if mispType == "" {
		return nil, nil
	}

	// Join values for OR search
	searchReq := MISPAttributeSearchRequest{
		Value:     strings.Join(values, "||"),
		Type:      mispType,
		Published: p.config.PublishedOnly,
	}

	body, err := json.Marshal(searchReq)
	if err != nil {
		return nil, err
	}

	req, err := p.newRequest(ctx, "POST", "/attributes/restSearch", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("MISP batch search failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("MISP returned status %d", resp.StatusCode)
	}

	var searchResp MISPAttributeSearchResponse
	if err := json.NewDecoder(resp.Body).Decode(&searchResp); err != nil {
		return nil, err
	}

	// Convert matches
	matches := make([]Match, 0, len(searchResp.Response.Attribute))
	for _, attr := range searchResp.Response.Attribute {
		indicator := p.attributeToIndicator(attr, iocType)
		matches = append(matches, Match{
			Indicator:    indicator,
			MatchedOn:    string(iocType),
			MatchedValue: attr.Value,
			Source:       "misp",
			Timestamp:    time.Now(),
		})
	}

	return matches, nil
}

// newRequest creates an authenticated MISP API request.
func (p *MISPProvider) newRequest(ctx context.Context, method, path string, body io.Reader) (*http.Request, error) {
	url := strings.TrimSuffix(p.config.BaseURL, "/") + path

	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, err
	}

	apiKey := os.Getenv(p.config.APIKey)
	req.Header.Set("Authorization", apiKey)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	return req, nil
}

// attributeToIndicator converts a MISP attribute to common format.
func (p *MISPProvider) attributeToIndicator(attr MISPAttribute, iocType IOCType) Indicator {
	// Parse timestamps
	firstSeen := time.Unix(attr.FirstSeen, 0)
	lastSeen := time.Unix(attr.LastSeen, 0)
	if attr.LastSeen == 0 {
		lastSeen = firstSeen
	}

	// Determine threat type from MISP category
	threatType := categoryToThreatType(attr.Category)

	// Calculate confidence based on MISP threat level
	confidence := threatLevelToConfidence(attr.Event.ThreatLevelID)

	// Extract tags
	tags := make([]string, 0, len(attr.Tag))
	for _, t := range attr.Tag {
		tags = append(tags, t.Name)
	}

	return Indicator{
		ID:          attr.UUID,
		Type:        iocType,
		Value:       attr.Value,
		ThreatType:  threatType,
		Confidence:  confidence,
		Severity:    threatLevelToSeverity(attr.Event.ThreatLevelID),
		Source:      "misp",
		FirstSeen:   firstSeen,
		LastSeen:    lastSeen,
		Tags:        tags,
		Description: attr.Comment,
		Reference:   fmt.Sprintf("%s/events/view/%s", p.config.BaseURL, attr.EventID),
		Raw:         attr,
	}
}

// MISP API types

// MISPAttributeSearchRequest is the MISP attribute search request.
type MISPAttributeSearchRequest struct {
	Value     string `json:"value,omitempty"`
	Type      string `json:"type,omitempty"`
	Category  string `json:"category,omitempty"`
	Timestamp int64  `json:"timestamp,omitempty"`
	Published bool   `json:"published,omitempty"`
	Limit     int    `json:"limit,omitempty"`
}

// MISPAttributeSearchResponse is the MISP attribute search response.
type MISPAttributeSearchResponse struct {
	Response struct {
		Attribute []MISPAttribute `json:"Attribute"`
	} `json:"response"`
}

// MISPAttribute represents a MISP attribute.
type MISPAttribute struct {
	ID        string     `json:"id"`
	UUID      string     `json:"uuid"`
	EventID   string     `json:"event_id"`
	Type      string     `json:"type"`
	Category  string     `json:"category"`
	Value     string     `json:"value"`
	Comment   string     `json:"comment"`
	FirstSeen int64      `json:"first_seen"`
	LastSeen  int64      `json:"last_seen"`
	ToIDS     bool       `json:"to_ids"`
	Timestamp string     `json:"timestamp"`
	Tag       []MISPTag  `json:"Tag,omitempty"`
	Event     MISPEvent  `json:"Event,omitempty"`
}

// MISPTag represents a MISP tag.
type MISPTag struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Color string `json:"colour"`
}

// MISPEvent represents minimal MISP event info.
type MISPEvent struct {
	ID            string `json:"id"`
	UUID          string `json:"uuid"`
	Info          string `json:"info"`
	ThreatLevelID string `json:"threat_level_id"`
	Published     bool   `json:"published"`
}

// Helper functions

func toMISPType(iocType IOCType) string {
	switch iocType {
	case IOCTypeIP:
		return "ip-src|ip-dst"
	case IOCTypeDomain:
		return "domain"
	case IOCTypeURL:
		return "url"
	case IOCTypeHash:
		return "md5|sha1|sha256"
	case IOCTypeEmail:
		return "email-src|email-dst"
	default:
		return ""
	}
}

func categoryToThreatType(category string) ThreatType {
	switch category {
	case "Network activity":
		return ThreatTypeC2
	case "Payload delivery":
		return ThreatTypeMalware
	case "Artifacts dropped":
		return ThreatTypeMalware
	case "Payload installation":
		return ThreatTypeMalware
	case "Persistence mechanism":
		return ThreatTypeMalware
	case "External analysis":
		return ThreatTypeUnknown
	default:
		return ThreatTypeUnknown
	}
}

func threatLevelToConfidence(level string) float64 {
	switch level {
	case "1": // High
		return 0.9
	case "2": // Medium
		return 0.7
	case "3": // Low
		return 0.5
	default: // Undefined
		return 0.3
	}
}

func threatLevelToSeverity(level string) string {
	switch level {
	case "1":
		return "critical"
	case "2":
		return "high"
	case "3":
		return "medium"
	default:
		return "low"
	}
}
