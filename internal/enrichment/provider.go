// Package enrichment provides threat intelligence provider integrations.
package enrichment

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"time"
)

// validateExternalURL rejects base URLs that resolve to internal address ranges
// to prevent Server-Side Request Forgery (SSRF) against internal infrastructure.
//
// Blocked ranges: link-local (169.254.x / fe80:: — AWS/GCP/Azure IMDS),
// RFC-1918 private networks (10.x, 172.16-31.x, 192.168.x), shared address
// space (100.64.x — RFC 6598), IPv6 unique-local (fc00::/7), and the
// unspecified address (0.0.0.0, ::).
//
// Loopback (127.x, ::1) is intentionally NOT blocked so that local test
// servers remain accessible during development and testing.
func validateExternalURL(rawURL string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}

	host := parsed.Hostname()
	if host == "" {
		return fmt.Errorf("URL has no host: %s", rawURL)
	}

	// Resolve host to IPs (handles both DNS names and IP literals).
	ips, err := net.LookupHost(host)
	if err != nil {
		// DNS failure: pass through and let the HTTP client handle it.
		return nil
	}

	for _, ipStr := range ips {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}
		if isInternalIP(ip) {
			return fmt.Errorf("SSRF protection: URL %q resolves to an internal address (%s)", rawURL, ipStr)
		}
	}

	return nil
}

// internalNetworks holds the pre-parsed CIDR ranges checked by isInternalIP.
// Parsed once at init to avoid repeated net.ParseCIDR calls on every invocation.
var internalNetworks []*net.IPNet

func init() {
	cidrs := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"100.64.0.0/10", // Shared address space (RFC 6598)
		"fc00::/7",      // IPv6 unique local
	}
	for _, cidr := range cidrs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		internalNetworks = append(internalNetworks, network)
	}
}

// isInternalIP returns true for link-local, RFC-1918, shared-address-space,
// and unspecified addresses. Loopback is excluded to allow local/test servers.
func isInternalIP(ip net.IP) bool {
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return true
	}

	for _, network := range internalNetworks {
		if network.Contains(ip) {
			return true
		}
	}

	return false
}

// IOCType represents the type of indicator of compromise.
type IOCType string

const (
	IOCTypeIP     IOCType = "ip"
	IOCTypeDomain IOCType = "domain"
	IOCTypeURL    IOCType = "url"
	IOCTypeHash   IOCType = "hash"
	IOCTypeEmail  IOCType = "email"
	IOCTypeFile   IOCType = "filename"
)

// ThreatType categorizes the threat.
type ThreatType string

const (
	ThreatTypeMalware    ThreatType = "malware"
	ThreatTypeC2         ThreatType = "c2"
	ThreatTypePhishing   ThreatType = "phishing"
	ThreatTypeBotnet     ThreatType = "botnet"
	ThreatTypeScanner    ThreatType = "scanner"
	ThreatTypeTOR        ThreatType = "tor"
	ThreatTypeVPN        ThreatType = "vpn"
	ThreatTypeProxy      ThreatType = "proxy"
	ThreatTypeSpam       ThreatType = "spam"
	ThreatTypeAPT        ThreatType = "apt"
	ThreatTypeRansomware ThreatType = "ransomware"
	ThreatTypeUnknown    ThreatType = "unknown"
)

// Indicator represents a threat intelligence indicator.
type Indicator struct {
	ID          string     `json:"id"`
	Type        IOCType    `json:"type"`
	Value       string     `json:"value"`
	ThreatType  ThreatType `json:"threat_type"`
	Confidence  float64    `json:"confidence"`
	Severity    string     `json:"severity"`
	Source      string     `json:"source"`
	FirstSeen   time.Time  `json:"first_seen"`
	LastSeen    time.Time  `json:"last_seen"`
	Tags        []string   `json:"tags"`
	Description string     `json:"description,omitempty"`
	Reference   string     `json:"reference,omitempty"`
	Raw         any        `json:"raw,omitempty"`
}

// Match represents a threat intel match result.
type Match struct {
	Indicator    Indicator `json:"indicator"`
	MatchedOn    string    `json:"matched_on"`
	MatchedValue string    `json:"matched_value"`
	Source       string    `json:"source"`
	Timestamp    time.Time `json:"timestamp"`
}

// Provider is the interface for threat intelligence sources.
type Provider interface {
	Name() string
	GetIndicators(ctx context.Context, iocType IOCType, since time.Time) ([]Indicator, error)
	CheckIOC(ctx context.Context, iocType IOCType, value string) (*Match, error)
	CheckBatch(ctx context.Context, iocType IOCType, values []string) ([]Match, error)
	HealthCheck(ctx context.Context) error
	RateLimit() RateLimitStatus
}

// RateLimitStatus represents API rate limiting.
type RateLimitStatus struct {
	Remaining int       `json:"remaining"`
	Limit     int       `json:"limit"`
	ResetAt   time.Time `json:"reset_at"`
}

// ProviderConfig holds common provider configuration.
type ProviderConfig struct {
	APIKey     string        `yaml:"api_key_env"`
	BaseURL    string        `yaml:"base_url"`
	Timeout    time.Duration `yaml:"timeout"`
	RetryCount int           `yaml:"retry_count"`
	CacheTTL   time.Duration `yaml:"cache_ttl"`
	RateLimit  int           `yaml:"rate_limit"`
}

// DefaultProviderConfig returns sensible defaults.
func DefaultProviderConfig() ProviderConfig {
	return ProviderConfig{
		Timeout:    30 * time.Second,
		RetryCount: 3,
		CacheTTL:   1 * time.Hour,
		RateLimit:  60,
	}
}

// Alert represents an incoming security alert.
type Alert struct {
	ID          string         `json:"id"`
	Timestamp   time.Time      `json:"timestamp"`
	Source      string         `json:"source"`
	Severity    string         `json:"severity"`
	Title       string         `json:"title"`
	Description string         `json:"description"`
	SrcIP       string         `json:"src_ip,omitempty"`
	DstIP       string         `json:"dst_ip,omitempty"`
	Domain      string         `json:"domain,omitempty"`
	URL         string         `json:"url,omitempty"`
	Hash        string         `json:"hash,omitempty"`
	User        string         `json:"user,omitempty"`
	Host        string         `json:"host,omitempty"`
	Raw         map[string]any `json:"raw,omitempty"`
}

// EnrichedAlert is an alert with threat intelligence added.
type EnrichedAlert struct {
	OriginalAlert Alert     `json:"original_alert"`
	ThreatIntel   []Match   `json:"threat_intel"`
	RiskScore     int       `json:"risk_score"`
	Confidence    float64   `json:"confidence"`
	MITREMapping  []string  `json:"mitre_mapping"`
	Timestamp     time.Time `json:"enriched_at"`
}
