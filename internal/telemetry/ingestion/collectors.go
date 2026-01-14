// Package ingestion provides multi-source security telemetry collection.
// Consolidated from threat-telemetry-hub/internal/ingestion
package ingestion

import (
	"context"
	"time"
)

// Collector defines the interface for telemetry collectors
type Collector interface {
	// Name returns the collector name
	Name() string
	// Type returns the collector type (edr, siem, cloud)
	Type() string
	// Collect fetches events from the source
	Collect(ctx context.Context, since time.Time) ([]*RawEvent, error)
	// HealthCheck verifies connectivity
	HealthCheck(ctx context.Context) error
}

// RawEvent represents an unprocessed security event
type RawEvent struct {
	ID         string                 `json:"id"`
	Timestamp  time.Time              `json:"timestamp"`
	Source     string                 `json:"source"`      // crowdstrike, sentinelone, splunk, etc.
	SourceType string                 `json:"source_type"` // edr, siem, cloud
	Data       map[string]interface{} `json:"data"`
}

// CollectorConfig holds configuration for a collector
type CollectorConfig struct {
	Name       string            `yaml:"name"`
	Type       string            `yaml:"type"`
	Enabled    bool              `yaml:"enabled"`
	APIURL     string            `yaml:"api_url"`
	AuthType   string            `yaml:"auth_type"` // api_key, oauth, basic
	Credentials map[string]string `yaml:"credentials"`
	PollInterval time.Duration   `yaml:"poll_interval"`
}

// CrowdStrikeCollector collects events from CrowdStrike Falcon
type CrowdStrikeCollector struct {
	config CollectorConfig
}

// NewCrowdStrikeCollector creates a new CrowdStrike collector
func NewCrowdStrikeCollector(cfg CollectorConfig) *CrowdStrikeCollector {
	return &CrowdStrikeCollector{config: cfg}
}

func (c *CrowdStrikeCollector) Name() string { return "crowdstrike" }
func (c *CrowdStrikeCollector) Type() string { return "edr" }

func (c *CrowdStrikeCollector) Collect(ctx context.Context, since time.Time) ([]*RawEvent, error) {
	// TODO: Implement CrowdStrike Falcon API integration
	// - Authenticate with OAuth2
	// - Query detections endpoint
	// - Transform to RawEvent format
	return nil, nil
}

func (c *CrowdStrikeCollector) HealthCheck(ctx context.Context) error {
	return nil
}

// SentinelOneCollector collects events from SentinelOne
type SentinelOneCollector struct {
	config CollectorConfig
}

// NewSentinelOneCollector creates a new SentinelOne collector
func NewSentinelOneCollector(cfg CollectorConfig) *SentinelOneCollector {
	return &SentinelOneCollector{config: cfg}
}

func (c *SentinelOneCollector) Name() string { return "sentinelone" }
func (c *SentinelOneCollector) Type() string { return "edr" }

func (c *SentinelOneCollector) Collect(ctx context.Context, since time.Time) ([]*RawEvent, error) {
	// TODO: Implement SentinelOne API integration
	return nil, nil
}

func (c *SentinelOneCollector) HealthCheck(ctx context.Context) error {
	return nil
}

// DefenderCollector collects events from Microsoft Defender
type DefenderCollector struct {
	config CollectorConfig
}

// NewDefenderCollector creates a new Microsoft Defender collector
func NewDefenderCollector(cfg CollectorConfig) *DefenderCollector {
	return &DefenderCollector{config: cfg}
}

func (c *DefenderCollector) Name() string { return "defender" }
func (c *DefenderCollector) Type() string { return "edr" }

func (c *DefenderCollector) Collect(ctx context.Context, since time.Time) ([]*RawEvent, error) {
	// TODO: Implement Microsoft Graph Security API integration
	return nil, nil
}

func (c *DefenderCollector) HealthCheck(ctx context.Context) error {
	return nil
}
