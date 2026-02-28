// Package ingestion provides multi-source security telemetry collection.
// Consolidated from threat-telemetry-hub/internal/ingestion
package ingestion

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// ErrNotImplemented is returned by collector stubs that are not yet implemented.
var ErrNotImplemented = errors.New("collector not implemented")

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
	Name         string            `yaml:"name"`
	Type         string            `yaml:"type"`
	Enabled      bool              `yaml:"enabled"`
	APIURL       string            `yaml:"api_url"`
	AuthType     string            `yaml:"auth_type"` // api_key, oauth, basic
	Credentials  map[string]string `yaml:"credentials"`
	PollInterval time.Duration     `yaml:"poll_interval"`
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

func (c *CrowdStrikeCollector) Collect(_ context.Context, _ time.Time) ([]*RawEvent, error) {
	return nil, fmt.Errorf("CrowdStrike collector: %w", ErrNotImplemented)
}

func (c *CrowdStrikeCollector) HealthCheck(_ context.Context) error {
	return fmt.Errorf("CrowdStrike collector: %w", ErrNotImplemented)
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

func (c *SentinelOneCollector) Collect(_ context.Context, _ time.Time) ([]*RawEvent, error) {
	return nil, fmt.Errorf("SentinelOne collector: %w", ErrNotImplemented)
}

func (c *SentinelOneCollector) HealthCheck(_ context.Context) error {
	return fmt.Errorf("SentinelOne collector: %w", ErrNotImplemented)
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

func (c *DefenderCollector) Collect(_ context.Context, _ time.Time) ([]*RawEvent, error) {
	return nil, fmt.Errorf("Defender collector: %w", ErrNotImplemented)
}

func (c *DefenderCollector) HealthCheck(_ context.Context) error {
	return fmt.Errorf("Defender collector: %w", ErrNotImplemented)
}
