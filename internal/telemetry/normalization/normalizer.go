// Package normalization handles schema normalization for security events.
// Consolidated from threat-telemetry-hub/internal/normalization
package normalization

import (
	"fmt"
	"time"

	"github.com/lvonguyen/threatforge/internal/telemetry/ingestion"
)

// NormalizedEvent represents an event normalized to a standard schema
type NormalizedEvent struct {
	ID            string                 `json:"id"`
	Timestamp     time.Time              `json:"timestamp"`
	Schema        string                 `json:"schema"` // "ocsf" or "ecs"
	SchemaVersion string                 `json:"schema_version"`
	Category      string                 `json:"category"`
	Type          string                 `json:"type"`
	Severity      int                    `json:"severity"` // 0-100
	Source        SourceInfo             `json:"source"`
	Data          map[string]interface{} `json:"data"`
	Raw           map[string]interface{} `json:"raw,omitempty"`
}

// SourceInfo contains information about the event source
type SourceInfo struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	Vendor  string `json:"vendor"`
	Product string `json:"product"`
}

// NormalizerConfig holds configuration for normalization
type NormalizerConfig struct {
	DefaultSchema string `yaml:"default_schema"` // ocsf or ecs
}

// Normalizer handles schema normalization
type Normalizer struct {
	config NormalizerConfig
}

// NewNormalizer creates a new normalizer
func NewNormalizer(cfg NormalizerConfig) *Normalizer {
	return &Normalizer{config: cfg}
}

// Normalize converts a raw event to the configured schema
func (n *Normalizer) Normalize(raw *ingestion.RawEvent) (*NormalizedEvent, error) {
	switch n.config.DefaultSchema {
	case "ocsf":
		return n.normalizeToOCSF(raw)
	case "ecs":
		return n.normalizeToECS(raw)
	default:
		return nil, fmt.Errorf("unsupported schema: %s", n.config.DefaultSchema)
	}
}

// normalizeToOCSF converts to Open Cybersecurity Schema Framework
func (n *Normalizer) normalizeToOCSF(raw *ingestion.RawEvent) (*NormalizedEvent, error) {
	event := &NormalizedEvent{
		ID:            raw.ID,
		Timestamp:     raw.Timestamp,
		Schema:        "ocsf",
		SchemaVersion: "1.1.0",
		Source:        n.getSourceInfo(raw),
		Raw:           raw.Data,
		Data:          make(map[string]interface{}),
	}

	// Map to OCSF categories based on source type
	switch raw.SourceType {
	case "edr":
		event.Category = "security_finding"
		event.Type = "detection"
		event.Severity = 70
	case "siem":
		event.Category = "security_finding"
		event.Type = "alert"
		event.Severity = 50
	case "cloud":
		event.Category = "api_activity"
		event.Type = "audit"
		event.Severity = 30
	default:
		event.Category = "unknown"
		event.Type = "unknown"
		event.Severity = 0
	}

	return event, nil
}

// normalizeToECS converts to Elastic Common Schema
func (n *Normalizer) normalizeToECS(raw *ingestion.RawEvent) (*NormalizedEvent, error) {
	event := &NormalizedEvent{
		ID:            raw.ID,
		Timestamp:     raw.Timestamp,
		Schema:        "ecs",
		SchemaVersion: "8.11.0",
		Source:        n.getSourceInfo(raw),
		Raw:           raw.Data,
		Data:          make(map[string]interface{}),
	}

	// Map to ECS categories based on source type
	switch raw.SourceType {
	case "edr":
		event.Category = "malware"
		event.Type = "detection"
		event.Severity = 70
	case "siem":
		event.Category = "threat"
		event.Type = "indicator"
		event.Severity = 50
	case "cloud":
		event.Category = "configuration"
		event.Type = "change"
		event.Severity = 30
	default:
		event.Category = "unknown"
		event.Type = "unknown"
		event.Severity = 0
	}

	return event, nil
}

func (n *Normalizer) getSourceInfo(raw *ingestion.RawEvent) SourceInfo {
	vendorMap := map[string]string{
		"crowdstrike":    "CrowdStrike",
		"sentinelone":    "SentinelOne",
		"defender":       "Microsoft",
		"splunk":         "Splunk",
		"aws-cloudtrail": "Amazon Web Services",
		"azure-activity": "Microsoft",
		"gcp-audit":      "Google Cloud",
	}

	productMap := map[string]string{
		"crowdstrike":    "Falcon",
		"sentinelone":    "Singularity",
		"defender":       "Defender for Endpoint",
		"splunk":         "Splunk Enterprise",
		"aws-cloudtrail": "CloudTrail",
		"azure-activity": "Activity Log",
		"gcp-audit":      "Audit Logs",
	}

	return SourceInfo{
		Name:    raw.Source,
		Type:    raw.SourceType,
		Vendor:  vendorMap[raw.Source],
		Product: productMap[raw.Source],
	}
}
