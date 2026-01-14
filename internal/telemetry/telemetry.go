// Package telemetry provides multi-source security telemetry aggregation
// and normalization using OCSF (Open Cybersecurity Schema Framework).
//
// This module was consolidated from threat-telemetry-hub.
package telemetry

import (
	"context"
	"time"
)

// Event represents a normalized security event
type Event struct {
	ID           string                 `json:"id"`
	Timestamp    time.Time              `json:"timestamp"`
	Source       string                 `json:"source"`       // crowdstrike, sentinelone, defender, splunk, etc.
	EventType    string                 `json:"event_type"`   // process, network, file, auth, etc.
	Severity     int                    `json:"severity"`     // 0-100 normalized
	RiskScore    float64                `json:"risk_score"`   // AI-powered risk score
	MITRETactics []string               `json:"mitre_tactics"`
	MITRETechniques []string            `json:"mitre_techniques"`
	Entities     []Entity               `json:"entities"`
	Raw          map[string]interface{} `json:"raw"`
	Enrichments  *Enrichments           `json:"enrichments,omitempty"`
}

// Entity represents an entity involved in the event
type Entity struct {
	Type  string `json:"type"`  // user, host, ip, file, process
	Value string `json:"value"`
	Role  string `json:"role"`  // actor, target, observer
}

// Enrichments contains additional context added during enrichment
type Enrichments struct {
	ThreatIntel *ThreatIntelContext `json:"threat_intel,omitempty"`
	Identity    *IdentityContext    `json:"identity,omitempty"`
	Asset       *AssetContext       `json:"asset,omitempty"`
	Geo         *GeoContext         `json:"geo,omitempty"`
}

// ThreatIntelContext contains threat intelligence enrichment
type ThreatIntelContext struct {
	Sources    []string `json:"sources"`
	Indicators []string `json:"indicators"`
	Campaigns  []string `json:"campaigns"`
	Confidence float64  `json:"confidence"`
}

// IdentityContext contains identity provider enrichment
type IdentityContext struct {
	UserID      string   `json:"user_id"`
	DisplayName string   `json:"display_name"`
	Email       string   `json:"email"`
	Department  string   `json:"department"`
	Manager     string   `json:"manager"`
	RiskLevel   string   `json:"risk_level"`
	Groups      []string `json:"groups"`
}

// AssetContext contains CMDB asset enrichment
type AssetContext struct {
	AssetID      string   `json:"asset_id"`
	Hostname     string   `json:"hostname"`
	Environment  string   `json:"environment"` // prod, staging, dev
	Criticality  string   `json:"criticality"` // critical, high, medium, low
	Owner        string   `json:"owner"`
	BusinessUnit string   `json:"business_unit"`
	Tags         []string `json:"tags"`
}

// GeoContext contains geolocation enrichment
type GeoContext struct {
	Country     string  `json:"country"`
	City        string  `json:"city"`
	Latitude    float64 `json:"latitude"`
	Longitude   float64 `json:"longitude"`
	IsAnonymizer bool   `json:"is_anonymizer"`
}

// Collector ingests events from a specific source
type Collector interface {
	// Name returns the collector name
	Name() string
	// Collect fetches events from the source
	Collect(ctx context.Context, since time.Time) ([]Event, error)
	// HealthCheck verifies connectivity
	HealthCheck(ctx context.Context) error
}

// Normalizer converts source-specific events to unified schema
type Normalizer interface {
	// Normalize converts raw event to OCSF schema
	Normalize(event Event) (Event, error)
	// Schema returns the target schema (ocsf, ecs)
	Schema() string
}

// Correlator correlates related events into attack chains
type Correlator interface {
	// Correlate identifies related events
	Correlate(ctx context.Context, events []Event) ([]EventChain, error)
}

// EventChain represents a correlated sequence of events
type EventChain struct {
	ID         string    `json:"id"`
	StartTime  time.Time `json:"start_time"`
	EndTime    time.Time `json:"end_time"`
	Events     []Event   `json:"events"`
	RiskScore  float64   `json:"risk_score"`
	Summary    string    `json:"summary"`    // AI-generated summary
	MITREChain []string  `json:"mitre_chain"` // Ordered MITRE techniques
}
