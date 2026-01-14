// Package correlation provides event correlation and attack chain detection.
// Consolidated from threat-telemetry-hub/internal/correlation
package correlation

import (
	"context"
	"time"

	"github.com/lvonguyen/threatforge/internal/telemetry/normalization"
)

// EventChain represents a correlated sequence of events
type EventChain struct {
	ID         string                          `json:"id"`
	StartTime  time.Time                       `json:"start_time"`
	EndTime    time.Time                       `json:"end_time"`
	Events     []*normalization.NormalizedEvent `json:"events"`
	RiskScore  float64                         `json:"risk_score"`
	Summary    string                          `json:"summary"`
	MITREChain []string                        `json:"mitre_chain"`
}

// CorrelatorConfig holds configuration for the correlator
type CorrelatorConfig struct {
	TimeWindowMinutes int     `yaml:"time_window_minutes"`
	MinEventsForChain int     `yaml:"min_events_for_chain"`
	RiskThreshold     float64 `yaml:"risk_threshold"`
}

// Correlator correlates related events into attack chains
type Correlator struct {
	config CorrelatorConfig
}

// NewCorrelator creates a new correlator
func NewCorrelator(cfg CorrelatorConfig) *Correlator {
	return &Correlator{config: cfg}
}

// Correlate identifies related events and builds attack chains
func (c *Correlator) Correlate(ctx context.Context, events []*normalization.NormalizedEvent) ([]*EventChain, error) {
	if len(events) < c.config.MinEventsForChain {
		return nil, nil
	}

	var chains []*EventChain

	// Group events by entity (user, host, IP)
	byEntity := c.groupByEntity(events)

	for entity, entityEvents := range byEntity {
		// Find events within time window
		chain := c.buildChain(entity, entityEvents)
		if chain != nil && chain.RiskScore >= c.config.RiskThreshold {
			chains = append(chains, chain)
		}
	}

	return chains, nil
}

// groupByEntity groups events by their primary entity
func (c *Correlator) groupByEntity(events []*normalization.NormalizedEvent) map[string][]*normalization.NormalizedEvent {
	byEntity := make(map[string][]*normalization.NormalizedEvent)

	for _, event := range events {
		// Extract entity from event data (user, host, IP)
		entity := c.extractEntity(event)
		if entity != "" {
			byEntity[entity] = append(byEntity[entity], event)
		}
	}

	return byEntity
}

// extractEntity extracts the primary entity from an event
func (c *Correlator) extractEntity(event *normalization.NormalizedEvent) string {
	// Try common entity fields
	if user, ok := event.Data["user"].(string); ok && user != "" {
		return "user:" + user
	}
	if host, ok := event.Data["host"].(string); ok && host != "" {
		return "host:" + host
	}
	if ip, ok := event.Data["source_ip"].(string); ok && ip != "" {
		return "ip:" + ip
	}
	return ""
}

// buildChain builds an attack chain from related events
func (c *Correlator) buildChain(entity string, events []*normalization.NormalizedEvent) *EventChain {
	if len(events) < c.config.MinEventsForChain {
		return nil
	}

	chain := &EventChain{
		ID:        entity + "-chain",
		Events:    events,
		StartTime: events[0].Timestamp,
		EndTime:   events[len(events)-1].Timestamp,
	}

	// Calculate risk score based on event severities
	var totalSeverity float64
	for _, event := range events {
		totalSeverity += float64(event.Severity)
	}
	chain.RiskScore = totalSeverity / float64(len(events))

	// Generate summary
	chain.Summary = c.generateSummary(events)

	return chain
}

// generateSummary creates a human-readable summary of the attack chain
func (c *Correlator) generateSummary(events []*normalization.NormalizedEvent) string {
	if len(events) == 0 {
		return ""
	}

	// TODO: Integrate with AI for natural language summary
	return "Correlated event chain detected across multiple security sources"
}
