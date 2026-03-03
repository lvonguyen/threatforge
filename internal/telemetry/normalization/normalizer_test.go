package normalization

import (
	"testing"
	"time"

	"github.com/lvonguyen/threatforge/internal/telemetry/ingestion"
)

func makeRawEvent(id, source, sourceType string) *ingestion.RawEvent {
	return &ingestion.RawEvent{
		ID:         id,
		Timestamp:  time.Now(),
		Source:     source,
		SourceType: sourceType,
		Data:       map[string]interface{}{"key": "value"},
	}
}

// =============================================================================
// NewNormalizer
// =============================================================================

func TestNewNormalizer_StoresConfig(t *testing.T) {
	cfg := NormalizerConfig{DefaultSchema: "ocsf"}
	n := NewNormalizer(cfg)
	if n == nil {
		t.Fatal("NewNormalizer returned nil")
	}
	if n.config.DefaultSchema != "ocsf" {
		t.Errorf("expected DefaultSchema=ocsf, got %q", n.config.DefaultSchema)
	}
}

// =============================================================================
// Normalize — schema dispatch
// =============================================================================

func TestNormalize_UnsupportedSchema(t *testing.T) {
	n := NewNormalizer(NormalizerConfig{DefaultSchema: "splunk"})
	raw := makeRawEvent("e1", "crowdstrike", "edr")
	_, err := n.Normalize(raw)
	if err == nil {
		t.Fatal("expected error for unsupported schema, got nil")
	}
}

func TestNormalize_OCSF_SchemaFields(t *testing.T) {
	n := NewNormalizer(NormalizerConfig{DefaultSchema: "ocsf"})
	raw := makeRawEvent("e1", "crowdstrike", "edr")
	ev, err := n.Normalize(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ev.Schema != "ocsf" {
		t.Errorf("expected Schema=ocsf, got %q", ev.Schema)
	}
	if ev.SchemaVersion != "1.1.0" {
		t.Errorf("expected SchemaVersion=1.1.0, got %q", ev.SchemaVersion)
	}
}

func TestNormalize_ECS_SchemaFields(t *testing.T) {
	n := NewNormalizer(NormalizerConfig{DefaultSchema: "ecs"})
	raw := makeRawEvent("e1", "splunk", "siem")
	ev, err := n.Normalize(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ev.Schema != "ecs" {
		t.Errorf("expected Schema=ecs, got %q", ev.Schema)
	}
	if ev.SchemaVersion != "8.11.0" {
		t.Errorf("expected SchemaVersion=8.11.0, got %q", ev.SchemaVersion)
	}
}

// =============================================================================
// OCSF — source type mapping
// =============================================================================

func TestNormalize_OCSF_SourceTypes(t *testing.T) {
	tests := []struct {
		sourceType   string
		wantCategory string
		wantType     string
		wantSeverity int
	}{
		{"edr", "security_finding", "detection", 70},
		{"siem", "security_finding", "alert", 50},
		{"cloud", "api_activity", "audit", 30},
		{"unknown", "unknown", "unknown", 0},
		{"", "unknown", "unknown", 0},
	}

	n := NewNormalizer(NormalizerConfig{DefaultSchema: "ocsf"})

	for _, tt := range tests {
		t.Run("sourceType="+tt.sourceType, func(t *testing.T) {
			raw := makeRawEvent("e1", "crowdstrike", tt.sourceType)
			ev, err := n.Normalize(raw)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if ev.Category != tt.wantCategory {
				t.Errorf("Category: got %q, want %q", ev.Category, tt.wantCategory)
			}
			if ev.Type != tt.wantType {
				t.Errorf("Type: got %q, want %q", ev.Type, tt.wantType)
			}
			if ev.Severity != tt.wantSeverity {
				t.Errorf("Severity: got %d, want %d", ev.Severity, tt.wantSeverity)
			}
		})
	}
}

// =============================================================================
// ECS — source type mapping
// =============================================================================

func TestNormalize_ECS_SourceTypes(t *testing.T) {
	tests := []struct {
		sourceType   string
		wantCategory string
		wantType     string
		wantSeverity int
	}{
		{"edr", "malware", "detection", 70},
		{"siem", "threat", "indicator", 50},
		{"cloud", "configuration", "change", 30},
		{"unknown", "unknown", "unknown", 0},
		{"", "unknown", "unknown", 0},
	}

	n := NewNormalizer(NormalizerConfig{DefaultSchema: "ecs"})

	for _, tt := range tests {
		t.Run("sourceType="+tt.sourceType, func(t *testing.T) {
			raw := makeRawEvent("e1", "splunk", tt.sourceType)
			ev, err := n.Normalize(raw)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if ev.Category != tt.wantCategory {
				t.Errorf("Category: got %q, want %q", ev.Category, tt.wantCategory)
			}
			if ev.Type != tt.wantType {
				t.Errorf("Type: got %q, want %q", ev.Type, tt.wantType)
			}
			if ev.Severity != tt.wantSeverity {
				t.Errorf("Severity: got %d, want %d", ev.Severity, tt.wantSeverity)
			}
		})
	}
}

// =============================================================================
// NormalizedEvent field population
// =============================================================================

func TestNormalize_IDAndTimestampPreserved(t *testing.T) {
	n := NewNormalizer(NormalizerConfig{DefaultSchema: "ocsf"})
	ts := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	raw := &ingestion.RawEvent{
		ID:         "event-42",
		Timestamp:  ts,
		Source:     "crowdstrike",
		SourceType: "edr",
		Data:       map[string]interface{}{},
	}

	ev, err := n.Normalize(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ev.ID != "event-42" {
		t.Errorf("ID: got %q, want %q", ev.ID, "event-42")
	}
	if !ev.Timestamp.Equal(ts) {
		t.Errorf("Timestamp: got %v, want %v", ev.Timestamp, ts)
	}
}

func TestNormalize_RawDataPreserved(t *testing.T) {
	n := NewNormalizer(NormalizerConfig{DefaultSchema: "ocsf"})
	raw := &ingestion.RawEvent{
		ID:         "e1",
		Timestamp:  time.Now(),
		Source:     "crowdstrike",
		SourceType: "edr",
		Data:       map[string]interface{}{"process": "malware.exe", "pid": 1234},
	}

	ev, err := n.Normalize(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ev.Raw["process"] != "malware.exe" {
		t.Errorf("Raw data not preserved: expected process=malware.exe, got %v", ev.Raw["process"])
	}
}

func TestNormalize_EmptyData(t *testing.T) {
	n := NewNormalizer(NormalizerConfig{DefaultSchema: "ocsf"})
	raw := &ingestion.RawEvent{
		ID:         "e-empty",
		Timestamp:  time.Now(),
		Source:     "crowdstrike",
		SourceType: "edr",
		Data:       map[string]interface{}{},
	}

	ev, err := n.Normalize(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ev == nil {
		t.Fatal("expected non-nil NormalizedEvent for empty data")
	}
	if ev.Data == nil {
		t.Error("NormalizedEvent.Data should be initialised, got nil")
	}
}

// =============================================================================
// Source info / vendor mapping
// =============================================================================

func TestNormalize_SourceInfo_KnownVendors(t *testing.T) {
	tests := []struct {
		source      string
		wantVendor  string
		wantProduct string
	}{
		{"crowdstrike", "CrowdStrike", "Falcon"},
		{"sentinelone", "SentinelOne", "Singularity"},
		{"defender", "Microsoft", "Defender for Endpoint"},
		{"splunk", "Splunk", "Splunk Enterprise"},
		{"aws-cloudtrail", "Amazon Web Services", "CloudTrail"},
		{"azure-activity", "Microsoft", "Activity Log"},
		{"gcp-audit", "Google Cloud", "Audit Logs"},
	}

	n := NewNormalizer(NormalizerConfig{DefaultSchema: "ocsf"})

	for _, tt := range tests {
		t.Run(tt.source, func(t *testing.T) {
			raw := makeRawEvent("e1", tt.source, "edr")
			ev, err := n.Normalize(raw)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if ev.Source.Name != tt.source {
				t.Errorf("Source.Name: got %q, want %q", ev.Source.Name, tt.source)
			}
			if ev.Source.Vendor != tt.wantVendor {
				t.Errorf("Source.Vendor: got %q, want %q", ev.Source.Vendor, tt.wantVendor)
			}
			if ev.Source.Product != tt.wantProduct {
				t.Errorf("Source.Product: got %q, want %q", ev.Source.Product, tt.wantProduct)
			}
		})
	}
}

func TestNormalize_SourceInfo_UnknownSource(t *testing.T) {
	n := NewNormalizer(NormalizerConfig{DefaultSchema: "ocsf"})
	raw := makeRawEvent("e1", "unknown-vendor", "edr")
	ev, err := n.Normalize(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ev.Source.Vendor != "" {
		t.Errorf("unknown source should have empty Vendor, got %q", ev.Source.Vendor)
	}
	if ev.Source.Product != "" {
		t.Errorf("unknown source should have empty Product, got %q", ev.Source.Product)
	}
}
