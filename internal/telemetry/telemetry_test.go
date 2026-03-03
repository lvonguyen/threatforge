package telemetry

import (
	"context"
	"errors"
	"testing"
	"time"
)

// =============================================================================
// Helpers / stubs
// =============================================================================

type stubCollector struct {
	name      string
	events    []Event
	collectFn func(ctx context.Context, since time.Time) ([]Event, error)
	healthErr error
}

func (s *stubCollector) Name() string { return s.name }
func (s *stubCollector) Collect(ctx context.Context, since time.Time) ([]Event, error) {
	if s.collectFn != nil {
		return s.collectFn(ctx, since)
	}
	return s.events, nil
}
func (s *stubCollector) HealthCheck(_ context.Context) error { return s.healthErr }

type stubNormalizer struct {
	schema    string
	normalizeFn func(Event) (Event, error)
}

func (s *stubNormalizer) Normalize(ev Event) (Event, error) {
	if s.normalizeFn != nil {
		return s.normalizeFn(ev)
	}
	return ev, nil
}
func (s *stubNormalizer) Schema() string { return s.schema }

type stubCorrelator struct {
	correlateFn func(ctx context.Context, events []Event) ([]EventChain, error)
}

func (s *stubCorrelator) Correlate(ctx context.Context, events []Event) ([]EventChain, error) {
	if s.correlateFn != nil {
		return s.correlateFn(ctx, events)
	}
	return nil, nil
}

// =============================================================================
// Type definitions and interface compliance
// =============================================================================

func TestCollectorInterface_Compliance(t *testing.T) {
	// Ensure stubCollector satisfies Collector at compile time.
	var _ Collector = &stubCollector{}
}

func TestNormalizerInterface_Compliance(t *testing.T) {
	var _ Normalizer = &stubNormalizer{}
}

func TestCorrelatorInterface_Compliance(t *testing.T) {
	var _ Correlator = &stubCorrelator{}
}

// =============================================================================
// Event struct
// =============================================================================

func TestEvent_ZeroValue(t *testing.T) {
	var ev Event
	if ev.Severity != 0 {
		t.Errorf("Severity zero value: got %d", ev.Severity)
	}
	if ev.RiskScore != 0.0 {
		t.Errorf("RiskScore zero value: got %f", ev.RiskScore)
	}
	if ev.MITRETactics != nil {
		t.Error("MITRETactics should be nil at zero value")
	}
}

func TestEvent_FullPopulation(t *testing.T) {
	now := time.Now()
	ev := Event{
		ID:              "ev-1",
		Timestamp:       now,
		Source:          "crowdstrike",
		EventType:       "process",
		Severity:        85,
		RiskScore:       0.92,
		MITRETactics:    []string{"TA0001", "TA0002"},
		MITRETechniques: []string{"T1059", "T1003"},
		Entities: []Entity{
			{Type: "user", Value: "admin", Role: "actor"},
			{Type: "host", Value: "workstation-01", Role: "target"},
		},
		Raw: map[string]interface{}{"cmd": "powershell.exe"},
		Enrichments: &Enrichments{
			ThreatIntel: &ThreatIntelContext{
				Sources:    []string{"virustotal"},
				Confidence: 0.95,
			},
		},
	}

	if ev.ID != "ev-1" {
		t.Errorf("ID: got %q", ev.ID)
	}
	if !ev.Timestamp.Equal(now) {
		t.Error("Timestamp mismatch")
	}
	if ev.Severity != 85 {
		t.Errorf("Severity: got %d", ev.Severity)
	}
	if len(ev.MITRETactics) != 2 {
		t.Errorf("MITRETactics: got %d", len(ev.MITRETactics))
	}
	if len(ev.Entities) != 2 {
		t.Errorf("Entities: got %d", len(ev.Entities))
	}
	if ev.Enrichments == nil {
		t.Fatal("Enrichments should be populated")
	}
	if ev.Enrichments.ThreatIntel.Confidence != 0.95 {
		t.Errorf("ThreatIntel.Confidence: got %f", ev.Enrichments.ThreatIntel.Confidence)
	}
}

// =============================================================================
// Entity struct
// =============================================================================

func TestEntity_Fields(t *testing.T) {
	tests := []struct {
		name  string
		etype string
		value string
		role  string
	}{
		{"user entity", "user", "alice", "actor"},
		{"host entity", "host", "server-01", "target"},
		{"ip entity", "ip", "192.168.1.1", "observer"},
		{"process entity", "process", "calc.exe", "actor"},
		{"file entity", "file", "/tmp/malware", "target"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := Entity{Type: tt.etype, Value: tt.value, Role: tt.role}
			if e.Type != tt.etype {
				t.Errorf("Type: got %q, want %q", e.Type, tt.etype)
			}
			if e.Value != tt.value {
				t.Errorf("Value: got %q, want %q", e.Value, tt.value)
			}
			if e.Role != tt.role {
				t.Errorf("Role: got %q, want %q", e.Role, tt.role)
			}
		})
	}
}

// =============================================================================
// EventChain struct
// =============================================================================

func TestEventChain_Fields(t *testing.T) {
	start := time.Now()
	end := start.Add(10 * time.Minute)

	chain := EventChain{
		ID:        "chain-1",
		StartTime: start,
		EndTime:   end,
		Events: []Event{
			{ID: "e1", Severity: 70},
			{ID: "e2", Severity: 90},
		},
		RiskScore:  80.0,
		Summary:    "Lateral movement detected",
		MITREChain: []string{"T1059", "T1021"},
	}

	if chain.ID != "chain-1" {
		t.Errorf("ID: got %q", chain.ID)
	}
	if !chain.StartTime.Equal(start) {
		t.Error("StartTime mismatch")
	}
	if !chain.EndTime.Equal(end) {
		t.Error("EndTime mismatch")
	}
	if len(chain.Events) != 2 {
		t.Errorf("Events: got %d", len(chain.Events))
	}
	if chain.RiskScore != 80.0 {
		t.Errorf("RiskScore: got %f", chain.RiskScore)
	}
	if chain.Summary == "" {
		t.Error("Summary should not be empty")
	}
	if len(chain.MITREChain) != 2 {
		t.Errorf("MITREChain: got %d", len(chain.MITREChain))
	}
}

// =============================================================================
// Enrichments struct
// =============================================================================

func TestEnrichments_AllContextTypes(t *testing.T) {
	e := &Enrichments{
		ThreatIntel: &ThreatIntelContext{
			Sources:    []string{"virustotal", "alienvault"},
			Indicators: []string{"ioc-1"},
			Campaigns:  []string{"APT29"},
			Confidence: 0.8,
		},
		Identity: &IdentityContext{
			UserID:      "uid-42",
			DisplayName: "Alice Smith",
			Email:       "alice@example.com",
			Department:  "Engineering",
			Manager:     "bob@example.com",
			RiskLevel:   "high",
			Groups:      []string{"admins", "dev"},
		},
		Asset: &AssetContext{
			AssetID:      "asset-99",
			Hostname:     "workstation-01",
			Environment:  "prod",
			Criticality:  "critical",
			Owner:        "alice@example.com",
			BusinessUnit: "Security",
			Tags:         []string{"pci", "sox"},
		},
		Geo: &GeoContext{
			Country:      "US",
			City:         "Seattle",
			Latitude:     47.6062,
			Longitude:    -122.3321,
			IsAnonymizer: false,
		},
	}

	if e.ThreatIntel.Confidence != 0.8 {
		t.Errorf("ThreatIntel.Confidence: got %f", e.ThreatIntel.Confidence)
	}
	if e.Identity.RiskLevel != "high" {
		t.Errorf("Identity.RiskLevel: got %q", e.Identity.RiskLevel)
	}
	if e.Asset.Criticality != "critical" {
		t.Errorf("Asset.Criticality: got %q", e.Asset.Criticality)
	}
	if e.Geo.IsAnonymizer {
		t.Error("Geo.IsAnonymizer should be false")
	}
}

// =============================================================================
// Collector stub — event routing simulation
// =============================================================================

func TestCollector_Stub_ReturnsEvents(t *testing.T) {
	now := time.Now()
	stub := &stubCollector{
		name: "crowdstrike",
		events: []Event{
			{ID: "e1", Source: "crowdstrike", Severity: 70, Timestamp: now},
			{ID: "e2", Source: "crowdstrike", Severity: 50, Timestamp: now.Add(time.Minute)},
		},
	}

	events, err := stub.Collect(context.Background(), now.Add(-time.Hour))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}
}

func TestCollector_Stub_ErrorPropagation(t *testing.T) {
	stub := &stubCollector{
		name: "failing",
		collectFn: func(_ context.Context, _ time.Time) ([]Event, error) {
			return nil, errors.New("upstream timeout")
		},
	}

	_, err := stub.Collect(context.Background(), time.Now())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

// =============================================================================
// Normalizer stub — event passthrough
// =============================================================================

func TestNormalizer_Stub_Passthrough(t *testing.T) {
	stub := &stubNormalizer{schema: "ocsf"}
	input := Event{ID: "e1", Severity: 75}

	out, err := stub.Normalize(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.ID != "e1" {
		t.Errorf("ID: got %q, want e1", out.ID)
	}
	if out.Severity != 75 {
		t.Errorf("Severity: got %d, want 75", out.Severity)
	}
	if stub.Schema() != "ocsf" {
		t.Errorf("Schema: got %q, want ocsf", stub.Schema())
	}
}

func TestNormalizer_Stub_ErrorPropagation(t *testing.T) {
	stub := &stubNormalizer{
		normalizeFn: func(ev Event) (Event, error) {
			return Event{}, errors.New("schema mismatch")
		},
	}

	_, err := stub.Normalize(Event{ID: "e1"})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

// =============================================================================
// Correlator stub — chain production
// =============================================================================

func TestCorrelator_Stub_ReturnsChains(t *testing.T) {
	now := time.Now()
	stub := &stubCorrelator{
		correlateFn: func(_ context.Context, events []Event) ([]EventChain, error) {
			if len(events) < 2 {
				return nil, nil
			}
			return []EventChain{
				{ID: "chain-1", Events: events, RiskScore: 75.0, StartTime: now, EndTime: now.Add(5 * time.Minute)},
			}, nil
		},
	}

	events := []Event{
		{ID: "e1", Severity: 70},
		{ID: "e2", Severity: 80},
	}

	chains, err := stub.Correlate(context.Background(), events)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(chains) != 1 {
		t.Fatalf("expected 1 chain, got %d", len(chains))
	}
	if chains[0].RiskScore != 75.0 {
		t.Errorf("RiskScore: got %f", chains[0].RiskScore)
	}
}

func TestCorrelator_Stub_EmptyInputReturnsNil(t *testing.T) {
	stub := &stubCorrelator{}
	chains, err := stub.Correlate(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if chains != nil {
		t.Errorf("expected nil chains for nil input, got %v", chains)
	}
}

// =============================================================================
// Pipeline simulation: collect -> normalize -> correlate
// =============================================================================

func TestPipeline_CollectNormalizeCorrelate(t *testing.T) {
	now := time.Now()

	collector := &stubCollector{
		name: "crowdstrike",
		events: []Event{
			{ID: "e1", Source: "crowdstrike", Severity: 80, Timestamp: now},
			{ID: "e2", Source: "crowdstrike", Severity: 70, Timestamp: now.Add(time.Minute)},
		},
	}

	normalizer := &stubNormalizer{
		schema: "ocsf",
		normalizeFn: func(ev Event) (Event, error) {
			// Simulate schema enrichment: tag the event type.
			ev.EventType = "normalized"
			return ev, nil
		},
	}

	correlator := &stubCorrelator{
		correlateFn: func(_ context.Context, events []Event) ([]EventChain, error) {
			return []EventChain{
				{ID: "chain-1", Events: events, RiskScore: 75.0},
			}, nil
		},
	}

	// Collect.
	raw, err := collector.Collect(context.Background(), now.Add(-time.Hour))
	if err != nil {
		t.Fatalf("collect: %v", err)
	}

	// Normalize.
	normalized := make([]Event, 0, len(raw))
	for _, ev := range raw {
		ne, err := normalizer.Normalize(ev)
		if err != nil {
			t.Fatalf("normalize: %v", err)
		}
		normalized = append(normalized, ne)
	}

	for _, ev := range normalized {
		if ev.EventType != "normalized" {
			t.Errorf("event %q: EventType not set by normalizer", ev.ID)
		}
	}

	// Correlate.
	chains, err := correlator.Correlate(context.Background(), normalized)
	if err != nil {
		t.Fatalf("correlate: %v", err)
	}
	if len(chains) != 1 {
		t.Fatalf("expected 1 chain, got %d", len(chains))
	}
	if len(chains[0].Events) != 2 {
		t.Errorf("chain events: got %d, want 2", len(chains[0].Events))
	}
}

func TestPipeline_NormalizerError_StopsProcessing(t *testing.T) {
	now := time.Now()

	collector := &stubCollector{
		events: []Event{
			{ID: "bad-event", Severity: 90, Timestamp: now},
		},
	}

	normalizer := &stubNormalizer{
		normalizeFn: func(ev Event) (Event, error) {
			return Event{}, errors.New("unsupported source schema")
		},
	}

	raw, err := collector.Collect(context.Background(), now.Add(-time.Hour))
	if err != nil {
		t.Fatalf("collect: %v", err)
	}

	var normErrors int
	for _, ev := range raw {
		_, err := normalizer.Normalize(ev)
		if err != nil {
			normErrors++
		}
	}

	if normErrors != 1 {
		t.Errorf("expected 1 normalization error, got %d", normErrors)
	}
}
