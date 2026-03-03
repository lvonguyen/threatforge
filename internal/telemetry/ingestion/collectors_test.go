package ingestion

import (
	"context"
	"errors"
	"testing"
	"time"
)

// =============================================================================
// Helpers
// =============================================================================

// stubCollector is a minimal Collector implementation for testing dispatch logic.
type stubCollector struct {
	name       string
	ctype      string
	events     []*RawEvent
	collectErr error
	healthErr  error
}

func (s *stubCollector) Name() string { return s.name }
func (s *stubCollector) Type() string { return s.ctype }
func (s *stubCollector) Collect(_ context.Context, _ time.Time) ([]*RawEvent, error) {
	return s.events, s.collectErr
}
func (s *stubCollector) HealthCheck(_ context.Context) error { return s.healthErr }

// =============================================================================
// CrowdStrikeCollector
// =============================================================================

func TestNewCrowdStrikeCollector_Identity(t *testing.T) {
	cfg := CollectorConfig{Name: "crowdstrike", Type: "edr"}
	c := NewCrowdStrikeCollector(cfg)
	if c == nil {
		t.Fatal("NewCrowdStrikeCollector returned nil")
	}
	if c.Name() != "crowdstrike" {
		t.Errorf("Name: got %q, want crowdstrike", c.Name())
	}
	if c.Type() != "edr" {
		t.Errorf("Type: got %q, want edr", c.Type())
	}
}

func TestCrowdStrikeCollector_CollectNotImplemented(t *testing.T) {
	c := NewCrowdStrikeCollector(CollectorConfig{})
	_, err := c.Collect(context.Background(), time.Now())
	if err == nil {
		t.Fatal("expected ErrNotImplemented, got nil")
	}
	if !errors.Is(err, ErrNotImplemented) {
		t.Errorf("expected errors.Is(err, ErrNotImplemented), got: %v", err)
	}
}

func TestCrowdStrikeCollector_HealthCheckNotImplemented(t *testing.T) {
	c := NewCrowdStrikeCollector(CollectorConfig{})
	err := c.HealthCheck(context.Background())
	if err == nil {
		t.Fatal("expected ErrNotImplemented, got nil")
	}
	if !errors.Is(err, ErrNotImplemented) {
		t.Errorf("expected errors.Is(err, ErrNotImplemented), got: %v", err)
	}
}

// =============================================================================
// SentinelOneCollector
// =============================================================================

func TestNewSentinelOneCollector_Identity(t *testing.T) {
	c := NewSentinelOneCollector(CollectorConfig{})
	if c == nil {
		t.Fatal("NewSentinelOneCollector returned nil")
	}
	if c.Name() != "sentinelone" {
		t.Errorf("Name: got %q, want sentinelone", c.Name())
	}
	if c.Type() != "edr" {
		t.Errorf("Type: got %q, want edr", c.Type())
	}
}

func TestSentinelOneCollector_CollectNotImplemented(t *testing.T) {
	c := NewSentinelOneCollector(CollectorConfig{})
	_, err := c.Collect(context.Background(), time.Now())
	if !errors.Is(err, ErrNotImplemented) {
		t.Errorf("expected ErrNotImplemented, got: %v", err)
	}
}

func TestSentinelOneCollector_HealthCheckNotImplemented(t *testing.T) {
	c := NewSentinelOneCollector(CollectorConfig{})
	err := c.HealthCheck(context.Background())
	if !errors.Is(err, ErrNotImplemented) {
		t.Errorf("expected ErrNotImplemented, got: %v", err)
	}
}

// =============================================================================
// DefenderCollector
// =============================================================================

func TestNewDefenderCollector_Identity(t *testing.T) {
	c := NewDefenderCollector(CollectorConfig{})
	if c == nil {
		t.Fatal("NewDefenderCollector returned nil")
	}
	if c.Name() != "defender" {
		t.Errorf("Name: got %q, want defender", c.Name())
	}
	if c.Type() != "edr" {
		t.Errorf("Type: got %q, want edr", c.Type())
	}
}

func TestDefenderCollector_CollectNotImplemented(t *testing.T) {
	c := NewDefenderCollector(CollectorConfig{})
	_, err := c.Collect(context.Background(), time.Now())
	if !errors.Is(err, ErrNotImplemented) {
		t.Errorf("expected ErrNotImplemented, got: %v", err)
	}
}

func TestDefenderCollector_HealthCheckNotImplemented(t *testing.T) {
	c := NewDefenderCollector(CollectorConfig{})
	err := c.HealthCheck(context.Background())
	if !errors.Is(err, ErrNotImplemented) {
		t.Errorf("expected ErrNotImplemented, got: %v", err)
	}
}

// =============================================================================
// RawEvent struct
// =============================================================================

func TestRawEvent_Fields(t *testing.T) {
	ts := time.Now()
	ev := &RawEvent{
		ID:         "raw-1",
		Timestamp:  ts,
		Source:     "crowdstrike",
		SourceType: "edr",
		Data:       map[string]interface{}{"process": "calc.exe"},
	}
	if ev.ID != "raw-1" {
		t.Errorf("ID: got %q", ev.ID)
	}
	if !ev.Timestamp.Equal(ts) {
		t.Errorf("Timestamp mismatch")
	}
	if ev.Source != "crowdstrike" {
		t.Errorf("Source: got %q", ev.Source)
	}
	if ev.SourceType != "edr" {
		t.Errorf("SourceType: got %q", ev.SourceType)
	}
	if ev.Data["process"] != "calc.exe" {
		t.Errorf("Data[process]: got %v", ev.Data["process"])
	}
}

// =============================================================================
// Collector interface compliance (via stubCollector)
// =============================================================================

func TestCollectorInterface_SuccessfulCollect(t *testing.T) {
	ts := time.Now()
	stub := &stubCollector{
		name:  "test-collector",
		ctype: "siem",
		events: []*RawEvent{
			{ID: "e1", Timestamp: ts, Source: "splunk", SourceType: "siem", Data: map[string]interface{}{}},
		},
	}

	// Verify interface compliance at compile-time via assignment.
	var _ Collector = stub

	events, err := stub.Collect(context.Background(), time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].ID != "e1" {
		t.Errorf("event ID: got %q, want e1", events[0].ID)
	}
}

func TestCollectorInterface_FailedCollect(t *testing.T) {
	stub := &stubCollector{
		name:       "failing-collector",
		ctype:      "edr",
		collectErr: errors.New("api timeout"),
	}

	_, err := stub.Collect(context.Background(), time.Now())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if err.Error() != "api timeout" {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestCollectorInterface_HealthCheckFailure(t *testing.T) {
	stub := &stubCollector{
		name:      "unhealthy",
		ctype:     "edr",
		healthErr: errors.New("connection refused"),
	}

	err := stub.HealthCheck(context.Background())
	if err == nil {
		t.Fatal("expected health check error, got nil")
	}
}

// =============================================================================
// Concurrent collection via interface (safety check)
// =============================================================================

func TestCollectorInterface_ConcurrentCollect(t *testing.T) {
	ts := time.Now()
	stub := &stubCollector{
		name:  "concurrent-collector",
		ctype: "edr",
		events: []*RawEvent{
			{ID: "e1", Timestamp: ts, Source: "crowdstrike", SourceType: "edr", Data: map[string]interface{}{}},
		},
	}

	const goroutines = 20
	errs := make(chan error, goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			events, err := stub.Collect(context.Background(), time.Now())
			if err != nil {
				errs <- err
				return
			}
			if len(events) != 1 {
				errs <- errors.New("unexpected event count")
				return
			}
			errs <- nil
		}()
	}

	for i := 0; i < goroutines; i++ {
		if err := <-errs; err != nil {
			t.Errorf("goroutine error: %v", err)
		}
	}
}

// =============================================================================
// CollectorConfig
// =============================================================================

func TestCollectorConfig_Fields(t *testing.T) {
	cfg := CollectorConfig{
		Name:         "crowdstrike",
		Type:         "edr",
		Enabled:      true,
		APIURL:       "https://api.crowdstrike.com",
		AuthType:     "oauth",
		Credentials:  map[string]string{"client_id": "abc", "client_secret": "xyz"},
		PollInterval: 5 * time.Minute,
	}

	if cfg.Name != "crowdstrike" {
		t.Errorf("Name: got %q", cfg.Name)
	}
	if !cfg.Enabled {
		t.Error("Enabled should be true")
	}
	if cfg.PollInterval != 5*time.Minute {
		t.Errorf("PollInterval: got %v", cfg.PollInterval)
	}
	if cfg.Credentials["client_id"] != "abc" {
		t.Errorf("Credentials[client_id]: got %q", cfg.Credentials["client_id"])
	}
}
