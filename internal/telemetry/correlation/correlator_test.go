package correlation

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lvonguyen/threatforge/internal/telemetry/normalization"
)

// =============================================================================
// Helpers
// =============================================================================

func makeEvent(id, entity, entityType string, severity int, ts time.Time) *normalization.NormalizedEvent {
	ev := &normalization.NormalizedEvent{
		ID:        id,
		Timestamp: ts,
		Severity:  severity,
		Data:      make(map[string]interface{}),
	}
	switch entityType {
	case "user":
		ev.Data["user"] = entity
	case "host":
		ev.Data["host"] = entity
	case "ip":
		ev.Data["source_ip"] = entity
	}
	return ev
}

func defaultConfig() CorrelatorConfig {
	return CorrelatorConfig{
		TimeWindowMinutes: 5,
		MinEventsForChain: 2,
		RiskThreshold:     0.0,
	}
}

// =============================================================================
// NewCorrelator
// =============================================================================

// TestNewCorrelator verifies that NewCorrelator stores the supplied config.
func TestNewCorrelator(t *testing.T) {
	cfg := CorrelatorConfig{
		TimeWindowMinutes: 10,
		MinEventsForChain: 3,
		RiskThreshold:     50.0,
	}
	c := NewCorrelator(cfg)
	if c == nil {
		t.Fatal("NewCorrelator returned nil")
	}
	if c.config.TimeWindowMinutes != 10 {
		t.Errorf("expected TimeWindowMinutes=10, got %d", c.config.TimeWindowMinutes)
	}
	if c.config.MinEventsForChain != 3 {
		t.Errorf("expected MinEventsForChain=3, got %d", c.config.MinEventsForChain)
	}
	if c.config.RiskThreshold != 50.0 {
		t.Errorf("expected RiskThreshold=50.0, got %f", c.config.RiskThreshold)
	}
}

// =============================================================================
// Correlate — top-level behaviour
// =============================================================================

// TestCorrelate_BelowMinReturnsNil verifies that Correlate returns nil when the
// total number of events is below MinEventsForChain.
func TestCorrelate_BelowMinReturnsNil(t *testing.T) {
	c := NewCorrelator(CorrelatorConfig{MinEventsForChain: 3, RiskThreshold: 0})

	events := []*normalization.NormalizedEvent{
		makeEvent("e1", "alice", "user", 50, time.Now()),
		makeEvent("e2", "alice", "user", 60, time.Now()),
	}

	chains, err := c.Correlate(context.Background(), events)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if chains != nil {
		t.Errorf("expected nil chains below MinEventsForChain, got %v", chains)
	}
}

// TestCorrelate_EmptyEventsReturnsNil verifies that an empty event list returns nil.
func TestCorrelate_EmptyEventsReturnsNil(t *testing.T) {
	c := NewCorrelator(defaultConfig())

	chains, err := c.Correlate(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if chains != nil {
		t.Errorf("expected nil chains for empty input, got %v", chains)
	}
}

// TestCorrelate_SingleEntityChain verifies that events sharing the same entity
// are grouped into a single chain.
func TestCorrelate_SingleEntityChain(t *testing.T) {
	c := NewCorrelator(defaultConfig())
	now := time.Now()

	events := []*normalization.NormalizedEvent{
		makeEvent("e1", "alice", "user", 40, now),
		makeEvent("e2", "alice", "user", 60, now.Add(time.Minute)),
		makeEvent("e3", "alice", "user", 80, now.Add(2*time.Minute)),
	}

	chains, err := c.Correlate(context.Background(), events)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(chains) != 1 {
		t.Fatalf("expected 1 chain, got %d", len(chains))
	}
	if len(chains[0].Events) != 3 {
		t.Errorf("expected 3 events in chain, got %d", len(chains[0].Events))
	}
}

// TestCorrelate_DifferentEntitiesSeparateChains verifies that events belonging
// to different entities produce separate chains.
func TestCorrelate_DifferentEntitiesSeparateChains(t *testing.T) {
	c := NewCorrelator(defaultConfig())
	now := time.Now()

	events := []*normalization.NormalizedEvent{
		makeEvent("e1", "alice", "user", 50, now),
		makeEvent("e2", "alice", "user", 60, now.Add(time.Minute)),
		makeEvent("e3", "bob", "user", 70, now),
		makeEvent("e4", "bob", "user", 80, now.Add(time.Minute)),
	}

	chains, err := c.Correlate(context.Background(), events)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(chains) != 2 {
		t.Fatalf("expected 2 chains (one per user), got %d", len(chains))
	}
}

// TestCorrelate_RiskThresholdFiltersChains verifies that chains whose risk score
// falls below RiskThreshold are excluded from results.
func TestCorrelate_RiskThresholdFiltersChains(t *testing.T) {
	c := NewCorrelator(CorrelatorConfig{
		MinEventsForChain: 2,
		RiskThreshold:     75.0,
	})
	now := time.Now()

	// Low-severity events — average 30, below threshold of 75
	events := []*normalization.NormalizedEvent{
		makeEvent("e1", "alice", "user", 20, now),
		makeEvent("e2", "alice", "user", 40, now.Add(time.Minute)),
	}

	chains, err := c.Correlate(context.Background(), events)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(chains) != 0 {
		t.Errorf("expected 0 chains below risk threshold, got %d", len(chains))
	}
}

// TestCorrelate_RiskThresholdPassesChains verifies that chains meeting or
// exceeding RiskThreshold are included.
func TestCorrelate_RiskThresholdPassesChains(t *testing.T) {
	c := NewCorrelator(CorrelatorConfig{
		MinEventsForChain: 2,
		RiskThreshold:     70.0,
	})
	now := time.Now()

	// High-severity events — average 80, above threshold
	events := []*normalization.NormalizedEvent{
		makeEvent("e1", "alice", "user", 80, now),
		makeEvent("e2", "alice", "user", 80, now.Add(time.Minute)),
	}

	chains, err := c.Correlate(context.Background(), events)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(chains) != 1 {
		t.Fatalf("expected 1 chain above risk threshold, got %d", len(chains))
	}
}

// TestCorrelate_NoEntityEventsDropped verifies that events with no extractable
// entity are silently discarded (no chain produced).
func TestCorrelate_NoEntityEventsDropped(t *testing.T) {
	c := NewCorrelator(defaultConfig())
	now := time.Now()

	// Events with empty Data — no user/host/source_ip
	events := []*normalization.NormalizedEvent{
		{ID: "e1", Timestamp: now, Severity: 80, Data: map[string]interface{}{}},
		{ID: "e2", Timestamp: now.Add(time.Minute), Severity: 90, Data: map[string]interface{}{}},
	}

	chains, err := c.Correlate(context.Background(), events)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(chains) != 0 {
		t.Errorf("expected 0 chains when no entity can be extracted, got %d", len(chains))
	}
}

// =============================================================================
// groupByEntity / extractEntity
// =============================================================================

// TestGroupByEntity_UserKey verifies that "user" data field produces "user:<name>" key.
func TestGroupByEntity_UserKey(t *testing.T) {
	c := NewCorrelator(defaultConfig())
	events := []*normalization.NormalizedEvent{
		makeEvent("e1", "charlie", "user", 50, time.Now()),
	}
	byEntity := c.groupByEntity(events)
	if _, ok := byEntity["user:charlie"]; !ok {
		t.Errorf("expected key 'user:charlie', got keys: %v", keys(byEntity))
	}
}

// TestGroupByEntity_HostKey verifies that "host" data field produces "host:<name>" key.
func TestGroupByEntity_HostKey(t *testing.T) {
	c := NewCorrelator(defaultConfig())
	events := []*normalization.NormalizedEvent{
		makeEvent("e1", "server01", "host", 50, time.Now()),
	}
	byEntity := c.groupByEntity(events)
	if _, ok := byEntity["host:server01"]; !ok {
		t.Errorf("expected key 'host:server01', got keys: %v", keys(byEntity))
	}
}

// TestGroupByEntity_IPKey verifies that "source_ip" data field produces "ip:<addr>" key.
func TestGroupByEntity_IPKey(t *testing.T) {
	c := NewCorrelator(defaultConfig())
	events := []*normalization.NormalizedEvent{
		makeEvent("e1", "10.0.0.1", "ip", 50, time.Now()),
	}
	byEntity := c.groupByEntity(events)
	if _, ok := byEntity["ip:10.0.0.1"]; !ok {
		t.Errorf("expected key 'ip:10.0.0.1', got keys: %v", keys(byEntity))
	}
}

// TestGroupByEntity_UserPriority verifies that when "user" is present, it takes
// precedence over "host" and "source_ip".
func TestGroupByEntity_UserPriority(t *testing.T) {
	c := NewCorrelator(defaultConfig())
	ev := &normalization.NormalizedEvent{
		ID:        "e1",
		Timestamp: time.Now(),
		Severity:  50,
		Data: map[string]interface{}{
			"user":      "dave",
			"host":      "server01",
			"source_ip": "192.168.1.1",
		},
	}
	byEntity := c.groupByEntity([]*normalization.NormalizedEvent{ev})
	if _, ok := byEntity["user:dave"]; !ok {
		t.Errorf("expected 'user:dave' to take priority, got keys: %v", keys(byEntity))
	}
	if _, ok := byEntity["host:server01"]; ok {
		t.Error("host key should not be created when user is present")
	}
}

// TestGroupByEntity_EmptyEntitySkipped verifies that events with no extractable
// entity are omitted from the map.
func TestGroupByEntity_EmptyEntitySkipped(t *testing.T) {
	c := NewCorrelator(defaultConfig())
	ev := &normalization.NormalizedEvent{
		ID:        "e1",
		Timestamp: time.Now(),
		Severity:  50,
		Data:      map[string]interface{}{},
	}
	byEntity := c.groupByEntity([]*normalization.NormalizedEvent{ev})
	if len(byEntity) != 0 {
		t.Errorf("expected empty map for event with no entity, got %v", byEntity)
	}
}

// TestGroupByEntity_NonStringUserIgnored verifies that a non-string "user" field
// falls through to the next entity type.
func TestGroupByEntity_NonStringUserIgnored(t *testing.T) {
	c := NewCorrelator(defaultConfig())
	ev := &normalization.NormalizedEvent{
		ID:        "e1",
		Timestamp: time.Now(),
		Severity:  50,
		Data: map[string]interface{}{
			"user": 12345, // numeric — should be ignored
			"host": "fallback-host",
		},
	}
	byEntity := c.groupByEntity([]*normalization.NormalizedEvent{ev})
	if _, ok := byEntity["host:fallback-host"]; !ok {
		t.Errorf("expected fallback to 'host:fallback-host', got keys: %v", keys(byEntity))
	}
}

// =============================================================================
// buildChain
// =============================================================================

// TestBuildChain_BelowMinReturnsNil verifies that buildChain returns nil when
// the event count is below MinEventsForChain.
func TestBuildChain_BelowMinReturnsNil(t *testing.T) {
	c := NewCorrelator(CorrelatorConfig{MinEventsForChain: 3})
	now := time.Now()
	events := []*normalization.NormalizedEvent{
		makeEvent("e1", "alice", "user", 50, now),
		makeEvent("e2", "alice", "user", 60, now.Add(time.Minute)),
	}
	chain := c.buildChain("user:alice", events)
	if chain != nil {
		t.Error("buildChain should return nil when events < MinEventsForChain")
	}
}

// TestBuildChain_AtMinProducesChain verifies that exactly MinEventsForChain
// events produces a chain.
func TestBuildChain_AtMinProducesChain(t *testing.T) {
	c := NewCorrelator(CorrelatorConfig{MinEventsForChain: 2})
	now := time.Now()
	events := []*normalization.NormalizedEvent{
		makeEvent("e1", "alice", "user", 50, now),
		makeEvent("e2", "alice", "user", 70, now.Add(time.Minute)),
	}
	chain := c.buildChain("user:alice", events)
	if chain == nil {
		t.Fatal("buildChain should produce a chain at MinEventsForChain")
	}
}

// TestBuildChain_EventsSortedByTimestamp verifies that events within a chain
// are sorted ascending by timestamp regardless of input order.
func TestBuildChain_EventsSortedByTimestamp(t *testing.T) {
	c := NewCorrelator(defaultConfig())
	base := time.Now()

	// Deliberately out of order
	events := []*normalization.NormalizedEvent{
		makeEvent("e3", "alice", "user", 90, base.Add(2*time.Minute)),
		makeEvent("e1", "alice", "user", 50, base),
		makeEvent("e2", "alice", "user", 70, base.Add(time.Minute)),
	}

	chain := c.buildChain("user:alice", events)
	if chain == nil {
		t.Fatal("expected non-nil chain")
	}

	for i := 1; i < len(chain.Events); i++ {
		if chain.Events[i].Timestamp.Before(chain.Events[i-1].Timestamp) {
			t.Errorf("events not sorted: event[%d] (%v) is before event[%d] (%v)",
				i, chain.Events[i].Timestamp, i-1, chain.Events[i-1].Timestamp)
		}
	}
}

// TestBuildChain_StartEndTime verifies that StartTime and EndTime reflect the
// earliest and latest event timestamps after sorting.
func TestBuildChain_StartEndTime(t *testing.T) {
	c := NewCorrelator(defaultConfig())
	base := time.Now().Truncate(time.Second)

	events := []*normalization.NormalizedEvent{
		makeEvent("e2", "alice", "user", 70, base.Add(5*time.Minute)),
		makeEvent("e1", "alice", "user", 50, base),
	}

	chain := c.buildChain("user:alice", events)
	if chain == nil {
		t.Fatal("expected non-nil chain")
	}

	if !chain.StartTime.Equal(base) {
		t.Errorf("expected StartTime=%v, got %v", base, chain.StartTime)
	}
	if !chain.EndTime.Equal(base.Add(5 * time.Minute)) {
		t.Errorf("expected EndTime=%v, got %v", base.Add(5*time.Minute), chain.EndTime)
	}
}

// TestBuildChain_IDContainsEntity verifies the chain ID encodes the entity.
func TestBuildChain_IDContainsEntity(t *testing.T) {
	c := NewCorrelator(defaultConfig())
	now := time.Now()
	events := []*normalization.NormalizedEvent{
		makeEvent("e1", "alice", "user", 50, now),
		makeEvent("e2", "alice", "user", 60, now.Add(time.Minute)),
	}
	chain := c.buildChain("user:alice", events)
	if chain == nil {
		t.Fatal("expected non-nil chain")
	}
	if !strings.Contains(chain.ID, "user:alice") {
		t.Errorf("chain ID should contain entity 'user:alice', got: %q", chain.ID)
	}
}

// TestBuildChain_IDContainsNanosecond verifies that the chain ID includes a
// nanosecond-precision timestamp for uniqueness.
func TestBuildChain_IDContainsNanosecond(t *testing.T) {
	c := NewCorrelator(defaultConfig())
	now := time.Now()
	events := []*normalization.NormalizedEvent{
		makeEvent("e1", "alice", "user", 50, now),
		makeEvent("e2", "alice", "user", 60, now.Add(time.Minute)),
	}
	chain := c.buildChain("user:alice", events)
	if chain == nil {
		t.Fatal("expected non-nil chain")
	}
	expected := fmt.Sprintf("%d", now.UnixNano())
	if !strings.Contains(chain.ID, expected) {
		t.Errorf("chain ID should contain UnixNano %s, got: %q", expected, chain.ID)
	}
}

// TestBuildChain_IDUniqueness verifies two chains built from events at different
// nanosecond timestamps produce distinct IDs.
func TestBuildChain_IDUniqueness(t *testing.T) {
	c := NewCorrelator(defaultConfig())
	t1 := time.Now()
	t2 := t1.Add(time.Nanosecond)

	eventsA := []*normalization.NormalizedEvent{
		makeEvent("a1", "alice", "user", 50, t1),
		makeEvent("a2", "alice", "user", 60, t1.Add(time.Minute)),
	}
	eventsB := []*normalization.NormalizedEvent{
		makeEvent("b1", "alice", "user", 50, t2),
		makeEvent("b2", "alice", "user", 60, t2.Add(time.Minute)),
	}

	chainA := c.buildChain("user:alice", eventsA)
	chainB := c.buildChain("user:alice", eventsB)

	if chainA == nil || chainB == nil {
		t.Fatal("expected both chains to be non-nil")
	}
	if chainA.ID == chainB.ID {
		t.Errorf("chains with different start timestamps should have distinct IDs, both got %q", chainA.ID)
	}
}

// =============================================================================
// calculateChainRiskScore (tested via buildChain)
// =============================================================================

// TestRiskScore_Average verifies that the chain risk score is the arithmetic
// mean of event severity values.
func TestRiskScore_Average(t *testing.T) {
	tests := []struct {
		name       string
		severities []int
		wantScore  float64
	}{
		{"equal severities", []int{60, 60}, 60.0},
		{"varied severities", []int{20, 40, 60, 80}, 50.0},
		{"single above min", []int{100, 50}, 75.0},
		{"all zeros", []int{0, 0, 0}, 0.0},
		{"max severity", []int{100, 100}, 100.0},
	}

	c := NewCorrelator(CorrelatorConfig{MinEventsForChain: 2})

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			now := time.Now()
			var events []*normalization.NormalizedEvent
			for i, sev := range tt.severities {
				id := fmt.Sprintf("e%d", i+1)
				events = append(events, makeEvent(id, "alice", "user", sev, now.Add(time.Duration(i)*time.Minute)))
			}
			chain := c.buildChain("user:alice", events)
			if chain == nil {
				t.Fatalf("expected non-nil chain for severities %v", tt.severities)
			}
			if chain.RiskScore != tt.wantScore {
				t.Errorf("expected RiskScore=%.2f, got %.2f (severities: %v)",
					tt.wantScore, chain.RiskScore, tt.severities)
			}
		})
	}
}

// =============================================================================
// generateSummary
// =============================================================================

// TestGenerateSummary_NonEmptyEvents verifies that a non-empty event list
// returns a non-empty summary string.
func TestGenerateSummary_NonEmptyEvents(t *testing.T) {
	c := NewCorrelator(defaultConfig())
	events := []*normalization.NormalizedEvent{
		makeEvent("e1", "alice", "user", 50, time.Now()),
	}
	summary := c.generateSummary(events)
	if summary == "" {
		t.Error("generateSummary should return a non-empty string for non-empty events")
	}
}

// TestGenerateSummary_EmptyEvents verifies that an empty event list returns
// an empty string.
func TestGenerateSummary_EmptyEvents(t *testing.T) {
	c := NewCorrelator(defaultConfig())
	summary := c.generateSummary(nil)
	if summary != "" {
		t.Errorf("generateSummary should return empty string for nil events, got %q", summary)
	}
}

// TestGenerateSummary_EmptySlice verifies that an empty (not nil) slice also
// returns an empty string.
func TestGenerateSummary_EmptySlice(t *testing.T) {
	c := NewCorrelator(defaultConfig())
	summary := c.generateSummary([]*normalization.NormalizedEvent{})
	if summary != "" {
		t.Errorf("generateSummary should return empty string for empty slice, got %q", summary)
	}
}

// TestGenerateSummary_MatchesExpected verifies the static summary text that is
// returned by the current implementation.
func TestGenerateSummary_MatchesExpected(t *testing.T) {
	c := NewCorrelator(defaultConfig())
	events := []*normalization.NormalizedEvent{
		makeEvent("e1", "alice", "user", 50, time.Now()),
		makeEvent("e2", "alice", "user", 60, time.Now().Add(time.Minute)),
	}
	got := c.generateSummary(events)
	want := "Correlated event chain detected across multiple security sources"
	if got != want {
		t.Errorf("generateSummary: got %q, want %q", got, want)
	}
}

// TestChain_SummarySet verifies that the Summary field is populated on the
// EventChain returned by buildChain.
func TestChain_SummarySet(t *testing.T) {
	c := NewCorrelator(defaultConfig())
	now := time.Now()
	events := []*normalization.NormalizedEvent{
		makeEvent("e1", "alice", "user", 50, now),
		makeEvent("e2", "alice", "user", 60, now.Add(time.Minute)),
	}
	chain := c.buildChain("user:alice", events)
	if chain == nil {
		t.Fatal("expected non-nil chain")
	}
	if chain.Summary == "" {
		t.Error("chain Summary should be populated by buildChain")
	}
}

// =============================================================================
// Concurrency safety
// =============================================================================

// TestCorrelate_ConcurrentCalls verifies that Correlate is safe to call from
// multiple goroutines simultaneously without data races (run with -race).
func TestCorrelate_ConcurrentCalls(t *testing.T) {
	c := NewCorrelator(defaultConfig())
	now := time.Now()

	makeEvents := func(user string) []*normalization.NormalizedEvent {
		return []*normalization.NormalizedEvent{
			makeEvent(user+"-e1", user, "user", 50, now),
			makeEvent(user+"-e2", user, "user", 70, now.Add(time.Minute)),
		}
	}

	const numGoroutines = 20
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			user := fmt.Sprintf("user%d", idx)
			_, err := c.Correlate(context.Background(), makeEvents(user))
			if err != nil {
				t.Errorf("goroutine %d: unexpected error: %v", idx, err)
			}
		}(i)
	}

	wg.Wait()
}

// TestGroupByEntity_ConcurrentReads verifies groupByEntity does not mutate
// shared state when called concurrently (no write-after-read races on events).
func TestGroupByEntity_ConcurrentReads(t *testing.T) {
	c := NewCorrelator(defaultConfig())
	now := time.Now()

	events := []*normalization.NormalizedEvent{
		makeEvent("e1", "alice", "user", 50, now),
		makeEvent("e2", "bob", "user", 60, now),
		makeEvent("e3", "charlie", "host", 70, now),
	}

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result := c.groupByEntity(events)
			if len(result) != 3 {
				t.Errorf("expected 3 entities, got %d", len(result))
			}
		}()
	}
	wg.Wait()
}

// =============================================================================
// Mixed entity type tests
// =============================================================================

// TestCorrelate_MixedEntityTypes verifies that user/host/ip events are grouped
// separately even when sharing the same string value.
func TestCorrelate_MixedEntityTypes(t *testing.T) {
	c := NewCorrelator(defaultConfig())
	now := time.Now()

	events := []*normalization.NormalizedEvent{
		makeEvent("u1", "target", "user", 50, now),
		makeEvent("u2", "target", "user", 60, now.Add(time.Minute)),
		makeEvent("h1", "target", "host", 70, now),
		makeEvent("h2", "target", "host", 80, now.Add(time.Minute)),
	}

	chains, err := c.Correlate(context.Background(), events)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// "user:target" and "host:target" are distinct entities — expect 2 chains
	if len(chains) != 2 {
		t.Errorf("expected 2 chains for different entity types, got %d", len(chains))
	}
}

// TestCorrelate_SingleEventPerEntityNoChain verifies that a single event per
// entity never meets MinEventsForChain=2 and produces no chains, even though
// the total event count exceeds the threshold.
func TestCorrelate_SingleEventPerEntityNoChain(t *testing.T) {
	c := NewCorrelator(CorrelatorConfig{MinEventsForChain: 2, RiskThreshold: 0})
	now := time.Now()

	// 3 total events but each belongs to a unique entity — no entity has >= 2
	events := []*normalization.NormalizedEvent{
		makeEvent("e1", "alice", "user", 80, now),
		makeEvent("e2", "bob", "user", 80, now),
		makeEvent("e3", "charlie", "user", 80, now),
	}

	chains, err := c.Correlate(context.Background(), events)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(chains) != 0 {
		t.Errorf("expected 0 chains when no entity has >= MinEventsForChain, got %d", len(chains))
	}
}

// TestCorrelate_ZeroRiskScoreEvents verifies that events with severity 0
// produce a chain with risk score 0 (which meets a 0.0 threshold).
func TestCorrelate_ZeroRiskScoreEvents(t *testing.T) {
	c := NewCorrelator(CorrelatorConfig{MinEventsForChain: 2, RiskThreshold: 0.0})
	now := time.Now()

	events := []*normalization.NormalizedEvent{
		makeEvent("e1", "alice", "user", 0, now),
		makeEvent("e2", "alice", "user", 0, now.Add(time.Minute)),
	}

	chains, err := c.Correlate(context.Background(), events)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(chains) != 1 {
		t.Fatalf("expected 1 chain with zero risk score, got %d", len(chains))
	}
	if chains[0].RiskScore != 0.0 {
		t.Errorf("expected RiskScore=0.0, got %f", chains[0].RiskScore)
	}
}

// TestCorrelate_ContextNotUsedBeyondCall verifies a cancelled context does not
// prevent Correlate from returning results (current implementation is sync and
// does not check ctx mid-flight, so this should always complete).
func TestCorrelate_CancelledContextReturnsGracefully(t *testing.T) {
	c := NewCorrelator(defaultConfig())
	now := time.Now()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // immediately cancelled

	events := []*normalization.NormalizedEvent{
		makeEvent("e1", "alice", "user", 50, now),
		makeEvent("e2", "alice", "user", 70, now.Add(time.Minute)),
	}

	// Correlate is synchronous and does not check ctx — it should still return
	chains, err := c.Correlate(ctx, events)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(chains) != 1 {
		t.Errorf("expected 1 chain even with cancelled context, got %d", len(chains))
	}
}

// =============================================================================
// Helpers (non-test)
// =============================================================================

func keys[K comparable, V any](m map[K]V) []K {
	out := make([]K, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
