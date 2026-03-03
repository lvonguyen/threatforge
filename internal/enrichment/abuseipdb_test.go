package enrichment

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// newAbuseIPDBProvider creates a provider pointed at the given test server URL.
func newAbuseIPDBProvider(t *testing.T, serverURL string) *AbuseIPDBProvider {
	t.Helper()
	os.Setenv("TEST_ABUSE_KEY", "test-api-key")
	defer os.Unsetenv("TEST_ABUSE_KEY")

	p, err := NewAbuseIPDBProvider("TEST_ABUSE_KEY", 5*time.Second)
	if err != nil {
		t.Fatalf("creating AbuseIPDB provider: %v", err)
	}
	// Bypass rate limiting in tests.
	p.limiter = fastLimiter()
	p.httpClient = &http.Client{
		Timeout:   5 * time.Second,
		Transport: &testTransport{baseURL: serverURL},
	}
	return p
}

func abuseResponse(score int) abuseIPDBCheckResponse {
	return abuseIPDBCheckResponse{
		Data: abuseIPDBData{
			IPAddress:            "1.2.3.4",
			IsPublic:             true,
			AbuseConfidenceScore: score,
			TotalReports:         10,
			LastReportedAt:       "2024-01-15T10:00:00+00:00",
		},
	}
}

// =============================================================================
// NewAbuseIPDBProvider Tests
// =============================================================================

func TestNewAbuseIPDBProvider_MissingEnvVar(t *testing.T) {
	os.Unsetenv("TEST_ABUSE_KEY")

	_, err := NewAbuseIPDBProvider("TEST_ABUSE_KEY", 30*time.Second)
	if err == nil {
		t.Fatal("expected error when env var is missing")
	}
	if !strings.Contains(err.Error(), "TEST_ABUSE_KEY") {
		t.Errorf("error should mention env var name, got: %v", err)
	}
}

func TestNewAbuseIPDBProvider_Success(t *testing.T) {
	os.Setenv("TEST_ABUSE_KEY", "test-api-key")
	defer os.Unsetenv("TEST_ABUSE_KEY")

	p, err := NewAbuseIPDBProvider("TEST_ABUSE_KEY", 30*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p == nil {
		t.Fatal("provider should not be nil")
	}
	if p.Name() != "abuseipdb" {
		t.Errorf("expected name 'abuseipdb', got %q", p.Name())
	}
}

// =============================================================================
// CheckIOC Tests
// =============================================================================

func TestAbuseCheckIOC_NonIPReturnsNil(t *testing.T) {
	os.Setenv("TEST_ABUSE_KEY", "test-api-key")
	defer os.Unsetenv("TEST_ABUSE_KEY")

	p, _ := NewAbuseIPDBProvider("TEST_ABUSE_KEY", 5*time.Second)

	for _, iocType := range []IOCType{IOCTypeDomain, IOCTypeURL, IOCTypeHash, IOCTypeEmail} {
		match, err := p.CheckIOC(context.Background(), iocType, "value")
		if err != nil {
			t.Errorf("type %s: expected nil error, got: %v", iocType, err)
		}
		if match != nil {
			t.Errorf("type %s: expected nil match for non-IP type, got: %+v", iocType, match)
		}
	}
}

func TestAbuseCheckIOC_HighScore(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/api/v2/check") {
			t.Errorf("expected /api/v2/check path, got %s", r.URL.Path)
		}
		if r.Header.Get("Key") == "" {
			t.Error("expected 'Key' header")
		}
		if r.URL.Query().Get("ipAddress") == "" {
			t.Error("expected ipAddress query param")
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(abuseResponse(95))
	}))
	defer server.Close()

	p := newAbuseIPDBProvider(t, server.URL)
	match, err := p.CheckIOC(context.Background(), IOCTypeIP, "1.2.3.4")
	if err != nil {
		t.Fatalf("CheckIOC failed: %v", err)
	}
	if match == nil {
		t.Fatal("expected match for high abuse score")
	}
	if match.Source != "abuseipdb" {
		t.Errorf("expected source 'abuseipdb', got %q", match.Source)
	}
	if match.Indicator.Confidence != 0.95 {
		t.Errorf("expected confidence 0.95, got %f", match.Indicator.Confidence)
	}
	if match.Indicator.Severity != "critical" {
		t.Errorf("expected critical severity, got %s", match.Indicator.Severity)
	}
}

func TestAbuseCheckIOC_ZeroScoreReturnsNil(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(abuseResponse(0))
	}))
	defer server.Close()

	p := newAbuseIPDBProvider(t, server.URL)
	match, err := p.CheckIOC(context.Background(), IOCTypeIP, "8.8.8.8")
	if err != nil {
		t.Fatalf("CheckIOC failed: %v", err)
	}
	if match != nil {
		t.Errorf("expected nil match for score 0, got: %+v", match)
	}
}

func TestAbuseCheckIOC_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	p := newAbuseIPDBProvider(t, server.URL)
	match, err := p.CheckIOC(context.Background(), IOCTypeIP, "1.2.3.4")
	if err != nil {
		t.Fatalf("expected nil error on 404, got: %v", err)
	}
	if match != nil {
		t.Errorf("expected nil match on 404")
	}
}

func TestAbuseCheckIOC_RateLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()

	p := newAbuseIPDBProvider(t, server.URL)
	_, err := p.CheckIOC(context.Background(), IOCTypeIP, "1.2.3.4")
	if err == nil {
		t.Fatal("expected error on 429")
	}
	if !strings.Contains(err.Error(), "rate limit") {
		t.Errorf("expected rate limit error, got: %v", err)
	}
}

// =============================================================================
// CheckBatch Tests
// =============================================================================

func TestAbuseCheckBatch_AllSucceed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(abuseResponse(80))
	}))
	defer server.Close()

	p := newAbuseIPDBProvider(t, server.URL)
	matches, err := p.CheckBatch(context.Background(), IOCTypeIP, []string{"1.1.1.1", "2.2.2.2"})
	if err != nil {
		t.Fatalf("CheckBatch failed: %v", err)
	}
	if len(matches) != 2 {
		t.Errorf("expected 2 matches, got %d", len(matches))
	}
}

func TestAbuseCheckBatch_AllFail(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("server error"))
	}))
	defer server.Close()

	p := newAbuseIPDBProvider(t, server.URL)
	_, err := p.CheckBatch(context.Background(), IOCTypeIP, []string{"1.1.1.1", "2.2.2.2"})
	if err == nil {
		t.Fatal("expected error when all lookups fail")
	}
}

// =============================================================================
// abuseIPDBSeverity Unit Tests
// =============================================================================

func TestAbuseIPDBSeverity(t *testing.T) {
	tests := []struct {
		confidence float64
		expected   string
	}{
		{0.75, "critical"},
		{0.9, "critical"},
		{1.0, "critical"},
		{0.5, "high"},
		{0.6, "high"},
		{0.25, "medium"},
		{0.4, "medium"},
		{0.24, "low"},
		{0.0, "low"},
	}
	for _, tt := range tests {
		got := abuseIPDBSeverity(tt.confidence)
		if got != tt.expected {
			t.Errorf("abuseIPDBSeverity(%f): expected %q, got %q", tt.confidence, tt.expected, got)
		}
	}
}

// =============================================================================
// abuseIPDBBuildMatch Unit Tests
// =============================================================================

func TestAbuseIPDBBuildMatch_ScoreToConfidence(t *testing.T) {
	tests := []struct {
		score    int
		wantNil  bool
		wantConf float64
		wantSev  string
	}{
		{0, true, 0, ""},
		{50, false, 0.5, "high"},
		{75, false, 0.75, "critical"},
		{100, false, 1.0, "critical"},
	}
	for _, tt := range tests {
		data := &abuseIPDBData{AbuseConfidenceScore: tt.score}
		result := abuseIPDBBuildMatch(IOCTypeIP, "1.2.3.4", data)
		if tt.wantNil {
			if result != nil {
				t.Errorf("score=%d: expected nil, got %+v", tt.score, result)
			}
			continue
		}
		if result == nil {
			t.Fatalf("score=%d: expected match, got nil", tt.score)
		}
		if result.Indicator.Confidence != tt.wantConf {
			t.Errorf("score=%d: expected confidence %f, got %f", tt.score, tt.wantConf, result.Indicator.Confidence)
		}
		if result.Indicator.Severity != tt.wantSev {
			t.Errorf("score=%d: expected severity %q, got %q", tt.score, tt.wantSev, result.Indicator.Severity)
		}
	}
}

// =============================================================================
// HealthCheck Tests
// =============================================================================

func TestAbuseHealthCheck_OK(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(abuseResponse(0))
	}))
	defer server.Close()

	p := newAbuseIPDBProvider(t, server.URL)
	if err := p.HealthCheck(context.Background()); err != nil {
		t.Errorf("expected nil error, got: %v", err)
	}
}

func TestAbuseHealthCheck_Unauthorized(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	p := newAbuseIPDBProvider(t, server.URL)
	err := p.HealthCheck(context.Background())
	if err == nil {
		t.Fatal("expected error on 401")
	}
	if !strings.Contains(err.Error(), "authentication failed") {
		t.Errorf("expected auth error, got: %v", err)
	}
}

func TestAbuseHealthCheck_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	p := newAbuseIPDBProvider(t, server.URL)
	err := p.HealthCheck(context.Background())
	if err == nil {
		t.Fatal("expected error on 500")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("expected 500 in error, got: %v", err)
	}
}
