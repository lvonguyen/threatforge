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

// newGNProvider creates a provider pointed at the given test server URL.
func newGNProvider(t *testing.T, serverURL string) *GreyNoiseProvider {
	t.Helper()
	os.Setenv("TEST_GN_KEY", "test-api-key")
	defer os.Unsetenv("TEST_GN_KEY")

	p, err := NewGreyNoiseProvider("TEST_GN_KEY", 5*time.Second)
	if err != nil {
		t.Fatalf("creating GreyNoise provider: %v", err)
	}
	// Bypass rate limiting in tests.
	p.limiter = fastLimiter()
	p.httpClient = &http.Client{
		Timeout:   5 * time.Second,
		Transport: &testTransport{baseURL: serverURL},
	}
	return p
}

// =============================================================================
// NewGreyNoiseProvider Tests
// =============================================================================

func TestNewGreyNoiseProvider_MissingEnvVar(t *testing.T) {
	os.Unsetenv("TEST_GN_KEY")

	_, err := NewGreyNoiseProvider("TEST_GN_KEY", 30*time.Second)
	if err == nil {
		t.Fatal("expected error when env var is missing")
	}
	if !strings.Contains(err.Error(), "TEST_GN_KEY") {
		t.Errorf("error should mention env var name, got: %v", err)
	}
}

func TestNewGreyNoiseProvider_Success(t *testing.T) {
	os.Setenv("TEST_GN_KEY", "test-api-key")
	defer os.Unsetenv("TEST_GN_KEY")

	p, err := NewGreyNoiseProvider("TEST_GN_KEY", 30*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p == nil {
		t.Fatal("provider should not be nil")
	}
	if p.Name() != "greynoise" {
		t.Errorf("expected name 'greynoise', got %q", p.Name())
	}
}

// =============================================================================
// CheckIOC Tests
// =============================================================================

func TestGNCheckIOC_NonIPReturnsNil(t *testing.T) {
	os.Setenv("TEST_GN_KEY", "test-api-key")
	defer os.Unsetenv("TEST_GN_KEY")

	p, _ := NewGreyNoiseProvider("TEST_GN_KEY", 5*time.Second)

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

func TestGNCheckIOC_MaliciousIP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/v3/community/") {
			t.Errorf("expected /v3/community/ path, got %s", r.URL.Path)
		}
		if r.Header.Get("key") == "" {
			t.Error("expected 'key' header")
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(gnCommunityResponse{
			IP:             "1.2.3.4",
			Noise:          true,
			Riot:           false,
			Classification: "malicious",
			Name:           "BadActor",
			LastSeen:       "2024-01-15",
		})
	}))
	defer server.Close()

	p := newGNProvider(t, server.URL)
	match, err := p.CheckIOC(context.Background(), IOCTypeIP, "1.2.3.4")
	if err != nil {
		t.Fatalf("CheckIOC failed: %v", err)
	}
	if match == nil {
		t.Fatal("expected match, got nil")
	}
	if match.Source != "greynoise" {
		t.Errorf("expected source 'greynoise', got %q", match.Source)
	}
	if match.Indicator.ThreatType != ThreatTypeMalware {
		t.Errorf("expected malware threat type, got %s", match.Indicator.ThreatType)
	}
	if match.Indicator.Confidence != 0.9 {
		t.Errorf("expected confidence 0.9 (malicious+noise), got %f", match.Indicator.Confidence)
	}
}

func TestGNCheckIOC_BenignReturnsNil(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(gnCommunityResponse{
			IP:             "8.8.8.8",
			Noise:          false,
			Riot:           false,
			Classification: "benign",
		})
	}))
	defer server.Close()

	p := newGNProvider(t, server.URL)
	match, err := p.CheckIOC(context.Background(), IOCTypeIP, "8.8.8.8")
	if err != nil {
		t.Fatalf("CheckIOC failed: %v", err)
	}
	if match != nil {
		t.Errorf("expected nil match for benign IP, got: %+v", match)
	}
}

func TestGNCheckIOC_RiotReturnsNil(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(gnCommunityResponse{
			IP:             "1.1.1.1",
			Noise:          false,
			Riot:           true,
			Classification: "benign",
		})
	}))
	defer server.Close()

	p := newGNProvider(t, server.URL)
	match, err := p.CheckIOC(context.Background(), IOCTypeIP, "1.1.1.1")
	if err != nil {
		t.Fatalf("CheckIOC failed: %v", err)
	}
	if match != nil {
		t.Errorf("expected nil match for riot IP, got: %+v", match)
	}
}

func TestGNCheckIOC_UnknownNoNoiseReturnsNil(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(gnCommunityResponse{
			IP:             "5.6.7.8",
			Noise:          false,
			Riot:           false,
			Classification: "unknown",
		})
	}))
	defer server.Close()

	p := newGNProvider(t, server.URL)
	match, err := p.CheckIOC(context.Background(), IOCTypeIP, "5.6.7.8")
	if err != nil {
		t.Fatalf("CheckIOC failed: %v", err)
	}
	if match != nil {
		t.Errorf("expected nil match for unknown IP with no noise, got: %+v", match)
	}
}

func TestGNCheckIOC_UnknownWithNoise(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(gnCommunityResponse{
			IP:             "5.6.7.8",
			Noise:          true,
			Riot:           false,
			Classification: "unknown",
		})
	}))
	defer server.Close()

	p := newGNProvider(t, server.URL)
	match, err := p.CheckIOC(context.Background(), IOCTypeIP, "5.6.7.8")
	if err != nil {
		t.Fatalf("CheckIOC failed: %v", err)
	}
	if match == nil {
		t.Fatal("expected match for unknown+noise IP")
	}
	if match.Indicator.Confidence != 0.5 {
		t.Errorf("expected confidence 0.5 for unknown+noise, got %f", match.Indicator.Confidence)
	}
}

func TestGNCheckIOC_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	p := newGNProvider(t, server.URL)
	match, err := p.CheckIOC(context.Background(), IOCTypeIP, "9.9.9.9")
	if err != nil {
		t.Fatalf("expected nil error on 404, got: %v", err)
	}
	if match != nil {
		t.Errorf("expected nil match on 404")
	}
}

func TestGNCheckIOC_RateLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()

	p := newGNProvider(t, server.URL)
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

func TestGNCheckBatch_MixedResults(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// malicious for IPs ending in .1, not found for .2
		if strings.HasSuffix(r.URL.Path, "/1.2.3.1") {
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(gnCommunityResponse{
				IP: "1.2.3.1", Noise: true, Classification: "malicious",
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	p := newGNProvider(t, server.URL)
	matches, err := p.CheckBatch(context.Background(), IOCTypeIP, []string{"1.2.3.1", "1.2.3.2"})
	if err != nil {
		t.Fatalf("CheckBatch should not error on partial hits: %v", err)
	}
	if len(matches) != 1 {
		t.Errorf("expected 1 match, got %d", len(matches))
	}
}

// =============================================================================
// HealthCheck Tests
// =============================================================================

func TestGNHealthCheck_OK(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ping" {
			t.Errorf("expected /ping path, got %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"message":"pong"}`))
	}))
	defer server.Close()

	p := newGNProvider(t, server.URL)
	if err := p.HealthCheck(context.Background()); err != nil {
		t.Errorf("expected nil error, got: %v", err)
	}
}

func TestGNHealthCheck_Unauthorized(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	p := newGNProvider(t, server.URL)
	err := p.HealthCheck(context.Background())
	if err == nil {
		t.Fatal("expected error on 401")
	}
	if !strings.Contains(err.Error(), "authentication failed") {
		t.Errorf("expected auth error, got: %v", err)
	}
}

func TestGNHealthCheck_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	p := newGNProvider(t, server.URL)
	err := p.HealthCheck(context.Background())
	if err == nil {
		t.Fatal("expected error on 500")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("expected 500 in error, got: %v", err)
	}
}

// =============================================================================
// gnBuildMatch Unit Tests
// =============================================================================

func TestGnBuildMatch_Confidence(t *testing.T) {
	tests := []struct {
		name           string
		resp           gnCommunityResponse
		wantNil        bool
		wantConfidence float64
	}{
		{
			name:           "malicious+noise",
			resp:           gnCommunityResponse{Classification: "malicious", Noise: true},
			wantConfidence: 0.9,
		},
		{
			name:           "malicious no noise",
			resp:           gnCommunityResponse{Classification: "malicious", Noise: false},
			wantConfidence: 0.75,
		},
		{
			name:           "unknown+noise",
			resp:           gnCommunityResponse{Classification: "unknown", Noise: true},
			wantConfidence: 0.5,
		},
		{
			name:    "benign",
			resp:    gnCommunityResponse{Classification: "benign"},
			wantNil: true,
		},
		{
			name:    "riot",
			resp:    gnCommunityResponse{Classification: "benign", Riot: true},
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := gnBuildMatch(IOCTypeIP, "1.2.3.4", &tt.resp)
			if tt.wantNil {
				if result != nil {
					t.Errorf("expected nil, got: %+v", result)
				}
				return
			}
			if result == nil {
				t.Fatal("expected match, got nil")
			}
			if result.Indicator.Confidence != tt.wantConfidence {
				t.Errorf("expected confidence %f, got %f", tt.wantConfidence, result.Indicator.Confidence)
			}
		})
	}
}
