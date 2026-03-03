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

	"golang.org/x/time/rate"
)

// fastLimiter returns a rate limiter that allows requests immediately (for tests).
func fastLimiter() *rate.Limiter {
	return rate.NewLimiter(rate.Inf, 1)
}

// =============================================================================
// NewVirusTotalProvider Tests
// =============================================================================

func TestNewVirusTotalProvider_MissingEnvVar(t *testing.T) {
	os.Unsetenv("TEST_VT_KEY")

	_, err := NewVirusTotalProvider("TEST_VT_KEY", 30*time.Second, 0)
	if err == nil {
		t.Fatal("expected error when env var is missing")
	}
	if !strings.Contains(err.Error(), "TEST_VT_KEY") {
		t.Errorf("error should mention env var name, got: %v", err)
	}
}

func TestNewVirusTotalProvider_Success(t *testing.T) {
	os.Setenv("TEST_VT_KEY", "test-api-key")
	defer os.Unsetenv("TEST_VT_KEY")

	p, err := NewVirusTotalProvider("TEST_VT_KEY", 30*time.Second, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p == nil {
		t.Fatal("provider should not be nil")
	}
	if p.Name() != "virustotal" {
		t.Errorf("expected name 'virustotal', got %q", p.Name())
	}
}

func TestNewVirusTotalProvider_RateLimitDefault(t *testing.T) {
	os.Setenv("TEST_VT_KEY", "test-api-key")
	defer os.Unsetenv("TEST_VT_KEY")

	// rateLimit=0 should default to vtFreeRateLimit (4)
	p, err := NewVirusTotalProvider("TEST_VT_KEY", 30*time.Second, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.rateLimit.Limit != vtFreeRateLimit {
		t.Errorf("expected default rate limit %d, got %d", vtFreeRateLimit, p.rateLimit.Limit)
	}
	if p.rateLimit.Remaining != vtFreeRateLimit {
		t.Errorf("expected remaining %d, got %d", vtFreeRateLimit, p.rateLimit.Remaining)
	}
}

// =============================================================================
// CheckIOC Tests
// =============================================================================

func vtMaliciousResponse(malicious, total int, tags []string) vtResponse {
	harmless := total - malicious
	if harmless < 0 {
		harmless = 0
	}
	return vtResponse{
		Data: vtData{
			ID: "test-id",
			Attributes: vtAttributes{
				LastAnalysisStats: vtAnalysisStats{
					Malicious:  malicious,
					Undetected: harmless,
				},
				LastAnalysisDate:    time.Now().Unix(),
				FirstSubmissionDate: time.Now().Add(-24 * time.Hour).Unix(),
				Tags:                tags,
			},
		},
	}
}

func TestVTCheckIOC_IP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/ip_addresses/") {
			t.Errorf("expected /ip_addresses/ path, got %s", r.URL.Path)
		}
		if r.Header.Get("x-apikey") == "" {
			t.Error("expected x-apikey header")
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(vtMaliciousResponse(5, 10, []string{"malware"}))
	}))
	defer server.Close()

	p := vtProviderWithServer(t, server.URL)
	match, err := p.CheckIOC(context.Background(), IOCTypeIP, "1.2.3.4")
	if err != nil {
		t.Fatalf("CheckIOC failed: %v", err)
	}
	if match == nil {
		t.Fatal("expected match, got nil")
	}
	if match.Source != "virustotal" {
		t.Errorf("expected source 'virustotal', got %q", match.Source)
	}
	if match.MatchedValue != "1.2.3.4" {
		t.Errorf("expected matched value '1.2.3.4', got %q", match.MatchedValue)
	}
}

func TestVTCheckIOC_Domain(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/domains/") {
			t.Errorf("expected /domains/ path, got %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(vtMaliciousResponse(3, 10, []string{"phish"}))
	}))
	defer server.Close()

	p := vtProviderWithServer(t, server.URL)
	match, err := p.CheckIOC(context.Background(), IOCTypeDomain, "evil.com")
	if err != nil {
		t.Fatalf("CheckIOC failed: %v", err)
	}
	if match == nil {
		t.Fatal("expected match, got nil")
	}
	if match.Indicator.ThreatType != ThreatTypePhishing {
		t.Errorf("expected phishing threat type, got %s", match.Indicator.ThreatType)
	}
}

func TestVTCheckIOC_URL(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/urls/") {
			t.Errorf("expected /urls/ path, got %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(vtMaliciousResponse(2, 5, []string{"malware"}))
	}))
	defer server.Close()

	p := vtProviderWithServer(t, server.URL)
	match, err := p.CheckIOC(context.Background(), IOCTypeURL, "http://evil.com/payload")
	if err != nil {
		t.Fatalf("CheckIOC failed: %v", err)
	}
	if match == nil {
		t.Fatal("expected match, got nil")
	}
}

func TestVTCheckIOC_Hash(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/files/") {
			t.Errorf("expected /files/ path, got %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(vtMaliciousResponse(8, 10, []string{"ransomware"}))
	}))
	defer server.Close()

	p := vtProviderWithServer(t, server.URL)
	match, err := p.CheckIOC(context.Background(), IOCTypeHash, "d41d8cd98f00b204e9800998ecf8427e")
	if err != nil {
		t.Fatalf("CheckIOC failed: %v", err)
	}
	if match == nil {
		t.Fatal("expected match, got nil")
	}
	if match.Indicator.ThreatType != ThreatTypeRansomware {
		t.Errorf("expected ransomware, got %s", match.Indicator.ThreatType)
	}
}

func TestVTCheckIOC_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	p := vtProviderWithServer(t, server.URL)
	match, err := p.CheckIOC(context.Background(), IOCTypeIP, "1.2.3.4")
	if err != nil {
		t.Fatalf("expected nil error on 404, got: %v", err)
	}
	if match != nil {
		t.Errorf("expected nil match on 404, got: %+v", match)
	}
}

func TestVTCheckIOC_RateLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()

	p := vtProviderWithServer(t, server.URL)
	_, err := p.CheckIOC(context.Background(), IOCTypeIP, "1.2.3.4")
	if err == nil {
		t.Fatal("expected error on 429")
	}
	if !strings.Contains(err.Error(), "rate limit") {
		t.Errorf("expected rate limit error, got: %v", err)
	}
}

// vtProviderWithServer creates a provider whose HTTP client points at the test server.
// It monkey-patches vtBaseURL at the function level by creating the endpoint inline.
func vtProviderWithServer(t *testing.T, serverURL string) *VirusTotalProvider {
	t.Helper()
	os.Setenv("TEST_VT_KEY", "test-api-key")
	defer os.Unsetenv("TEST_VT_KEY")

	p, err := NewVirusTotalProvider("TEST_VT_KEY", 5*time.Second, 60)
	if err != nil {
		t.Fatalf("creating provider: %v", err)
	}

	// Bypass rate limiting in tests so batch tests complete quickly.
	p.limiter = fastLimiter()

	// Replace the http.Client transport with one that redirects all requests to server.
	p.httpClient = &http.Client{
		Timeout:   5 * time.Second,
		Transport: &testTransport{baseURL: serverURL},
	}
	return p
}

// testTransport rewrites the host of every request to point at a test server.
type testTransport struct {
	baseURL string
}

func (t *testTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Replace the base URL portion, keep the path.
	newURL := t.baseURL + req.URL.Path
	if req.URL.RawQuery != "" {
		newURL += "?" + req.URL.RawQuery
	}
	newReq, err := http.NewRequestWithContext(req.Context(), req.Method, newURL, req.Body)
	if err != nil {
		return nil, err
	}
	newReq.Header = req.Header
	return http.DefaultTransport.RoundTrip(newReq)
}

// =============================================================================
// CheckBatch Tests
// =============================================================================

func TestCheckBatch_AllSucceed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(vtMaliciousResponse(3, 10, []string{"malware"}))
	}))
	defer server.Close()

	p := vtProviderWithServer(t, server.URL)
	matches, err := p.CheckBatch(context.Background(), IOCTypeIP, []string{"1.1.1.1", "2.2.2.2"})
	if err != nil {
		t.Fatalf("CheckBatch failed: %v", err)
	}
	if len(matches) != 2 {
		t.Errorf("expected 2 matches, got %d", len(matches))
	}
}

func TestCheckBatch_PartialFailures(t *testing.T) {
	call := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		call++
		if call%2 == 0 {
			// Alternate: even calls return 404 (not found = no match, no error)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(vtMaliciousResponse(3, 10, []string{"malware"}))
	}))
	defer server.Close()

	p := vtProviderWithServer(t, server.URL)
	values := []string{"1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"}
	matches, err := p.CheckBatch(context.Background(), IOCTypeIP, values)
	if err != nil {
		t.Fatalf("partial failures should not error when some succeed: %v", err)
	}
	// Odd calls succeed (calls 1,3 → 2 matches), even calls return 404 (no match)
	if len(matches) != 2 {
		t.Errorf("expected 2 matches, got %d", len(matches))
	}
}

func TestCheckBatch_AllFail(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("server error"))
	}))
	defer server.Close()

	p := vtProviderWithServer(t, server.URL)
	_, err := p.CheckBatch(context.Background(), IOCTypeIP, []string{"1.1.1.1", "2.2.2.2"})
	if err == nil {
		t.Fatal("expected error when all lookups fail")
	}
}

// =============================================================================
// vtBuildMatch Tests
// =============================================================================

func TestVtBuildMatch_CleanResult(t *testing.T) {
	attrs := &vtAttributes{
		LastAnalysisStats: vtAnalysisStats{
			Malicious:  0,
			Suspicious: 0,
			Undetected: 10,
			Harmless:   5,
		},
	}
	result := vtBuildMatch(IOCTypeIP, "1.2.3.4", attrs)
	if result != nil {
		t.Errorf("expected nil for 0 positives, got: %+v", result)
	}
}

func TestVtBuildMatch_ZeroTotal(t *testing.T) {
	attrs := &vtAttributes{
		LastAnalysisStats: vtAnalysisStats{},
	}
	result := vtBuildMatch(IOCTypeIP, "1.2.3.4", attrs)
	if result != nil {
		t.Errorf("expected nil for zero total, got: %+v", result)
	}
}

func TestVtBuildMatch_MaliciousResult(t *testing.T) {
	attrs := &vtAttributes{
		LastAnalysisStats: vtAnalysisStats{
			Malicious:  5,
			Undetected: 5,
		},
		LastAnalysisDate:    1700000000,
		FirstSubmissionDate: 1690000000,
		Tags:                []string{"malware"},
	}
	result := vtBuildMatch(IOCTypeIP, "1.2.3.4", attrs)
	if result == nil {
		t.Fatal("expected match, got nil")
	}
	if result.Indicator.ThreatType != ThreatTypeMalware {
		t.Errorf("expected malware, got %s", result.Indicator.ThreatType)
	}
	if result.Indicator.Confidence != 0.5 {
		t.Errorf("expected confidence 0.5, got %f", result.Indicator.Confidence)
	}
	if result.Indicator.FirstSeen.IsZero() {
		t.Error("FirstSeen should not be zero")
	}
	if result.Indicator.LastSeen.IsZero() {
		t.Error("LastSeen should not be zero")
	}
}

func TestVtBuildMatch_LowSampleCountHalvesConfidence(t *testing.T) {
	// total < 10 → confidence *= 0.5
	attrs := &vtAttributes{
		LastAnalysisStats: vtAnalysisStats{
			Malicious:  4,
			Undetected: 4,
		},
		Tags: []string{},
	}
	result := vtBuildMatch(IOCTypeIP, "1.2.3.4", attrs)
	if result == nil {
		t.Fatal("expected match, got nil")
	}
	// malRatio = 4/8 = 0.5, confidence = 0.5 * 0.5 = 0.25
	expected := 0.25
	if result.Indicator.Confidence != expected {
		t.Errorf("expected confidence %f, got %f", expected, result.Indicator.Confidence)
	}
}

func TestVtBuildMatch_ZeroTimestamps(t *testing.T) {
	attrs := &vtAttributes{
		LastAnalysisStats: vtAnalysisStats{
			Malicious:  3,
			Undetected: 7,
		},
		LastAnalysisDate:    0,
		FirstSubmissionDate: 0,
		Tags:                []string{},
	}
	result := vtBuildMatch(IOCTypeIP, "1.2.3.4", attrs)
	if result == nil {
		t.Fatal("expected match, got nil")
	}
	if !result.Indicator.FirstSeen.IsZero() {
		t.Errorf("expected zero FirstSeen, got: %v", result.Indicator.FirstSeen)
	}
	if !result.Indicator.LastSeen.IsZero() {
		t.Errorf("expected zero LastSeen, got: %v", result.Indicator.LastSeen)
	}
}

// =============================================================================
// vtSeverity Tests
// =============================================================================

func TestVtSeverity(t *testing.T) {
	tests := []struct {
		ratio    float64
		expected string
	}{
		{0.5, "critical"},
		{0.75, "critical"},
		{1.0, "critical"},
		{0.25, "high"},
		{0.4, "high"},
		{0.1, "medium"},
		{0.2, "medium"},
		{0.09, "low"},
		{0.0, "low"},
	}
	for _, tt := range tests {
		got := vtSeverity(tt.ratio)
		if got != tt.expected {
			t.Errorf("vtSeverity(%f): expected %q, got %q", tt.ratio, tt.expected, got)
		}
	}
}

// =============================================================================
// vtInferThreatType Tests
// =============================================================================

func TestVtInferThreatType(t *testing.T) {
	tests := []struct {
		tags     []string
		expected ThreatType
	}{
		{[]string{"malware", "trojan"}, ThreatTypeMalware},
		{[]string{"phish"}, ThreatTypePhishing},
		{[]string{"phishing"}, ThreatTypePhishing},
		{[]string{"ransomware"}, ThreatTypeRansomware},
		{[]string{"botnet"}, ThreatTypeBotnet},
		{[]string{"c2"}, ThreatTypeC2},
		{[]string{"command-and-control"}, ThreatTypeC2},
		{[]string{"scanner"}, ThreatTypeScanner},
		{[]string{"tor"}, ThreatTypeTOR},
		{[]string{"spam"}, ThreatTypeSpam},
		{[]string{"totally-unknown"}, ThreatTypeUnknown},
		{[]string{}, ThreatTypeUnknown},
	}
	for _, tt := range tests {
		attrs := &vtAttributes{Tags: tt.tags}
		got := vtInferThreatType(attrs)
		if got != tt.expected {
			t.Errorf("tags %v: expected %s, got %s", tt.tags, tt.expected, got)
		}
	}
}

// =============================================================================
// vtEndpoint Tests
// =============================================================================

func TestVtEndpoint(t *testing.T) {
	tests := []struct {
		iocType IOCType
		value   string
		wantSub string
		wantErr bool
	}{
		{IOCTypeIP, "1.2.3.4", "/ip_addresses/1.2.3.4", false},
		{IOCTypeDomain, "evil.com", "/domains/evil.com", false},
		{IOCTypeURL, "http://x.com", "/urls/", false}, // base64 encoded
		{IOCTypeHash, "d41d8cd98f00b204e9800998ecf8427e", "/files/", false},
		{IOCTypeEmail, "x@y.com", "", true},
		{IOCTypeFile, "/etc/passwd", "", true},
	}
	for _, tt := range tests {
		ep, err := vtEndpoint(tt.iocType, tt.value)
		if tt.wantErr {
			if err == nil {
				t.Errorf("type %s: expected error, got none", tt.iocType)
			}
			continue
		}
		if err != nil {
			t.Errorf("type %s: unexpected error: %v", tt.iocType, err)
			continue
		}
		if !strings.Contains(ep, tt.wantSub) {
			t.Errorf("type %s: expected %q in endpoint, got %q", tt.iocType, tt.wantSub, ep)
		}
	}
}

// =============================================================================
// HealthCheck Tests
// =============================================================================

func TestVtHealthCheck_OK(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v3/users/me" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data":{}}`))
	}))
	defer server.Close()

	p := vtProviderWithServer(t, server.URL)
	if err := p.HealthCheck(context.Background()); err != nil {
		t.Errorf("expected nil error, got: %v", err)
	}
}

func TestVtHealthCheck_Unauthorized(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	p := vtProviderWithServer(t, server.URL)
	err := p.HealthCheck(context.Background())
	if err == nil {
		t.Fatal("expected error on 401")
	}
	if !strings.Contains(err.Error(), "authentication failed") {
		t.Errorf("expected auth error, got: %v", err)
	}
}

func TestVtHealthCheck_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	p := vtProviderWithServer(t, server.URL)
	err := p.HealthCheck(context.Background())
	if err == nil {
		t.Fatal("expected error on 500")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("expected status 500 in error, got: %v", err)
	}
}
