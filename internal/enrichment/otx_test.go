package enrichment

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// =============================================================================
// Provider Creation Tests
// =============================================================================

// TestNewOTXProvider_MissingAPIKey verifies that creating a provider without
// an API key in the environment returns an error.
func TestNewOTXProvider_MissingAPIKey(t *testing.T) {
	os.Unsetenv("TEST_OTX_KEY")

	config := OTXConfig{
		ProviderConfig: ProviderConfig{
			APIKey:  "TEST_OTX_KEY",
			BaseURL: "https://otx.alienvault.com",
		},
	}

	_, err := NewOTXProvider(config)
	if err == nil {
		t.Error("NewOTXProvider should fail when API key env var is empty")
	}

	if !strings.Contains(err.Error(), "OTX API key not found") {
		t.Errorf("error should mention missing API key, got: %v", err)
	}
}

// TestNewOTXProvider_Success verifies successful provider creation.
func TestNewOTXProvider_Success(t *testing.T) {
	os.Setenv("TEST_OTX_KEY", "test-api-key")
	defer os.Unsetenv("TEST_OTX_KEY")

	config := DefaultOTXConfig()
	config.APIKey = "TEST_OTX_KEY"

	provider, err := NewOTXProvider(config)
	if err != nil {
		t.Fatalf("NewOTXProvider should succeed: %v", err)
	}

	if provider == nil {
		t.Error("provider should not be nil")
	}

	if provider.Name() != "otx" {
		t.Errorf("expected name 'otx', got %q", provider.Name())
	}
}

// TestNewOTXProvider_DefaultBaseURL verifies default base URL is set.
func TestNewOTXProvider_DefaultBaseURL(t *testing.T) {
	os.Setenv("TEST_OTX_KEY", "test-api-key")
	defer os.Unsetenv("TEST_OTX_KEY")

	config := OTXConfig{
		ProviderConfig: ProviderConfig{
			APIKey:  "TEST_OTX_KEY",
			BaseURL: "", // Empty - should use default
			Timeout: 30 * time.Second,
		},
	}

	provider, err := NewOTXProvider(config)
	if err != nil {
		t.Fatalf("NewOTXProvider should succeed: %v", err)
	}

	if provider.config.BaseURL != otxDefaultBaseURL {
		t.Errorf("expected default base URL %q, got %q", otxDefaultBaseURL, provider.config.BaseURL)
	}
}

// =============================================================================
// Health Check Tests
// =============================================================================

// TestHealthCheck_Success verifies successful health check.
func TestHealthCheck_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/user/me" {
			t.Errorf("expected path /api/v1/user/me, got %s", r.URL.Path)
		}

		if r.Header.Get("X-OTX-API-KEY") != "test-api-key" {
			t.Errorf("expected API key header, got %q", r.Header.Get("X-OTX-API-KEY"))
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"username": "testuser"}`))
	}))
	defer server.Close()

	os.Setenv("TEST_OTX_KEY", "test-api-key")
	defer os.Unsetenv("TEST_OTX_KEY")

	config := DefaultOTXConfig()
	config.APIKey = "TEST_OTX_KEY"
	config.BaseURL = server.URL

	provider, _ := NewOTXProvider(config)

	err := provider.HealthCheck(context.Background())
	if err != nil {
		t.Errorf("HealthCheck should succeed: %v", err)
	}
}

// TestHealthCheck_Unauthorized verifies health check fails on 401.
func TestHealthCheck_Unauthorized(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error": "Invalid API key"}`))
	}))
	defer server.Close()

	os.Setenv("TEST_OTX_KEY", "invalid-key")
	defer os.Unsetenv("TEST_OTX_KEY")

	config := DefaultOTXConfig()
	config.APIKey = "TEST_OTX_KEY"
	config.BaseURL = server.URL

	provider, _ := NewOTXProvider(config)

	err := provider.HealthCheck(context.Background())
	if err == nil {
		t.Error("HealthCheck should fail on unauthorized")
	}

	if !strings.Contains(err.Error(), "invalid API key") {
		t.Errorf("error should mention invalid API key, got: %v", err)
	}
}

// TestHealthCheck_ServerError verifies health check fails on server error.
func TestHealthCheck_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	os.Setenv("TEST_OTX_KEY", "test-api-key")
	defer os.Unsetenv("TEST_OTX_KEY")

	config := DefaultOTXConfig()
	config.APIKey = "TEST_OTX_KEY"
	config.BaseURL = server.URL

	provider, _ := NewOTXProvider(config)

	err := provider.HealthCheck(context.Background())
	if err == nil {
		t.Error("HealthCheck should fail on server error")
	}

	if !strings.Contains(err.Error(), "status 500") {
		t.Errorf("error should mention status code, got: %v", err)
	}
}

// =============================================================================
// CheckIOC Tests
// =============================================================================

// TestCheckIOC_IPFound verifies successful IP lookup.
func TestCheckIOC_IPFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/indicators/IPv4/") {
			t.Errorf("expected IPv4 indicator path, got %s", r.URL.Path)
		}

		resp := OTXGeneralResponse{
			Indicator: "8.8.8.8",
			Type:      "IPv4",
			PulseInfo: OTXPulseInfo{
				Count: 3,
				Pulses: []OTXPulse{
					{
						ID:          "pulse-123",
						Name:        "Suspicious IP Activity",
						Description: "Known malicious IP",
						Tags:        []string{"malware", "c2"},
						Created:     "2024-01-15T10:00:00.000000",
						Modified:    "2024-01-16T12:00:00.000000",
					},
				},
			},
			CountryCode: "US",
			ASN:         "AS15169",
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	os.Setenv("TEST_OTX_KEY", "test-api-key")
	defer os.Unsetenv("TEST_OTX_KEY")

	config := DefaultOTXConfig()
	config.APIKey = "TEST_OTX_KEY"
	config.BaseURL = server.URL

	provider, _ := NewOTXProvider(config)

	match, err := provider.CheckIOC(context.Background(), IOCTypeIP, "8.8.8.8")
	if err != nil {
		t.Fatalf("CheckIOC failed: %v", err)
	}

	if match == nil {
		t.Fatal("expected match, got nil")
	}

	if match.MatchedValue != "8.8.8.8" {
		t.Errorf("expected matched value '8.8.8.8', got %q", match.MatchedValue)
	}

	if match.Source != "otx" {
		t.Errorf("expected source 'otx', got %q", match.Source)
	}

	if match.Indicator.ThreatType != ThreatTypeMalware {
		t.Errorf("expected threat type malware, got %s", match.Indicator.ThreatType)
	}
}

// TestCheckIOC_NotFound verifies 404 response handling.
func TestCheckIOC_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	os.Setenv("TEST_OTX_KEY", "test-api-key")
	defer os.Unsetenv("TEST_OTX_KEY")

	config := DefaultOTXConfig()
	config.APIKey = "TEST_OTX_KEY"
	config.BaseURL = server.URL

	provider, _ := NewOTXProvider(config)

	match, err := provider.CheckIOC(context.Background(), IOCTypeIP, "192.168.1.1")
	if err != nil {
		t.Fatalf("CheckIOC should not error on 404: %v", err)
	}

	if match != nil {
		t.Error("expected nil match for not found")
	}
}

// TestCheckIOC_NoPulses verifies handling when indicator exists but has no pulses.
func TestCheckIOC_NoPulses(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := OTXGeneralResponse{
			Indicator: "1.1.1.1",
			Type:      "IPv4",
			PulseInfo: OTXPulseInfo{
				Count:  0,
				Pulses: []OTXPulse{},
			},
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	os.Setenv("TEST_OTX_KEY", "test-api-key")
	defer os.Unsetenv("TEST_OTX_KEY")

	config := DefaultOTXConfig()
	config.APIKey = "TEST_OTX_KEY"
	config.BaseURL = server.URL

	provider, _ := NewOTXProvider(config)

	match, err := provider.CheckIOC(context.Background(), IOCTypeIP, "1.1.1.1")
	if err != nil {
		t.Fatalf("CheckIOC failed: %v", err)
	}

	if match != nil {
		t.Error("expected nil match when no pulses")
	}
}

// TestCheckIOC_Domain verifies domain lookup.
func TestCheckIOC_Domain(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/indicators/domain/") {
			t.Errorf("expected domain indicator path, got %s", r.URL.Path)
		}

		resp := OTXGeneralResponse{
			Indicator: "malicious.com",
			Type:      "domain",
			PulseInfo: OTXPulseInfo{
				Count: 5,
				Pulses: []OTXPulse{
					{
						ID:          "pulse-456",
						Name:        "Phishing Campaign",
						Description: "Known phishing domain",
						Tags:        []string{"phishing", "credential-theft"},
						Created:     "2024-01-10T08:00:00.000000",
					},
				},
			},
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	os.Setenv("TEST_OTX_KEY", "test-api-key")
	defer os.Unsetenv("TEST_OTX_KEY")

	config := DefaultOTXConfig()
	config.APIKey = "TEST_OTX_KEY"
	config.BaseURL = server.URL

	provider, _ := NewOTXProvider(config)

	match, err := provider.CheckIOC(context.Background(), IOCTypeDomain, "malicious.com")
	if err != nil {
		t.Fatalf("CheckIOC failed: %v", err)
	}

	if match == nil {
		t.Fatal("expected match, got nil")
	}

	if match.Indicator.ThreatType != ThreatTypePhishing {
		t.Errorf("expected threat type phishing, got %s", match.Indicator.ThreatType)
	}
}

// TestCheckIOC_Hash verifies file hash lookup.
func TestCheckIOC_Hash(t *testing.T) {
	testHash := "d41d8cd98f00b204e9800998ecf8427e" // MD5

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/indicators/file/") {
			t.Errorf("expected file indicator path, got %s", r.URL.Path)
		}

		resp := OTXGeneralResponse{
			Indicator: testHash,
			Type:      "FileHash-MD5",
			PulseInfo: OTXPulseInfo{
				Count: 2,
				Pulses: []OTXPulse{
					{
						ID:          "pulse-789",
						Name:        "Ransomware Sample",
						Description: "Known ransomware hash",
						Tags:        []string{"ransomware", "lockbit"},
						Adversary:   "LockBit",
					},
				},
			},
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	os.Setenv("TEST_OTX_KEY", "test-api-key")
	defer os.Unsetenv("TEST_OTX_KEY")

	config := DefaultOTXConfig()
	config.APIKey = "TEST_OTX_KEY"
	config.BaseURL = server.URL

	provider, _ := NewOTXProvider(config)

	match, err := provider.CheckIOC(context.Background(), IOCTypeHash, testHash)
	if err != nil {
		t.Fatalf("CheckIOC failed: %v", err)
	}

	if match == nil {
		t.Fatal("expected match, got nil")
	}

	if match.Indicator.ThreatType != ThreatTypeRansomware {
		t.Errorf("expected threat type ransomware, got %s", match.Indicator.ThreatType)
	}

	if match.Indicator.Severity != "critical" {
		t.Errorf("expected severity critical for ransomware, got %s", match.Indicator.Severity)
	}
}

// TestCheckIOC_UnsupportedType verifies unsupported IOC types return nil.
func TestCheckIOC_UnsupportedType(t *testing.T) {
	os.Setenv("TEST_OTX_KEY", "test-api-key")
	defer os.Unsetenv("TEST_OTX_KEY")

	config := DefaultOTXConfig()
	config.APIKey = "TEST_OTX_KEY"

	provider, _ := NewOTXProvider(config)

	match, err := provider.CheckIOC(context.Background(), IOCTypeFile, "/some/file/path")
	if err != nil {
		t.Errorf("unsupported type should not error: %v", err)
	}

	if match != nil {
		t.Error("expected nil match for unsupported type")
	}
}

// =============================================================================
// Cache Tests
// =============================================================================

// TestCache_HitAvoidsDuplicateRequest verifies cache prevents duplicate API calls.
func TestCache_HitAvoidsDuplicateRequest(t *testing.T) {
	var requestCount int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)

		resp := OTXGeneralResponse{
			Indicator: "8.8.8.8",
			Type:      "IPv4",
			PulseInfo: OTXPulseInfo{
				Count: 1,
				Pulses: []OTXPulse{
					{ID: "pulse-1", Name: "Test", Tags: []string{"test"}},
				},
			},
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	os.Setenv("TEST_OTX_KEY", "test-api-key")
	defer os.Unsetenv("TEST_OTX_KEY")

	config := DefaultOTXConfig()
	config.APIKey = "TEST_OTX_KEY"
	config.BaseURL = server.URL
	config.CacheTTL = 1 * time.Hour

	provider, _ := NewOTXProvider(config)

	// First call - should hit API
	_, err := provider.CheckIOC(context.Background(), IOCTypeIP, "8.8.8.8")
	if err != nil {
		t.Fatalf("first CheckIOC failed: %v", err)
	}

	// Second call - should hit cache
	_, err = provider.CheckIOC(context.Background(), IOCTypeIP, "8.8.8.8")
	if err != nil {
		t.Fatalf("second CheckIOC failed: %v", err)
	}

	// Third call with same IP different case - should hit cache
	_, err = provider.CheckIOC(context.Background(), IOCTypeIP, "8.8.8.8")
	if err != nil {
		t.Fatalf("third CheckIOC failed: %v", err)
	}

	if atomic.LoadInt32(&requestCount) != 1 {
		t.Errorf("expected 1 API request (cache hit), got %d", requestCount)
	}
}

// TestCache_NegativeResultsCached verifies not-found results are cached.
func TestCache_NegativeResultsCached(t *testing.T) {
	var requestCount int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	os.Setenv("TEST_OTX_KEY", "test-api-key")
	defer os.Unsetenv("TEST_OTX_KEY")

	config := DefaultOTXConfig()
	config.APIKey = "TEST_OTX_KEY"
	config.BaseURL = server.URL
	config.CacheTTL = 1 * time.Hour

	provider, _ := NewOTXProvider(config)

	// First call - should hit API, get 404
	match1, err := provider.CheckIOC(context.Background(), IOCTypeIP, "192.168.1.1")
	if err != nil {
		t.Fatalf("first CheckIOC failed: %v", err)
	}
	if match1 != nil {
		t.Error("expected nil match for not found")
	}

	// Second call - should return cached negative result
	match2, err := provider.CheckIOC(context.Background(), IOCTypeIP, "192.168.1.1")
	if err != nil {
		t.Fatalf("second CheckIOC failed: %v", err)
	}
	if match2 != nil {
		t.Error("expected nil match from cache")
	}

	if atomic.LoadInt32(&requestCount) != 1 {
		t.Errorf("expected 1 API request (negative cached), got %d", requestCount)
	}
}

// TestCache_Expiration verifies cache entries expire correctly.
func TestCache_Expiration(t *testing.T) {
	var requestCount int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)

		resp := OTXGeneralResponse{
			Indicator: "8.8.8.8",
			Type:      "IPv4",
			PulseInfo: OTXPulseInfo{
				Count: 1,
				Pulses: []OTXPulse{
					{ID: "pulse-1", Name: "Test", Tags: []string{"test"}},
				},
			},
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	os.Setenv("TEST_OTX_KEY", "test-api-key")
	defer os.Unsetenv("TEST_OTX_KEY")

	config := DefaultOTXConfig()
	config.APIKey = "TEST_OTX_KEY"
	config.BaseURL = server.URL
	config.CacheTTL = 50 * time.Millisecond // Short TTL for testing

	provider, _ := NewOTXProvider(config)

	// First call
	_, _ = provider.CheckIOC(context.Background(), IOCTypeIP, "8.8.8.8")

	// Wait for cache to expire
	time.Sleep(100 * time.Millisecond)

	// Second call after expiration - should hit API again
	_, _ = provider.CheckIOC(context.Background(), IOCTypeIP, "8.8.8.8")

	if atomic.LoadInt32(&requestCount) != 2 {
		t.Errorf("expected 2 API requests after cache expiration, got %d", requestCount)
	}
}

// TestCache_ConcurrentAccess verifies cache is thread-safe.
func TestCache_ConcurrentAccess(t *testing.T) {
	var requestCount int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		time.Sleep(10 * time.Millisecond) // Simulate latency

		resp := OTXGeneralResponse{
			Indicator: "8.8.8.8",
			Type:      "IPv4",
			PulseInfo: OTXPulseInfo{
				Count: 1,
				Pulses: []OTXPulse{
					{ID: "pulse-1", Name: "Test", Tags: []string{"test"}},
				},
			},
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	os.Setenv("TEST_OTX_KEY", "test-api-key")
	defer os.Unsetenv("TEST_OTX_KEY")

	config := DefaultOTXConfig()
	config.APIKey = "TEST_OTX_KEY"
	config.BaseURL = server.URL
	config.CacheTTL = 1 * time.Hour

	provider, _ := NewOTXProvider(config)

	// Prime the cache with a single request
	_, _ = provider.CheckIOC(context.Background(), IOCTypeIP, "8.8.8.8")

	// Now hit cache concurrently
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = provider.CheckIOC(context.Background(), IOCTypeIP, "8.8.8.8")
		}()
	}
	wg.Wait()

	// All should have hit cache after the initial request
	if atomic.LoadInt32(&requestCount) != 1 {
		t.Errorf("expected 1 API request with cache, got %d", requestCount)
	}
}

// =============================================================================
// CheckBatch Tests
// =============================================================================

// TestCheckBatch_MultipleIOCs verifies batch checking of multiple IOCs.
func TestCheckBatch_MultipleIOCs(t *testing.T) {
	var requestCount int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)

		// Return match for specific IPs
		if strings.Contains(r.URL.Path, "8.8.8.8") {
			resp := OTXGeneralResponse{
				Indicator: "8.8.8.8",
				Type:      "IPv4",
				PulseInfo: OTXPulseInfo{
					Count:  1,
					Pulses: []OTXPulse{{ID: "p1", Tags: []string{"test"}}},
				},
			}
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(resp)
			return
		}

		if strings.Contains(r.URL.Path, "1.1.1.1") {
			resp := OTXGeneralResponse{
				Indicator: "1.1.1.1",
				Type:      "IPv4",
				PulseInfo: OTXPulseInfo{
					Count:  2,
					Pulses: []OTXPulse{{ID: "p2", Tags: []string{"malware"}}},
				},
			}
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(resp)
			return
		}

		// Other IPs not found
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	os.Setenv("TEST_OTX_KEY", "test-api-key")
	defer os.Unsetenv("TEST_OTX_KEY")

	config := DefaultOTXConfig()
	config.APIKey = "TEST_OTX_KEY"
	config.BaseURL = server.URL

	provider, _ := NewOTXProvider(config)

	values := []string{"8.8.8.8", "192.168.1.1", "1.1.1.1", "10.0.0.1"}
	matches, err := provider.CheckBatch(context.Background(), IOCTypeIP, values)
	if err != nil {
		t.Fatalf("CheckBatch failed: %v", err)
	}

	if len(matches) != 2 {
		t.Errorf("expected 2 matches, got %d", len(matches))
	}

	if atomic.LoadInt32(&requestCount) != 4 {
		t.Errorf("expected 4 API requests for 4 IOCs, got %d", requestCount)
	}
}

// TestCheckBatch_ContextCancellation verifies batch respects context cancellation.
func TestCheckBatch_ContextCancellation(t *testing.T) {
	var requestCount int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		time.Sleep(100 * time.Millisecond) // Slow response

		resp := OTXGeneralResponse{
			Indicator: "8.8.8.8",
			Type:      "IPv4",
			PulseInfo: OTXPulseInfo{Count: 0},
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	os.Setenv("TEST_OTX_KEY", "test-api-key")
	defer os.Unsetenv("TEST_OTX_KEY")

	config := DefaultOTXConfig()
	config.APIKey = "TEST_OTX_KEY"
	config.BaseURL = server.URL

	provider, _ := NewOTXProvider(config)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	values := []string{"1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4", "5.5.5.5"}
	_, err := provider.CheckBatch(ctx, IOCTypeIP, values)

	if err != context.DeadlineExceeded {
		t.Errorf("expected context.DeadlineExceeded, got: %v", err)
	}

	// Should have processed fewer than all 5
	if atomic.LoadInt32(&requestCount) >= 5 {
		t.Errorf("expected fewer than 5 requests due to cancellation, got %d", requestCount)
	}
}

// TestCheckBatch_CacheUtilization verifies batch uses cache effectively.
func TestCheckBatch_CacheUtilization(t *testing.T) {
	var requestCount int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)

		resp := OTXGeneralResponse{
			Indicator: "8.8.8.8",
			Type:      "IPv4",
			PulseInfo: OTXPulseInfo{
				Count:  1,
				Pulses: []OTXPulse{{ID: "p1", Tags: []string{"test"}}},
			},
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	os.Setenv("TEST_OTX_KEY", "test-api-key")
	defer os.Unsetenv("TEST_OTX_KEY")

	config := DefaultOTXConfig()
	config.APIKey = "TEST_OTX_KEY"
	config.BaseURL = server.URL
	config.CacheTTL = 1 * time.Hour

	provider, _ := NewOTXProvider(config)

	// First batch with some duplicate IPs
	values1 := []string{"8.8.8.8", "8.8.8.8", "8.8.8.8"}
	_, _ = provider.CheckBatch(context.Background(), IOCTypeIP, values1)

	// Due to caching within batch, should be minimal requests
	firstBatchCount := atomic.LoadInt32(&requestCount)

	// Second batch with cached value
	values2 := []string{"8.8.8.8"}
	_, _ = provider.CheckBatch(context.Background(), IOCTypeIP, values2)

	// Second batch should hit cache
	if atomic.LoadInt32(&requestCount) != firstBatchCount {
		t.Errorf("second batch should hit cache, requests went from %d to %d",
			firstBatchCount, atomic.LoadInt32(&requestCount))
	}
}

// =============================================================================
// GetIndicators Tests
// =============================================================================

// TestGetIndicators_Success verifies fetching indicators from pulses.
func TestGetIndicators_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/pulses/subscribed") {
			t.Errorf("expected pulses/subscribed path, got %s", r.URL.Path)
		}

		resp := OTXPulseListResponse{
			Count: 2,
			Results: []OTXPulse{
				{
					ID:   "pulse-1",
					Name: "Threat Report 1",
					Tags: []string{"malware"},
					Indicators: []OTXIndicator{
						{ID: "ind-1", Indicator: "8.8.8.8", Type: "IPv4"},
						{ID: "ind-2", Indicator: "malicious.com", Type: "domain"},
					},
				},
				{
					ID:   "pulse-2",
					Name: "Threat Report 2",
					Tags: []string{"c2"},
					Indicators: []OTXIndicator{
						{ID: "ind-3", Indicator: "1.2.3.4", Type: "IPv4"},
					},
				},
			},
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	os.Setenv("TEST_OTX_KEY", "test-api-key")
	defer os.Unsetenv("TEST_OTX_KEY")

	config := DefaultOTXConfig()
	config.APIKey = "TEST_OTX_KEY"
	config.BaseURL = server.URL

	provider, _ := NewOTXProvider(config)

	since := time.Now().Add(-24 * time.Hour)
	indicators, err := provider.GetIndicators(context.Background(), IOCTypeIP, since)
	if err != nil {
		t.Fatalf("GetIndicators failed: %v", err)
	}

	// Should only return IP type indicators
	if len(indicators) != 2 {
		t.Errorf("expected 2 IP indicators, got %d", len(indicators))
	}

	for _, ind := range indicators {
		if ind.Type != IOCTypeIP {
			t.Errorf("expected IP type, got %s", ind.Type)
		}
	}
}

// TestGetIndicators_FiltersByType verifies type filtering.
func TestGetIndicators_FiltersByType(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := OTXPulseListResponse{
			Count: 1,
			Results: []OTXPulse{
				{
					ID:   "pulse-1",
					Name: "Mixed Indicators",
					Tags: []string{"test"},
					Indicators: []OTXIndicator{
						{ID: "ind-1", Indicator: "8.8.8.8", Type: "IPv4"},
						{ID: "ind-2", Indicator: "malicious.com", Type: "domain"},
						{ID: "ind-3", Indicator: "http://evil.com/path", Type: "URL"},
						{ID: "ind-4", Indicator: "abc123def456", Type: "FileHash-MD5"},
					},
				},
			},
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	os.Setenv("TEST_OTX_KEY", "test-api-key")
	defer os.Unsetenv("TEST_OTX_KEY")

	config := DefaultOTXConfig()
	config.APIKey = "TEST_OTX_KEY"
	config.BaseURL = server.URL

	provider, _ := NewOTXProvider(config)
	since := time.Now().Add(-24 * time.Hour)

	// Test domain filter
	domains, err := provider.GetIndicators(context.Background(), IOCTypeDomain, since)
	if err != nil {
		t.Fatalf("GetIndicators failed: %v", err)
	}
	if len(domains) != 1 {
		t.Errorf("expected 1 domain indicator, got %d", len(domains))
	}

	// Test URL filter
	urls, err := provider.GetIndicators(context.Background(), IOCTypeURL, since)
	if err != nil {
		t.Fatalf("GetIndicators failed: %v", err)
	}
	if len(urls) != 1 {
		t.Errorf("expected 1 URL indicator, got %d", len(urls))
	}
}

// =============================================================================
// Rate Limit Tests
// =============================================================================

// TestRateLimit_UpdateFromHeaders verifies rate limit parsing from headers.
func TestRateLimit_UpdateFromHeaders(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Remaining", "45")
		w.Header().Set("X-RateLimit-Limit", "60")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"username": "test"}`))
	}))
	defer server.Close()

	os.Setenv("TEST_OTX_KEY", "test-api-key")
	defer os.Unsetenv("TEST_OTX_KEY")

	config := DefaultOTXConfig()
	config.APIKey = "TEST_OTX_KEY"
	config.BaseURL = server.URL

	provider, _ := NewOTXProvider(config)

	_ = provider.HealthCheck(context.Background())

	status := provider.RateLimit()
	if status.Remaining != 45 {
		t.Errorf("expected Remaining=45, got %d", status.Remaining)
	}
	if status.Limit != 60 {
		t.Errorf("expected Limit=60, got %d", status.Limit)
	}
}

// =============================================================================
// Threat Type Detection Tests
// =============================================================================

// TestDetermineThreatType verifies threat type detection from tags.
func TestDetermineThreatType(t *testing.T) {
	os.Setenv("TEST_OTX_KEY", "test-api-key")
	defer os.Unsetenv("TEST_OTX_KEY")

	config := DefaultOTXConfig()
	config.APIKey = "TEST_OTX_KEY"

	provider, _ := NewOTXProvider(config)

	tests := []struct {
		tags     []string
		expected ThreatType
	}{
		{[]string{"malware", "trojan"}, ThreatTypeMalware},
		{[]string{"c2", "command-and-control"}, ThreatTypeC2},
		{[]string{"phishing", "credential"}, ThreatTypePhishing},
		{[]string{"botnet", "ddos"}, ThreatTypeBotnet},
		{[]string{"scanner", "reconnaissance"}, ThreatTypeScanner},
		{[]string{"tor", "anonymity"}, ThreatTypeTOR},
		{[]string{"vpn", "privacy"}, ThreatTypeVPN},
		{[]string{"proxy", "relay"}, ThreatTypeProxy},
		{[]string{"spam", "email"}, ThreatTypeSpam},
		{[]string{"apt", "nation-state"}, ThreatTypeAPT},
		{[]string{"ransomware", "lockbit"}, ThreatTypeRansomware},
		{[]string{"unknown", "other"}, ThreatTypeUnknown},
	}

	for _, tt := range tests {
		pulse := OTXPulse{Tags: tt.tags}
		result := provider.determineThreatType(pulse)
		if result != tt.expected {
			t.Errorf("tags %v: expected %s, got %s", tt.tags, tt.expected, result)
		}
	}
}

// TestDetermineSeverity verifies severity detection.
func TestDetermineSeverity(t *testing.T) {
	os.Setenv("TEST_OTX_KEY", "test-api-key")
	defer os.Unsetenv("TEST_OTX_KEY")

	config := DefaultOTXConfig()
	config.APIKey = "TEST_OTX_KEY"

	provider, _ := NewOTXProvider(config)

	tests := []struct {
		pulse    OTXPulse
		expected string
	}{
		{OTXPulse{Tags: []string{"apt"}, Adversary: ""}, "critical"},
		{OTXPulse{Tags: []string{"ransomware"}}, "critical"},
		{OTXPulse{Tags: []string{"malware"}}, "high"},
		{OTXPulse{Tags: []string{"c2"}}, "high"},
		{OTXPulse{Tags: []string{}, Adversary: "APT29"}, "high"}, // Adversary present
		{OTXPulse{Tags: []string{"phishing"}}, "medium"},
		{OTXPulse{Tags: []string{"botnet"}}, "medium"},
		{OTXPulse{Tags: []string{"test", "unknown"}}, "low"},
	}

	for _, tt := range tests {
		result := provider.determineSeverity(tt.pulse)
		if result != tt.expected {
			t.Errorf("pulse %+v: expected %s, got %s", tt.pulse, tt.expected, result)
		}
	}
}

// TestCalculateConfidence verifies confidence scoring.
func TestCalculateConfidence(t *testing.T) {
	os.Setenv("TEST_OTX_KEY", "test-api-key")
	defer os.Unsetenv("TEST_OTX_KEY")

	config := DefaultOTXConfig()
	config.APIKey = "TEST_OTX_KEY"

	provider, _ := NewOTXProvider(config)

	tests := []struct {
		pulseCount int
		expected   float64
	}{
		{15, 0.95},
		{10, 0.95},
		{7, 0.85},
		{5, 0.85},
		{4, 0.75},
		{3, 0.75},
		{2, 0.65},
		{1, 0.65},
		{0, 0.5},
	}

	for _, tt := range tests {
		result := provider.calculateConfidence(tt.pulseCount)
		if result != tt.expected {
			t.Errorf("pulseCount %d: expected %f, got %f", tt.pulseCount, tt.expected, result)
		}
	}
}

// =============================================================================
// Hash Detection Tests
// =============================================================================

// TestDetectHashType verifies hash type detection by length.
func TestDetectHashType(t *testing.T) {
	tests := []struct {
		hash     string
		expected string
	}{
		{"d41d8cd98f00b204e9800998ecf8427e", "MD5"},               // 32 chars
		{"da39a3ee5e6b4b0d3255bfef95601890afd80709", "SHA1"},      // 40 chars
		{"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "SHA256"}, // 64 chars
		{"tooshort", ""},
		{"", ""},
	}

	for _, tt := range tests {
		result := detectHashType(tt.hash)
		if result != tt.expected {
			t.Errorf("hash %q: expected %q, got %q", tt.hash, tt.expected, result)
		}
	}
}

// =============================================================================
// IOC Type Conversion Tests
// =============================================================================

// TestOTXTypeToIOCType verifies OTX type conversion.
func TestOTXTypeToIOCType(t *testing.T) {
	tests := []struct {
		otxType  string
		expected IOCType
	}{
		{"IPv4", IOCTypeIP},
		{"IPv6", IOCTypeIP},
		{"domain", IOCTypeDomain},
		{"hostname", IOCTypeDomain},
		{"URL", IOCTypeURL},
		{"URI", IOCTypeURL},
		{"FileHash-MD5", IOCTypeHash},
		{"FileHash-SHA1", IOCTypeHash},
		{"FileHash-SHA256", IOCTypeHash},
		{"email", IOCTypeEmail},
		{"filepath", IOCTypeFile},
		{"unknown-type", ""},
	}

	for _, tt := range tests {
		result := otxTypeToIOCType(tt.otxType)
		if result != tt.expected {
			t.Errorf("otxType %q: expected %q, got %q", tt.otxType, tt.expected, result)
		}
	}
}

// =============================================================================
// Default Config Tests
// =============================================================================

// TestDefaultOTXConfig verifies sensible defaults.
func TestDefaultOTXConfig(t *testing.T) {
	config := DefaultOTXConfig()

	if config.APIKey != "OTX_API_KEY" {
		t.Errorf("expected default API key env var 'OTX_API_KEY', got %q", config.APIKey)
	}

	if config.BaseURL != otxDefaultBaseURL {
		t.Errorf("expected default base URL %q, got %q", otxDefaultBaseURL, config.BaseURL)
	}

	if config.Timeout != 30*time.Second {
		t.Errorf("expected 30s timeout, got %v", config.Timeout)
	}

	if config.CacheTTL != 1*time.Hour {
		t.Errorf("expected 1h cache TTL, got %v", config.CacheTTL)
	}

	if config.RateLimit != 60 {
		t.Errorf("expected rate limit 60, got %d", config.RateLimit)
	}

	if config.PulseLimit != 50 {
		t.Errorf("expected pulse limit 50, got %d", config.PulseLimit)
	}
}
