package splunk

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// =============================================================================
// Security Fix Tests
// =============================================================================

// TestValidateToken_EmptyTokenFailsClosed verifies that when no token is
// configured in the environment, requests are rejected (fail closed).
// This is a critical security fix - previously returned true (allow all).
func TestValidateToken_EmptyTokenFailsClosed(t *testing.T) {
	// Ensure token env var is not set
	os.Unsetenv("TEST_HEC_TOKEN")

	config := ReceiverConfig{
		TokenEnv: "TEST_HEC_TOKEN",
	}
	receiver := NewHECReceiver(config, nil)

	req := httptest.NewRequest(http.MethodPost, "/services/collector/event", nil)
	req.Header.Set("Authorization", "Splunk some-token")

	if receiver.validateToken(req) {
		t.Error("validateToken should return false when token env var is empty (fail closed)")
	}
}

// TestValidateToken_QueryParamRejected verifies that tokens passed via query
// parameter are rejected. This prevents token leakage in logs and browser history.
func TestValidateToken_QueryParamRejected(t *testing.T) {
	const testToken = "secret-token-123"
	os.Setenv("TEST_HEC_TOKEN", testToken)
	defer os.Unsetenv("TEST_HEC_TOKEN")

	config := ReceiverConfig{
		TokenEnv: "TEST_HEC_TOKEN",
	}
	receiver := NewHECReceiver(config, nil)

	// Try to authenticate via query parameter (should fail)
	req := httptest.NewRequest(http.MethodPost, "/services/collector/event?token="+testToken, nil)

	if receiver.validateToken(req) {
		t.Error("validateToken should reject tokens passed via query parameter")
	}
}

// TestValidateToken_HeaderAuthWorks verifies that valid tokens in the
// Authorization header are accepted.
func TestValidateToken_HeaderAuthWorks(t *testing.T) {
	const testToken = "secret-token-123"
	os.Setenv("TEST_HEC_TOKEN", testToken)
	defer os.Unsetenv("TEST_HEC_TOKEN")

	config := ReceiverConfig{
		TokenEnv: "TEST_HEC_TOKEN",
	}
	receiver := NewHECReceiver(config, nil)

	req := httptest.NewRequest(http.MethodPost, "/services/collector/event", nil)
	req.Header.Set("Authorization", "Splunk "+testToken)

	if !receiver.validateToken(req) {
		t.Error("validateToken should accept valid token in Authorization header")
	}
}

// TestValidateToken_InvalidHeaderRejected verifies that malformed Authorization
// headers are rejected.
func TestValidateToken_InvalidHeaderRejected(t *testing.T) {
	const testToken = "secret-token-123"
	os.Setenv("TEST_HEC_TOKEN", testToken)
	defer os.Unsetenv("TEST_HEC_TOKEN")

	config := ReceiverConfig{
		TokenEnv: "TEST_HEC_TOKEN",
	}
	receiver := NewHECReceiver(config, nil)

	tests := []struct {
		name   string
		header string
	}{
		{"empty header", ""},
		{"wrong prefix", "Bearer " + testToken},
		{"no prefix", testToken},
		{"wrong token", "Splunk wrong-token"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/services/collector/event", nil)
			if tt.header != "" {
				req.Header.Set("Authorization", tt.header)
			}

			if receiver.validateToken(req) {
				t.Errorf("validateToken should reject header: %q", tt.header)
			}
		})
	}
}

// TestHandleRaw_ErrorHandling verifies that handler errors in the raw endpoint
// are properly propagated and stats are updated.
func TestHandleRaw_ErrorHandling(t *testing.T) {
	const testToken = "test-token"
	os.Setenv("TEST_HEC_TOKEN", testToken)
	defer os.Unsetenv("TEST_HEC_TOKEN")

	handlerError := errors.New("processing failed")
	handlerCalled := false

	config := ReceiverConfig{
		TokenEnv:     "TEST_HEC_TOKEN",
		MaxEventSize: 1024 * 1024,
	}
	receiver := NewHECReceiver(config, func(ctx context.Context, events []HECEvent) error {
		handlerCalled = true
		return handlerError
	})

	body := []byte(`{"event": "test"}`)
	req := httptest.NewRequest(http.MethodPost, "/services/collector/raw", bytes.NewReader(body))
	req.Header.Set("Authorization", "Splunk "+testToken)

	rr := httptest.NewRecorder()
	receiver.handleRaw(rr, req)

	if !handlerCalled {
		t.Error("handler should have been called")
	}

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", rr.Code)
	}

	stats := receiver.Stats()
	if stats.EventsDropped != 1 {
		t.Errorf("expected EventsDropped=1, got %d", stats.EventsDropped)
	}
}

// TestHandleRaw_SuccessUpdatesStats verifies that successful requests update
// the receiver stats correctly.
func TestHandleRaw_SuccessUpdatesStats(t *testing.T) {
	const testToken = "test-token"
	os.Setenv("TEST_HEC_TOKEN", testToken)
	defer os.Unsetenv("TEST_HEC_TOKEN")

	config := ReceiverConfig{
		TokenEnv:     "TEST_HEC_TOKEN",
		MaxEventSize: 1024 * 1024,
	}
	receiver := NewHECReceiver(config, func(ctx context.Context, events []HECEvent) error {
		return nil // success
	})

	body := []byte(`{"event": "test"}`)
	req := httptest.NewRequest(http.MethodPost, "/services/collector/raw", bytes.NewReader(body))
	req.Header.Set("Authorization", "Splunk "+testToken)

	rr := httptest.NewRecorder()
	receiver.handleRaw(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}

	stats := receiver.Stats()
	if stats.EventsReceived != 1 {
		t.Errorf("expected EventsReceived=1, got %d", stats.EventsReceived)
	}
	if stats.BytesReceived != int64(len(body)) {
		t.Errorf("expected BytesReceived=%d, got %d", len(body), stats.BytesReceived)
	}
}

// TestParseEvents_MaxBatchSizeEnforced verifies that batches exceeding
// MaxBatchSize are rejected to prevent DoS attacks.
func TestParseEvents_MaxBatchSizeEnforced(t *testing.T) {
	config := ReceiverConfig{
		MaxBatchSize: 5, // Small limit for testing
	}
	receiver := NewHECReceiver(config, nil)

	// Create batch of 10 events (exceeds limit of 5)
	var events []string
	for i := 0; i < 10; i++ {
		events = append(events, `{"event":"test"}`)
	}
	body := []byte(strings.Join(events, "\n"))

	_, err := receiver.parseEvents(body)
	if err == nil {
		t.Error("parseEvents should return error when batch exceeds MaxBatchSize")
	}

	if !strings.Contains(err.Error(), "batch exceeds maximum size") {
		t.Errorf("error should mention batch size limit, got: %v", err)
	}
}

// TestParseEvents_WithinLimitSucceeds verifies that batches within MaxBatchSize
// are processed successfully.
func TestParseEvents_WithinLimitSucceeds(t *testing.T) {
	config := ReceiverConfig{
		MaxBatchSize: 10,
	}
	receiver := NewHECReceiver(config, nil)

	// Create batch of 5 events (within limit of 10)
	var events []string
	for i := 0; i < 5; i++ {
		events = append(events, `{"event":"test"}`)
	}
	body := []byte(strings.Join(events, "\n"))

	parsed, err := receiver.parseEvents(body)
	if err != nil {
		t.Errorf("parseEvents should succeed for batch within limit: %v", err)
	}

	if len(parsed) != 5 {
		t.Errorf("expected 5 events, got %d", len(parsed))
	}
}

// TestParseEvents_SingleEvent verifies that single JSON events bypass batch
// parsing and succeed regardless of MaxBatchSize.
func TestParseEvents_SingleEvent(t *testing.T) {
	config := ReceiverConfig{
		MaxBatchSize: 1, // Even with limit of 1, single event should work
	}
	receiver := NewHECReceiver(config, nil)

	body := []byte(`{"event":"single test event","host":"testhost"}`)

	parsed, err := receiver.parseEvents(body)
	if err != nil {
		t.Errorf("parseEvents should succeed for single event: %v", err)
	}

	if len(parsed) != 1 {
		t.Errorf("expected 1 event, got %d", len(parsed))
	}

	if parsed[0].Host != "testhost" {
		t.Errorf("expected host=testhost, got %s", parsed[0].Host)
	}
}

// TestHandleEvent_AuthFailure verifies that unauthenticated requests to the
// event endpoint are rejected with 403.
func TestHandleEvent_AuthFailure(t *testing.T) {
	const testToken = "test-token"
	os.Setenv("TEST_HEC_TOKEN", testToken)
	defer os.Unsetenv("TEST_HEC_TOKEN")

	config := ReceiverConfig{
		TokenEnv:     "TEST_HEC_TOKEN",
		MaxEventSize: 1024 * 1024,
		MaxBatchSize: 1000,
	}
	receiver := NewHECReceiver(config, nil)

	body := []byte(`{"event":"test"}`)
	req := httptest.NewRequest(http.MethodPost, "/services/collector/event", bytes.NewReader(body))
	// No Authorization header

	rr := httptest.NewRecorder()
	receiver.handleEvent(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected status 403, got %d", rr.Code)
	}

	var response map[string]any
	json.Unmarshal(rr.Body.Bytes(), &response)
	if response["code"] != float64(4) {
		t.Errorf("expected HEC error code 4 (invalid token), got %v", response["code"])
	}
}

// TestHandleEvent_Success verifies successful event ingestion.
func TestHandleEvent_Success(t *testing.T) {
	const testToken = "test-token"
	os.Setenv("TEST_HEC_TOKEN", testToken)
	defer os.Unsetenv("TEST_HEC_TOKEN")

	var receivedEvents []HECEvent

	config := ReceiverConfig{
		TokenEnv:     "TEST_HEC_TOKEN",
		MaxEventSize: 1024 * 1024,
		MaxBatchSize: 1000,
	}
	receiver := NewHECReceiver(config, func(ctx context.Context, events []HECEvent) error {
		receivedEvents = events
		return nil
	})

	body := []byte(`{"event":"test data","host":"myhost"}`)
	req := httptest.NewRequest(http.MethodPost, "/services/collector/event", bytes.NewReader(body))
	req.Header.Set("Authorization", "Splunk "+testToken)

	rr := httptest.NewRecorder()
	receiver.handleEvent(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}

	if len(receivedEvents) != 1 {
		t.Fatalf("expected 1 event, got %d", len(receivedEvents))
	}

	if receivedEvents[0].Host != "myhost" {
		t.Errorf("expected host=myhost, got %s", receivedEvents[0].Host)
	}
}

// =============================================================================
// Stats Accuracy Tests
// =============================================================================

// TestReceiverStats_Concurrent verifies that stats are updated correctly under
// concurrent access.
func TestReceiverStats_Concurrent(t *testing.T) {
	const testToken = "test-token"
	os.Setenv("TEST_HEC_TOKEN", testToken)
	defer os.Unsetenv("TEST_HEC_TOKEN")

	config := ReceiverConfig{
		TokenEnv:     "TEST_HEC_TOKEN",
		MaxEventSize: 1024 * 1024,
		MaxBatchSize: 1000,
	}
	receiver := NewHECReceiver(config, func(ctx context.Context, events []HECEvent) error {
		return nil
	})

	// Send 100 requests concurrently
	done := make(chan bool, 100)
	for i := 0; i < 100; i++ {
		go func() {
			body := []byte(`{"event":"test"}`)
			req := httptest.NewRequest(http.MethodPost, "/services/collector/event", bytes.NewReader(body))
			req.Header.Set("Authorization", "Splunk "+testToken)
			rr := httptest.NewRecorder()
			receiver.handleEvent(rr, req)
			done <- true
		}()
	}

	// Wait for all requests
	for i := 0; i < 100; i++ {
		<-done
	}

	stats := receiver.Stats()
	if stats.EventsReceived != 100 {
		t.Errorf("expected EventsReceived=100, got %d", stats.EventsReceived)
	}
}

// =============================================================================
// Rate Limiting Tests
// =============================================================================

// TestRateLimiting_RejectsExcessRequests verifies that requests exceeding the
// rate limit are rejected with 429 Too Many Requests.
func TestRateLimiting_RejectsExcessRequests(t *testing.T) {
	const testToken = "test-token"
	os.Setenv("TEST_HEC_TOKEN", testToken)
	defer os.Unsetenv("TEST_HEC_TOKEN")

	config := ReceiverConfig{
		TokenEnv:     "TEST_HEC_TOKEN",
		MaxEventSize: 1024 * 1024,
		MaxBatchSize: 1000,
		RateLimit:    1,  // 1 request per second
		RateBurst:    1,  // No burst allowed
	}
	receiver := NewHECReceiver(config, func(ctx context.Context, events []HECEvent) error {
		return nil
	})

	// First request should succeed
	body := []byte(`{"event":"test"}`)
	req1 := httptest.NewRequest(http.MethodPost, "/services/collector/event", bytes.NewReader(body))
	req1.Header.Set("Authorization", "Splunk "+testToken)
	rr1 := httptest.NewRecorder()
	receiver.handleEvent(rr1, req1)

	if rr1.Code != http.StatusOK {
		t.Errorf("first request should succeed, got status %d", rr1.Code)
	}

	// Second request immediately after should be rate limited
	req2 := httptest.NewRequest(http.MethodPost, "/services/collector/event", bytes.NewReader(body))
	req2.Header.Set("Authorization", "Splunk "+testToken)
	rr2 := httptest.NewRecorder()
	receiver.handleEvent(rr2, req2)

	if rr2.Code != http.StatusTooManyRequests {
		t.Errorf("second request should be rate limited, got status %d", rr2.Code)
	}

	// Verify stats
	stats := receiver.Stats()
	if stats.RateLimited != 1 {
		t.Errorf("expected RateLimited=1, got %d", stats.RateLimited)
	}
}

// TestRateLimiting_BurstAllowed verifies that burst requests within the burst
// limit are allowed.
func TestRateLimiting_BurstAllowed(t *testing.T) {
	const testToken = "test-token"
	os.Setenv("TEST_HEC_TOKEN", testToken)
	defer os.Unsetenv("TEST_HEC_TOKEN")

	config := ReceiverConfig{
		TokenEnv:     "TEST_HEC_TOKEN",
		MaxEventSize: 1024 * 1024,
		MaxBatchSize: 1000,
		RateLimit:    1,   // 1 request per second sustained
		RateBurst:    10,  // Allow burst of 10
	}
	receiver := NewHECReceiver(config, func(ctx context.Context, events []HECEvent) error {
		return nil
	})

	body := []byte(`{"event":"test"}`)
	successCount := 0

	// Send 10 requests rapidly (should all succeed due to burst)
	for i := 0; i < 10; i++ {
		req := httptest.NewRequest(http.MethodPost, "/services/collector/event", bytes.NewReader(body))
		req.Header.Set("Authorization", "Splunk "+testToken)
		rr := httptest.NewRecorder()
		receiver.handleEvent(rr, req)

		if rr.Code == http.StatusOK {
			successCount++
		}
	}

	if successCount != 10 {
		t.Errorf("expected 10 requests to succeed with burst=10, got %d", successCount)
	}

	// 11th request should be rate limited
	req := httptest.NewRequest(http.MethodPost, "/services/collector/event", bytes.NewReader(body))
	req.Header.Set("Authorization", "Splunk "+testToken)
	rr := httptest.NewRecorder()
	receiver.handleEvent(rr, req)

	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("11th request should be rate limited, got status %d", rr.Code)
	}
}

// TestRateLimiting_DisabledWhenZero verifies that rate limiting is disabled
// when RateLimit is set to 0.
func TestRateLimiting_DisabledWhenZero(t *testing.T) {
	const testToken = "test-token"
	os.Setenv("TEST_HEC_TOKEN", testToken)
	defer os.Unsetenv("TEST_HEC_TOKEN")

	config := ReceiverConfig{
		TokenEnv:     "TEST_HEC_TOKEN",
		MaxEventSize: 1024 * 1024,
		MaxBatchSize: 1000,
		RateLimit:    0,  // Disabled
		RateBurst:    0,
	}
	receiver := NewHECReceiver(config, func(ctx context.Context, events []HECEvent) error {
		return nil
	})

	body := []byte(`{"event":"test"}`)

	// Send 100 requests rapidly - all should succeed
	for i := 0; i < 100; i++ {
		req := httptest.NewRequest(http.MethodPost, "/services/collector/event", bytes.NewReader(body))
		req.Header.Set("Authorization", "Splunk "+testToken)
		rr := httptest.NewRecorder()
		receiver.handleEvent(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("request %d should succeed when rate limiting disabled, got %d", i, rr.Code)
		}
	}

	stats := receiver.Stats()
	if stats.RateLimited != 0 {
		t.Errorf("expected RateLimited=0 when disabled, got %d", stats.RateLimited)
	}
}

// TestRateLimiting_RawEndpoint verifies that rate limiting also applies to
// the raw endpoint.
func TestRateLimiting_RawEndpoint(t *testing.T) {
	const testToken = "test-token"
	os.Setenv("TEST_HEC_TOKEN", testToken)
	defer os.Unsetenv("TEST_HEC_TOKEN")

	config := ReceiverConfig{
		TokenEnv:     "TEST_HEC_TOKEN",
		MaxEventSize: 1024 * 1024,
		MaxBatchSize: 1000,
		RateLimit:    1,
		RateBurst:    1,
	}
	receiver := NewHECReceiver(config, func(ctx context.Context, events []HECEvent) error {
		return nil
	})

	body := []byte(`raw event data`)

	// First request succeeds
	req1 := httptest.NewRequest(http.MethodPost, "/services/collector/raw", bytes.NewReader(body))
	req1.Header.Set("Authorization", "Splunk "+testToken)
	rr1 := httptest.NewRecorder()
	receiver.handleRaw(rr1, req1)

	if rr1.Code != http.StatusOK {
		t.Errorf("first raw request should succeed, got %d", rr1.Code)
	}

	// Second request rate limited
	req2 := httptest.NewRequest(http.MethodPost, "/services/collector/raw", bytes.NewReader(body))
	req2.Header.Set("Authorization", "Splunk "+testToken)
	rr2 := httptest.NewRecorder()
	receiver.handleRaw(rr2, req2)

	if rr2.Code != http.StatusTooManyRequests {
		t.Errorf("second raw request should be rate limited, got %d", rr2.Code)
	}
}

// TestRateLimiting_HealthEndpointExempt verifies that the health endpoint
// is not rate limited (always available for monitoring).
func TestRateLimiting_HealthEndpointExempt(t *testing.T) {
	config := ReceiverConfig{
		RateLimit: 1,
		RateBurst: 1,
	}
	receiver := NewHECReceiver(config, nil)

	// Send many health check requests - all should succeed
	for i := 0; i < 100; i++ {
		req := httptest.NewRequest(http.MethodGet, "/services/collector/health", nil)
		rr := httptest.NewRecorder()
		receiver.handleHealth(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("health request %d should always succeed, got %d", i, rr.Code)
		}
	}
}

// TestRateLimiting_ResponseFormat verifies that rate limit responses follow
// the HEC error format.
func TestRateLimiting_ResponseFormat(t *testing.T) {
	const testToken = "test-token"
	os.Setenv("TEST_HEC_TOKEN", testToken)
	defer os.Unsetenv("TEST_HEC_TOKEN")

	config := ReceiverConfig{
		TokenEnv:     "TEST_HEC_TOKEN",
		MaxEventSize: 1024 * 1024,
		RateLimit:    1,
		RateBurst:    0, // Immediately rate limit
	}
	receiver := NewHECReceiver(config, nil)

	body := []byte(`{"event":"test"}`)
	req := httptest.NewRequest(http.MethodPost, "/services/collector/event", bytes.NewReader(body))
	req.Header.Set("Authorization", "Splunk "+testToken)
	rr := httptest.NewRecorder()
	receiver.handleEvent(rr, req)

	// Should be rate limited immediately with burst=0
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", rr.Code)
	}

	var response map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatalf("response should be valid JSON: %v", err)
	}

	if response["code"] != float64(9) {
		t.Errorf("expected HEC code 9 for rate limit, got %v", response["code"])
	}

	if response["text"] != "Rate limit exceeded" {
		t.Errorf("expected rate limit message, got %v", response["text"])
	}
}
