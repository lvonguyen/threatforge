// Package splunk provides bidirectional Splunk HEC integration.
// Receives events via HEC endpoint and sends enriched alerts back to Splunk.
package splunk

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/lvonguyen/threatforge/internal/enrichment"
	"golang.org/x/time/rate"
)

// HECReceiver receives events via Splunk HEC protocol.
type HECReceiver struct {
	config   ReceiverConfig
	handler  EventHandler
	server   *http.Server
	limiter  *rate.Limiter
	mu       sync.RWMutex
	stats    ReceiverStats
}

// ReceiverConfig holds HEC receiver configuration.
type ReceiverConfig struct {
	Port            int           `yaml:"port"`
	TokenEnv        string        `yaml:"token_env"`
	TLSCertFile     string        `yaml:"tls_cert_file"`
	TLSKeyFile      string        `yaml:"tls_key_file"`
	MaxBatchSize    int           `yaml:"max_batch_size"`
	MaxEventSize    int           `yaml:"max_event_size"`
	AckEnabled      bool          `yaml:"ack_enabled"`
	ReadTimeout     time.Duration `yaml:"read_timeout"`
	WriteTimeout    time.Duration `yaml:"write_timeout"`
	RateLimit       float64       `yaml:"rate_limit"`  // Requests per second (0 = disabled)
	RateBurst       int           `yaml:"rate_burst"`  // Max burst size
}

// DefaultReceiverConfig returns sensible defaults.
func DefaultReceiverConfig() ReceiverConfig {
	return ReceiverConfig{
		Port:         8088,
		TokenEnv:     "SPLUNK_HEC_TOKEN_INBOUND",
		MaxBatchSize: 1000,
		MaxEventSize: 1024 * 1024, // 1MB
		AckEnabled:   false,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		RateLimit:    100, // 100 requests per second
		RateBurst:    200, // Allow burst of 200 requests
	}
}

// ReceiverStats tracks receiver metrics.
type ReceiverStats struct {
	EventsReceived int64
	EventsDropped  int64
	BytesReceived  int64
	RateLimited    int64 // Requests rejected due to rate limiting
	LastEventAt    time.Time
}

// EventHandler processes received events.
type EventHandler func(ctx context.Context, events []HECEvent) error

// HECEvent represents a Splunk HEC event.
type HECEvent struct {
	Time       float64        `json:"time,omitempty"`
	Host       string         `json:"host,omitempty"`
	Source     string         `json:"source,omitempty"`
	SourceType string         `json:"sourcetype,omitempty"`
	Index      string         `json:"index,omitempty"`
	Event      any            `json:"event"`
	Fields     map[string]any `json:"fields,omitempty"`
}

// NewHECReceiver creates a new HEC receiver.
func NewHECReceiver(config ReceiverConfig, handler EventHandler) *HECReceiver {
	var limiter *rate.Limiter
	if config.RateLimit > 0 {
		limiter = rate.NewLimiter(rate.Limit(config.RateLimit), config.RateBurst)
	}

	return &HECReceiver{
		config:  config,
		handler: handler,
		limiter: limiter,
	}
}

// Start begins listening for HEC events.
func (r *HECReceiver) Start(ctx context.Context) error {
	mux := http.NewServeMux()

	// HEC endpoints
	mux.HandleFunc("/services/collector/event", r.handleEvent)
	mux.HandleFunc("/services/collector/event/1.0", r.handleEvent)
	mux.HandleFunc("/services/collector/raw", r.handleRaw)
	mux.HandleFunc("/services/collector/health", r.handleHealth)
	mux.HandleFunc("/services/collector/health/1.0", r.handleHealth)

	r.server = &http.Server{
		Addr:         fmt.Sprintf(":%d", r.config.Port),
		Handler:      mux,
		ReadTimeout:  r.config.ReadTimeout,
		WriteTimeout: r.config.WriteTimeout,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		r.server.Shutdown(shutdownCtx)
	}()

	if r.config.TLSCertFile != "" && r.config.TLSKeyFile != "" {
		return r.server.ListenAndServeTLS(r.config.TLSCertFile, r.config.TLSKeyFile)
	}
	return r.server.ListenAndServe()
}

// Stats returns current receiver statistics.
func (r *HECReceiver) Stats() ReceiverStats {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.stats
}

// checkRateLimit returns true if the request should be rejected due to rate limiting.
func (r *HECReceiver) checkRateLimit() bool {
	if r.limiter == nil {
		return false // Rate limiting disabled
	}
	if !r.limiter.Allow() {
		r.mu.Lock()
		r.stats.RateLimited++
		r.mu.Unlock()
		return true
	}
	return false
}

// handleEvent processes HEC event endpoint requests.
func (r *HECReceiver) handleEvent(w http.ResponseWriter, req *http.Request) {
	// Validate token first (before rate limit to prevent unauthenticated DoS)
	if !r.validateToken(req) {
		http.Error(w, `{"text":"Invalid token","code":4}`, http.StatusForbidden)
		return
	}

	// Check rate limit (only for authenticated requests)
	if r.checkRateLimit() {
		w.Header().Set("Retry-After", "1")
		http.Error(w, `{"text":"Rate limit exceeded","code":9}`, http.StatusTooManyRequests)
		return
	}

	// Read body
	body, err := io.ReadAll(io.LimitReader(req.Body, int64(r.config.MaxEventSize)))
	if err != nil {
		http.Error(w, `{"text":"Error reading body","code":6}`, http.StatusBadRequest)
		return
	}

	// Parse events (may be multiple JSON objects or newline-delimited)
	events, err := r.parseEvents(body)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"text":"%s","code":6}`, err.Error()), http.StatusBadRequest)
		return
	}

	// Update stats
	r.mu.Lock()
	r.stats.EventsReceived += int64(len(events))
	r.stats.BytesReceived += int64(len(body))
	r.stats.LastEventAt = time.Now()
	r.mu.Unlock()

	// Process events
	if r.handler != nil {
		if err := r.handler(req.Context(), events); err != nil {
			r.mu.Lock()
			r.stats.EventsDropped += int64(len(events))
			r.mu.Unlock()
			http.Error(w, `{"text":"Error processing events","code":8}`, http.StatusInternalServerError)
			return
		}
	}

	// Success response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"text":"Success","code":0}`))
}

// handleRaw processes raw HEC endpoint requests.
func (r *HECReceiver) handleRaw(w http.ResponseWriter, req *http.Request) {
	// Validate token first (before rate limit to prevent unauthenticated DoS)
	if !r.validateToken(req) {
		http.Error(w, `{"text":"Invalid token","code":4}`, http.StatusForbidden)
		return
	}

	// Check rate limit (only for authenticated requests)
	if r.checkRateLimit() {
		w.Header().Set("Retry-After", "1")
		http.Error(w, `{"text":"Rate limit exceeded","code":9}`, http.StatusTooManyRequests)
		return
	}

	body, err := io.ReadAll(io.LimitReader(req.Body, int64(r.config.MaxEventSize)))
	if err != nil {
		http.Error(w, `{"text":"Error reading body","code":6}`, http.StatusBadRequest)
		return
	}

	// Wrap raw data as event
	events := []HECEvent{{
		Event:      string(body),
		SourceType: req.URL.Query().Get("sourcetype"),
		Source:     req.URL.Query().Get("source"),
		Host:       req.URL.Query().Get("host"),
		Index:      req.URL.Query().Get("index"),
	}}

	// Update stats
	r.mu.Lock()
	r.stats.EventsReceived += int64(len(events))
	r.stats.BytesReceived += int64(len(body))
	r.stats.LastEventAt = time.Now()
	r.mu.Unlock()

	// Process events with proper error handling
	if r.handler != nil {
		if err := r.handler(req.Context(), events); err != nil {
			r.mu.Lock()
			r.stats.EventsDropped += int64(len(events))
			r.mu.Unlock()
			http.Error(w, `{"text":"Error processing events","code":8}`, http.StatusInternalServerError)
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"text":"Success","code":0}`))
}

// handleHealth handles health check requests.
func (r *HECReceiver) handleHealth(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"text":"HEC is healthy","code":17}`))
}

// validateToken checks the HEC token.
func (r *HECReceiver) validateToken(req *http.Request) bool {
	expectedToken := os.Getenv(r.config.TokenEnv)
	if expectedToken == "" {
		return false // Fail closed: reject requests when token not configured
	}

	// Only accept Authorization header (not query params to avoid log exposure)
	auth := req.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Splunk ") {
		return false
	}

	return strings.TrimPrefix(auth, "Splunk ") == expectedToken
}

// parseEvents parses HEC event body (JSON or newline-delimited).
func (r *HECReceiver) parseEvents(body []byte) ([]HECEvent, error) {
	var events []HECEvent

	// Try single JSON object first
	var single HECEvent
	if err := json.Unmarshal(body, &single); err == nil {
		return []HECEvent{single}, nil
	}

	// Try newline-delimited JSON with batch size limit
	decoder := json.NewDecoder(bytes.NewReader(body))
	for decoder.More() {
		// Enforce MaxBatchSize to prevent DoS
		if len(events) >= r.config.MaxBatchSize {
			return nil, fmt.Errorf("batch exceeds maximum size of %d events", r.config.MaxBatchSize)
		}

		var event HECEvent
		if err := decoder.Decode(&event); err != nil {
			return nil, fmt.Errorf("failed to parse event: %w", err)
		}
		events = append(events, event)
	}

	if len(events) == 0 {
		return nil, fmt.Errorf("no valid events found")
	}

	return events, nil
}

// ===========================================================================
// HEC Sender - Sends enriched alerts back to Splunk
// ===========================================================================

// HECSender sends events to Splunk via HEC.
type HECSender struct {
	config     SenderConfig
	httpClient *http.Client
	mu         sync.RWMutex
	stats      SenderStats
}

// SenderConfig holds HEC sender configuration.
type SenderConfig struct {
	HECURL       string        `yaml:"hec_url"`
	TokenEnv     string        `yaml:"token_env"`
	Index        string        `yaml:"index"`
	SourceType   string        `yaml:"sourcetype"`
	Source       string        `yaml:"source"`
	BatchSize    int           `yaml:"batch_size"`
	BatchTimeout time.Duration `yaml:"batch_timeout"`
	Timeout      time.Duration `yaml:"timeout"`
	RetryCount   int           `yaml:"retry_count"`
	VerifySSL    bool          `yaml:"verify_ssl"`
}

// DefaultSenderConfig returns sensible defaults.
func DefaultSenderConfig() SenderConfig {
	return SenderConfig{
		Index:        "threatforge_enriched",
		SourceType:   "threatforge:alert",
		Source:       "threatforge",
		BatchSize:    100,
		BatchTimeout: 5 * time.Second,
		Timeout:      30 * time.Second,
		RetryCount:   3,
		VerifySSL:    true,
	}
}

// SenderStats tracks sender metrics.
type SenderStats struct {
	EventsSent   int64
	EventsFailed int64
	BytesSent    int64
	LastSendAt   time.Time
}

// NewHECSender creates a new HEC sender.
func NewHECSender(config SenderConfig) (*HECSender, error) {
	token := os.Getenv(config.TokenEnv)
	if token == "" {
		return nil, fmt.Errorf("HEC token not found in env var: %s", config.TokenEnv)
	}

	if config.HECURL == "" {
		return nil, fmt.Errorf("HEC URL is required")
	}

	return &HECSender{
		config: config,
		httpClient: &http.Client{
			Timeout: config.Timeout,
		},
	}, nil
}

// Send sends a single enriched alert to Splunk.
func (s *HECSender) Send(ctx context.Context, alert *enrichment.EnrichedAlert) error {
	return s.SendBatch(ctx, []*enrichment.EnrichedAlert{alert})
}

// SendBatch sends multiple enriched alerts to Splunk.
func (s *HECSender) SendBatch(ctx context.Context, alerts []*enrichment.EnrichedAlert) error {
	if len(alerts) == 0 {
		return nil
	}

	// Build HEC events
	var events []HECEvent
	for _, alert := range alerts {
		events = append(events, HECEvent{
			Time:       float64(alert.Timestamp.Unix()),
			Host:       alert.OriginalAlert.Host,
			Source:     s.config.Source,
			SourceType: s.config.SourceType,
			Index:      s.config.Index,
			Event:      alert,
			Fields: map[string]any{
				"risk_score":    alert.RiskScore,
				"confidence":    alert.Confidence,
				"intel_sources": len(alert.ThreatIntel),
			},
		})
	}

	// Serialize as newline-delimited JSON
	var buf bytes.Buffer
	var marshalErrors int
	for _, event := range events {
		data, err := json.Marshal(event)
		if err != nil {
			marshalErrors++
			continue
		}
		buf.Write(data)
		buf.WriteByte('\n')
	}

	// Track marshal failures in stats
	if marshalErrors > 0 {
		s.mu.Lock()
		s.stats.EventsFailed += int64(marshalErrors)
		s.mu.Unlock()
	}

	// If all events failed to marshal, return error
	if buf.Len() == 0 {
		return fmt.Errorf("failed to marshal all %d events", len(alerts))
	}

	// Send to Splunk
	return s.sendWithRetry(ctx, buf.Bytes(), len(events)-marshalErrors)
}

// sendWithRetry sends data with retries.
func (s *HECSender) sendWithRetry(ctx context.Context, data []byte, eventCount int) error {
	var lastErr error

	for attempt := 0; attempt <= s.config.RetryCount; attempt++ {
		if attempt > 0 {
			// Exponential backoff
			time.Sleep(time.Duration(attempt*attempt) * time.Second)
		}

		err := s.send(ctx, data, eventCount)
		if err == nil {
			return nil
		}
		lastErr = err
	}

	s.mu.Lock()
	s.stats.EventsFailed += int64(eventCount) // Count actual events, not batches
	s.mu.Unlock()

	return fmt.Errorf("failed after %d retries: %w", s.config.RetryCount, lastErr)
}

// send performs the actual HTTP request.
func (s *HECSender) send(ctx context.Context, data []byte, eventCount int) error {
	url := strings.TrimSuffix(s.config.HECURL, "/") + "/services/collector/event"

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(data))
	if err != nil {
		return err
	}

	token := os.Getenv(s.config.TokenEnv)
	req.Header.Set("Authorization", "Splunk "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("HEC request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("HEC returned %d: %s", resp.StatusCode, string(body))
	}

	// Update stats with actual event count
	s.mu.Lock()
	s.stats.EventsSent += int64(eventCount)
	s.stats.BytesSent += int64(len(data))
	s.stats.LastSendAt = time.Now()
	s.mu.Unlock()

	return nil
}

// Stats returns current sender statistics.
func (s *HECSender) Stats() SenderStats {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.stats
}

// HealthCheck verifies connectivity to Splunk HEC.
func (s *HECSender) HealthCheck(ctx context.Context) error {
	url := strings.TrimSuffix(s.config.HECURL, "/") + "/services/collector/health"

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("Splunk HEC health check failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Splunk HEC returned status %d", resp.StatusCode)
	}

	return nil
}
