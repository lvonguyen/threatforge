// Package main provides the entry point for ThreatForge server.
// This is a detection engineering pipeline with threat intelligence correlation.
package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/lvonguyen/threatforge/internal/config"
	"github.com/lvonguyen/threatforge/internal/enrichment"
	"github.com/lvonguyen/threatforge/internal/repository"
	"github.com/redis/go-redis/v9"
)

// Version information (injected at build time via ldflags)
var (
	Version   = "dev"
	GitCommit = "unknown"
	BuildTime = "unknown"
)

// Package-level state: initialized once during main() startup, effectively immutable after init.
// Safe for concurrent read access from HTTP handlers.
var (
	repoManager   *repository.Manager
	redisClient   *redis.Client
	cfg           *config.Config
	tiProviders   []enrichment.Provider
	pipelineStats *Stats
)

// Stats holds pipeline statistics.
// pipelineStats is initialized at startup and fields are accessed via atomic operations. Safe for concurrent use.
type Stats struct {
	EventsReceived atomic.Int64 `json:"events_received"`
	EventsEnriched atomic.Int64 `json:"events_enriched"`
	EventsFailed   atomic.Int64 `json:"events_failed"`
	CacheHits      atomic.Int64 `json:"cache_hits"`
	CacheMisses    atomic.Int64 `json:"cache_misses"`
	ThreatMatches  atomic.Int64 `json:"threat_matches"`
}

func main() {
	// Parse command-line flags
	configPath := flag.String("config", "configs/config.yaml", "Path to config file")
	showVersion := flag.Bool("version", false, "Show version information")
	flag.Parse()

	// Show version and exit
	if *showVersion {
		fmt.Printf("ThreatForge %s (commit: %s, built: %s)\n", Version, GitCommit, BuildTime)
		os.Exit(0)
	}

	// Initialize logger
	logger := log.New(os.Stdout, "[threatforge] ", log.LstdFlags|log.Lshortfile)

	logger.Printf("Starting ThreatForge %s", Version)
	logger.Printf("Config: %s", *configPath)

	// Load configuration
	var err error
	cfg, err = config.Load(*configPath)
	if err != nil {
		logger.Printf("Warning: Failed to load config, using defaults: %v", err)
		cfg = config.DefaultConfig()
	}

	// Setup context with cancellation for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initialize pipeline stats
	pipelineStats = &Stats{}

	// Initialize Redis client
	redisClient = redis.NewClient(&redis.Options{
		Addr:     cfg.Redis.Addr,
		Password: os.Getenv(cfg.Redis.PasswordEnv),
		DB:       cfg.Redis.DB,
		PoolSize: cfg.Redis.PoolSize,
	})
	if err := redisClient.Ping(ctx).Err(); err != nil {
		logger.Printf("Warning: Redis not available: %v (cache disabled)", err)
		redisClient = nil
	} else {
		logger.Printf("Redis connected: %s", cfg.Redis.Addr)
	}

	// Initialize threat intel providers
	tiProviders = initThreatIntelProviders(cfg, logger)

	// Initialize repository manager
	repoManager, err = repository.NewManager("repositories")
	if err != nil {
		logger.Printf("Warning: Repository manager initialization failed: %v", err)
	} else {
		logger.Printf("Repository manager initialized")
	}

	// Handle shutdown signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Setup router
	r := chi.NewRouter()

	// Middleware
	r.Use(middleware.RequestID)
	r.Use(securityHeadersMiddleware)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(30 * time.Second))

	// Health endpoints
	r.Get("/health", handleHealth)
	r.Get("/ready", handleReady)

	// API routes (require API key auth)
	r.Route("/api/v1", func(r chi.Router) {
		r.Use(apiKeyAuthMiddleware)
		// Ingest endpoints
		r.Post("/ingest", handleIngest)
		r.Post("/ingest/batch", handleIngestBatch)

		// Enrichment endpoints
		r.Post("/enrich", handleEnrich)
		r.Post("/enrich/ioc", handleEnrichIOC)

		// Detection endpoints
		r.Get("/rules", handleListRules)
		r.Post("/rules/reload", handleReloadRules)

		// Stats endpoints
		r.Get("/stats", handleStats)

		// Repository endpoints
		r.Route("/repos", func(r chi.Router) {
			r.Get("/", handleListRepos)
			r.Post("/clone", handleCloneRepo)
			r.Get("/{name}", handleGetRepoStatus)
			r.Post("/{name}/sync", handleSyncRepo)
			r.Delete("/{name}", handleDeleteRepo)
		})
	})

	// HEC-compatible endpoints (for Splunk integration)
	r.Route("/services/collector", func(r chi.Router) {
		// Health endpoints — unauthenticated (must be registered before auth middleware)
		r.Get("/health", handleHECHealth)
		r.Get("/health/1.0", handleHECHealth)

		// Authenticated HEC endpoints
		r.Group(func(r chi.Router) {
			r.Use(hecAuthMiddleware)
			r.Post("/event", handleHECEvent)
			r.Post("/event/1.0", handleHECEvent)
			r.Post("/raw", handleHECRaw)
		})
	})

	// Create server
	server := &http.Server{
		Addr:              fmt.Sprintf(":%d", cfg.Server.Port),
		Handler:           r,
		ReadTimeout:       30 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	// Start server in goroutine
	go func() {
		logger.Printf("Server listening on %s", server.Addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatalf("Server error: %v", err)
		}
	}()

	// Wait for shutdown signal
	sig := <-sigChan
	logger.Printf("Received signal: %v, shutting down...", sig)
	cancel()

	// Stop threat intel provider background goroutines before shutting down the HTTP server.
	for _, p := range tiProviders {
		if stopper, ok := p.(interface{ Stop() }); ok {
			stopper.Stop()
		}
	}

	// Graceful shutdown
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Printf("Shutdown error: %v", err)
	}

	logger.Printf("Server stopped")
}

// apiKeyAuthMiddleware enforces API key authentication on protected routes.
// Fail-closed: rejects all requests when THREATFORGE_API_KEY is unset.
func apiKeyAuthMiddleware(next http.Handler) http.Handler {
	apiKey := os.Getenv("THREATFORGE_API_KEY")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if apiKey == "" {
			http.Error(w, `{"error":"api key not configured"}`, http.StatusUnauthorized)
			return
		}
		provided := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if provided == "" || subtle.ConstantTimeCompare([]byte(provided), []byte(apiKey)) != 1 {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// hecAuthMiddleware enforces HEC token authentication. Fail-closed when token is unset.
// Health endpoints are registered outside this middleware group (not matched here).
func hecAuthMiddleware(next http.Handler) http.Handler {
	expectedToken := os.Getenv("SPLUNK_HEC_TOKEN_INBOUND")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if expectedToken == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]any{"text": "HEC token not configured", "code": 4})
			return
		}
		provided := strings.TrimPrefix(r.Header.Get("Authorization"), "Splunk ")
		if provided == "" || subtle.ConstantTimeCompare([]byte(provided), []byte(expectedToken)) != 1 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]any{"text": "Invalid token", "code": 4})
			return
		}
		next.ServeHTTP(w, r)
	})
}

// validateRepoName checks a repo name for path traversal. Used by URL param handlers.
func validateRepoName(name string) bool {
	return name != "" && filepath.Base(name) == name && !strings.ContainsAny(name, `/\`)
}

// Health and readiness handlers

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "healthy", "version": Version})
}

func handleReady(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	status := map[string]any{
		"status":    "ready",
		"redis":     redisClient != nil,
		"providers": len(tiProviders),
	}

	// Check Redis connectivity
	if redisClient != nil {
		if err := redisClient.Ping(r.Context()).Err(); err != nil {
			status["redis"] = false
			status["status"] = "degraded"
		}
	}

	// Check providers health
	for _, p := range tiProviders {
		if err := p.HealthCheck(r.Context()); err != nil {
			status[p.Name()+"_status"] = "unavailable"
			status["status"] = "degraded"
		}
	}

	statusCode := http.StatusOK
	if status["status"] == "degraded" {
		statusCode = http.StatusServiceUnavailable
	}
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(status)
}

// securityHeadersMiddleware sets standard security response headers.
func securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "0")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		next.ServeHTTP(w, r)
	})
}

// Ingest handlers

func handleIngest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var req IngestRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid JSON"})
		return
	}

	eventID := pipelineStats.EventsReceived.Add(1)

	// Queue event if Redis available
	if redisClient != nil && req.Event != nil {
		eventJSON, err := json.Marshal(req.Event)
		if err != nil {
			log.Printf("failed to marshal ingest event: %v", err)
			pipelineStats.EventsFailed.Add(1)
		} else if err := redisClient.LPush(r.Context(), "threatforge:ingest:queue", eventJSON).Err(); err != nil {
			log.Printf("redis LPush failed: %v", err)
			pipelineStats.EventsFailed.Add(1)
		}
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]any{
		"status":   "received",
		"event_id": fmt.Sprintf("evt-%d", eventID),
	})
}

func handleIngestBatch(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var events []IngestRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 10<<20)).Decode(&events); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid JSON array"})
		return
	}

	const maxBatchSize = 1000
	if len(events) > maxBatchSize {
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		json.NewEncoder(w).Encode(map[string]string{
			"error": fmt.Sprintf("batch size %d exceeds maximum %d", len(events), maxBatchSize),
		})
		return
	}

	count := len(events)

	// Queue events if Redis available
	if redisClient != nil && count > 0 {
		pipe := redisClient.Pipeline()
		for _, evt := range events {
			eventJSON, err := json.Marshal(evt.Event)
			if err != nil {
				log.Printf("failed to marshal event: %v", err)
				continue
			}
			pipe.LPush(r.Context(), "threatforge:ingest:queue", eventJSON)
		}
		if _, err := pipe.Exec(r.Context()); err != nil {
			log.Printf("redis pipeline failed: %v", err)
			http.Error(w, `{"error":"internal queue failure"}`, http.StatusInternalServerError)
			return
		}
	}

	// Increment counter AFTER pipeline succeeds to avoid double-counting on retry
	pipelineStats.EventsReceived.Add(int64(count))

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]any{
		"status": "received",
		"count":  count,
	})
}

// Enrichment handlers

func handleEnrich(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var req EnrichRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid JSON"})
		return
	}

	enriched := enrichment.EnrichedAlert{
		OriginalAlert: req.Alert,
		Timestamp:     time.Now(),
	}

	// Extract IOCs from alert and check against providers
	iocs := extractIOCs(req.Alert)
	for _, ioc := range iocs {
		for _, provider := range tiProviders {
			match, err := provider.CheckIOC(r.Context(), ioc.Type, ioc.Value)
			if err != nil {
				continue
			}
			if match != nil {
				enriched.ThreatIntel = append(enriched.ThreatIntel, *match)
				pipelineStats.ThreatMatches.Add(1)
			}
		}
	}

	// Calculate risk score based on matches
	enriched.RiskScore = calculateRiskScore(enriched.ThreatIntel)
	enriched.Confidence = calculateConfidence(enriched.ThreatIntel)

	pipelineStats.EventsEnriched.Add(1)

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(enriched)
}

func handleEnrichIOC(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var req IOCRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid JSON"})
		return
	}

	if req.Type == "" || req.Value == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "type and value required"})
		return
	}

	iocType := enrichment.IOCType(req.Type)
	switch iocType {
	case enrichment.IOCTypeIP, enrichment.IOCTypeDomain, enrichment.IOCTypeURL,
		enrichment.IOCTypeHash, enrichment.IOCTypeEmail, enrichment.IOCTypeFile:
		// valid
	default:
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "unsupported IOC type"})
		return
	}
	valueHash := sha256.Sum256([]byte(req.Value))
	cacheKey := fmt.Sprintf("ioc:%s:%s", req.Type, hex.EncodeToString(valueHash[:]))

	// Check cache first
	if redisClient != nil {
		if cached, err := redisClient.Get(r.Context(), cacheKey).Result(); err == nil {
			pipelineStats.CacheHits.Add(1)
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(cached))
			return
		}
	}
	pipelineStats.CacheMisses.Add(1)

	// Query providers
	var matches []enrichment.Match
	for _, provider := range tiProviders {
		match, err := provider.CheckIOC(r.Context(), iocType, req.Value)
		if err != nil {
			continue
		}
		if match != nil {
			matches = append(matches, *match)
			pipelineStats.ThreatMatches.Add(1)
		}
	}

	result := map[string]any{
		"found":   len(matches) > 0,
		"matches": matches,
		"sources": len(tiProviders),
	}

	// Cache result
	if redisClient != nil {
		if resultJSON, err := json.Marshal(result); err != nil {
			log.Printf("failed to marshal IOC cache result: %v", err)
		} else if err := redisClient.Set(r.Context(), cacheKey, resultJSON, cfg.Redis.CacheTTL).Err(); err != nil {
			log.Printf("redis IOC cache write failed: %v", err)
		}
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(result)
}

// Detection handlers

func handleListRules(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	rules := loadRulesFromDisk()
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]any{
		"rules": rules,
		"count": len(rules),
	})
}

func handleReloadRules(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	rules := loadRulesFromDisk()
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]any{
		"status":  "reloaded",
		"count":   len(rules),
		"sources": []string{cfg.Detection.SigmaRulesPath, cfg.Detection.CustomRulesPath},
	})
}

// ruleFile describes a detection rule file on disk.
type ruleFile struct {
	Name   string `json:"name"`
	Path   string `json:"path"`
	Source string `json:"source"` // "sigma" or "custom"
}

// loadRulesFromDisk scans configured rule directories and returns metadata for
// each .yml/.yaml rule file found.
func loadRulesFromDisk() []ruleFile {
	var rules []ruleFile
	rules = append(rules, scanRuleDir(cfg.Detection.SigmaRulesPath, "sigma")...)
	rules = append(rules, scanRuleDir(cfg.Detection.CustomRulesPath, "custom")...)
	return rules
}

func scanRuleDir(dir, source string) []ruleFile {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var files []ruleFile
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".yml") && !strings.HasSuffix(name, ".yaml") {
			continue
		}
		files = append(files, ruleFile{
			Name:   name,
			Path:   dir + "/" + name,
			Source: source,
		})
	}
	return files
}

// Stats handler

func handleStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	stats := map[string]any{
		"events_received": pipelineStats.EventsReceived.Load(),
		"events_enriched": pipelineStats.EventsEnriched.Load(),
		"events_failed":   pipelineStats.EventsFailed.Load(),
		"cache_hits":      pipelineStats.CacheHits.Load(),
		"cache_misses":    pipelineStats.CacheMisses.Load(),
		"threat_matches":  pipelineStats.ThreatMatches.Load(),
		"providers":       len(tiProviders),
		"redis_connected": redisClient != nil,
	}

	// Add provider rate limit status
	providerStats := make(map[string]any)
	for _, p := range tiProviders {
		providerStats[p.Name()] = p.RateLimit()
	}
	stats["provider_status"] = providerStats

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(stats)
}

// HEC-compatible handlers

func handleHECEvent(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Parse HEC event format
	var events []map[string]any
	decoder := json.NewDecoder(io.LimitReader(r.Body, 10<<20))
	for decoder.More() {
		var evt map[string]any
		if err := decoder.Decode(&evt); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]any{"text": "Invalid data format", "code": 6})
			return
		}
		events = append(events, evt)
	}

	pipelineStats.EventsReceived.Add(int64(len(events)))

	// Queue for processing
	if redisClient != nil {
		pipe := redisClient.Pipeline()
		for _, evt := range events {
			eventJSON, err := json.Marshal(evt)
			if err != nil {
				log.Printf("failed to marshal HEC event: %v", err)
				continue
			}
			pipe.LPush(r.Context(), "threatforge:hec:queue", eventJSON)
		}
		if _, err := pipe.Exec(r.Context()); err != nil {
			log.Printf("redis HEC pipeline failed: %v", err)
			http.Error(w, `{"error":"internal queue failure"}`, http.StatusInternalServerError)
			return
		}
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]any{"text": "Success", "code": 0})
}

func handleHECRaw(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Read raw data
	body, err := io.ReadAll(io.LimitReader(r.Body, 10<<20))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{"text": "Read error", "code": 6})
		return
	}

	pipelineStats.EventsReceived.Add(1)

	// Queue raw event
	if redisClient != nil {
		if err := redisClient.LPush(r.Context(), "threatforge:hec:raw", body).Err(); err != nil {
			log.Printf("redis HEC raw push failed: %v", err)
			pipelineStats.EventsFailed.Add(1)
		}
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]any{"text": "Success", "code": 0})
}

func handleHECHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"text":"HEC is healthy","code":17}`))
}

// Repository handlers

// CloneRequest represents a request to clone a repository.
type CloneRequest struct {
	Name      string `json:"name"`
	RemoteURL string `json:"remote_url"`
	Branch    string `json:"branch,omitempty"`
	Depth     int    `json:"depth,omitempty"`
}

func handleListRepos(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if repoManager == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]string{"error": "repository manager not initialized"})
		return
	}

	repos := repoManager.List()
	response := map[string]interface{}{
		"repositories": repos,
		"count":        len(repos),
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

func handleCloneRepo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if repoManager == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]string{"error": "repository manager not initialized"})
		return
	}

	var req CloneRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid request body"})
		return
	}

	if req.Name == "" || req.RemoteURL == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "name and remote_url are required"})
		return
	}

	repo := &repository.Repository{
		Name:      req.Name,
		RemoteURL: req.RemoteURL,
		Branch:    req.Branch,
		Depth:     req.Depth,
	}

	result, err := repoManager.Clone(r.Context(), repo)
	if err != nil {
		log.Printf("clone failed for %q: %v", req.Name, err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "clone failed"})
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]any{
		"success":     result.Success,
		"commit_hash": result.CommitHash,
		"cloned_at":   result.ClonedAt,
		"duration_ms": result.Duration.Milliseconds(),
	})
}

func handleGetRepoStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if repoManager == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]string{"error": "repository manager not initialized"})
		return
	}

	name := chi.URLParam(r, "name")
	if !validateRepoName(name) {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid repository name"})
		return
	}
	status, err := repoManager.Status(r.Context(), name)
	if err != nil {
		log.Printf("repo status failed for %q: %v", name, err)
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "repository not found"})
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(status)
}

func handleSyncRepo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if repoManager == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]string{"error": "repository manager not initialized"})
		return
	}

	name := chi.URLParam(r, "name")
	if !validateRepoName(name) {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid repository name"})
		return
	}
	result, err := repoManager.Pull(r.Context(), name)
	if err != nil {
		log.Printf("sync failed for %q: %v", name, err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "sync failed"})
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]any{
		"success":     result.Success,
		"commit_hash": result.CommitHash,
		"duration_ms": result.Duration.Milliseconds(),
	})
}

func handleDeleteRepo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if repoManager == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]string{"error": "repository manager not initialized"})
		return
	}

	name := chi.URLParam(r, "name")
	if !validateRepoName(name) {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid repository name"})
		return
	}

	// Check for deleteFiles query param
	deleteFiles := r.URL.Query().Get("delete_files") == "true"

	if err := repoManager.Remove(name, deleteFiles); err != nil {
		log.Printf("repo remove failed for %q: %v", name, err)
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "repository not found"})
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "removed"})
}

// initThreatIntelProviders initializes enabled threat intel providers.
func initThreatIntelProviders(cfg *config.Config, logger *log.Logger) []enrichment.Provider {
	var providers []enrichment.Provider

	// Initialize OTX if enabled
	if cfg.ThreatIntel.OTX.Enabled {
		otxCfg := enrichment.OTXConfig{
			ProviderConfig: enrichment.ProviderConfig{
				APIKey:   cfg.ThreatIntel.OTX.APIKeyEnv,
				Timeout:  cfg.ThreatIntel.OTX.Timeout,
				CacheTTL: cfg.Redis.CacheTTL,
			},
		}
		otx, err := enrichment.NewOTXProvider(otxCfg)
		if err != nil {
			logger.Printf("Warning: OTX provider init failed: %v", err)
		} else {
			providers = append(providers, otx)
			logger.Printf("OTX provider initialized")
		}
	}

	// Initialize MISP if enabled
	if cfg.ThreatIntel.MISP.Enabled {
		mispCfg := enrichment.MISPConfig{
			ProviderConfig: enrichment.ProviderConfig{
				APIKey:   cfg.ThreatIntel.MISP.APIKeyEnv,
				BaseURL:  cfg.ThreatIntel.MISP.BaseURL,
				Timeout:  cfg.ThreatIntel.MISP.Timeout,
				CacheTTL: cfg.Redis.CacheTTL,
			},
			VerifySSL:     cfg.ThreatIntel.MISP.VerifySSL,
			PublishedOnly: cfg.ThreatIntel.MISP.PublishedOnly,
		}
		misp, err := enrichment.NewMISPProvider(mispCfg)
		if err != nil {
			logger.Printf("Warning: MISP provider init failed: %v", err)
		} else {
			providers = append(providers, misp)
			logger.Printf("MISP provider initialized")
		}
	}

	if cfg.ThreatIntel.VirusTotal.Enabled {
		vt, err := enrichment.NewVirusTotalProvider(
			cfg.ThreatIntel.VirusTotal.APIKeyEnv,
			cfg.ThreatIntel.VirusTotal.Timeout,
			cfg.ThreatIntel.VirusTotal.RateLimit,
		)
		if err != nil {
			logger.Printf("Warning: VirusTotal provider init failed: %v", err)
		} else {
			providers = append(providers, vt)
			logger.Printf("VirusTotal provider initialized")
		}
	}

	logger.Printf("Threat intel providers initialized: %d", len(providers))
	return providers
}

// IngestRequest represents a single event to ingest.
type IngestRequest struct {
	Event     map[string]any `json:"event"`
	Timestamp string         `json:"time,omitempty"`
	Host      string         `json:"host,omitempty"`
	Source    string         `json:"source,omitempty"`
}

// EnrichRequest represents an enrichment request.
type EnrichRequest struct {
	Alert enrichment.Alert `json:"alert"`
}

// IOCRequest represents an IOC lookup request.
type IOCRequest struct {
	Type  string `json:"type"` // ip, domain, url, hash
	Value string `json:"value"`
}

// IOC holds an extracted indicator of compromise.
type IOC struct {
	Type  enrichment.IOCType
	Value string
}

// extractIOCs extracts indicators of compromise from an alert.
func extractIOCs(alert enrichment.Alert) []IOC {
	var iocs []IOC

	if alert.SrcIP != "" {
		iocs = append(iocs, IOC{Type: enrichment.IOCTypeIP, Value: alert.SrcIP})
	}
	if alert.DstIP != "" {
		iocs = append(iocs, IOC{Type: enrichment.IOCTypeIP, Value: alert.DstIP})
	}
	if alert.Domain != "" {
		iocs = append(iocs, IOC{Type: enrichment.IOCTypeDomain, Value: alert.Domain})
	}
	if alert.URL != "" {
		iocs = append(iocs, IOC{Type: enrichment.IOCTypeURL, Value: alert.URL})
	}
	if alert.Hash != "" {
		iocs = append(iocs, IOC{Type: enrichment.IOCTypeHash, Value: alert.Hash})
	}

	return iocs
}

// calculateRiskScore computes a risk score (0-100) based on threat matches.
func calculateRiskScore(matches []enrichment.Match) int {
	if len(matches) == 0 {
		return 0
	}

	var totalScore float64
	for _, m := range matches {
		// Base score from severity
		switch m.Indicator.Severity {
		case "critical":
			totalScore += 40
		case "high":
			totalScore += 30
		case "medium":
			totalScore += 20
		case "low":
			totalScore += 10
		default:
			totalScore += 5
		}
		// Boost for high confidence
		totalScore += m.Indicator.Confidence * 10
	}

	score := int(totalScore / float64(len(matches)))
	if score > 100 {
		score = 100
	}
	return score
}

// calculateConfidence computes aggregate confidence (0.0-1.0) from matches.
func calculateConfidence(matches []enrichment.Match) float64 {
	if len(matches) == 0 {
		return 0.0
	}

	var total float64
	for _, m := range matches {
		total += m.Indicator.Confidence
	}
	return total / float64(len(matches))
}
