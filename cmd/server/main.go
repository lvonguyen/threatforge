// Package main provides the entry point for ThreatForge server.
// This is a detection engineering pipeline with threat intelligence correlation.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/lvonguyen/threatforge/internal/repository"
)

// Version information (injected at build time via ldflags)
var (
	Version   = "dev"
	GitCommit = "unknown"
	BuildTime = "unknown"
)

// Global repository manager
var repoManager *repository.Manager

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

	// TODO: Load configuration
	// cfg, err := config.Load(*configPath)

	// Initialize repository manager
	var err error
	repoManager, err = repository.NewManager("repositories")
	if err != nil {
		logger.Printf("Warning: Repository manager initialization failed: %v", err)
	} else {
		logger.Printf("Repository manager initialized")
	}

	// Setup context with cancellation for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle shutdown signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Setup router
	r := chi.NewRouter()

	// Middleware
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(30 * time.Second))

	// Health endpoints
	r.Get("/health", handleHealth)
	r.Get("/ready", handleReady)

	// API routes
	r.Route("/api/v1", func(r chi.Router) {
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
		r.Post("/event", handleHECEvent)
		r.Post("/event/1.0", handleHECEvent)
		r.Post("/raw", handleHECRaw)
		r.Get("/health", handleHECHealth)
		r.Get("/health/1.0", handleHECHealth)
	})

	// Create server
	server := &http.Server{
		Addr:         ":8080",
		Handler:      r,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
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

	// Graceful shutdown
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Printf("Shutdown error: %v", err)
	}

	logger.Printf("Server stopped")
	_ = ctx // silence unused variable warning
}

// Health and readiness handlers

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"healthy","version":"` + Version + `"}`))
}

func handleReady(w http.ResponseWriter, r *http.Request) {
	// TODO: Check dependencies (Redis, threat intel providers)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ready"}`))
}

// Ingest handlers

func handleIngest(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement single event ingestion
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"received"}`))
}

func handleIngestBatch(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement batch event ingestion
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"received","count":0}`))
}

// Enrichment handlers

func handleEnrich(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement alert enrichment
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"enriched"}`))
}

func handleEnrichIOC(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement IOC lookup
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"found":false}`))
}

// Detection handlers

func handleListRules(w http.ResponseWriter, r *http.Request) {
	// TODO: List loaded detection rules
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"rules":[],"count":0}`))
}

func handleReloadRules(w http.ResponseWriter, r *http.Request) {
	// TODO: Reload detection rules from disk
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"reloaded"}`))
}

// Stats handler

func handleStats(w http.ResponseWriter, r *http.Request) {
	// TODO: Return pipeline statistics
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"events_received":0,"events_enriched":0,"cache_hits":0}`))
}

// HEC-compatible handlers

func handleHECEvent(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement HEC event endpoint
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"text":"Success","code":0}`))
}

func handleHECRaw(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement HEC raw endpoint
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"text":"Success","code":0}`))
}

func handleHECHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"text":"HEC is healthy","code":17}`))
}

// Repository handlers

// CloneRequest represents a request to clone a repository.
type CloneRequest struct {
	Name       string `json:"name"`
	RemoteURL  string `json:"remote_url"`
	Branch     string `json:"branch,omitempty"`
	Depth      int    `json:"depth,omitempty"`
	SSHKeyPath string `json:"ssh_key_path,omitempty"`
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
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
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
		Name:       req.Name,
		RemoteURL:  req.RemoteURL,
		Branch:     req.Branch,
		Depth:      req.Depth,
		SSHKeyPath: req.SSHKeyPath,
	}

	result, err := repoManager.Clone(r.Context(), repo)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":  err.Error(),
			"result": result,
		})
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(result)
}

func handleGetRepoStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if repoManager == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]string{"error": "repository manager not initialized"})
		return
	}

	name := chi.URLParam(r, "name")
	status, err := repoManager.Status(r.Context(), name)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
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
	result, err := repoManager.Pull(r.Context(), name)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":  err.Error(),
			"result": result,
		})
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(result)
}

func handleDeleteRepo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if repoManager == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]string{"error": "repository manager not initialized"})
		return
	}

	name := chi.URLParam(r, "name")

	// Check for deleteFiles query param
	deleteFiles := r.URL.Query().Get("delete_files") == "true"

	if err := repoManager.Remove(name, deleteFiles); err != nil {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "removed"})
}

