package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg == nil {
		t.Fatal("DefaultConfig returned nil")
	}

	t.Run("server_defaults", func(t *testing.T) {
		if cfg.Server.Port != 8080 {
			t.Errorf("Server.Port = %d, want 8080", cfg.Server.Port)
		}
		if cfg.Server.ReadTimeout != 30*time.Second {
			t.Errorf("Server.ReadTimeout = %v, want 30s", cfg.Server.ReadTimeout)
		}
		if cfg.Server.WriteTimeout != 30*time.Second {
			t.Errorf("Server.WriteTimeout = %v, want 30s", cfg.Server.WriteTimeout)
		}
		if cfg.Server.ShutdownTimeout != 10*time.Second {
			t.Errorf("Server.ShutdownTimeout = %v, want 10s", cfg.Server.ShutdownTimeout)
		}
	})

	t.Run("redis_defaults", func(t *testing.T) {
		if cfg.Redis.Addr != "localhost:6379" {
			t.Errorf("Redis.Addr = %q, want %q", cfg.Redis.Addr, "localhost:6379")
		}
		if cfg.Redis.DB != 0 {
			t.Errorf("Redis.DB = %d, want 0", cfg.Redis.DB)
		}
		if cfg.Redis.PoolSize != 10 {
			t.Errorf("Redis.PoolSize = %d, want 10", cfg.Redis.PoolSize)
		}
		if cfg.Redis.CacheTTL != time.Hour {
			t.Errorf("Redis.CacheTTL = %v, want 1h", cfg.Redis.CacheTTL)
		}
	})

	t.Run("splunk_receiver_defaults", func(t *testing.T) {
		r := cfg.Splunk.Receiver
		if !r.Enabled {
			t.Error("Splunk.Receiver.Enabled should be true by default")
		}
		if r.Port != 8088 {
			t.Errorf("Splunk.Receiver.Port = %d, want 8088", r.Port)
		}
		if r.MaxBatchSize != 1000 {
			t.Errorf("Splunk.Receiver.MaxBatchSize = %d, want 1000", r.MaxBatchSize)
		}
		if r.MaxEventSize != 1024*1024 {
			t.Errorf("Splunk.Receiver.MaxEventSize = %d, want 1048576", r.MaxEventSize)
		}
	})

	t.Run("splunk_sender_defaults", func(t *testing.T) {
		s := cfg.Splunk.Sender
		if !s.Enabled {
			t.Error("Splunk.Sender.Enabled should be true by default")
		}
		if s.Index != "threatforge_enriched" {
			t.Errorf("Splunk.Sender.Index = %q, want %q", s.Index, "threatforge_enriched")
		}
		if s.BatchSize != 100 {
			t.Errorf("Splunk.Sender.BatchSize = %d, want 100", s.BatchSize)
		}
		if s.RetryCount != 3 {
			t.Errorf("Splunk.Sender.RetryCount = %d, want 3", s.RetryCount)
		}
		if !s.VerifySSL {
			t.Error("Splunk.Sender.VerifySSL should be true by default")
		}
	})

	t.Run("threat_intel_disabled_by_default", func(t *testing.T) {
		ti := cfg.ThreatIntel
		if ti.MISP.Enabled {
			t.Error("MISP should be disabled by default")
		}
		if ti.OTX.Enabled {
			t.Error("OTX should be disabled by default")
		}
		if ti.VirusTotal.Enabled {
			t.Error("VirusTotal should be disabled by default")
		}
		if ti.GreyNoise.Enabled {
			t.Error("GreyNoise should be disabled by default")
		}
		if ti.AbuseIPDB.Enabled {
			t.Error("AbuseIPDB should be disabled by default")
		}
	})

	t.Run("detection_defaults", func(t *testing.T) {
		if cfg.Detection.SigmaRulesPath != "rules/sigma" {
			t.Errorf("Detection.SigmaRulesPath = %q, want %q", cfg.Detection.SigmaRulesPath, "rules/sigma")
		}
		if cfg.Detection.ReloadInterval != 5*time.Minute {
			t.Errorf("Detection.ReloadInterval = %v, want 5m", cfg.Detection.ReloadInterval)
		}
	})

	t.Run("logging_defaults", func(t *testing.T) {
		if cfg.Logging.Level != "info" {
			t.Errorf("Logging.Level = %q, want %q", cfg.Logging.Level, "info")
		}
		if cfg.Logging.Format != "json" {
			t.Errorf("Logging.Format = %q, want %q", cfg.Logging.Format, "json")
		}
	})

	t.Run("repositories_defaults", func(t *testing.T) {
		if cfg.Repositories.BasePath != "repositories" {
			t.Errorf("Repositories.BasePath = %q, want %q", cfg.Repositories.BasePath, "repositories")
		}
		if len(cfg.Repositories.Repos) != 0 {
			t.Errorf("Repositories.Repos should be empty, got %d entries", len(cfg.Repositories.Repos))
		}
	})
}

func TestLoad(t *testing.T) {
	t.Run("valid_yaml", func(t *testing.T) {
		dir := t.TempDir()
		yamlContent := `
server:
  port: 9090
  read_timeout: 60s
redis:
  addr: "redis:6379"
  db: 1
logging:
  level: "debug"
  format: "console"
`
		path := filepath.Join(dir, "config.yaml")
		if err := os.WriteFile(path, []byte(yamlContent), 0o644); err != nil {
			t.Fatalf("failed to write temp config: %v", err)
		}

		cfg, err := Load(path)
		if err != nil {
			t.Fatalf("Load returned error: %v", err)
		}

		if cfg.Server.Port != 9090 {
			t.Errorf("Server.Port = %d, want 9090", cfg.Server.Port)
		}
		if cfg.Redis.Addr != "redis:6379" {
			t.Errorf("Redis.Addr = %q, want %q", cfg.Redis.Addr, "redis:6379")
		}
		if cfg.Redis.DB != 1 {
			t.Errorf("Redis.DB = %d, want 1", cfg.Redis.DB)
		}
		if cfg.Logging.Level != "debug" {
			t.Errorf("Logging.Level = %q, want %q", cfg.Logging.Level, "debug")
		}
	})

	t.Run("preserves_defaults_for_unset_fields", func(t *testing.T) {
		dir := t.TempDir()
		yamlContent := `
server:
  port: 9999
`
		path := filepath.Join(dir, "config.yaml")
		if err := os.WriteFile(path, []byte(yamlContent), 0o644); err != nil {
			t.Fatalf("failed to write temp config: %v", err)
		}

		cfg, err := Load(path)
		if err != nil {
			t.Fatalf("Load returned error: %v", err)
		}

		if cfg.Server.Port != 9999 {
			t.Errorf("Server.Port = %d, want 9999", cfg.Server.Port)
		}
		// Unset field should keep default
		if cfg.Redis.Addr != "localhost:6379" {
			t.Errorf("Redis.Addr = %q, want default %q", cfg.Redis.Addr, "localhost:6379")
		}
	})

	t.Run("file_not_found", func(t *testing.T) {
		_, err := Load("/nonexistent/path/config.yaml")
		if err == nil {
			t.Error("Load should return error for missing file")
		}
	})

	t.Run("invalid_yaml", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "bad.yaml")
		// Control characters are rejected by yaml.v3.
		if err := os.WriteFile(path, []byte("\x00\x01\x02"), 0o644); err != nil {
			t.Fatalf("failed to write temp config: %v", err)
		}

		_, err := Load(path)
		if err == nil {
			t.Error("Load should return error for invalid YAML")
		}
	})
}

func TestEnabledProviders(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(*Config)
		expected []string
	}{
		{
			name:     "none_enabled",
			setup:    func(c *Config) {},
			expected: nil,
		},
		{
			name: "misp_only",
			setup: func(c *Config) {
				c.ThreatIntel.MISP.Enabled = true
			},
			expected: []string{"misp"},
		},
		{
			name: "all_enabled",
			setup: func(c *Config) {
				c.ThreatIntel.MISP.Enabled = true
				c.ThreatIntel.OTX.Enabled = true
				c.ThreatIntel.VirusTotal.Enabled = true
				c.ThreatIntel.GreyNoise.Enabled = true
				c.ThreatIntel.AbuseIPDB.Enabled = true
			},
			expected: []string{"misp", "otx", "virustotal", "greynoise", "abuseipdb"},
		},
		{
			name: "greynoise_and_abuseipdb",
			setup: func(c *Config) {
				c.ThreatIntel.GreyNoise.Enabled = true
				c.ThreatIntel.AbuseIPDB.Enabled = true
			},
			expected: []string{"greynoise", "abuseipdb"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := DefaultConfig()
			tc.setup(cfg)
			got := cfg.EnabledProviders()

			if len(got) != len(tc.expected) {
				t.Errorf("EnabledProviders() = %v, want %v", got, tc.expected)
				return
			}
			for i, p := range got {
				if p != tc.expected[i] {
					t.Errorf("EnabledProviders()[%d] = %q, want %q", i, p, tc.expected[i])
				}
			}
		})
	}
}

func TestRepositoryConfig(t *testing.T) {
	repo := RepositoryConfig{
		Name:         "sigma-rules",
		RemoteURL:    "https://github.com/SigmaHQ/sigma",
		Branch:       "main",
		Depth:        1,
		AutoSync:     true,
		SyncInterval: 24 * time.Hour,
	}

	if repo.Name != "sigma-rules" {
		t.Errorf("Name = %q, want %q", repo.Name, "sigma-rules")
	}
	if repo.Depth != 1 {
		t.Errorf("Depth = %d, want 1", repo.Depth)
	}
	if !repo.AutoSync {
		t.Error("AutoSync should be true")
	}
	if repo.SyncInterval != 24*time.Hour {
		t.Errorf("SyncInterval = %v, want 24h", repo.SyncInterval)
	}
}
