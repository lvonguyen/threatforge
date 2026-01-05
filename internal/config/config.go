// Package config provides configuration management for ThreatForge.
package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config holds all ThreatForge configuration.
type Config struct {
	Server      ServerConfig      `yaml:"server"`
	Redis       RedisConfig       `yaml:"redis"`
	Splunk      SplunkConfig      `yaml:"splunk"`
	ThreatIntel ThreatIntelConfig `yaml:"threat_intel"`
	Detection   DetectionConfig   `yaml:"detection"`
	Logging     LoggingConfig     `yaml:"logging"`
}

// ServerConfig holds HTTP server settings.
type ServerConfig struct {
	Port            int           `yaml:"port"`
	ReadTimeout     time.Duration `yaml:"read_timeout"`
	WriteTimeout    time.Duration `yaml:"write_timeout"`
	ShutdownTimeout time.Duration `yaml:"shutdown_timeout"`
}

// RedisConfig holds Redis connection settings.
type RedisConfig struct {
	Addr        string        `yaml:"addr"`
	PasswordEnv string        `yaml:"password_env"`
	DB          int           `yaml:"db"`
	PoolSize    int           `yaml:"pool_size"`
	CacheTTL    time.Duration `yaml:"cache_ttl"`
}

// SplunkConfig holds Splunk HEC settings.
type SplunkConfig struct {
	Receiver ReceiverConfig `yaml:"receiver"`
	Sender   SenderConfig   `yaml:"sender"`
}

// ReceiverConfig holds HEC receiver settings.
type ReceiverConfig struct {
	Enabled      bool          `yaml:"enabled"`
	Port         int           `yaml:"port"`
	TokenEnv     string        `yaml:"token_env"`
	TLSCertFile  string        `yaml:"tls_cert_file"`
	TLSKeyFile   string        `yaml:"tls_key_file"`
	MaxBatchSize int           `yaml:"max_batch_size"`
	MaxEventSize int           `yaml:"max_event_size"`
	ReadTimeout  time.Duration `yaml:"read_timeout"`
	WriteTimeout time.Duration `yaml:"write_timeout"`
}

// SenderConfig holds HEC sender settings.
type SenderConfig struct {
	Enabled      bool          `yaml:"enabled"`
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

// ThreatIntelConfig holds threat intel provider settings.
type ThreatIntelConfig struct {
	MISP       MISPConfig       `yaml:"misp"`
	OTX        OTXConfig        `yaml:"otx"`
	VirusTotal VirusTotalConfig `yaml:"virustotal"`
	GreyNoise  GreyNoiseConfig  `yaml:"greynoise"`
	AbuseIPDB  AbuseIPDBConfig  `yaml:"abuseipdb"`
}

// MISPConfig holds MISP settings.
type MISPConfig struct {
	Enabled       bool          `yaml:"enabled"`
	BaseURL       string        `yaml:"base_url"`
	APIKeyEnv     string        `yaml:"api_key_env"`
	VerifySSL     bool          `yaml:"verify_ssl"`
	Timeout       time.Duration `yaml:"timeout"`
	RateLimit     int           `yaml:"rate_limit"`
	PublishedOnly bool          `yaml:"published_only"`
}

// OTXConfig holds AlienVault OTX settings.
type OTXConfig struct {
	Enabled   bool          `yaml:"enabled"`
	APIKeyEnv string        `yaml:"api_key_env"`
	Timeout   time.Duration `yaml:"timeout"`
	RateLimit int           `yaml:"rate_limit"`
}

// VirusTotalConfig holds VirusTotal settings.
type VirusTotalConfig struct {
	Enabled   bool          `yaml:"enabled"`
	APIKeyEnv string        `yaml:"api_key_env"`
	Timeout   time.Duration `yaml:"timeout"`
	RateLimit int           `yaml:"rate_limit"` // Free tier: 4 req/min
}

// GreyNoiseConfig holds GreyNoise settings.
type GreyNoiseConfig struct {
	Enabled   bool          `yaml:"enabled"`
	APIKeyEnv string        `yaml:"api_key_env"`
	Timeout   time.Duration `yaml:"timeout"`
	RateLimit int           `yaml:"rate_limit"`
}

// AbuseIPDBConfig holds AbuseIPDB settings.
type AbuseIPDBConfig struct {
	Enabled   bool          `yaml:"enabled"`
	APIKeyEnv string        `yaml:"api_key_env"`
	Timeout   time.Duration `yaml:"timeout"`
	RateLimit int           `yaml:"rate_limit"`
}

// DetectionConfig holds detection engine settings.
type DetectionConfig struct {
	SigmaRulesPath  string        `yaml:"sigma_rules_path"`
	CustomRulesPath string        `yaml:"custom_rules_path"`
	ReloadInterval  time.Duration `yaml:"reload_interval"`
}

// LoggingConfig holds logging settings.
type LoggingConfig struct {
	Level  string `yaml:"level"` // debug, info, warn, error
	Format string `yaml:"format"` // json, console
}

// Load reads configuration from a YAML file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	cfg := DefaultConfig()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	return cfg, nil
}

// DefaultConfig returns sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			Port:            8080,
			ReadTimeout:     30 * time.Second,
			WriteTimeout:    30 * time.Second,
			ShutdownTimeout: 10 * time.Second,
		},
		Redis: RedisConfig{
			Addr:     "localhost:6379",
			DB:       0,
			PoolSize: 10,
			CacheTTL: 1 * time.Hour,
		},
		Splunk: SplunkConfig{
			Receiver: ReceiverConfig{
				Enabled:      true,
				Port:         8088,
				TokenEnv:     "SPLUNK_HEC_TOKEN_INBOUND",
				MaxBatchSize: 1000,
				MaxEventSize: 1024 * 1024,
				ReadTimeout:  30 * time.Second,
				WriteTimeout: 30 * time.Second,
			},
			Sender: SenderConfig{
				Enabled:      true,
				TokenEnv:     "SPLUNK_HEC_TOKEN_OUTBOUND",
				Index:        "threatforge_enriched",
				SourceType:   "threatforge:alert",
				Source:       "threatforge",
				BatchSize:    100,
				BatchTimeout: 5 * time.Second,
				Timeout:      30 * time.Second,
				RetryCount:   3,
				VerifySSL:    true,
			},
		},
		ThreatIntel: ThreatIntelConfig{
			MISP: MISPConfig{
				Enabled:       false,
				APIKeyEnv:     "MISP_API_KEY",
				VerifySSL:     true,
				Timeout:       30 * time.Second,
				RateLimit:     60,
				PublishedOnly: true,
			},
			OTX: OTXConfig{
				Enabled:   false,
				APIKeyEnv: "OTX_API_KEY",
				Timeout:   30 * time.Second,
				RateLimit: 60,
			},
			VirusTotal: VirusTotalConfig{
				Enabled:   false,
				APIKeyEnv: "VIRUSTOTAL_API_KEY",
				Timeout:   30 * time.Second,
				RateLimit: 4, // Free tier
			},
			GreyNoise: GreyNoiseConfig{
				Enabled:   false,
				APIKeyEnv: "GREYNOISE_API_KEY",
				Timeout:   30 * time.Second,
				RateLimit: 60,
			},
			AbuseIPDB: AbuseIPDBConfig{
				Enabled:   false,
				APIKeyEnv: "ABUSEIPDB_API_KEY",
				Timeout:   30 * time.Second,
				RateLimit: 60,
			},
		},
		Detection: DetectionConfig{
			SigmaRulesPath:  "rules/sigma",
			CustomRulesPath: "rules/custom",
			ReloadInterval:  5 * time.Minute,
		},
		Logging: LoggingConfig{
			Level:  "info",
			Format: "json",
		},
	}
}

// EnabledProviders returns a list of enabled threat intel providers.
func (c *Config) EnabledProviders() []string {
	var providers []string
	if c.ThreatIntel.MISP.Enabled {
		providers = append(providers, "misp")
	}
	if c.ThreatIntel.OTX.Enabled {
		providers = append(providers, "otx")
	}
	if c.ThreatIntel.VirusTotal.Enabled {
		providers = append(providers, "virustotal")
	}
	if c.ThreatIntel.GreyNoise.Enabled {
		providers = append(providers, "greynoise")
	}
	if c.ThreatIntel.AbuseIPDB.Enabled {
		providers = append(providers, "abuseipdb")
	}
	return providers
}

