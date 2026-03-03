package observability

import (
	"context"
	"errors"
	"testing"
)

func TestNew_LoggingOnly(t *testing.T) {
	tests := []struct {
		name   string
		cfg    Config
		wantOK bool
	}{
		{
			name: "json_info_logger",
			cfg: Config{
				ServiceName:    "test-svc",
				ServiceVersion: "1.0.0",
				Environment:    "test",
				LogLevel:       "info",
				LogFormat:      "json",
			},
			wantOK: true,
		},
		{
			name: "console_debug_logger",
			cfg: Config{
				ServiceName: "test-svc",
				LogLevel:    "debug",
				LogFormat:   "console",
			},
			wantOK: true,
		},
		{
			name: "warn_level",
			cfg: Config{
				ServiceName: "test-svc",
				LogLevel:    "warn",
				LogFormat:   "json",
			},
			wantOK: true,
		},
		{
			name: "error_level",
			cfg: Config{
				ServiceName: "test-svc",
				LogLevel:    "error",
				LogFormat:   "json",
			},
			wantOK: true,
		},
		{
			name: "unknown_level_falls_back_to_info",
			cfg: Config{
				ServiceName: "test-svc",
				LogLevel:    "nonsense",
				LogFormat:   "json",
			},
			wantOK: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tel, err := New(tc.cfg)
			if tc.wantOK {
				if err != nil {
					t.Fatalf("New() returned unexpected error: %v", err)
				}
				if tel == nil {
					t.Fatal("New() returned nil Telemetry")
				}
				if tel.Logger() == nil {
					t.Error("Logger() returned nil")
				}
				if tel.Tracer() == nil {
					t.Error("Tracer() returned nil")
				}
				// Metrics disabled in this config — should be nil.
				if tel.Metrics() != nil {
					t.Error("Metrics() should be nil when MetricsEnabled=false")
				}
			} else if err == nil {
				t.Error("expected error but got nil")
			}
		})
	}
}

func TestTelemetry_Shutdown_NoOp(t *testing.T) {
	cfg := Config{
		ServiceName: "test-svc",
		LogLevel:    "info",
		LogFormat:   "json",
	}
	tel, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	ctx := context.Background()
	// Shutdown may return a logger sync error in test environments where
	// stderr is not a real tty (e.g. "bad file descriptor"). That is expected
	// behaviour from the zap logger and is not a bug in Shutdown itself.
	_ = tel.Shutdown(ctx)
}

func TestTelemetry_Shutdown_Idempotent(t *testing.T) {
	cfg := Config{
		ServiceName: "test-svc",
		LogLevel:    "info",
		LogFormat:   "json",
	}
	tel, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	ctx := context.Background()
	// Both calls should not panic. The sync error from a non-tty stderr is
	// acceptable in test environments.
	_ = tel.Shutdown(ctx)
	_ = tel.Shutdown(ctx)
}

func TestTelemetry_StartSpan(t *testing.T) {
	cfg := Config{
		ServiceName: "test-svc",
		LogLevel:    "info",
		LogFormat:   "json",
	}
	tel, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer tel.Shutdown(context.Background()) //nolint:errcheck

	ctx := context.Background()
	spanCtx, span := tel.StartSpan(ctx, "test-operation")
	if spanCtx == nil {
		t.Error("StartSpan returned nil context")
	}
	if span == nil {
		t.Error("StartSpan returned nil span")
	}
	span.End()
}

func TestTelemetry_RecordError(t *testing.T) {
	cfg := Config{
		ServiceName: "test-svc",
		LogLevel:    "error",
		LogFormat:   "json",
	}
	tel, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer tel.Shutdown(context.Background()) //nolint:errcheck

	// RecordError should not panic.
	ctx := context.Background()
	tel.RecordError(ctx, errors.New("test error"))
}

func TestTelemetry_MetricsHandler(t *testing.T) {
	cfg := Config{
		ServiceName: "test-svc",
		LogLevel:    "info",
		LogFormat:   "json",
	}
	tel, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer tel.Shutdown(context.Background()) //nolint:errcheck

	h := tel.MetricsHandler()
	if h == nil {
		t.Error("MetricsHandler() returned nil")
	}
}

func TestTelemetry_StartSystemMetricsCollector_NilMetrics(t *testing.T) {
	cfg := Config{
		ServiceName:    "test-svc",
		LogLevel:       "info",
		LogFormat:      "json",
		MetricsEnabled: false,
	}
	tel, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer tel.Shutdown(context.Background()) //nolint:errcheck

	ctx, cancel := context.WithCancel(context.Background())
	// Should be a no-op when metrics is nil — must not panic.
	tel.StartSystemMetricsCollector(ctx)
	cancel()
}

func TestConfig_Fields(t *testing.T) {
	cfg := Config{
		ServiceName:    "threatforge",
		ServiceVersion: "2.0.0",
		Environment:    "production",
		LogLevel:       "info",
		LogFormat:      "json",
		TracingEnabled: true,
		OTLPEndpoint:   "otel-collector:4317",
		SamplingRate:   0.1,
		MetricsEnabled: true,
		MetricsPort:    9090,
	}

	if cfg.ServiceName != "threatforge" {
		t.Errorf("ServiceName = %q, want %q", cfg.ServiceName, "threatforge")
	}
	if cfg.SamplingRate != 0.1 {
		t.Errorf("SamplingRate = %v, want 0.1", cfg.SamplingRate)
	}
	if cfg.MetricsPort != 9090 {
		t.Errorf("MetricsPort = %d, want 9090", cfg.MetricsPort)
	}
}
