# Changelog

All notable changes to ThreatForge are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [Unreleased]

### Planned
- Redis IOC cache layer
- Complete Sigma rule evaluator
- VirusTotal / GreyNoise / AbuseIPDB provider implementations
- Kafka streaming ingestion mode
- Unit test coverage to 80%

---

## [0.4.0] - 2026-02-26

### Added
- MIT License

### Security
- Architecture hardening: OTLP TLS for secure telemetry export
- Singleflight deduplication on concurrent threat intel lookups
- Batch cap enforcement to prevent unbounded memory growth
- Security headers middleware (X-Content-Type-Options, X-Frame-Options, HSTS)

---

## [0.3.0] - 2026-02-25

### Added
- Redis client integration for IOC cache layer (schema-ready)
- Threat intelligence provider abstraction (interface pattern)
- MISP full API integration
- AlienVault OTX provider (basic implementation)
- VirusTotal provider stub (API defined)
- Implementation status table and roadmap in documentation

---

## [0.2.0] - 2026-02-20

### Added
- OTX (AlienVault) threat intel provider
- Retry-After header on 429 rate limit responses
- Rate limiting for Splunk HEC receiver
- Comprehensive HECSender unit tests
- Security fix test suite for Splunk HEC integration
- Mermaid architecture diagram with color-coded subsystems

### Fixed
- Race condition on server shutdown (graceful drain)
- Pre-production security blockers in HEC integration
- Critical security vulnerabilities in Splunk HEC integration
- Token validation order: validate before rate limit check
- Icon rendering: moved SVG assets outside markdown headers

### Performance
- HEC token caching at initialization (eliminates per-request lookup)

---

## [0.1.0] - 2026-01-20

### Added
- Initial ThreatForge scaffold (Go 1.24, chi router, zap logging)
- MITRE ATT&CK framework mapping (`internal/mitre/`)
- IR playbook management engine (`internal/playbooks/`)
- API rate limiting gateway (`internal/api/gateway/`)
- Compliance finding schema (`internal/compliance/`)
- OpenTelemetry observability stack (logging, metrics, tracing)
- Architecture Decision Records (ADR-001: Threat Intel Architecture)
- Technical runbooks index and quick-reference commands
- Disaster Recovery / Business Continuity plan (RTO: 4h, RPO: 30min)
- Repository management for remote clone workflows
- Merge of threat-telemetry-hub module:
  - EDR collectors: CrowdStrike Falcon, SentinelOne, Microsoft Defender
  - OCSF/ECS schema normalization
  - Event correlation engine
- Merge of cs-remediation-agents module:
  - Cloud remediation agents (AWS Lambda, Azure Functions, GCP Cloud Functions)
  - Pre-built action library (isolate, revoke, block, quarantine)
  - Human-in-the-loop approval workflows
