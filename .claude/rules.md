# ThreatForge - Claude Rules

## Project Context

- **Type**: Portfolio project for Staff/Principal Cloud Architect interviews
- **Language**: Go 1.22+
- **Module**: `github.com/lvonguyen/threatforge`
- **Status**: Active development

## Code Conventions

### Structure
- Use `cmd/{app}/main.go` for entrypoints
- Use `internal/` for private packages
- Use `configs/` for YAML configuration templates

### Style
- Provider abstraction via interfaces (e.g., `Provider` for threat intel sources)
- Error wrapping: `fmt.Errorf("context: %w", err)`
- Structured logging (chi middleware for HTTP)
- All write operations support `--dry-run` flag where applicable

### Security
- Zero stored credentials - API keys from environment
- No hardcoded secrets, tenant IDs, or internal URLs
- Reference "a large automotive enterprise" not specific company names
- Threat intel API keys loaded at runtime from env vars

## Documentation Standards

### No Emoji
Use ASCII symbols only:
- `[x]` not checkmark emoji
- `[!]` not warning emoji
- `->` not arrow emoji

### File Naming
- `HLD.md` - High-Level Design (markdown)
- `docs/HLD.docx` - High-Level Design (Word)
- `docs/pitch-deck-internal.pptx` - Stakeholder deck
- `docs/pitch-deck-interview.pptx` - Interview prep deck

### STAR Stories
Write STAR stories to shared repository:
- **Path**: `/Users/lvonguyen/repos/remote/gh/star-stories/`
- **Markdown**: `threatforge.md`
- **Word**: `threatforge.docx`
- Include quantified outcomes (%, hours saved, detection rates)
- Reference enterprise patterns (Sigma, MITRE ATT&CK, SOAR)

## When Generating Code

1. Follow existing patterns in codebase
2. Include comprehensive error handling
3. Add structured logging at key points
4. Support configuration via YAML + env vars
5. Include unit test stubs

## When Generating Docs

1. Use Georgia font specifications from project instructions
2. No emoji - ASCII symbols only
3. Include quantified outcomes in STAR stories
4. Reference enterprise patterns

## Architecture Patterns

### Provider Interface
- All threat intel sources implement `Provider`
- Common `Indicator` and `Match` types
- Rate limiting tracked per provider

### Ingestion Layer
- Splunk HEC receiver (inbound)
- Splunk HEC sender (enriched output)
- Support for Kafka streaming (future)

### Enrichment Pipeline
- IOC extraction from alerts
- Multi-provider correlation
- Risk scoring and prioritization

## Naming Conventions

- Provider-specific types prefixed: `MISPProvider`, `MISPConfig`
- Common types in `provider.go`: `Indicator`, `Match`, `Alert`
- Avoid generic names like `Config`, `Provider` in implementations

## Key Abstractions

| Interface | Purpose |
|-----------|---------|
| `Provider` | Threat intelligence source |
| `EventHandler` | Process received events |

## Splunk Integration Notes

- HEC endpoint: `/services/collector/event`
- Token in `Authorization: Splunk <token>` header
- Support newline-delimited JSON batches

## Project-Specific Notes

- Detection-as-Code with Sigma rules (Git-managed)
- Multi-source threat intel correlation (MISP, OTX, VirusTotal, GreyNoise)
- Splunk coexistence - enrich, don't replace

---

*See portfolio-level instructions in Claude Project for full specifications.*
