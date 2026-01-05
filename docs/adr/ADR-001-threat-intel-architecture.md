# ADR-001: Threat Intelligence Architecture

## Status

Accepted

## Date

2026-01-05

## Context

We need to design an architecture for ThreatForge that:
- Aggregates threat intelligence from multiple sources
- Enriches Indicators of Compromise (IOCs)
- Maps threats to MITRE ATT&CK framework
- Provides actionable incident response playbooks
- Integrates with existing security tools

### Requirements

- Support for STIX/TAXII, MISP, and commercial feeds
- Real-time IOC matching against network/endpoint data
- MITRE ATT&CK mapping for context
- Automated playbook execution
- High availability for production use

## Decision

We will implement a **threat intelligence platform** with the following components:

1. **Feed Ingestion** - Collect IOCs from multiple sources
2. **Normalization** - Convert to internal IOC format
3. **Enrichment** - Add context from VirusTotal, MISP, etc.
4. **MITRE Mapping** - Associate IOCs with techniques
5. **Matching Engine** - Real-time IOC matching
6. **Playbook Engine** - Automated IR response

## Architecture

```
+-----------+  +-----------+  +-----------+
| MISP Feed |  | STIX/TAXII|  | Commercial|
+-----+-----+  +-----+-----+  +-----+-----+
      |              |              |
      v              v              v
+----------------------------------------+
|           Feed Ingestion               |
+-------------------+--------------------+
                    |
                    v
+----------------------------------------+
|           Normalization                |
|        (Internal IOC Schema)           |
+-------------------+--------------------+
                    |
        +-----------+-----------+
        |                       |
        v                       v
+---------------+       +---------------+
| Enrichment    |       | MITRE ATT&CK  |
| (VT, MISP)    |       | Mapper        |
+-------+-------+       +-------+-------+
        |                       |
        +-----------+-----------+
                    |
                    v
+----------------------------------------+
|           IOC Repository               |
|         (PostgreSQL + Redis)           |
+-------------------+--------------------+
                    |
        +-----------+-----------+
        |                       |
        v                       v
+---------------+       +---------------+
| Matching      |       | Playbook      |
| Engine        |       | Engine        |
+---------------+       +---------------+
```

## Rationale

### IOC Schema

We use an internal schema that combines:
- STIX 2.1 concepts (for interoperability)
- Custom fields for enrichment data
- MITRE ATT&CK references

### Enrichment Strategy

| Provider | Use Case | Rate Limit |
|----------|----------|------------|
| VirusTotal | Hash/URL reputation | 500/day (free) |
| MISP | Threat context | Internal |
| AbuseIPDB | IP reputation | 1000/day |
| Shodan | Infrastructure intel | 1 QPS |

Enrichment is cached to reduce API calls and improve performance.

### MITRE ATT&CK Integration

- Map IOCs to techniques based on behavior
- Track technique coverage
- Generate detection recommendations
- Support kill chain visualization

### Playbook Design

Playbooks follow SOAR patterns:
- Trigger conditions
- Sequential/parallel steps
- Human approval gates
- Automated actions (block, alert, ticket)

## Consequences

### Positive
- Comprehensive threat intel aggregation
- Automated enrichment reduces manual work
- MITRE context aids analysis
- Playbooks enable consistent response

### Negative
- Multiple API dependencies
- Complex caching requirements
- Playbook maintenance overhead

### Mitigations
- Implement fallback providers
- Cache aggressively with TTL
- Version playbooks with testing

## Related Decisions

- ADR-002: IOC Storage Strategy
- ADR-003: Enrichment Provider Selection
- ADR-004: Playbook Execution Engine

