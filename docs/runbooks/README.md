# ThreatForge Technical Runbooks

## Overview

This directory contains operational runbooks for ThreatForge threat intelligence platform. Each runbook provides step-by-step procedures for common operational tasks and incident response.

## Runbook Index

| Runbook | Description | Priority |
|---------|-------------|----------|
| [01-deployment.md](./01-deployment.md) | Deployment procedures | High |
| [02-feed-management.md](./02-feed-management.md) | Managing threat feeds | High |
| [03-enrichment-issues.md](./03-enrichment-issues.md) | Enrichment troubleshooting | Medium |
| [04-playbook-management.md](./04-playbook-management.md) | IR playbook operations | High |
| [05-mitre-mapping.md](./05-mitre-mapping.md) | MITRE ATT&CK issues | Medium |

## Quick Reference

### Common Commands

```bash
# Check overall health
curl -s http://localhost:8080/health | jq .

# View active IOCs
curl -s http://localhost:8080/api/v1/iocs?status=active&limit=10 | jq .

# Trigger feed sync
curl -X POST http://localhost:8080/api/v1/feeds/sync

# Execute playbook
curl -X POST http://localhost:8080/api/v1/playbooks/execute \
  -H "Content-Type: application/json" \
  -d '{"playbook_id": "malware-response", "trigger": {"ioc_id": "abc123"}}'
```

### Key Metrics

| Metric | Description | Alert Threshold |
|--------|-------------|-----------------|
| `iocs_ingested_total` | IOCs ingested | <10/hour = warn |
| `enrichment_duration_seconds` | Enrichment latency | >10s = warn |
| `playbooks_executed_total` | Playbook executions | Monitor trend |
| `mitre_techniques_active` | Tracked techniques | >0 expected |

## Troubleshooting Quick Reference

### Feed Not Syncing

1. Check feed health: `curl -s http://localhost:8080/api/v1/feeds | jq .`
2. Verify credentials
3. Check network connectivity to feed source
4. Review feed logs: `kubectl logs -l app=threatforge | grep feed`

### Enrichment Failing

1. Check provider status pages
2. Verify API keys not expired
3. Check rate limit status
4. Enable fallback providers

### Playbook Stuck

1. Check playbook status: `curl -s http://localhost:8080/api/v1/playbooks/executions/{id}`
2. Review step that's blocking
3. Check for pending human approvals
4. Verify downstream integrations (SIEM, ticketing)

## Contact Points

| Role | Contact | Hours |
|------|---------|-------|
| On-Call Engineer | PagerDuty | 24/7 |
| Security Team | security@company.com | 24/7 |
| Threat Intel Team | threat-intel@company.com | Business hours |

