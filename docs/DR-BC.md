# ThreatForge - Disaster Recovery & Business Continuity

**Version:** 1.0
**Author:** Liem Vo-Nguyen
**Last Updated:** January 2026

---

## Executive Summary

This document outlines the DR/BC strategy for ThreatForge Threat Intelligence Platform across multi-cloud deployments.

---

## Recovery Objectives

| Metric | Target | Description |
|--------|--------|-------------|
| **RTO** | 4 hours | Maximum acceptable downtime |
| **RPO** | 30 minutes | Maximum acceptable data loss |
| **MTTR** | 2 hours | Average time to restore |

---

## Service Criticality

| Component | Criticality | RTO | RPO | Notes |
|-----------|-------------|-----|-----|-------|
| IOC Database | Critical | 1 hour | 15 min | Core threat data |
| Enrichment API | High | 2 hours | N/A | Stateless |
| MITRE ATT&CK Module | Medium | 4 hours | N/A | Rebuilt from source |
| IR Playbooks | Medium | 4 hours | N/A | Stored in Git |
| Splunk Integration | High | 2 hours | 30 min | Event streaming |
| MISP Integration | Medium | 4 hours | 1 hour | External dependency |

---

## Multi-Cloud DR Architecture

### Primary Architecture

```
Primary Region
├── Kubernetes Cluster
│   ├── ThreatForge API (3 replicas)
│   ├── Enrichment Service (2 replicas)
│   └── MITRE Mapper (2 replicas)
├── PostgreSQL (IOC database)
├── Redis (Cache)
├── Object Storage (Threat feeds)
└── Secret Manager

        Replication
            │
            ▼
DR Region
├── K8s Cluster (standby)
├── PostgreSQL replica
├── Redis (empty, rebuilt)
└── Object Storage replica
```

### Cross-Cloud DR Option

- Primary: AWS
- DR: Azure or GCP
- Velero for K8s backup
- pg_dump to cloud storage
- Container images in multi-cloud registry

---

## Backup Strategy

### Database Backups

| Database | Method | Frequency | Retention |
|----------|--------|-----------|-----------|
| IOC PostgreSQL | WAL archiving | Continuous | 7 days |
| IOC PostgreSQL | Full dump | Daily | 30 days |
| Redis | RDB snapshot | Every 15 min | 24 hours |

### Threat Intelligence Data

| Data | Method | Frequency | Retention |
|------|--------|-----------|-----------|
| IOC feeds | S3/Blob sync | Hourly | 90 days |
| MITRE data | Git sync | Daily | Infinite |
| IR Playbooks | Git sync | Real-time | Infinite |

---

## Failover Procedures

### Automated Failover

**Triggers:**
- Primary health check fails
- IOC database unavailable > 10 min
- API response time > 30 seconds

**Steps:**
1. DNS failover to DR
2. Promote database replica
3. Scale up K8s pods
4. Warm Redis cache from DB
5. Notify on-call

### Manual Failover

1. Notify stakeholders
2. Stop primary ingestion
3. Verify DB replication lag
4. Promote DR database
5. Update MISP/Splunk endpoints
6. Scale up services
7. Verify enrichment working
8. Resume threat feed ingestion

---

## Quarterly DR Testing

| Quarter | Test Type | Duration |
|---------|-----------|----------|
| Q1 | Tabletop | 2 hours |
| Q2 | Database failover | 4 hours |
| Q3 | Full failover | 8 hours |
| Q4 | Chaos testing | 4 hours |

### Test Scenarios

1. IOC database failure
2. Enrichment service outage
3. External feed unavailable
4. Complete region failure
5. Network partition

---

## SLA Targets

**ThreatForge Target:** 99.5% uptime (3.65 hours/month downtime)

---

## Integration Recovery

| Integration | Recovery Steps |
|-------------|----------------|
| MISP | Re-establish API connection, verify feed sync |
| Splunk | Update HEC endpoint, replay buffered events |
| VirusTotal | API key rotation if needed |
| AbuseIPDB | Verify rate limits reset |

---

## DR Cost Summary (Monthly)

| Component | AWS | Azure | GCP |
|-----------|-----|-------|-----|
| K8s standby | $75 | $0 | $75 |
| Database replica | $100 | $95 | $90 |
| Storage | $30 | $30 | $25 |
| **Total** | **$205** | **$125** | **$190** |

---

## Author

**Liem Vo-Nguyen**
- LinkedIn: linkedin.com/in/liemvonguyen

