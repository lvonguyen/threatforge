<img src="../../../reference/templates/icons/homelab-svg-assets/assets/rapid7-dark.svg" width="48" height="48" alt="ThreatForge" align="left" style="margin-right: 10px;">

# ThreatForge

![Go Version](https://img.shields.io/badge/go-1.24-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Development Status](https://img.shields.io/badge/status-active%20development-blue)
![Implementation](https://img.shields.io/badge/implementation-45%25-yellow)

**Detection Engineering Pipeline with Threat Intelligence Correlation**

ThreatForge is an enterprise-grade detection pipeline that enriches security alerts with threat intelligence, applies ML-based anomaly detection, and integrates seamlessly with existing Splunk deployments. It enables Detection-as-Code workflows using Sigma rules while providing real-time IOC correlation from multiple threat intel feeds.

---

## Architecture

```mermaid
%%{init: {'theme': 'base', 'themeVariables': {'fontFamily': 'Georgia'}}}%%
flowchart TB
    subgraph INPUT["INPUT SOURCES"]
        style INPUT fill:#3b82f6,stroke:#1e40af,color:#fff
        HEC["Splunk HEC\nWebhook"]
        KAFKA["Kafka\nConsumer"]
        SYSLOG["Syslog\nRFC 5424"]
        PUBSUB["Cloud\nPub/Sub"]
    end

    subgraph DETECTION["DETECTION ENGINE"]
        style DETECTION fill:#1e40af,stroke:#0f172a,color:#fff
        SIGMA["Sigma Rule\nEvaluator\n1000+ rules"]
        CUSTOM["Custom Rule\nEngine\nYARA-L style"]
        ML["ML Anomaly\nDetector\nBehavioral baselines"]
    end

    subgraph THREATINTEL["THREAT INTEL CORRELATION"]
        style THREATINTEL fill:#f59e0b,stroke:#b45309,color:#fff
        MISP["MISP"]
        OTX["OTX\nAlienVault"]
        VT["VirusTotal"]
        GN["GreyNoise"]
        ABUSE["AbuseIPDB"]
        CACHE[("IOC Cache\nRedis")]
    end

    subgraph ENRICHMENT["ENRICHMENT and SCORING"]
        style ENRICHMENT fill:#22c55e,stroke:#15803d,color:#fff
        ENRICH["Alert + Detection Match\n+ Threat Intel Context\n+ Risk Score"]
    end

    subgraph OUTPUT["OUTPUT DESTINATIONS"]
        style OUTPUT fill:#ef4444,stroke:#b91c1c,color:#fff
        SPLUNK_OUT["Splunk HEC\nenriched"]
        SOAR["SOAR\nPhantom/XSOAR"]
        SNOW["ServiceNow\nSecOps"]
        NOTIFY["Slack/Teams\nPagerDuty"]
    end

    HEC --> SIGMA
    KAFKA --> SIGMA
    SYSLOG --> SIGMA
    PUBSUB --> SIGMA
    HEC --> CUSTOM
    KAFKA --> CUSTOM
    SYSLOG --> CUSTOM
    PUBSUB --> CUSTOM
    HEC --> ML
    KAFKA --> ML
    SYSLOG --> ML
    PUBSUB --> ML

    SIGMA --> MISP
    CUSTOM --> MISP
    ML --> MISP

    MISP --> CACHE
    OTX --> CACHE
    VT --> CACHE
    GN --> CACHE
    ABUSE --> CACHE

    CACHE --> ENRICH

    ENRICH --> SPLUNK_OUT
    ENRICH --> SOAR
    ENRICH --> SNOW
    ENRICH --> NOTIFY
```

---

## What This Solves

Enterprise SOCs face critical challenges:
- **Alert Fatigue:** 10K+ daily alerts, 95% false positives
- **Context Gap:** Raw alerts lack threat intel enrichment
- **Detection Drift:** Correlation rules managed ad-hoc, no version control
- **Intel Silos:** Multiple threat feeds, no unified correlation

ThreatForge addresses these with:
- Splunk coexistence (enrich, don't replace)
- Multi-source threat intel correlation (MISP, OTX, VirusTotal, GreyNoise)
- Detection-as-Code with Sigma rules (Git-managed, CI/CD tested)
- ML behavioral baselines for anomaly detection
- SOAR integration for automated response

---

## Quick Start

### Prerequisites

- Go 1.24+
- Docker & Docker Compose
- Redis
- Splunk instance (for integration testing)
- API keys for threat intel providers (optional)

### Local Development

```bash
# Clone repository
git clone https://github.com/lvonguyen/threatforge.git
cd threatforge

# Initialize Sigma rules submodule
git submodule update --init --recursive

# Copy environment template
cp configs/config.example.yaml configs/config.yaml

# Start dependencies
docker-compose up -d redis

# Run server
go run cmd/server/main.go --config configs/config.yaml

# Test webhook endpoint
curl -X POST http://localhost:8080/api/v1/ingest \
  -H "Content-Type: application/json" \
  -d '{"source_ip": "185.220.101.1", "event_type": "network_connection"}'
```

### Splunk Configuration

```spl
# Create alert action to send to ThreatForge
| search index=security sourcetype=WinEventLog:Security EventCode=4688
| eval threat_forge_payload=json_object(
    "source_ip", src_ip,
    "dest_ip", dest_ip,
    "user", user,
    "process", process_name,
    "command_line", CommandLine
  )
| sendalert threatforge param.endpoint="http://threatforge:8080/api/v1/ingest"
```

---

## Key Features

### Detection-as-Code with Sigma

```yaml
# rules/custom/credential_access/mimikatz_execution.yml
title: Mimikatz Execution Detection
id: f8f50f5c-587f-4e5e-a2de-74c5e7df1e9a
status: stable
description: Detects Mimikatz execution via command line patterns
author: ThreatForge
date: 2024/01/15
references:
    - https://attack.mitre.org/techniques/T1003/001/
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - 'sekurlsa::logonpasswords'
            - 'lsadump::sam'
            - 'privilege::debug'
    condition: selection
falsepositives:
    - Legitimate security assessments
level: critical
tags:
    - attack.credential_access
    - attack.t1003.001
```

### Multi-Source Threat Intel

| Source | Type | Update Frequency | Cost |
|--------|------|------------------|------|
| MISP | Self-hosted aggregator | Real-time | Free (OSS) |
| AlienVault OTX | Community intel | Hourly | Free |
| VirusTotal | File/URL/IP reputation | Real-time | Freemium |
| GreyNoise | Internet scanner ID | Hourly | Freemium |
| AbuseIPDB | IP reputation | Real-time | Freemium |
| Mandiant | APT attribution | Daily | Enterprise |

### Splunk Integration Modes

**Mode 1: Webhook Receiver**
- Splunk alert action sends to ThreatForge webhook
- ThreatForge enriches and returns to Splunk HEC
- Best for: Targeted high-value alerts

**Mode 2: Streaming Processor**
- Kafka/Kinesis between Splunk and ThreatForge
- Continuous enrichment pipeline
- Best for: High-volume processing

**Mode 3: Batch Export**
- Scheduled export from Splunk via REST API
- Daily/hourly threat hunting
- Best for: Retrospective analysis

<img src="../../../reference/templates/icons/homelab-svg-assets/assets/prometheus.svg" width="24" height="24" alt="Telemetry">

### Telemetry Hub (Merged)

Multi-source security telemetry aggregation and normalization:

| Source Type | Integrations | Schema |
|-------------|--------------|--------|
| **EDR** | CrowdStrike Falcon, SentinelOne, Microsoft Defender | OCSF |
| **SIEM** | Splunk, Microsoft Sentinel, Elasticsearch | ECS |
| **Cloud** | AWS CloudTrail, Azure Activity Logs, GCP Audit Logs | OCSF |

- **AI-Powered Analysis**: Claude-based contextual risk scoring
- **Attack Chain Correlation**: Identifies related events across sources
- **Identity Enrichment**: Context from Entra ID/Okta
- **Asset Enrichment**: CMDB integration for business context

<img src="../../../reference/templates/icons/homelab-svg-assets/assets/vault.svg" width="24" height="24" alt="Security">

### Auto-Remediation Agents (Merged)

Automated response to security findings:

- **Cloud Remediation**: AWS (Lambda), Azure (Functions), GCP (Cloud Functions)
- **Action Library**: Pre-built actions for common remediations
  - Isolate compromised instance
  - Revoke IAM credentials
  - Block malicious IP
  - Quarantine suspicious file
- **Approval Workflows**: Human-in-the-loop for critical actions
- **Rollback Support**: Undo remediation if false positive

---

## Tech Stack

| Component | Technology | Purpose |
|-----------|------------|---------|
| API Server | Go 1.24+ | Core detection engine |
| Rule Engine | go-sigma | Sigma rule evaluation |
| Cache | Redis | IOC lookup cache |
| Queue | Kafka (optional) | High-volume streaming |
| Database | PostgreSQL | Detection history, metrics |
| ML | Go + Python sidecar | Anomaly detection |

---

## Implementation Status

| Component | Status | Notes |
|-----------|--------|-------|
| **Ingestion** | | |
| Splunk HEC integration | Done | Ingest + output working |
| Kafka consumer | Planned | Interface defined |
| Syslog receiver | Planned | |
| Cloud Pub/Sub | Planned | |
| **Threat Intel** | | |
| Provider abstraction | Done | Interface pattern |
| MISP client | Done | Full API integration |
| AlienVault OTX | Done | Basic implementation |
| VirusTotal | In Progress | API defined |
| GreyNoise | Planned | |
| AbuseIPDB | Planned | |
| **Detection Engine** | | |
| Sigma rule loader | In Progress | go-sigma integration started |
| Custom rule engine | Planned | YARA-L style |
| ML anomaly detector | Planned | Design complete |
| **Enrichment** | | |
| Redis IOC cache | In Progress | Schema defined |
| MITRE ATT&CK mapping | Done | Technique mapping complete |
| Risk scoring | In Progress | Basic implementation |
| **Output** | | |
| Splunk HEC output | Done | Enriched events |
| SOAR webhook | Planned | |
| ServiceNow SecOps | Planned | |
| Notifications | Planned | |
| **Testing** | | |
| Unit tests | 10% | HEC + security coverage |
| Integration tests | Planned | |

---

## Observability

<img src="../../../reference/templates/icons/homelab-svg-assets/assets/grafana.svg" width="32" height="32" alt="Observability">

- **Logging**: Structured JSON logging with zap
- **Metrics**: Prometheus metrics at `/metrics`
  - IOC ingestion/enrichment rates
  - Playbook execution metrics
  - MITRE technique coverage
- **Tracing**: OpenTelemetry distributed tracing (TLS-secured OTLP)
- **Health**: Kubernetes-ready probes at `/health`, `/ready`, `/live`

---

## Repository Structure

```
threatforge/
├── cmd/
│   └── server/main.go           # API server entrypoint
├── internal/
│   ├── api/gateway/             # API rate limiting
│   ├── compliance/              # Compliance finding schema
│   ├── config/config.go         # Configuration management
│   ├── enrichment/              # Alert enrichment pipeline
│   ├── ingestion/               # Splunk HEC integration
│   ├── mitre/                   # MITRE ATT&CK framework mapping
│   ├── observability/           # Logging, metrics, tracing
│   ├── playbooks/               # IR playbook management
│   ├── threatintel/             # Threat intel providers
│   ├── telemetry/               # Telemetry Hub (merged)
│   │   ├── ingestion/           # EDR/SIEM collectors (CrowdStrike, SentinelOne, Defender)
│   │   ├── normalization/       # OCSF/ECS schema normalization
│   │   └── correlation/         # Event correlation engine
│   └── remediation/             # Auto-Remediation Agents (merged)
│       ├── agents/              # Cloud-specific remediation agents
│       ├── actions/             # Remediation action library
│       └── workflows/           # Remediation workflows
├── rules/
│   ├── sigma/                   # Sigma rules (git submodule)
│   └── custom/                  # Organization-specific rules
├── configs/
│   └── config.yaml              # Configuration template
├── docs/
│   ├── adr/                     # Architecture Decision Records
│   ├── runbooks/                # Technical runbooks
│   └── DR-BC.md                 # Disaster Recovery & Business Continuity
├── k8s/
│   └── deployment.yaml          # Kubernetes manifests
├── Dockerfile
├── docker-compose.yml
├── go.mod
└── README.md
```

---

## Roadmap

### Phase 1: Core Pipeline (Active)
- [x] Splunk HEC integration (ingest + output)
- [x] MISP threat intel provider
- [x] AlienVault OTX provider
- [x] MITRE ATT&CK mapping
- [x] Redis client integration
- [ ] Complete Sigma rule evaluator
- [ ] VirusTotal / GreyNoise / AbuseIPDB providers
- [ ] Redis IOC cache layer

### Phase 2: Detection Engineering
- [ ] Git-based rule sync
- [ ] Rule testing framework
- [ ] MITRE ATT&CK coverage dashboard
- [ ] Custom rule DSL (YARA-L style)
- [ ] Unit test coverage to 80%

### Phase 3: ML and Analytics
- [ ] Behavioral baseline engine
- [ ] Anomaly detection models (Python sidecar)
- [ ] Entity risk scoring refinement
- [ ] Threat hunting notebooks

### Phase 4: Enterprise Integration
- [ ] SOAR webhook outputs (Phantom/XSOAR)
- [ ] ServiceNow SecOps integration
- [ ] Kafka streaming mode
- [ ] Syslog/Pub-Sub ingestion
- [ ] Multi-tenant support

---

## Documentation

- [ADR-001: Threat Intel Architecture](docs/adr/ADR-001-threat-intel-architecture.md)
- [Technical Runbooks](docs/runbooks/README.md)
- [DR/BC Plan](docs/DR-BC.md)
- [Changelog](CHANGELOG.md)

---

## License

MIT License - See [LICENSE](LICENSE)

---

**Author:** Liem Vo-Nguyen
**LinkedIn:** [linkedin.com/in/liemvonguyen](https://linkedin.com/in/liemvonguyen)
