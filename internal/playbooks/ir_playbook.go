// Package playbooks provides incident response playbook management
package playbooks

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

// IRPlaybook represents an incident response playbook
type IRPlaybook struct {
	ID          string       `yaml:"id" json:"id"`
	Name        string       `yaml:"name" json:"name"`
	Description string       `yaml:"description" json:"description"`
	Category    string       `yaml:"category" json:"category"` // malware, phishing, data_breach, etc.
	Severity    string       `yaml:"severity" json:"severity"` // critical, high, medium, low
	Triggers    []Trigger    `yaml:"triggers" json:"triggers"`
	Steps       []Step       `yaml:"steps" json:"steps"`
	Escalation  Escalation   `yaml:"escalation" json:"escalation"`
	Metadata    Metadata     `yaml:"metadata" json:"metadata"`
}

// Trigger defines when a playbook should be activated
type Trigger struct {
	Type      string            `yaml:"type" json:"type"`           // alert, threshold, manual
	Condition string            `yaml:"condition" json:"condition"` // e.g., "severity >= high"
	Source    string            `yaml:"source" json:"source"`       // e.g., "crowdstrike", "splunk"
	Tags      map[string]string `yaml:"tags" json:"tags"`
}

// Step represents a single step in the playbook
type Step struct {
	ID          string        `yaml:"id" json:"id"`
	Name        string        `yaml:"name" json:"name"`
	Description string        `yaml:"description" json:"description"`
	Type        string        `yaml:"type" json:"type"`     // manual, automated, conditional
	Owner       string        `yaml:"owner" json:"owner"`   // role responsible
	Timeout     time.Duration `yaml:"timeout" json:"timeout"`
	Actions     []Action      `yaml:"actions" json:"actions"`
	OnSuccess   string        `yaml:"on_success" json:"on_success"` // next step ID
	OnFailure   string        `yaml:"on_failure" json:"on_failure"` // step ID or "escalate"
}

// Action represents an action within a step
type Action struct {
	Type       string            `yaml:"type" json:"type"`     // isolate, collect, notify, remediate
	Target     string            `yaml:"target" json:"target"` // what to act on
	Parameters map[string]string `yaml:"parameters" json:"parameters"`
	Automated  bool              `yaml:"automated" json:"automated"`
}

// Escalation defines escalation procedures
type Escalation struct {
	TimeLimit    time.Duration `yaml:"time_limit" json:"time_limit"`
	NotifyRoles  []string      `yaml:"notify_roles" json:"notify_roles"`
	Channels     []string      `yaml:"channels" json:"channels"` // slack, email, pagerduty
	ExternalTeam string        `yaml:"external_team" json:"external_team"`
}

// Metadata contains playbook metadata
type Metadata struct {
	Author       string    `yaml:"author" json:"author"`
	Version      string    `yaml:"version" json:"version"`
	CreatedAt    time.Time `yaml:"created_at" json:"created_at"`
	UpdatedAt    time.Time `yaml:"updated_at" json:"updated_at"`
	ReviewedAt   time.Time `yaml:"reviewed_at" json:"reviewed_at"`
	NextReview   time.Time `yaml:"next_review" json:"next_review"`
	MITRETactics []string  `yaml:"mitre_tactics" json:"mitre_tactics"`
	Compliance   []string  `yaml:"compliance" json:"compliance"` // SOC2, PCI-DSS, etc.
}

// PlaybookManager manages IR playbooks
type PlaybookManager struct {
	playbooks map[string]*IRPlaybook
	logger    *zap.Logger
}

// NewPlaybookManager creates a new playbook manager
func NewPlaybookManager(logger *zap.Logger) *PlaybookManager {
	pm := &PlaybookManager{
		playbooks: make(map[string]*IRPlaybook),
		logger:    logger,
	}

	// Load default playbooks
	pm.loadDefaultPlaybooks()

	return pm
}

// GetPlaybook returns a playbook by ID
func (pm *PlaybookManager) GetPlaybook(id string) (*IRPlaybook, bool) {
	pb, ok := pm.playbooks[id]
	return pb, ok
}

// GetPlaybooksByCategory returns playbooks for a category
func (pm *PlaybookManager) GetPlaybooksByCategory(category string) []*IRPlaybook {
	result := make([]*IRPlaybook, 0)
	for _, pb := range pm.playbooks {
		if pb.Category == category {
			result = append(result, pb)
		}
	}
	return result
}

// GetPlaybookForTrigger finds the best matching playbook for a trigger
func (pm *PlaybookManager) GetPlaybookForTrigger(ctx context.Context, triggerType, source string, tags map[string]string) (*IRPlaybook, error) {
	for _, pb := range pm.playbooks {
		for _, trigger := range pb.Triggers {
			if trigger.Type == triggerType && (trigger.Source == "" || trigger.Source == source) {
				// Check tag match
				if pm.matchesTags(trigger.Tags, tags) {
					return pb, nil
				}
			}
		}
	}
	return nil, fmt.Errorf("no matching playbook found")
}

func (pm *PlaybookManager) matchesTags(required, provided map[string]string) bool {
	for k, v := range required {
		if provided[k] != v {
			return false
		}
	}
	return true
}

// LoadPlaybook loads a playbook from YAML
func (pm *PlaybookManager) LoadPlaybook(yamlData []byte) error {
	var pb IRPlaybook
	if err := yaml.Unmarshal(yamlData, &pb); err != nil {
		return fmt.Errorf("parsing playbook YAML: %w", err)
	}

	pm.playbooks[pb.ID] = &pb
	pm.logger.Info("Playbook loaded",
		zap.String("id", pb.ID),
		zap.String("name", pb.Name),
	)

	return nil
}

// ExportPlaybook exports a playbook to YAML
func (pm *PlaybookManager) ExportPlaybook(id string) ([]byte, error) {
	pb, ok := pm.playbooks[id]
	if !ok {
		return nil, fmt.Errorf("playbook not found: %s", id)
	}

	return yaml.Marshal(pb)
}

func (pm *PlaybookManager) loadDefaultPlaybooks() {
	// Malware Detection Playbook
	pm.playbooks["pb-malware-001"] = &IRPlaybook{
		ID:          "pb-malware-001",
		Name:        "Malware Detection Response",
		Description: "Standard response procedure for malware detection on endpoints",
		Category:    "malware",
		Severity:    "high",
		Triggers: []Trigger{
			{Type: "alert", Source: "crowdstrike", Tags: map[string]string{"type": "malware"}},
			{Type: "alert", Source: "sentinelone", Tags: map[string]string{"type": "malware"}},
			{Type: "alert", Source: "defender", Tags: map[string]string{"category": "Malware"}},
		},
		Steps: []Step{
			{
				ID:          "step-1",
				Name:        "Isolate Endpoint",
				Description: "Immediately isolate the affected endpoint from the network",
				Type:        "automated",
				Owner:       "security_analyst",
				Timeout:     5 * time.Minute,
				Actions: []Action{
					{Type: "isolate", Target: "endpoint", Automated: true},
					{Type: "notify", Target: "security_team", Parameters: map[string]string{"channel": "slack"}},
				},
				OnSuccess: "step-2",
				OnFailure: "escalate",
			},
			{
				ID:          "step-2",
				Name:        "Collect Forensic Evidence",
				Description: "Gather memory dump, disk image, and relevant logs",
				Type:        "automated",
				Owner:       "security_analyst",
				Timeout:     30 * time.Minute,
				Actions: []Action{
					{Type: "collect", Target: "memory", Automated: true},
					{Type: "collect", Target: "logs", Automated: true},
					{Type: "collect", Target: "artifacts", Automated: true},
				},
				OnSuccess: "step-3",
				OnFailure: "step-3",
			},
			{
				ID:          "step-3",
				Name:        "Analyze Malware",
				Description: "Submit sample for analysis and review IOCs",
				Type:        "manual",
				Owner:       "malware_analyst",
				Timeout:     2 * time.Hour,
				Actions: []Action{
					{Type: "analyze", Target: "sample"},
					{Type: "enrich", Target: "iocs"},
				},
				OnSuccess: "step-4",
				OnFailure: "escalate",
			},
			{
				ID:          "step-4",
				Name:        "Remediate and Recover",
				Description: "Remove malware and restore endpoint to clean state",
				Type:        "manual",
				Owner:       "security_analyst",
				Timeout:     4 * time.Hour,
				Actions: []Action{
					{Type: "remediate", Target: "endpoint"},
					{Type: "verify", Target: "clean_state"},
				},
				OnSuccess: "step-5",
				OnFailure: "escalate",
			},
			{
				ID:          "step-5",
				Name:        "Post-Incident Review",
				Description: "Document findings and update detection rules",
				Type:        "manual",
				Owner:       "security_lead",
				Timeout:     24 * time.Hour,
				Actions: []Action{
					{Type: "document", Target: "incident_report"},
					{Type: "update", Target: "detection_rules"},
				},
				OnSuccess: "",
				OnFailure: "",
			},
		},
		Escalation: Escalation{
			TimeLimit:    4 * time.Hour,
			NotifyRoles:  []string{"security_lead", "ciso"},
			Channels:     []string{"pagerduty", "email"},
			ExternalTeam: "incident_response_vendor",
		},
		Metadata: Metadata{
			Author:       "Security Team",
			Version:      "1.0",
			CreatedAt:    time.Now(),
			UpdatedAt:    time.Now(),
			MITRETactics: []string{"TA0002", "TA0003", "TA0005"},
			Compliance:   []string{"SOC2", "PCI-DSS"},
		},
	}

	// Phishing Response Playbook
	pm.playbooks["pb-phishing-001"] = &IRPlaybook{
		ID:          "pb-phishing-001",
		Name:        "Phishing Email Response",
		Description: "Response procedure for reported phishing emails",
		Category:    "phishing",
		Severity:    "medium",
		Triggers: []Trigger{
			{Type: "alert", Source: "proofpoint"},
			{Type: "manual", Condition: "user_report"},
		},
		Steps: []Step{
			{
				ID:          "step-1",
				Name:        "Quarantine Email",
				Description: "Remove phishing email from all mailboxes",
				Type:        "automated",
				Owner:       "security_analyst",
				Timeout:     15 * time.Minute,
				Actions: []Action{
					{Type: "quarantine", Target: "email", Automated: true},
					{Type: "block", Target: "sender", Automated: true},
				},
				OnSuccess: "step-2",
				OnFailure: "escalate",
			},
			{
				ID:          "step-2",
				Name:        "Identify Affected Users",
				Description: "Find all users who received or clicked the phishing email",
				Type:        "automated",
				Owner:       "security_analyst",
				Timeout:     30 * time.Minute,
				Actions: []Action{
					{Type: "search", Target: "mail_logs", Automated: true},
					{Type: "search", Target: "proxy_logs", Automated: true},
				},
				OnSuccess: "step-3",
				OnFailure: "step-3",
			},
			{
				ID:          "step-3",
				Name:        "Credential Reset",
				Description: "Force password reset for users who clicked",
				Type:        "manual",
				Owner:       "security_analyst",
				Timeout:     1 * time.Hour,
				Actions: []Action{
					{Type: "reset", Target: "credentials"},
					{Type: "notify", Target: "affected_users"},
				},
				OnSuccess: "step-4",
				OnFailure: "escalate",
			},
			{
				ID:          "step-4",
				Name:        "Document and Close",
				Description: "Create incident report and update block lists",
				Type:        "manual",
				Owner:       "security_analyst",
				Timeout:     4 * time.Hour,
				Actions: []Action{
					{Type: "document", Target: "incident_report"},
					{Type: "update", Target: "block_lists"},
				},
				OnSuccess: "",
				OnFailure: "",
			},
		},
		Escalation: Escalation{
			TimeLimit:   2 * time.Hour,
			NotifyRoles: []string{"security_lead"},
			Channels:    []string{"slack", "email"},
		},
		Metadata: Metadata{
			Author:       "Security Team",
			Version:      "1.0",
			CreatedAt:    time.Now(),
			UpdatedAt:    time.Now(),
			MITRETactics: []string{"TA0001"},
			Compliance:   []string{"SOC2"},
		},
	}

	// Data Breach Response Playbook
	pm.playbooks["pb-breach-001"] = &IRPlaybook{
		ID:          "pb-breach-001",
		Name:        "Data Breach Response",
		Description: "Response procedure for suspected or confirmed data breach",
		Category:    "data_breach",
		Severity:    "critical",
		Triggers: []Trigger{
			{Type: "alert", Source: "dlp"},
			{Type: "alert", Tags: map[string]string{"category": "data_exfiltration"}},
			{Type: "manual", Condition: "breach_report"},
		},
		Steps: []Step{
			{
				ID:          "step-1",
				Name:        "Activate Breach Response Team",
				Description: "Notify all required stakeholders immediately",
				Type:        "automated",
				Owner:       "security_lead",
				Timeout:     15 * time.Minute,
				Actions: []Action{
					{Type: "notify", Target: "ciso", Parameters: map[string]string{"channel": "pagerduty"}},
					{Type: "notify", Target: "legal", Parameters: map[string]string{"channel": "phone"}},
					{Type: "notify", Target: "privacy_officer", Parameters: map[string]string{"channel": "phone"}},
				},
				OnSuccess: "step-2",
				OnFailure: "escalate",
			},
			{
				ID:          "step-2",
				Name:        "Contain the Breach",
				Description: "Stop ongoing data exfiltration",
				Type:        "automated",
				Owner:       "security_analyst",
				Timeout:     30 * time.Minute,
				Actions: []Action{
					{Type: "isolate", Target: "affected_systems", Automated: true},
					{Type: "block", Target: "exfil_destination", Automated: true},
					{Type: "revoke", Target: "compromised_credentials", Automated: true},
				},
				OnSuccess: "step-3",
				OnFailure: "escalate",
			},
			{
				ID:          "step-3",
				Name:        "Assess Impact",
				Description: "Determine what data was accessed or exfiltrated",
				Type:        "manual",
				Owner:       "security_lead",
				Timeout:     4 * time.Hour,
				Actions: []Action{
					{Type: "analyze", Target: "logs"},
					{Type: "analyze", Target: "dlp_events"},
					{Type: "document", Target: "data_inventory"},
				},
				OnSuccess: "step-4",
				OnFailure: "escalate",
			},
			{
				ID:          "step-4",
				Name:        "Legal and Regulatory Notification",
				Description: "Prepare and submit required notifications",
				Type:        "manual",
				Owner:       "legal",
				Timeout:     72 * time.Hour,
				Actions: []Action{
					{Type: "prepare", Target: "notification_letter"},
					{Type: "submit", Target: "regulatory_bodies"},
					{Type: "notify", Target: "affected_individuals"},
				},
				OnSuccess: "step-5",
				OnFailure: "escalate",
			},
			{
				ID:          "step-5",
				Name:        "Remediation and Recovery",
				Description: "Implement fixes and restore operations",
				Type:        "manual",
				Owner:       "security_lead",
				Timeout:     168 * time.Hour, // 1 week
				Actions: []Action{
					{Type: "remediate", Target: "vulnerabilities"},
					{Type: "restore", Target: "systems"},
					{Type: "update", Target: "security_controls"},
				},
				OnSuccess: "",
				OnFailure: "escalate",
			},
		},
		Escalation: Escalation{
			TimeLimit:    1 * time.Hour,
			NotifyRoles:  []string{"ciso", "ceo", "legal"},
			Channels:     []string{"pagerduty", "phone"},
			ExternalTeam: "forensics_firm",
		},
		Metadata: Metadata{
			Author:       "Security Team",
			Version:      "1.0",
			CreatedAt:    time.Now(),
			UpdatedAt:    time.Now(),
			MITRETactics: []string{"TA0009", "TA0010"},
			Compliance:   []string{"GDPR", "CCPA", "PCI-DSS", "HIPAA"},
		},
	}

	pm.logger.Info("Default playbooks loaded",
		zap.Int("count", len(pm.playbooks)),
	)
}

// ListPlaybooks returns all playbooks
func (pm *PlaybookManager) ListPlaybooks() []*IRPlaybook {
	result := make([]*IRPlaybook, 0, len(pm.playbooks))
	for _, pb := range pm.playbooks {
		result = append(result, pb)
	}
	return result
}

