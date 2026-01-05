// Package compliance provides finding schema and compliance mapping for threat intelligence
package compliance

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"
)

// IOCType represents indicator of compromise types
type IOCType string

const (
	IOCTypeIP         IOCType = "ip"
	IOCTypeDomain     IOCType = "domain"
	IOCTypeURL        IOCType = "url"
	IOCTypeFileHash   IOCType = "file_hash"
	IOCTypeEmail      IOCType = "email"
	IOCTypeCVE        IOCType = "cve"
	IOCTypeMalware    IOCType = "malware"
	IOCTypeActor      IOCType = "threat_actor"
	IOCTypeCampaign   IOCType = "campaign"
	IOCTypeTool       IOCType = "tool"
	IOCTypeAttackPattern IOCType = "attack_pattern"
)

// ThreatCategory categorizes the threat
type ThreatCategory string

const (
	CategoryMalware     ThreatCategory = "malware"
	CategoryRansomware  ThreatCategory = "ransomware"
	CategoryPhishing    ThreatCategory = "phishing"
	CategoryAPT         ThreatCategory = "apt"
	CategoryCybercrime  ThreatCategory = "cybercrime"
	CategoryHacktivism  ThreatCategory = "hacktivism"
	CategoryInsider     ThreatCategory = "insider"
)

// ConfidenceLevel represents intel confidence
type ConfidenceLevel string

const (
	ConfidenceHigh    ConfidenceLevel = "high"
	ConfidenceMedium  ConfidenceLevel = "medium"
	ConfidenceLow     ConfidenceLevel = "low"
	ConfidenceUnknown ConfidenceLevel = "unknown"
)

// WorkflowStatus represents the intel workflow status
type WorkflowStatus string

const (
	StatusNew          WorkflowStatus = "new"
	StatusTriaged      WorkflowStatus = "triaged"
	StatusAssigned     WorkflowStatus = "assigned"
	StatusInProgress   WorkflowStatus = "in_progress"
	StatusActionable   WorkflowStatus = "actionable"
	StatusRetired      WorkflowStatus = "retired"
	StatusFalsePositive WorkflowStatus = "false_positive"
)

// ThreatIntelFinding represents a threat intelligence finding
type ThreatIntelFinding struct {
	// Core Identification
	ID              string     `json:"id"`
	Source          string     `json:"source"`
	SourceFindingID string     `json:"source_finding_id"`
	Type            IOCType    `json:"type"`
	Category        ThreatCategory `json:"category"`
	Value           string     `json:"value"`
	Title           string     `json:"title"`
	Description     string     `json:"description"`

	// Threat Assessment
	ThreatLevel      string          `json:"threat_level"`
	Confidence       ConfidenceLevel `json:"confidence"`
	AIRiskScore      float64         `json:"ai_risk_score"`
	AIRiskLevel      string          `json:"ai_risk_level"`
	AIRiskRationale  string          `json:"ai_risk_rationale"`

	// MITRE ATT&CK Mapping
	MITRETactics     []string `json:"mitre_tactics,omitempty"`
	MITRETechniques  []string `json:"mitre_techniques,omitempty"`
	MITRESubtechniques []string `json:"mitre_subtechniques,omitempty"`

	// Attribution
	ThreatActors  []string `json:"threat_actors,omitempty"`
	Campaigns     []string `json:"campaigns,omitempty"`
	Malware       []string `json:"malware,omitempty"`
	Tools         []string `json:"tools,omitempty"`

	// Context
	TargetSectors   []string `json:"target_sectors,omitempty"`
	TargetRegions   []string `json:"target_regions,omitempty"`
	TargetPlatforms []string `json:"target_platforms,omitempty"`

	// Enrichment
	RelatedIOCs     []string `json:"related_iocs,omitempty"`
	RelatedCVEs     []CVEReference `json:"related_cves,omitempty"`
	GeoLocation     *GeoLocation `json:"geo_location,omitempty"`
	ASN             *ASNInfo `json:"asn,omitempty"`

	// Workflow
	Status         string         `json:"status"`
	WorkflowStatus WorkflowStatus `json:"workflow_status"`
	Assignee       *AssigneeInfo  `json:"assignee,omitempty"`

	// Ownership
	TechnicalContact *Contact `json:"technical_contact,omitempty"`
	Team             string   `json:"team,omitempty"`

	// Timestamps
	FirstSeenAt  time.Time  `json:"first_seen_at"`
	LastSeenAt   time.Time  `json:"last_seen_at"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
	RetiredAt    *time.Time `json:"retired_at,omitempty"`

	// Deduplication
	DeduplicationKey string   `json:"deduplication_key"`
	RelatedFindings  []string `json:"related_findings,omitempty"`

	// Ticketing
	TicketID     string `json:"ticket_id,omitempty"`
	TicketURL    string `json:"ticket_url,omitempty"`

	// Raw Data
	RawData map[string]interface{} `json:"raw_data,omitempty"`
	Tags    map[string]string      `json:"tags,omitempty"`
}

// CVEReference represents a CVE with hyperlink
type CVEReference struct {
	ID          string    `json:"id"`
	URL         string    `json:"url"`
	NVDUrl      string    `json:"nvd_url"`
	Description string    `json:"description"`
	CVSS        float64   `json:"cvss"`
	Published   time.Time `json:"published"`
}

// GeoLocation represents geographic location
type GeoLocation struct {
	Country     string  `json:"country"`
	CountryCode string  `json:"country_code"`
	City        string  `json:"city,omitempty"`
	Latitude    float64 `json:"latitude,omitempty"`
	Longitude   float64 `json:"longitude,omitempty"`
}

// ASNInfo represents ASN information
type ASNInfo struct {
	Number       int    `json:"number"`
	Organization string `json:"organization"`
	ISP          string `json:"isp,omitempty"`
}

// AssigneeInfo represents finding assignment
type AssigneeInfo struct {
	UserID     string     `json:"user_id"`
	UserEmail  string     `json:"user_email"`
	UserName   string     `json:"user_name"`
	Team       string     `json:"team"`
	AssignedAt time.Time  `json:"assigned_at"`
	AssignedBy string     `json:"assigned_by"`
}

// Contact represents a contact person
type Contact struct {
	Name  string `json:"name"`
	Email string `json:"email"`
	Team  string `json:"team,omitempty"`
}

// GenerateDeduplicationKey generates a unique key
func (f *ThreatIntelFinding) GenerateDeduplicationKey() string {
	components := []string{
		string(f.Type),
		f.Value,
		f.Source,
	}
	data := strings.Join(components, "|")
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:16])
}

// BuildCVEURLs populates CVE URLs
func (c *CVEReference) BuildCVEURLs() {
	if c.ID == "" {
		return
	}
	c.NVDUrl = "https://nvd.nist.gov/vuln/detail/" + c.ID
	c.URL = c.NVDUrl
}

// IsExpired checks if the IOC has expired
func (f *ThreatIntelFinding) IsExpired() bool {
	if f.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*f.ExpiresAt)
}

// IsHighConfidence checks if the finding has high confidence
func (f *ThreatIntelFinding) IsHighConfidence() bool {
	return f.Confidence == ConfidenceHigh
}

