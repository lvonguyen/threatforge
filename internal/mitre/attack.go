// Package mitre provides MITRE ATT&CK framework mapping and analysis
package mitre

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// AttackFramework provides MITRE ATT&CK framework functionality
type AttackFramework struct {
	techniques map[string]*Technique
	tactics    map[string]*Tactic
	mu         sync.RWMutex
	logger     *zap.Logger
	httpClient *http.Client
}

// Technique represents a MITRE ATT&CK technique
type Technique struct {
	ID          string   `json:"id"`           // e.g., "T1059"
	Name        string   `json:"name"`         // e.g., "Command and Scripting Interpreter"
	Description string   `json:"description"`
	Tactics     []string `json:"tactics"`      // e.g., ["execution"]
	Platforms   []string `json:"platforms"`    // e.g., ["Windows", "Linux", "macOS"]
	Detection   string   `json:"detection"`
	Mitigations []string `json:"mitigations"`
	URL         string   `json:"url"`
	SubTechniques []SubTechnique `json:"sub_techniques,omitempty"`
}

// SubTechnique represents a sub-technique
type SubTechnique struct {
	ID          string `json:"id"`   // e.g., "T1059.001"
	Name        string `json:"name"` // e.g., "PowerShell"
	Description string `json:"description"`
}

// Tactic represents a MITRE ATT&CK tactic
type Tactic struct {
	ID          string `json:"id"`          // e.g., "TA0002"
	Name        string `json:"name"`        // e.g., "Execution"
	ShortName   string `json:"short_name"`  // e.g., "execution"
	Description string `json:"description"`
	URL         string `json:"url"`
}

// Mapping represents a technique mapping for an IOC or event
type Mapping struct {
	TechniqueID   string  `json:"technique_id"`
	TechniqueName string  `json:"technique_name"`
	TacticID      string  `json:"tactic_id"`
	TacticName    string  `json:"tactic_name"`
	Confidence    float64 `json:"confidence"` // 0.0 - 1.0
	Evidence      string  `json:"evidence"`
}

// NewAttackFramework creates a new MITRE ATT&CK framework instance
func NewAttackFramework(logger *zap.Logger) *AttackFramework {
	af := &AttackFramework{
		techniques: make(map[string]*Technique),
		tactics:    make(map[string]*Tactic),
		logger:     logger,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}

	// Initialize with common techniques
	af.initializeCommonTechniques()
	af.initializeTactics()

	return af
}

// MapIOC maps an IOC to potential MITRE ATT&CK techniques
func (af *AttackFramework) MapIOC(ctx context.Context, iocType, iocValue string) ([]Mapping, error) {
	mappings := make([]Mapping, 0)

	switch strings.ToLower(iocType) {
	case "ip", "ipv4", "ipv6":
		mappings = af.mapIPIndicator(iocValue)
	case "domain", "url":
		mappings = af.mapDomainIndicator(iocValue)
	case "hash", "md5", "sha1", "sha256":
		mappings = af.mapHashIndicator(iocValue)
	case "file", "filename":
		mappings = af.mapFileIndicator(iocValue)
	case "process", "command":
		mappings = af.mapProcessIndicator(iocValue)
	case "registry":
		mappings = af.mapRegistryIndicator(iocValue)
	default:
		af.logger.Debug("Unknown IOC type for MITRE mapping",
			zap.String("type", iocType),
		)
	}

	return mappings, nil
}

// MapEvent maps a security event to MITRE ATT&CK techniques
func (af *AttackFramework) MapEvent(ctx context.Context, eventType string, eventData map[string]interface{}) ([]Mapping, error) {
	mappings := make([]Mapping, 0)

	// Map based on event type
	switch strings.ToLower(eventType) {
	case "process_creation", "process_start":
		mappings = append(mappings, af.mapProcessCreation(eventData)...)
	case "network_connection":
		mappings = append(mappings, af.mapNetworkConnection(eventData)...)
	case "file_creation", "file_modification":
		mappings = append(mappings, af.mapFileActivity(eventData)...)
	case "registry_modification":
		mappings = append(mappings, af.mapRegistryActivity(eventData)...)
	case "authentication_failure":
		mappings = append(mappings, af.mapAuthFailure(eventData)...)
	case "privilege_escalation":
		mappings = append(mappings, af.mapPrivilegeEscalation(eventData)...)
	}

	return mappings, nil
}

// GetTechnique returns a technique by ID
func (af *AttackFramework) GetTechnique(id string) (*Technique, bool) {
	af.mu.RLock()
	defer af.mu.RUnlock()
	t, ok := af.techniques[strings.ToUpper(id)]
	return t, ok
}

// GetTactic returns a tactic by ID or short name
func (af *AttackFramework) GetTactic(id string) (*Tactic, bool) {
	af.mu.RLock()
	defer af.mu.RUnlock()
	t, ok := af.tactics[strings.ToLower(id)]
	return t, ok
}

// GetTechniquesByTactic returns all techniques for a given tactic
func (af *AttackFramework) GetTechniquesByTactic(tacticID string) []*Technique {
	af.mu.RLock()
	defer af.mu.RUnlock()

	result := make([]*Technique, 0)
	tacticShortName := strings.ToLower(tacticID)

	for _, t := range af.techniques {
		for _, tactic := range t.Tactics {
			if strings.ToLower(tactic) == tacticShortName {
				result = append(result, t)
				break
			}
		}
	}

	return result
}

// Mapping helper functions

func (af *AttackFramework) mapIPIndicator(ip string) []Mapping {
	return []Mapping{
		{
			TechniqueID:   "T1071",
			TechniqueName: "Application Layer Protocol",
			TacticID:      "TA0011",
			TacticName:    "Command and Control",
			Confidence:    0.6,
			Evidence:      fmt.Sprintf("IP indicator: %s", ip),
		},
	}
}

func (af *AttackFramework) mapDomainIndicator(domain string) []Mapping {
	mappings := []Mapping{
		{
			TechniqueID:   "T1071",
			TechniqueName: "Application Layer Protocol",
			TacticID:      "TA0011",
			TacticName:    "Command and Control",
			Confidence:    0.7,
			Evidence:      fmt.Sprintf("Domain indicator: %s", domain),
		},
	}

	// Check for DGA-like characteristics
	if af.looksDGA(domain) {
		mappings = append(mappings, Mapping{
			TechniqueID:   "T1568.002",
			TechniqueName: "Domain Generation Algorithms",
			TacticID:      "TA0011",
			TacticName:    "Command and Control",
			Confidence:    0.8,
			Evidence:      fmt.Sprintf("Potential DGA domain: %s", domain),
		})
	}

	return mappings
}

func (af *AttackFramework) mapHashIndicator(hash string) []Mapping {
	return []Mapping{
		{
			TechniqueID:   "T1204",
			TechniqueName: "User Execution",
			TacticID:      "TA0002",
			TacticName:    "Execution",
			Confidence:    0.5,
			Evidence:      fmt.Sprintf("Malicious file hash: %s", hash),
		},
	}
}

func (af *AttackFramework) mapFileIndicator(filename string) []Mapping {
	mappings := make([]Mapping, 0)
	lowerName := strings.ToLower(filename)

	// Check for common malware patterns
	if strings.Contains(lowerName, "mimikatz") {
		mappings = append(mappings, Mapping{
			TechniqueID:   "T1003",
			TechniqueName: "OS Credential Dumping",
			TacticID:      "TA0006",
			TacticName:    "Credential Access",
			Confidence:    0.9,
			Evidence:      fmt.Sprintf("Mimikatz-related file: %s", filename),
		})
	}

	return mappings
}

func (af *AttackFramework) mapProcessIndicator(command string) []Mapping {
	mappings := make([]Mapping, 0)
	lowerCmd := strings.ToLower(command)

	// PowerShell
	if strings.Contains(lowerCmd, "powershell") {
		mappings = append(mappings, Mapping{
			TechniqueID:   "T1059.001",
			TechniqueName: "PowerShell",
			TacticID:      "TA0002",
			TacticName:    "Execution",
			Confidence:    0.7,
			Evidence:      "PowerShell execution detected",
		})
	}

	// Encoded commands
	if strings.Contains(lowerCmd, "-encodedcommand") || strings.Contains(lowerCmd, "-enc") {
		mappings = append(mappings, Mapping{
			TechniqueID:   "T1027",
			TechniqueName: "Obfuscated Files or Information",
			TacticID:      "TA0005",
			TacticName:    "Defense Evasion",
			Confidence:    0.8,
			Evidence:      "Encoded command detected",
		})
	}

	return mappings
}

func (af *AttackFramework) mapRegistryIndicator(regPath string) []Mapping {
	mappings := make([]Mapping, 0)
	lowerPath := strings.ToLower(regPath)

	// Persistence locations
	if strings.Contains(lowerPath, "run") || strings.Contains(lowerPath, "runonce") {
		mappings = append(mappings, Mapping{
			TechniqueID:   "T1547.001",
			TechniqueName: "Registry Run Keys / Startup Folder",
			TacticID:      "TA0003",
			TacticName:    "Persistence",
			Confidence:    0.8,
			Evidence:      fmt.Sprintf("Registry persistence: %s", regPath),
		})
	}

	return mappings
}

func (af *AttackFramework) mapProcessCreation(data map[string]interface{}) []Mapping {
	mappings := make([]Mapping, 0)

	if cmdLine, ok := data["command_line"].(string); ok {
		mappings = append(mappings, af.mapProcessIndicator(cmdLine)...)
	}

	return mappings
}

func (af *AttackFramework) mapNetworkConnection(data map[string]interface{}) []Mapping {
	return []Mapping{
		{
			TechniqueID:   "T1071",
			TechniqueName: "Application Layer Protocol",
			TacticID:      "TA0011",
			TacticName:    "Command and Control",
			Confidence:    0.5,
			Evidence:      "Network connection detected",
		},
	}
}

func (af *AttackFramework) mapFileActivity(data map[string]interface{}) []Mapping {
	mappings := make([]Mapping, 0)

	if filename, ok := data["filename"].(string); ok {
		mappings = append(mappings, af.mapFileIndicator(filename)...)
	}

	return mappings
}

func (af *AttackFramework) mapRegistryActivity(data map[string]interface{}) []Mapping {
	mappings := make([]Mapping, 0)

	if regPath, ok := data["registry_path"].(string); ok {
		mappings = append(mappings, af.mapRegistryIndicator(regPath)...)
	}

	return mappings
}

func (af *AttackFramework) mapAuthFailure(data map[string]interface{}) []Mapping {
	return []Mapping{
		{
			TechniqueID:   "T1110",
			TechniqueName: "Brute Force",
			TacticID:      "TA0006",
			TacticName:    "Credential Access",
			Confidence:    0.6,
			Evidence:      "Authentication failure detected",
		},
	}
}

func (af *AttackFramework) mapPrivilegeEscalation(data map[string]interface{}) []Mapping {
	return []Mapping{
		{
			TechniqueID:   "T1068",
			TechniqueName: "Exploitation for Privilege Escalation",
			TacticID:      "TA0004",
			TacticName:    "Privilege Escalation",
			Confidence:    0.7,
			Evidence:      "Privilege escalation activity detected",
		},
	}
}

func (af *AttackFramework) looksDGA(domain string) bool {
	// Simple heuristic for DGA detection
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return false
	}

	subdomain := parts[0]
	// High entropy, long random-looking subdomain
	return len(subdomain) > 12 && af.hasHighEntropy(subdomain)
}

func (af *AttackFramework) hasHighEntropy(s string) bool {
	// Simple entropy check - count unique characters
	chars := make(map[rune]bool)
	for _, c := range s {
		chars[c] = true
	}
	ratio := float64(len(chars)) / float64(len(s))
	return ratio > 0.6
}

func (af *AttackFramework) initializeCommonTechniques() {
	af.mu.Lock()
	defer af.mu.Unlock()

	// Add common techniques
	techniques := []*Technique{
		{ID: "T1059", Name: "Command and Scripting Interpreter", Tactics: []string{"execution"}},
		{ID: "T1059.001", Name: "PowerShell", Tactics: []string{"execution"}},
		{ID: "T1059.003", Name: "Windows Command Shell", Tactics: []string{"execution"}},
		{ID: "T1003", Name: "OS Credential Dumping", Tactics: []string{"credential-access"}},
		{ID: "T1003.001", Name: "LSASS Memory", Tactics: []string{"credential-access"}},
		{ID: "T1071", Name: "Application Layer Protocol", Tactics: []string{"command-and-control"}},
		{ID: "T1110", Name: "Brute Force", Tactics: []string{"credential-access"}},
		{ID: "T1068", Name: "Exploitation for Privilege Escalation", Tactics: []string{"privilege-escalation"}},
		{ID: "T1027", Name: "Obfuscated Files or Information", Tactics: []string{"defense-evasion"}},
		{ID: "T1204", Name: "User Execution", Tactics: []string{"execution"}},
		{ID: "T1547", Name: "Boot or Logon Autostart Execution", Tactics: []string{"persistence", "privilege-escalation"}},
		{ID: "T1547.001", Name: "Registry Run Keys / Startup Folder", Tactics: []string{"persistence", "privilege-escalation"}},
		{ID: "T1568", Name: "Dynamic Resolution", Tactics: []string{"command-and-control"}},
		{ID: "T1568.002", Name: "Domain Generation Algorithms", Tactics: []string{"command-and-control"}},
	}

	for _, t := range techniques {
		t.URL = fmt.Sprintf("https://attack.mitre.org/techniques/%s/", t.ID)
		af.techniques[t.ID] = t
	}
}

func (af *AttackFramework) initializeTactics() {
	af.mu.Lock()
	defer af.mu.Unlock()

	tactics := []*Tactic{
		{ID: "TA0001", Name: "Initial Access", ShortName: "initial-access"},
		{ID: "TA0002", Name: "Execution", ShortName: "execution"},
		{ID: "TA0003", Name: "Persistence", ShortName: "persistence"},
		{ID: "TA0004", Name: "Privilege Escalation", ShortName: "privilege-escalation"},
		{ID: "TA0005", Name: "Defense Evasion", ShortName: "defense-evasion"},
		{ID: "TA0006", Name: "Credential Access", ShortName: "credential-access"},
		{ID: "TA0007", Name: "Discovery", ShortName: "discovery"},
		{ID: "TA0008", Name: "Lateral Movement", ShortName: "lateral-movement"},
		{ID: "TA0009", Name: "Collection", ShortName: "collection"},
		{ID: "TA0010", Name: "Exfiltration", ShortName: "exfiltration"},
		{ID: "TA0011", Name: "Command and Control", ShortName: "command-and-control"},
		{ID: "TA0040", Name: "Impact", ShortName: "impact"},
	}

	for _, t := range tactics {
		t.URL = fmt.Sprintf("https://attack.mitre.org/tactics/%s/", t.ID)
		af.tactics[t.ShortName] = t
		af.tactics[t.ID] = t
	}
}

// ExportMappingsToJSON exports mappings to JSON format
func ExportMappingsToJSON(mappings []Mapping) ([]byte, error) {
	return json.MarshalIndent(mappings, "", "  ")
}

