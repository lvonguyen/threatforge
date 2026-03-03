package compliance

import (
	"testing"
	"time"
)

func TestFindingTypeConstants(t *testing.T) {
	tests := []struct {
		name     string
		ft       FindingType
		expected string
	}{
		{"ip", FindingTypeIP, "ip"},
		{"domain", FindingTypeDomain, "domain"},
		{"url", FindingTypeURL, "url"},
		{"file_hash", FindingTypeFileHash, "file_hash"},
		{"email", FindingTypeEmail, "email"},
		{"cve", FindingTypeCVE, "cve"},
		{"malware", FindingTypeMalware, "malware"},
		{"threat_actor", FindingTypeActor, "threat_actor"},
		{"campaign", FindingTypeCampaign, "campaign"},
		{"tool", FindingTypeTool, "tool"},
		{"attack_pattern", FindingTypeAttackPattern, "attack_pattern"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if string(tc.ft) != tc.expected {
				t.Errorf("FindingType %q = %q, want %q", tc.name, tc.ft, tc.expected)
			}
		})
	}
}

func TestConfidenceLevelConstants(t *testing.T) {
	tests := []struct {
		cl       ConfidenceLevel
		expected string
	}{
		{ConfidenceHigh, "high"},
		{ConfidenceMedium, "medium"},
		{ConfidenceLow, "low"},
		{ConfidenceUnknown, "unknown"},
	}
	for _, tc := range tests {
		t.Run(tc.expected, func(t *testing.T) {
			if string(tc.cl) != tc.expected {
				t.Errorf("ConfidenceLevel = %q, want %q", tc.cl, tc.expected)
			}
		})
	}
}

func TestWorkflowStatusConstants(t *testing.T) {
	tests := []struct {
		ws       WorkflowStatus
		expected string
	}{
		{StatusNew, "new"},
		{StatusTriaged, "triaged"},
		{StatusAssigned, "assigned"},
		{StatusInProgress, "in_progress"},
		{StatusActionable, "actionable"},
		{StatusRetired, "retired"},
		{StatusFalsePositive, "false_positive"},
	}
	for _, tc := range tests {
		t.Run(tc.expected, func(t *testing.T) {
			if string(tc.ws) != tc.expected {
				t.Errorf("WorkflowStatus = %q, want %q", tc.ws, tc.expected)
			}
		})
	}
}

func TestThreatIntelFinding_GenerateDeduplicationKey(t *testing.T) {
	t.Run("produces_consistent_key", func(t *testing.T) {
		f := &ThreatIntelFinding{
			Type:   FindingTypeIP,
			Value:  "192.168.1.1",
			Source: "misp",
		}
		k1 := f.GenerateDeduplicationKey()
		k2 := f.GenerateDeduplicationKey()
		if k1 != k2 {
			t.Errorf("deduplication key not deterministic: %q != %q", k1, k2)
		}
	})

	t.Run("different_inputs_produce_different_keys", func(t *testing.T) {
		f1 := &ThreatIntelFinding{Type: FindingTypeIP, Value: "1.1.1.1", Source: "misp"}
		f2 := &ThreatIntelFinding{Type: FindingTypeIP, Value: "2.2.2.2", Source: "misp"}
		k1 := f1.GenerateDeduplicationKey()
		k2 := f2.GenerateDeduplicationKey()
		if k1 == k2 {
			t.Error("different IOCs produced the same deduplication key")
		}
	})

	t.Run("key_is_hex_string", func(t *testing.T) {
		f := &ThreatIntelFinding{
			Type:   FindingTypeDomain,
			Value:  "evil.example.com",
			Source: "otx",
		}
		key := f.GenerateDeduplicationKey()
		for _, c := range key {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				t.Errorf("deduplication key %q contains non-hex character %q", key, c)
			}
		}
	})

	t.Run("source_contributes_to_key", func(t *testing.T) {
		f1 := &ThreatIntelFinding{Type: FindingTypeIP, Value: "1.1.1.1", Source: "misp"}
		f2 := &ThreatIntelFinding{Type: FindingTypeIP, Value: "1.1.1.1", Source: "otx"}
		if f1.GenerateDeduplicationKey() == f2.GenerateDeduplicationKey() {
			t.Error("different sources should produce different deduplication keys")
		}
	})
}

func TestThreatIntelFinding_IsExpired(t *testing.T) {
	t.Run("no_expiry_is_not_expired", func(t *testing.T) {
		f := &ThreatIntelFinding{}
		if f.IsExpired() {
			t.Error("finding with nil ExpiresAt should not be expired")
		}
	})

	t.Run("past_expiry_is_expired", func(t *testing.T) {
		past := time.Now().Add(-1 * time.Hour)
		f := &ThreatIntelFinding{ExpiresAt: &past}
		if !f.IsExpired() {
			t.Error("finding with past ExpiresAt should be expired")
		}
	})

	t.Run("future_expiry_is_not_expired", func(t *testing.T) {
		future := time.Now().Add(1 * time.Hour)
		f := &ThreatIntelFinding{ExpiresAt: &future}
		if f.IsExpired() {
			t.Error("finding with future ExpiresAt should not be expired")
		}
	})
}

func TestThreatIntelFinding_IsHighConfidence(t *testing.T) {
	tests := []struct {
		confidence ConfidenceLevel
		want       bool
	}{
		{ConfidenceHigh, true},
		{ConfidenceMedium, false},
		{ConfidenceLow, false},
		{ConfidenceUnknown, false},
	}

	for _, tc := range tests {
		t.Run(string(tc.confidence), func(t *testing.T) {
			f := &ThreatIntelFinding{Confidence: tc.confidence}
			if got := f.IsHighConfidence(); got != tc.want {
				t.Errorf("IsHighConfidence() = %v, want %v (confidence=%q)", got, tc.want, tc.confidence)
			}
		})
	}
}

func TestCVEReference_BuildCVEURLs(t *testing.T) {
	t.Run("builds_nvd_url", func(t *testing.T) {
		c := &CVEReference{ID: "CVE-2024-1234"}
		c.BuildCVEURLs()

		wantNVD := "https://nvd.nist.gov/vuln/detail/CVE-2024-1234"
		if c.NVDUrl != wantNVD {
			t.Errorf("NVDUrl = %q, want %q", c.NVDUrl, wantNVD)
		}
		if c.URL != wantNVD {
			t.Errorf("URL = %q, want %q", c.URL, wantNVD)
		}
	})

	t.Run("empty_id_is_noop", func(t *testing.T) {
		c := &CVEReference{ID: ""}
		c.BuildCVEURLs()
		if c.NVDUrl != "" {
			t.Errorf("NVDUrl should remain empty for empty ID, got %q", c.NVDUrl)
		}
		if c.URL != "" {
			t.Errorf("URL should remain empty for empty ID, got %q", c.URL)
		}
	})
}

func TestThreatIntelFinding_StructFields(t *testing.T) {
	now := time.Now()
	f := &ThreatIntelFinding{
		ID:              "find-001",
		Source:          "misp",
		SourceFindingID: "misp-42",
		Type:            FindingTypeFileHash,
		Category:        CategoryMalware,
		Value:           "abc123",
		Title:           "Ransomware hash",
		ThreatLevel:     "high",
		Confidence:      ConfidenceHigh,
		AIRiskScore:     9.2,
		WorkflowStatus:  StatusNew,
		FirstSeenAt:     now,
		LastSeenAt:      now,
		MITRETactics:    []string{"TA0002"},
		MITRETechniques: []string{"T1059"},
		Tags:            map[string]string{"env": "prod"},
	}

	if f.ID != "find-001" {
		t.Errorf("ID = %q, want %q", f.ID, "find-001")
	}
	if f.Category != CategoryMalware {
		t.Errorf("Category = %q, want %q", f.Category, CategoryMalware)
	}
	if f.AIRiskScore != 9.2 {
		t.Errorf("AIRiskScore = %v, want 9.2", f.AIRiskScore)
	}
	if len(f.MITRETactics) != 1 || f.MITRETactics[0] != "TA0002" {
		t.Errorf("MITRETactics = %v, want [TA0002]", f.MITRETactics)
	}
	if f.Tags["env"] != "prod" {
		t.Errorf("Tags[env] = %q, want %q", f.Tags["env"], "prod")
	}
}
