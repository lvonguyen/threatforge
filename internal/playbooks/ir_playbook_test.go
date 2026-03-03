package playbooks

import (
	"context"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
)

func newTestManager(t *testing.T) *PlaybookManager {
	t.Helper()
	return NewPlaybookManager(zaptest.NewLogger(t))
}

func TestNewPlaybookManager(t *testing.T) {
	pm := newTestManager(t)
	if pm == nil {
		t.Fatal("NewPlaybookManager returned nil")
	}

	playbooks := pm.ListPlaybooks()
	if len(playbooks) == 0 {
		t.Error("NewPlaybookManager should load default playbooks")
	}
}

func TestPlaybookManager_GetPlaybook(t *testing.T) {
	pm := newTestManager(t)

	t.Run("existing_playbook", func(t *testing.T) {
		pb, ok := pm.GetPlaybook("pb-malware-001")
		if !ok {
			t.Fatal("expected to find pb-malware-001")
		}
		if pb == nil {
			t.Fatal("GetPlaybook returned nil for existing ID")
		}
		if pb.ID != "pb-malware-001" {
			t.Errorf("ID = %q, want %q", pb.ID, "pb-malware-001")
		}
		if pb.Category != "malware" {
			t.Errorf("Category = %q, want %q", pb.Category, "malware")
		}
	})

	t.Run("missing_playbook", func(t *testing.T) {
		_, ok := pm.GetPlaybook("nonexistent-pb")
		if ok {
			t.Error("GetPlaybook should return false for missing ID")
		}
	})
}

func TestPlaybookManager_GetPlaybooksByCategory(t *testing.T) {
	pm := newTestManager(t)

	t.Run("malware_category", func(t *testing.T) {
		pbs := pm.GetPlaybooksByCategory("malware")
		if len(pbs) == 0 {
			t.Error("expected at least one malware playbook")
		}
		for _, pb := range pbs {
			if pb.Category != "malware" {
				t.Errorf("playbook %q has category %q, want %q", pb.ID, pb.Category, "malware")
			}
		}
	})

	t.Run("phishing_category", func(t *testing.T) {
		pbs := pm.GetPlaybooksByCategory("phishing")
		if len(pbs) == 0 {
			t.Error("expected at least one phishing playbook")
		}
	})

	t.Run("nonexistent_category", func(t *testing.T) {
		pbs := pm.GetPlaybooksByCategory("totally_made_up")
		if len(pbs) != 0 {
			t.Errorf("expected 0 playbooks for unknown category, got %d", len(pbs))
		}
	})
}

func TestPlaybookManager_LoadPlaybook(t *testing.T) {
	pm := newTestManager(t)

	t.Run("valid_yaml", func(t *testing.T) {
		yamlData := []byte(`
id: "pb-test-001"
name: "Test Playbook"
description: "A test playbook"
category: "test"
severity: "low"
steps:
  - id: "step-1"
    name: "Do something"
    type: "manual"
    owner: "analyst"
    timeout: 10m
`)
		if err := pm.LoadPlaybook(yamlData); err != nil {
			t.Fatalf("LoadPlaybook returned error: %v", err)
		}

		pb, ok := pm.GetPlaybook("pb-test-001")
		if !ok {
			t.Fatal("loaded playbook not found")
		}
		if pb.Name != "Test Playbook" {
			t.Errorf("Name = %q, want %q", pb.Name, "Test Playbook")
		}
		if len(pb.Steps) != 1 {
			t.Errorf("Steps count = %d, want 1", len(pb.Steps))
		}
	})

	t.Run("invalid_yaml", func(t *testing.T) {
		// Unclosed bracket produces a genuine yaml parse error.
		err := pm.LoadPlaybook([]byte("{id: ["))
		if err == nil {
			t.Error("LoadPlaybook should return error for invalid YAML")
		}
	})
}

func TestPlaybookManager_ExportPlaybook(t *testing.T) {
	pm := newTestManager(t)

	t.Run("existing_playbook", func(t *testing.T) {
		data, err := pm.ExportPlaybook("pb-malware-001")
		if err != nil {
			t.Fatalf("ExportPlaybook returned error: %v", err)
		}
		if len(data) == 0 {
			t.Error("ExportPlaybook returned empty data")
		}
	})

	t.Run("missing_playbook", func(t *testing.T) {
		_, err := pm.ExportPlaybook("nonexistent-id")
		if err == nil {
			t.Error("ExportPlaybook should return error for missing playbook")
		}
	})
}

func TestPlaybookManager_GetPlaybookForTrigger(t *testing.T) {
	pm := newTestManager(t)
	ctx := context.Background()

	t.Run("matching_alert_trigger", func(t *testing.T) {
		pb, err := pm.GetPlaybookForTrigger(ctx, "alert", "crowdstrike", map[string]string{"type": "malware"})
		if err != nil {
			t.Fatalf("GetPlaybookForTrigger returned error: %v", err)
		}
		if pb == nil {
			t.Fatal("expected a matching playbook, got nil")
		}
		if pb.Category != "malware" {
			t.Errorf("matched playbook category = %q, want %q", pb.Category, "malware")
		}
	})

	t.Run("no_match_returns_error", func(t *testing.T) {
		_, err := pm.GetPlaybookForTrigger(ctx, "alert", "unknown_source", map[string]string{"type": "exotic"})
		if err == nil {
			t.Error("GetPlaybookForTrigger should return error when no match found")
		}
	})
}

func TestPlaybookManager_ListPlaybooks(t *testing.T) {
	pm := newTestManager(t)
	pbs := pm.ListPlaybooks()

	// Default playbooks: malware, phishing, data_breach
	if len(pbs) < 3 {
		t.Errorf("ListPlaybooks returned %d, expected at least 3 default playbooks", len(pbs))
	}

	for _, pb := range pbs {
		if pb.ID == "" {
			t.Error("playbook with empty ID found")
		}
		if pb.Name == "" {
			t.Errorf("playbook %q has empty Name", pb.ID)
		}
	}
}

func TestDefaultPlaybooks_MalwareContent(t *testing.T) {
	pm := newTestManager(t)
	pb, ok := pm.GetPlaybook("pb-malware-001")
	if !ok {
		t.Fatal("pb-malware-001 not found")
	}

	if pb.Severity != "high" {
		t.Errorf("Severity = %q, want %q", pb.Severity, "high")
	}
	if len(pb.Steps) == 0 {
		t.Error("malware playbook should have steps")
	}
	if pb.Escalation.TimeLimit != 4*time.Hour {
		t.Errorf("Escalation.TimeLimit = %v, want 4h", pb.Escalation.TimeLimit)
	}
	if len(pb.Metadata.Compliance) == 0 {
		t.Error("malware playbook should have compliance tags")
	}
}

func TestDefaultPlaybooks_BreachContent(t *testing.T) {
	pm := newTestManager(t)
	pb, ok := pm.GetPlaybook("pb-breach-001")
	if !ok {
		t.Fatal("pb-breach-001 not found")
	}

	if pb.Severity != "critical" {
		t.Errorf("Severity = %q, want %q", pb.Severity, "critical")
	}
	if pb.Category != "data_breach" {
		t.Errorf("Category = %q, want %q", pb.Category, "data_breach")
	}
}

func TestIRPlaybook_StructFields(t *testing.T) {
	now := time.Now()
	pb := &IRPlaybook{
		ID:          "test-pb",
		Name:        "Test",
		Description: "desc",
		Category:    "malware",
		Severity:    "medium",
		Triggers: []Trigger{
			{Type: "alert", Source: "splunk", Tags: map[string]string{"k": "v"}},
		},
		Steps: []Step{
			{
				ID:      "s1",
				Name:    "Step 1",
				Type:    "automated",
				Owner:   "analyst",
				Timeout: 5 * time.Minute,
				Actions: []Action{
					{Type: "isolate", Target: "host", Automated: true},
				},
				OnSuccess: "s2",
				OnFailure: "escalate",
			},
		},
		Escalation: Escalation{
			TimeLimit:   1 * time.Hour,
			NotifyRoles: []string{"lead"},
			Channels:    []string{"slack"},
		},
		Metadata: Metadata{
			Author:    "tester",
			Version:   "1.0",
			CreatedAt: now,
		},
	}

	if pb.Triggers[0].Tags["k"] != "v" {
		t.Errorf("Trigger.Tags[k] = %q, want %q", pb.Triggers[0].Tags["k"], "v")
	}
	if !pb.Steps[0].Actions[0].Automated {
		t.Error("Action.Automated should be true")
	}
	if pb.Steps[0].OnFailure != "escalate" {
		t.Errorf("Step.OnFailure = %q, want %q", pb.Steps[0].OnFailure, "escalate")
	}
}

func TestNewPlaybookManager_WithNilLogger(t *testing.T) {
	// Verify the manager works with a no-op logger from zap.
	logger := zap.NewNop()
	pm := NewPlaybookManager(logger)
	if pm == nil {
		t.Fatal("NewPlaybookManager with nop logger returned nil")
	}
	pbs := pm.ListPlaybooks()
	if len(pbs) == 0 {
		t.Error("expected default playbooks to load")
	}
}
