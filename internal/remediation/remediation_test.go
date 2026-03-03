package remediation

import (
	"context"
	"testing"
	"time"
)

func TestAction_StructFields(t *testing.T) {
	tests := []struct {
		name   string
		action Action
	}{
		{
			name: "aws_isolate",
			action: Action{
				ID:          "act-001",
				Name:        "Isolate EC2 Instance",
				Description: "Remove instance from security group",
				Provider:    "aws",
				ActionType:  "isolate",
				Parameters:  map[string]interface{}{"instance_id": "i-12345678"},
				Reversible:  true,
				RiskLevel:   "high",
			},
		},
		{
			name: "azure_revoke",
			action: Action{
				ID:         "act-002",
				Provider:   "azure",
				ActionType: "revoke",
				Reversible: false,
				RiskLevel:  "critical",
			},
		},
		{
			name: "gcp_block",
			action: Action{
				ID:         "act-003",
				Provider:   "gcp",
				ActionType: "block",
				RiskLevel:  "medium",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.action.ID == "" {
				t.Error("Action.ID must not be empty")
			}
			if tc.action.Provider == "" {
				t.Error("Action.Provider must not be empty")
			}
			if tc.action.ActionType == "" {
				t.Error("Action.ActionType must not be empty")
			}
			if tc.action.RiskLevel == "" {
				t.Error("Action.RiskLevel must not be empty")
			}
		})
	}
}

func TestAction_Parameters(t *testing.T) {
	a := Action{
		ID:         "act-params",
		ActionType: "quarantine",
		Parameters: map[string]interface{}{
			"target":   "192.168.1.50",
			"duration": 3600,
			"notify":   true,
		},
	}

	if a.Parameters["target"] != "192.168.1.50" {
		t.Errorf("Parameters[target] = %v, want %q", a.Parameters["target"], "192.168.1.50")
	}
	if a.Parameters["duration"] != 3600 {
		t.Errorf("Parameters[duration] = %v, want 3600", a.Parameters["duration"])
	}
	if a.Parameters["notify"] != true {
		t.Errorf("Parameters[notify] = %v, want true", a.Parameters["notify"])
	}
}

func TestRemediationRequest_StructFields(t *testing.T) {
	now := time.Now()
	req := RemediationRequest{
		ID:          "req-001",
		FindingID:   "find-42",
		FindingType: "malware",
		Action: Action{
			ID:         "act-001",
			Provider:   "aws",
			ActionType: "isolate",
			RiskLevel:  "high",
		},
		RequestedBy:      "analyst@example.com",
		RequestedAt:      now,
		RequiresApproval: true,
		ApprovalStatus:   "pending",
	}

	if req.ID != "req-001" {
		t.Errorf("ID = %q, want %q", req.ID, "req-001")
	}
	if req.FindingID != "find-42" {
		t.Errorf("FindingID = %q, want %q", req.FindingID, "find-42")
	}
	if req.ApprovalStatus != "pending" {
		t.Errorf("ApprovalStatus = %q, want %q", req.ApprovalStatus, "pending")
	}
	if !req.RequiresApproval {
		t.Error("RequiresApproval should be true")
	}
	if req.Action.Provider != "aws" {
		t.Errorf("Action.Provider = %q, want %q", req.Action.Provider, "aws")
	}
}

func TestRemediationResult_StructFields(t *testing.T) {
	now := time.Now()
	result := RemediationResult{
		RequestID:  "req-001",
		Status:     "success",
		ExecutedAt: now,
		Message:    "Instance isolated successfully",
		RollbackID: "rb-001",
		AuditTrail: []AuditEntry{
			{
				Timestamp: now,
				Action:    "isolate",
				Actor:     "system",
				Details:   "Removed from sg-12345",
			},
		},
	}

	if result.RequestID != "req-001" {
		t.Errorf("RequestID = %q, want %q", result.RequestID, "req-001")
	}
	if result.Status != "success" {
		t.Errorf("Status = %q, want %q", result.Status, "success")
	}
	if result.RollbackID != "rb-001" {
		t.Errorf("RollbackID = %q, want %q", result.RollbackID, "rb-001")
	}
	if len(result.AuditTrail) != 1 {
		t.Errorf("AuditTrail length = %d, want 1", len(result.AuditTrail))
	}
	if result.AuditTrail[0].Actor != "system" {
		t.Errorf("AuditTrail[0].Actor = %q, want %q", result.AuditTrail[0].Actor, "system")
	}
}

func TestAuditEntry_StructFields(t *testing.T) {
	now := time.Now()
	entry := AuditEntry{
		Timestamp: now,
		Action:    "revoke_credentials",
		Actor:     "playbook-engine",
		Details:   "Revoked IAM key AKIAIOSFODNN7EXAMPLE",
	}

	if entry.Action != "revoke_credentials" {
		t.Errorf("Action = %q, want %q", entry.Action, "revoke_credentials")
	}
	if entry.Actor != "playbook-engine" {
		t.Errorf("Actor = %q, want %q", entry.Actor, "playbook-engine")
	}
	if entry.Timestamp != now {
		t.Errorf("Timestamp mismatch")
	}
}

func TestRemediationResult_StatusValues(t *testing.T) {
	statuses := []string{"success", "failed", "rolled_back"}
	for _, status := range statuses {
		t.Run(status, func(t *testing.T) {
			r := RemediationResult{Status: status}
			if r.Status != status {
				t.Errorf("Status = %q, want %q", r.Status, status)
			}
		})
	}
}

func TestRemediationRequest_ApprovalStatusValues(t *testing.T) {
	statuses := []string{"pending", "approved", "rejected"}
	for _, status := range statuses {
		t.Run(status, func(t *testing.T) {
			req := RemediationRequest{ApprovalStatus: status}
			if req.ApprovalStatus != status {
				t.Errorf("ApprovalStatus = %q, want %q", req.ApprovalStatus, status)
			}
		})
	}
}

func TestAction_RiskLevels(t *testing.T) {
	levels := []string{"low", "medium", "high", "critical"}
	for _, level := range levels {
		t.Run(level, func(t *testing.T) {
			a := Action{RiskLevel: level}
			if a.RiskLevel != level {
				t.Errorf("RiskLevel = %q, want %q", a.RiskLevel, level)
			}
		})
	}
}

func TestAction_Reversible(t *testing.T) {
	t.Run("reversible_action", func(t *testing.T) {
		a := Action{Reversible: true, ActionType: "isolate"}
		if !a.Reversible {
			t.Error("Reversible should be true")
		}
	})

	t.Run("irreversible_action", func(t *testing.T) {
		a := Action{Reversible: false, ActionType: "delete"}
		if a.Reversible {
			t.Error("Reversible should be false")
		}
	})
}

// TestAgentInterface verifies the Agent interface is satisfied by a mock,
// ensuring the interface contract is stable.
func TestAgentInterface(t *testing.T) {
	var _ Agent = (*mockAgent)(nil)

	m := &mockAgent{provider: "aws", actions: []string{"isolate", "revoke"}}
	ctx := context.Background()

	if m.Provider() != "aws" {
		t.Errorf("Provider() = %q, want %q", m.Provider(), "aws")
	}
	if len(m.SupportedActions()) != 2 {
		t.Errorf("SupportedActions() length = %d, want 2", len(m.SupportedActions()))
	}
	if err := m.HealthCheck(ctx); err != nil {
		t.Errorf("HealthCheck() unexpected error: %v", err)
	}

	req := RemediationRequest{ID: "req-test", Action: Action{Provider: "aws"}}
	result, err := m.Execute(ctx, req)
	if err != nil {
		t.Fatalf("Execute() unexpected error: %v", err)
	}
	if result.Status != "success" {
		t.Errorf("Execute() status = %q, want %q", result.Status, "success")
	}

	rb, err := m.Rollback(ctx, "rb-001")
	if err != nil {
		t.Fatalf("Rollback() unexpected error: %v", err)
	}
	if rb.Status != "rolled_back" {
		t.Errorf("Rollback() status = %q, want %q", rb.Status, "rolled_back")
	}
}

type mockAgent struct {
	provider string
	actions  []string
}

func (m *mockAgent) Provider() string           { return m.provider }
func (m *mockAgent) SupportedActions() []string { return m.actions }
func (m *mockAgent) Execute(_ context.Context, req RemediationRequest) (*RemediationResult, error) {
	return &RemediationResult{RequestID: req.ID, Status: "success"}, nil
}
func (m *mockAgent) Rollback(_ context.Context, rollbackID string) (*RemediationResult, error) {
	return &RemediationResult{RollbackID: rollbackID, Status: "rolled_back"}, nil
}
func (m *mockAgent) HealthCheck(_ context.Context) error { return nil }
