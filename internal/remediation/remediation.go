// Package remediation provides automated security remediation capabilities.
//
// This module was consolidated from cs-remediation-agents.
package remediation

import (
	"context"
	"time"
)

// Action represents a remediation action
type Action struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Provider    string                 `json:"provider"`   // aws, azure, gcp
	ActionType  string                 `json:"action_type"` // isolate, revoke, block, quarantine
	Parameters  map[string]interface{} `json:"parameters"`
	Reversible  bool                   `json:"reversible"`
	RiskLevel   string                 `json:"risk_level"` // low, medium, high, critical
}

// RemediationRequest represents a request to remediate a finding
type RemediationRequest struct {
	ID           string    `json:"id"`
	FindingID    string    `json:"finding_id"`
	FindingType  string    `json:"finding_type"`
	Action       Action    `json:"action"`
	RequestedBy  string    `json:"requested_by"`
	RequestedAt  time.Time `json:"requested_at"`
	RequiresApproval bool  `json:"requires_approval"`
	ApprovalStatus   string `json:"approval_status"` // pending, approved, rejected
	ApprovedBy       string `json:"approved_by,omitempty"`
}

// RemediationResult represents the outcome of a remediation action
type RemediationResult struct {
	RequestID    string    `json:"request_id"`
	Status       string    `json:"status"`    // success, failed, rolled_back
	ExecutedAt   time.Time `json:"executed_at"`
	Message      string    `json:"message"`
	RollbackID   string    `json:"rollback_id,omitempty"`
	AuditTrail   []AuditEntry `json:"audit_trail"`
}

// AuditEntry represents an entry in the remediation audit trail
type AuditEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Action    string    `json:"action"`
	Actor     string    `json:"actor"`
	Details   string    `json:"details"`
}

// Agent executes remediation actions for a specific cloud provider
type Agent interface {
	// Provider returns the cloud provider name
	Provider() string
	// SupportedActions returns actions this agent can perform
	SupportedActions() []string
	// Execute performs a remediation action
	Execute(ctx context.Context, request RemediationRequest) (*RemediationResult, error)
	// Rollback reverses a previously executed remediation
	Rollback(ctx context.Context, rollbackID string) (*RemediationResult, error)
	// HealthCheck verifies agent connectivity
	HealthCheck(ctx context.Context) error
}

// ActionLibrary provides a catalog of available remediation actions
type ActionLibrary interface {
	// List returns all available actions
	List(ctx context.Context) ([]Action, error)
	// Get returns a specific action by ID
	Get(ctx context.Context, actionID string) (*Action, error)
	// GetByFinding returns recommended actions for a finding type
	GetByFinding(ctx context.Context, findingType string) ([]Action, error)
}

// WorkflowEngine orchestrates multi-step remediation workflows
type WorkflowEngine interface {
	// Start initiates a remediation workflow
	Start(ctx context.Context, request RemediationRequest) (string, error)
	// Status returns the current status of a workflow
	Status(ctx context.Context, workflowID string) (string, error)
	// Approve approves a pending workflow step
	Approve(ctx context.Context, workflowID string, approver string) error
	// Reject rejects a pending workflow step
	Reject(ctx context.Context, workflowID string, rejecter string, reason string) error
}
