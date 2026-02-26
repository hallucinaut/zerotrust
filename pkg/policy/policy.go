// Package policy provides zero trust policy management.
package policy

import (
	"time"
)

// PolicyType represents a policy type.
type PolicyType string

const (
	TypeAccessPolicy   PolicyType = "access"
	TypeNetworkPolicy  PolicyType = "network"
	TypeDataPolicy     PolicyType = "data"
	TypeIdentityPolicy PolicyType = "identity"
	TypeDevicePolicy   PolicyType = "device"
)

// Policy represents a zero trust policy.
type Policy struct {
	ID         string
	Name       string
	Type       PolicyType
	Enabled    bool
	Priority   int
	Conditions []Condition
	Actions    []Action
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// Condition represents a policy condition.
type Condition struct {
	Field    string
	Operator string
	Value    interface{}
	Effect   string
}

// Action represents a policy action.
type Action struct {
	Type       string
	Resource   string
	Effect     string
	Conditions []Condition
}

// PolicyEngine evaluates policies.
type PolicyEngine struct {
	policies []Policy
}

// NewPolicyEngine creates a new policy engine.
func NewPolicyEngine() *PolicyEngine {
	return &PolicyEngine{
		policies: make([]Policy, 0),
	}
}

// AddPolicy adds a policy.
func (e *PolicyEngine) AddPolicy(policy Policy) {
	e.policies = append(e.policies, policy)
}

// Evaluate evaluates policies for a request.
func (e *PolicyEngine) Evaluate(request *Request) *EvaluationResult {
	result := &EvaluationResult{
		Allowed: false,
		Reason:  "no_matching_policy",
	}

	for _, policy := range e.policies {
		if !policy.Enabled {
			continue
		}

		if e.matchesPolicy(policy, request) {
			result.Allowed = policy.Actions[0].Effect == "allow"
			result.Reason = policy.Name
			break
		}
	}

	return result
}

// matchesPolicy checks if policy matches request.
func (e *PolicyEngine) matchesPolicy(policy Policy, request *Request) bool {
	for _, condition := range policy.Conditions {
		if !e.evaluateCondition(condition, request) {
			return false
		}
	}

	return true
}

// evaluateCondition evaluates a condition.
func (e *PolicyEngine) evaluateCondition(condition Condition, request *Request) bool {
	switch condition.Field {
	case "user":
		return evaluateStringCondition(condition, request.User)
	case "role":
		return evaluateStringCondition(condition, request.Role)
	case "ip":
		return evaluateStringCondition(condition, request.IP)
	case "device":
		return evaluateStringCondition(condition, request.Device)
	case "time":
		return evaluateTimeCondition(condition, request.Time)
	default:
		return false
	}
}

// evaluateStringCondition evaluates string condition.
func evaluateStringCondition(condition Condition, value string) bool {
	switch condition.Operator {
	case "==":
		return value == condition.Value.(string)
	case "!=":
		return value != condition.Value.(string)
	case "in":
		return contains(condition.Value.([]string), value)
	case "not_in":
		return !contains(condition.Value.([]string), value)
	}

	return false
}

// evaluateTimeCondition evaluates time condition.
func evaluateTimeCondition(condition Condition, currentTime time.Time) bool {
	t, ok := condition.Value.(time.Time)
	if !ok {
		return false
	}

	switch condition.Operator {
	case ">":
		return !currentTime.Before(t)
	case "<":
		return currentTime.Before(t)
	case ">=":
		return currentTime.After(t) || currentTime.Equal(t)
	case "<=":
		return !currentTime.After(t)
	}

	return false
}

// contains checks if slice contains value.
func contains(slice []string, value string) bool {
	for _, s := range slice {
		if s == value {
			return true
		}
	}
	return false
}

// Request represents a policy request.
type Request struct {
	User     string
	Role     string
	IP       string
	Device   string
	Time     time.Time
	Resource string
}

// EvaluationResult contains policy evaluation result.
type EvaluationResult struct {
	Allowed  bool
	Reason   string
	PolicyID string
}

// GeneratePolicy generates a zero trust policy.
func GeneratePolicy(name string, conditions []Condition, actions []Action) Policy {
	return Policy{
		ID:         "policy-" + time.Now().Format("20060102150405"),
		Name:       name,
		Type:       TypeAccessPolicy,
		Enabled:    true,
		Priority:   100,
		Conditions: conditions,
		Actions:    actions,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}
}

// GetPolicy returns policy by ID.
func (e *PolicyEngine) GetPolicy(id string) *Policy {
	for i := range e.policies {
		if e.policies[i].ID == id {
			return &e.policies[i]
		}
	}

	return nil
}

// GenerateReport generates policy report.
func GenerateReport(engine *PolicyEngine) string {
	var report string

	report += "=== Zero Trust Policy Report ===\n\n"
	report += "Total Policies: " + string(rune(len(engine.policies)+48)) + "\n"

	for i, policy := range engine.policies {
		status := "✓"
		if !policy.Enabled {
			status = "✗"
		}
		report += "\n[" + string(rune(i+49)) + "] " + status + " " + policy.Name + "\n"
		report += "    Type: " + string(policy.Type) + "\n"
		report += "    Priority: " + string(rune(policy.Priority+48)) + "\n"
		report += "    Conditions: " + string(rune(len(policy.Conditions)+48)) + "\n"
		report += "    Actions: " + string(rune(len(policy.Actions)+48)) + "\n"
	}

	return report
}

// GetEvaluationResult returns evaluation result.
func GetEvaluationResult(result *EvaluationResult) *EvaluationResult {
	return result
}
