package policy

import (
	"strings"
	"testing"
	"time"
)

func TestNewPolicyEngine(t *testing.T) {
	engine := NewPolicyEngine()
	if engine == nil {
		t.Fatal("Expected engine to be created")
	}
	if engine.policies == nil {
		t.Error("Expected policies slice to be initialized")
	}
}

func TestAddPolicy(t *testing.T) {
	engine := NewPolicyEngine()
	policy := Policy{
		ID:   "test-policy-1",
		Name: "Test Policy",
	}
	engine.AddPolicy(policy)
	if len(engine.policies) != 1 {
		t.Errorf("Expected 1 policy, got %d", len(engine.policies))
	}
}

func TestEvaluate_NoPolicies(t *testing.T) {
	engine := NewPolicyEngine()
	req := &Request{User: "alice"}
	result := engine.Evaluate(req)
	
	if result.Allowed {
		t.Error("Expected allowed to be false with no policies")
	}
	if result.Reason != "no_matching_policy" {
		t.Errorf("Expected reason 'no_matching_policy', got '%s'", result.Reason)
	}
}

func TestEvaluate_WithMatchingPolicy(t *testing.T) {
	engine := NewPolicyEngine()
	
	policy := Policy{
		ID:      "test-1",
		Name:    "Allow Admin",
		Enabled: true,
		Conditions: []Condition{
			{Field: "role", Operator: "==", Value: "admin"},
		},
		Actions: []Action{
			{Effect: "allow"},
		},
	}
	engine.AddPolicy(policy)
	
	req := &Request{Role: "admin"}
	result := engine.Evaluate(req)
	
	if !result.Allowed {
		t.Error("Expected request to be allowed")
	}
	if result.Reason != "Allow Admin" {
		t.Errorf("Expected reason 'Allow Admin', got '%s'", result.Reason)
	}
}

func TestEvaluate_WithNonMatchingPolicy(t *testing.T) {
	engine := NewPolicyEngine()
	
	policy := Policy{
		ID:      "test-1",
		Name:    "Allow Admin",
		Enabled: true,
		Conditions: []Condition{
			{Field: "role", Operator: "==", Value: "admin"},
		},
		Actions: []Action{
			{Effect: "allow"},
		},
	}
	engine.AddPolicy(policy)
	
	req := &Request{Role: "user"}
	result := engine.Evaluate(req)
	
	if result.Allowed {
		t.Error("Expected request to be denied")
	}
	if result.Reason != "no_matching_policy" {
		t.Errorf("Expected reason 'no_matching_policy', got '%s'", result.Reason)
	}
}

func TestEvaluate_DisabledPolicy(t *testing.T) {
	engine := NewPolicyEngine()
	
	policy := Policy{
		ID:      "test-1",
		Name:    "Allow Admin",
		Enabled: false,
		Conditions: []Condition{
			{Field: "role", Operator: "==", Value: "admin"},
		},
		Actions: []Action{
			{Effect: "allow"},
		},
	}
	engine.AddPolicy(policy)
	
	req := &Request{Role: "admin"}
	result := engine.Evaluate(req)
	
	if result.Allowed {
		t.Error("Expected disabled policy to be skipped")
	}
}

func TestEvaluateCondition_StringEq(t *testing.T) {
	cond := Condition{Field: "user", Operator: "==", Value: "alice"}
	engine := NewPolicyEngine()
	
	req1 := &Request{User: "alice"}
	if !engine.evaluateCondition(cond, req1) {
		t.Error("Expected true for matching user")
	}
	
	req2 := &Request{User: "bob"}
	if engine.evaluateCondition(cond, req2) {
		t.Error("Expected false for non-matching user")
	}
}

func TestEvaluateCondition_StringNeq(t *testing.T) {
	cond := Condition{Field: "user", Operator: "!=", Value: "alice"}
	engine := NewPolicyEngine()
	
	req1 := &Request{User: "bob"}
	if !engine.evaluateCondition(cond, req1) {
		t.Error("Expected true for bob != alice")
	}
	
	req2 := &Request{User: "alice"}
	if engine.evaluateCondition(cond, req2) {
		t.Error("Expected false for alice != alice")
	}
}

func TestEvaluateCondition_StringIn(t *testing.T) {
	cond := Condition{Field: "role", Operator: "in", Value: []string{"admin", "editor"}}
	engine := NewPolicyEngine()
	
	req1 := &Request{Role: "editor"}
	if !engine.evaluateCondition(cond, req1) {
		t.Error("Expected true for editor in list")
	}
	
	req2 := &Request{Role: "viewer"}
	if engine.evaluateCondition(cond, req2) {
		t.Error("Expected false for viewer not in list")
	}
}

func TestEvaluateCondition_StringNotIn(t *testing.T) {
	cond := Condition{Field: "ip", Operator: "not_in", Value: []string{"10.0.0.1"}}
	engine := NewPolicyEngine()
	
	req1 := &Request{IP: "192.168.1.1"}
	if !engine.evaluateCondition(cond, req1) {
		t.Error("Expected true for IP not in list")
	}
	
	req2 := &Request{IP: "10.0.0.1"}
	if engine.evaluateCondition(cond, req2) {
		t.Error("Expected false for IP in list")
	}
}

func TestEvaluateCondition_Time(t *testing.T) {
	now := time.Now()
	past := now.Add(-1 * time.Hour)
	future := now.Add(1 * time.Hour)
	
	engine := NewPolicyEngine()
	
	condLT := Condition{Field: "time", Operator: "<", Value: future}
	if !engine.evaluateCondition(condLT, &Request{Time: now}) {
		t.Error("Expected now < future to be true")
	}
	
	condGT := Condition{Field: "time", Operator: ">", Value: past}
	if !engine.evaluateCondition(condGT, &Request{Time: now}) {
		t.Error("Expected now > past to be true")
	}
}

func TestEvaluateCondition_Device(t *testing.T) {
	cond := Condition{Field: "device", Operator: "==", Value: "corp-laptop-1"}
	engine := NewPolicyEngine()
	
	req1 := &Request{Device: "corp-laptop-1"}
	if !engine.evaluateCondition(cond, req1) {
		t.Error("Expected true for matching device")
	}
}

func TestEvaluateCondition_InvalidField(t *testing.T) {
	cond := Condition{Field: "unknown", Operator: "==", Value: "test"}
	engine := NewPolicyEngine()
	req := &Request{}
	
	if engine.evaluateCondition(cond, req) {
		t.Error("Expected false for unknown field")
	}
}

func TestGeneratePolicy(t *testing.T) {
	conditions := []Condition{{Field: "role", Operator: "==", Value: "admin"}}
	actions := []Action{{Effect: "allow"}}
	
	policy := GeneratePolicy("Test Generate", conditions, actions)
	
	if policy.Name != "Test Generate" {
		t.Errorf("Expected name 'Test Generate', got '%s'", policy.Name)
	}
	if !policy.Enabled {
		t.Error("Expected generated policy to be enabled")
	}
	if len(policy.Conditions) != 1 {
		t.Errorf("Expected 1 condition, got %d", len(policy.Conditions))
	}
}

func TestGetPolicy(t *testing.T) {
	engine := NewPolicyEngine()
	policy := Policy{ID: "test-id", Name: "Test"}
	engine.AddPolicy(policy)
	
	p := engine.GetPolicy("test-id")
	if p == nil {
		t.Fatal("Expected to retrieve policy")
	}
	if p.Name != "Test" {
		t.Errorf("Expected name 'Test', got '%s'", p.Name)
	}
	
	missing := engine.GetPolicy("not-found")
	if missing != nil {
		t.Error("Expected nil for missing policy")
	}
}

func TestGenerateReport(t *testing.T) {
	engine := NewPolicyEngine()
	engine.AddPolicy(Policy{
		Name:     "Test Policy",
		Enabled:  true,
		Type:     TypeAccessPolicy,
		Priority: 1,
	})
	
	report := GenerateReport(engine)
	if !strings.Contains(report, "Zero Trust Policy Report") {
		t.Error("Expected report header")
	}
	if !strings.Contains(report, "Test Policy") {
		t.Error("Expected policy name in report")
	}
}

func TestGetEvaluationResult(t *testing.T) {
	result := &EvaluationResult{Allowed: true, Reason: "test"}
	r := GetEvaluationResult(result)
	
	if r != result {
		t.Error("Expected same pointer to be returned")
	}
}
