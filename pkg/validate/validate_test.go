package validate

import (
	"strings"
	"testing"
)

func TestNewValidator(t *testing.T) {
	v := NewValidator()
	if v == nil {
		t.Fatal("Expected Validator to be created")
	}
	if len(v.principles) != 5 {
		t.Errorf("Expected 5 principles, got %d", len(v.principles))
	}
}

func TestAssess_AllTrue(t *testing.T) {
	v := NewValidator()
	config := &Config{
		NetworkZeroTrust:    true,
		InternalTrust:       true,
		DeviceVerification:  true,
		MultiFactorAuth:     true,
		ContinuousAuth:      true,
		DeviceCompliance:    true,
		RoleBasedAccess:     true,
		PurposeLimitation:   true,
		MinimalPermissions:  true,
		NetworkSegmentation: true,
		ServiceIsolation:    true,
		VPCSegmentation:     true,
		IncidentResponse:    true,
		TelemetryEnabled:    true,
		LateralMovement:     true,
	}

	assessment := v.Assess(config)
	if assessment.OverallScore != 1.0 {
		t.Errorf("Expected score 1.0 for all true config, got %f", assessment.OverallScore)
	}
	if assessment.ComplianceStatus != "COMPLIANT" {
		t.Errorf("Expected status COMPLIANT, got %s", assessment.ComplianceStatus)
	}
	if len(assessment.Recommendations) != 0 {
		t.Errorf("Expected 0 recommendations, got %d", len(assessment.Recommendations))
	}
}

func TestAssess_AllFalse(t *testing.T) {
	v := NewValidator()
	config := &Config{} // all false

	assessment := v.Assess(config)
	if assessment.OverallScore > 0.3 {
		t.Errorf("Expected low score for all false config, got %f", assessment.OverallScore)
	}
	if assessment.ComplianceStatus != "NON_COMPLIANT" && assessment.ComplianceStatus != "CRITICAL" {
		t.Errorf("Expected status NON_COMPLIANT or CRITICAL, got %s", assessment.ComplianceStatus)
	}
	if len(assessment.Recommendations) != 5 {
		t.Errorf("Expected 5 recommendations, got %d", len(assessment.Recommendations))
	}
}

func TestCheckNeverTrust(t *testing.T) {
	v := NewValidator()
	
	// Test all true
	configAll := &Config{NetworkZeroTrust: true, InternalTrust: true, DeviceVerification: true}
	check := v.checkNeverTrust(configAll)
	if check.Score != 1.0 {
		t.Errorf("Expected score 1.0, got %f", check.Score)
	}
	
	// Test some false
	configSome := &Config{NetworkZeroTrust: false, InternalTrust: true, DeviceVerification: false}
	checkSome := v.checkNeverTrust(configSome)
	if checkSome.Score >= 1.0 {
		t.Errorf("Expected score < 1.0, got %f", checkSome.Score)
	}
	
	if check.Principle != PrincipleNeverTrust {
		t.Errorf("Expected principle %s, got %s", PrincipleNeverTrust, check.Principle)
	}
}

func TestCheckAlwaysVerify(t *testing.T) {
	v := NewValidator()
	config := &Config{MultiFactorAuth: true, ContinuousAuth: true, DeviceCompliance: true}
	check := v.checkAlwaysVerify(config)
	if check.Score != 1.0 {
		t.Errorf("Expected score 1.0, got %f", check.Score)
	}
	if check.Principle != PrincipleAlwaysVerify {
		t.Errorf("Expected principle %s, got %s", PrincipleAlwaysVerify, check.Principle)
	}
}

func TestCheckLeastPrivilege(t *testing.T) {
	v := NewValidator()
	config := &Config{RoleBasedAccess: true, PurposeLimitation: true, MinimalPermissions: true}
	check := v.checkLeastPrivilege(config)
	if check.Score != 1.0 {
		t.Errorf("Expected score 1.0, got %f", check.Score)
	}
	if check.Principle != PrincipleLeastPrivilege {
		t.Errorf("Expected principle %s, got %s", PrincipleLeastPrivilege, check.Principle)
	}
}

func TestCheckMicrosegmentation(t *testing.T) {
	v := NewValidator()
	config := &Config{NetworkSegmentation: true, ServiceIsolation: true, VPCSegmentation: true}
	check := v.checkMicrosegmentation(config)
	if check.Score != 1.0 {
		t.Errorf("Expected score 1.0, got %f", check.Score)
	}
	if check.Principle != PrincipleMicrosegmentation {
		t.Errorf("Expected principle %s, got %s", PrincipleMicrosegmentation, check.Principle)
	}
}

func TestCheckAssumeBreach(t *testing.T) {
	v := NewValidator()
	config := &Config{IncidentResponse: true, TelemetryEnabled: true, LateralMovement: true}
	check := v.checkAssumeBreach(config)
	if check.Score != 1.0 {
		t.Errorf("Expected score 1.0, got %f", check.Score)
	}
	if check.Principle != PrincipleAssumeBreach {
		t.Errorf("Expected principle %s, got %s", PrincipleAssumeBreach, check.Principle)
	}
}

func TestGetStatus(t *testing.T) {
	if getStatus(0.95) != "EXCELLENT" { t.Error("Expected EXCELLENT") }
	if getStatus(0.75) != "GOOD" { t.Error("Expected GOOD") }
	if getStatus(0.55) != "FAIR" { t.Error("Expected FAIR") }
	if getStatus(0.35) != "POOR" { t.Error("Expected POOR") }
	if getStatus(0.15) != "CRITICAL" { t.Error("Expected CRITICAL") }
}

func TestDetermineCompliance(t *testing.T) {
	if determineCompliance(0.85) != "COMPLIANT" { t.Error("Expected COMPLIANT") }
	if determineCompliance(0.65) != "AT_RISK" { t.Error("Expected AT_RISK") }
	if determineCompliance(0.45) != "NON_COMPLIANT" { t.Error("Expected NON_COMPLIANT") }
	if determineCompliance(0.25) != "CRITICAL" { t.Error("Expected CRITICAL") }
}

func TestGenerateReport(t *testing.T) {
	v := NewValidator()
	config := &Config{NetworkZeroTrust: true, MultiFactorAuth: true}
	assessment := v.Assess(config)
	
	report := GenerateReport(assessment)
	if !strings.Contains(report, "Zero Trust Assessment Report") {
		t.Error("Expected report header")
	}
	if !strings.Contains(report, "Overall Score") {
		t.Error("Expected Overall Score in report")
	}
}

func TestGetAssessment(t *testing.T) {
	assessment := &Assessment{OverallScore: 0.5}
	result := GetAssessment(assessment)
	if result != assessment {
		t.Error("Expected same assessment pointer")
	}
}
