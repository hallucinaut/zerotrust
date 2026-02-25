# zerotrust - Zero Trust Architecture Validator

[![Go](https://img.shields.io/badge/Go-1.21-blue)](https://go.dev/)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

**Validate and enforce zero trust architecture principles for modern security.**

Assess your infrastructure against zero trust principles and ensure proper implementation.

## 🚀 Features

- **Principle Validation**: Validate all 5 zero trust principles
- **Policy Management**: Create and manage zero trust policies
- **Configuration Assessment**: Assess zero trust posture
- **Compliance Checking**: Check security compliance
- **Risk Scoring**: Calculate zero trust risk scores
- **Policy Engine**: Evaluate access policies

## 📦 Installation

### Build from Source

```bash
git clone https://github.com/hallucinaut/zerotrust.git
cd zerotrust
go build -o zerotrust ./cmd/zerotrust
sudo mv zerotrust /usr/local/bin/
```

### Install via Go

```bash
go install github.com/hallucinaut/zerotrust/cmd/zerotrust@latest
```

## 🎯 Usage

### Assess Zero Trust

```bash
# Assess zero trust configuration
zerotrust assess config.json

# Validate policies
zerotrust validate policies.yaml
```

### Manage Policies

```bash
# Manage zero trust policies
zerotrust policy list
zerotrust policy add
```

### Check Posture

```bash
# Check zero trust posture
zerotrust check
```

### Programmatic Usage

```go
package main

import (
    "fmt"
    "github.com/hallucinaut/zerotrust/pkg/validate"
    "github.com/hallucinaut/zerotrust/pkg/policy"
)

func main() {
    // Create validator
    validator := validate.NewValidator()
    
    // Configure zero trust
    config := &validate.Config{
        NetworkZeroTrust:    true,
        MultiFactorAuth:     true,
        RoleBasedAccess:     true,
        NetworkSegmentation: true,
        // ... other settings
    }
    
    // Assess posture
    assessment := validator.Assess(config)
    
    fmt.Printf("Score: %.0f%%\n", assessment.OverallScore*100)
    fmt.Printf("Status: %s\n", assessment.ComplianceStatus)
    
    // Create policy engine
    engine := policy.NewPolicyEngine()
    engine.AddPolicy(policy.GeneratePolicy("allow-admin", conditions, actions))
    
    // Evaluate request
    result := engine.Evaluate(request)
    fmt.Printf("Allowed: %v\n", result.Allowed)
}
```

## 🔍 Zero Trust Principles

### 1. Never Trust

Verify all traffic regardless of origin:
- No implicit trust for internal networks
- Verify all connections
- Encrypt all communications

### 2. Always Verify

Continuous authentication and authorization:
- Multi-factor authentication
- Continuous session validation
- Device health verification

### 3. Least Privilege

Minimum necessary access:
- Role-based access control
- Just-in-time access
- Purpose-limited permissions

### 4. Microsegmentation

Network segmentation:
- Zone-based architecture
- Service isolation
- VPC segmentation

### 5. Assume Breach

Limit damage from breaches:
- Incident response readiness
- Full telemetry
- Lateral movement prevention

## 📊 Assessment Levels

| Score | Level | Status |
|-------|-------|--------|
| 90-100% | EXCELLENT | Fully compliant |
| 70-89% | GOOD | Mostly compliant |
| 50-69% | FAIR | Partial compliance |
| 30-49% | POOR | Significant gaps |
| <30% | CRITICAL | Major remediation needed |

## 🧪 Testing

```bash
# Run all tests
go test ./...

# Run with coverage
go test -cover ./...

# Run specific test
go test -v ./pkg/validate -run TestAssessZeroTrust
```

## 📋 Example Output

```
Assessing zero trust: config.json

=== Zero Trust Assessment Report ===

Assessment Date: 2024-02-25 16:00:00
Overall Score: 85%
Compliance: COMPLIANT

Principle Checks:
  [1] ✓ never-trust (90%)
  [2] ✓ always-verify (85%)
  [3] ✓ least-privilege (80%)
  [4] ✓ microsegmentation (85%)
  [5] ✓ assume-breach (85%)

No recommendations - excellent posture!
```

## 🔒 Security Use Cases

- **Zero Trust Implementation**: Validate deployment progress
- **Security Audits**: Assess compliance with zero trust
- **Risk Assessment**: Identify security gaps
- **Policy Management**: Manage access policies
- **Architecture Review**: Validate zero trust design

## 🛡️ Best Practices

1. **Implement all 5 principles** before claiming zero trust
2. **Continuous monitoring** is essential
3. **Regular assessments** to maintain posture
4. **Policy automation** for scale
5. **Incident response** readiness
6. **Device compliance** checking
7. **Least privilege** enforcement

## 🏗️ Architecture

```
zerotrust/
├── cmd/
│   └── zerotrust/
│       └── main.go          # CLI entry point
├── pkg/
│   ├── validate/
│   │   ├── validate.go     # Validation logic
│   │   └── validate_test.go # Unit tests
│   └── policy/
│       ├── policy.go       # Policy management
│       └── policy_test.go  # Unit tests
└── README.md
```

## 📄 License

MIT License

## 🙏 Acknowledgments

- Zero trust architecture researchers
- NIST Zero Trust Standards
- Security practitioners worldwide

## 🔗 Resources

- [NIST Zero Trust Architecture](https://csrc.nist.gov/publications/detail/sp/800-207/final)
- [Forrester Zero Trust](https://www.forrester.com/report/the-zero-trust-trends-report)
- [CISA Zero Trust Strategy](https://www.cisa.gov/zero-trust-strategy)

---

**Built with ❤️ by [hallucinaut](https://github.com/hallucinaut)**