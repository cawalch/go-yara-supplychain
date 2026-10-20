// Package analyzer orchestrates the multi-stage supply chain analysis pipeline.
package analyzer

// RiskLevel classifies the severity of detected package behaviors.
type RiskLevel string

const (
	RiskBenign   RiskLevel = "BENIGN"
	RiskLow      RiskLevel = "LOW"
	RiskMedium   RiskLevel = "MEDIUM"
	RiskHigh     RiskLevel = "HIGH"
	RiskCritical RiskLevel = "CRITICAL"
)

// Action dictates the recommended policy action for CI/CD gates.
type Action string

const (
	ActionPass  Action = "PASS"
	ActionWarn  Action = "WARN"
	ActionBlock Action = "BLOCK"
)

// EvidenceItem details a specific malicious or suspicious finding.
type EvidenceItem struct {
	RuleID      string    `json:"rule_id"`
	FilePath    string    `json:"file_path"`
	Severity    RiskLevel `json:"severity"`
	Category    string    `json:"category"`
	Description string    `json:"description"`
	Snippet     string    `json:"snippet,omitempty"`
}

// Verdict is the final determination of a package's safety and risk posture.
type Verdict struct {
	PackageName     string         `json:"package_name"`
	PackageVersion  string         `json:"package_version"`
	PackagePath     string         `json:"package_path"`
	RiskLevel       RiskLevel      `json:"risk_level"`
	Action          Action         `json:"action"`
	ConfidenceScore float64        `json:"confidence_score"` // 0.0 to 1.0
	HasInstallHooks bool           `json:"has_install_hooks"`
	HadObfuscation  bool           `json:"had_obfuscation"`
	Evidence        []EvidenceItem `json:"evidence,omitempty"`
}
