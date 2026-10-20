package analyzer

import (
	"fmt"
	"regexp"

	"github.com/cawalch/go-yara-supplychain/pkg/deobfuscate"
	"github.com/cawalch/go-yara-supplychain/pkg/ecosystems/npm"
	"github.com/cawalch/go-yara-supplychain/pkg/rules"
	"github.com/cawalch/go-yara/compiler"
)

var (
	pipeToShellRE = regexp.MustCompile(`(?i)(curl|wget)\s+[^|;` + "`" + `\r\n]+\|\s*(sh|bash|zsh|python)`)
)

// Engine coordinates the multi-stage supply chain analysis pipeline.
type Engine struct {
	compiledProg *compiler.CompiledProgram
}

// NewEngine creates an initialized Engine backed by compiled supply chain YARA rules.
func NewEngine() (*Engine, error) {
	prog, err := rules.GetCompiledRules()
	if err != nil {
		return nil, fmt.Errorf("initializing analyzer engine: %w", err)
	}
	return &Engine{compiledProg: prog}, nil
}

// AnalyzePackage analyzes an inspected npm package and returns an actionable verdict.
func (e *Engine) AnalyzePackage(pkg *npm.InspectedPackage) (*Verdict, error) {
	scanner := compiler.NewScanner(e.compiledProg)
	defer scanner.Close()

	verdict := &Verdict{
		PackageName:     pkg.Manifest.Name,
		PackageVersion:  pkg.Manifest.Version,
		PackagePath:     pkg.Path,
		RiskLevel:       RiskBenign,
		Action:          ActionPass,
		HasInstallHooks: pkg.HasHooks,
		Evidence:        make([]EvidenceItem, 0),
	}

	var score float64
	hadObfuscation := false

	// 1. Analyze Package Lifecycle Scripts (package.json scripts)
	for hookName, hookCmd := range pkg.HookScripts {
		// Check for direct shell pipes in install scripts (e.g. curl ... | bash)
		if pipeToShellRE.MatchString(hookCmd) {
			score += 0.95
			verdict.Evidence = append(verdict.Evidence, EvidenceItem{
				RuleID:      "Suspicious_Piped_Shell",
				FilePath:    "package.json",
				Severity:    RiskCritical,
				Category:    "dropper",
				Description: fmt.Sprintf("Install hook '%s' pipes remote content directly to shell interpreter: %s", hookName, hookCmd),
				Snippet:     hookCmd,
			})
			continue
		}

		// Disambiguate benign build commands (node-gyp rebuild, console notices)
		if IsBenignBuildHook(hookCmd) {
			continue
		}
	}

	// 2. Scan and Analyze Source Files
	for relPath, rawContent := range pkg.SourceFiles {
		// Normalization & De-obfuscation
		normRes := deobfuscate.Normalize(string(rawContent))
		if normRes.HadUnicodeTrap || normRes.HadStringConcat || len(normRes.DecodedPayloads) > 0 {
			hadObfuscation = true
		}

		// Disambiguate legitimate binary downloaders (esbuild, sharp)
		if IsBenignBinaryFetcher(normRes.NormalizedCode) {
			continue
		}

		// YARA Scan over normalized content
		scanRes, err := scanner.Scan([]byte(normRes.NormalizedCode))
		if err != nil {
			return nil, fmt.Errorf("scanning file %s: %w", relPath, err)
		}

		for _, rm := range scanRes.MatchedRules {
			item := extractEvidenceItem(rm, relPath, normRes.NormalizedCode)
			verdict.Evidence = append(verdict.Evidence, item)

			// Score contribution based on severity
			switch item.Severity {
			case RiskCritical:
				score += 0.90
			case RiskHigh:
				score += 0.60
			case RiskMedium:
				score += 0.35
			default:
				score += 0.10
			}
		}
	}

	verdict.HadObfuscation = hadObfuscation
	if hadObfuscation && len(verdict.Evidence) > 0 {
		score += 0.20 // obfuscation combined with suspicious behavior boosts risk
	}

	if score > 1.0 {
		score = 1.0
	}
	verdict.ConfidenceScore = score

	// Assign final verdict actions
	switch {
	case score >= 0.70:
		verdict.RiskLevel = RiskCritical
		verdict.Action = ActionBlock
	case score >= 0.40:
		verdict.RiskLevel = RiskHigh
		verdict.Action = ActionWarn
	case score >= 0.20:
		verdict.RiskLevel = RiskMedium
		verdict.Action = ActionWarn
	default:
		verdict.RiskLevel = RiskBenign
		verdict.Action = ActionPass
	}

	return verdict, nil
}

func extractEvidenceItem(rm compiler.RuleMatch, relPath, content string) EvidenceItem {
	severity := RiskMedium
	category := "suspicious"
	desc := "Suspicious supply chain pattern detected"

	switch rm.Rule {
	case "Suspicious_Piped_Shell":
		severity = RiskCritical
		category = "dropper"
		desc = "Remote script download piped directly to shell"
	case "Reverse_Shell_Payload":
		severity = RiskCritical
		category = "backdoor"
		desc = "Reverse shell network execution payload"
	case "Credential_And_Secret_Harvesting":
		severity = RiskHigh
		category = "credential-theft"
		desc = "Accessing sensitive cloud credentials or SSH private keys"
	case "Dynamic_Code_Synthesis":
		severity = RiskHigh
		category = "obfuscation"
		desc = "Dynamic evaluation of decoded byte/base64 payload"
	case "Suspicious_Exfiltration_Endpoint":
		severity = RiskMedium
		category = "exfiltration"
		desc = "Outbound connection to public webhook or raw IP address"
	}

	snippet := ""
	for _, matches := range rm.Matches {
		for i := range matches {
			m := &matches[i]
			if m.Offset < 0 || m.Offset >= int64(len(content)) {
				continue
			}
			start := m.Offset
			end := start + int64(m.Length)
			if end > int64(len(content)) {
				end = int64(len(content))
			}
			snippet = content[start:end]
			break
		}
		if snippet != "" {
			break
		}
	}

	return EvidenceItem{
		RuleID:      rm.Rule,
		FilePath:    relPath,
		Severity:    severity,
		Category:    category,
		Description: desc,
		Snippet:     snippet,
	}
}
