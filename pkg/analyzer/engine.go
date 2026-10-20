package analyzer

import (
	"fmt"
	"math"
	"regexp"
	"strings"

	"github.com/cawalch/go-yara-supplychain/pkg/deobfuscate"
	"github.com/cawalch/go-yara-supplychain/pkg/ecosystems/npm"
	"github.com/cawalch/go-yara-supplychain/pkg/ecosystems/php"
	"github.com/cawalch/go-yara-supplychain/pkg/ecosystems/pypi"
	"github.com/cawalch/go-yara-supplychain/pkg/ml"
	"github.com/cawalch/go-yara-supplychain/pkg/rules"
	"github.com/cawalch/go-yara/compiler"
)

var (
	pipeToShellRE = regexp.MustCompile(`(?i)(curl|wget)\s+[^|;` + "`" + `\r\n]+\|\s*(sh|bash|zsh|python|cmd\.exe|powershell)`)
	curlRE        = regexp.MustCompile(`(?i)\b(curl|wget|fetch|http\.get|urllib\.request|requests\.(get|post)|curl_exec|file_get_contents|fsockopen|stream_socket_client)\b`)
	evalRE        = regexp.MustCompile(`(?:\beval\s*\(|\b(?:new\s+)?Function\s*\(|\bvm\.runIn\w*\s*\(|\bexec\s*\(|\bassert\s*\(|\bcreate_function\s*\()`)
	childProcRE   = regexp.MustCompile(`(?i)\b(child_process\.(exec|spawn|execSync|fork)|subprocess\.(Popen|run|call|check_output)|os\.system|proc_open|shell_exec|passthru|popen)\b`)
	rawIPRE       = regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d{2,5})?\b`)
	webhookRE     = regexp.MustCompile(`(?i)(discord\.com/api/webhooks|api\.telegram\.org/bot|webhook\.site)`)
	sensitiveRE   = regexp.MustCompile(`(?i)(\.ssh/id_|\.aws/credentials|/\.env\b|['"` + "`" + `]\.env['"` + "`" + `]|/etc/shadow|/etc/passwd|os\.environ|wp-config\.php|DB_PASSWORD|AUTH_KEY)`)
)

// Engine coordinates the multi-stage supply chain analysis pipeline.
type Engine struct {
	compiledProg *compiler.CompiledProgram
	mlModel      *ml.Classifier
}

// NewEngine creates an initialized Engine backed by compiled supply chain YARA rules and ML inference model.
func NewEngine() (*Engine, error) {
	prog, err := rules.GetCompiledRules()
	if err != nil {
		return nil, fmt.Errorf("initializing analyzer engine: %w", err)
	}
	return &Engine{
		compiledProg: prog,
		mlModel:      ml.DefaultModel(),
	}, nil
}

// AnalyzePackage analyzes an inspected npm package and returns an actionable verdict.
func (e *Engine) AnalyzePackage(pkg *npm.InspectedPackage) (*Verdict, error) {
	return e.Analyze(TargetPackage{
		Ecosystem:   "npm",
		Path:        pkg.Path,
		Name:        pkg.Manifest.Name,
		Version:     pkg.Manifest.Version,
		HasHooks:    pkg.HasHooks,
		HookScripts: pkg.HookScripts,
		SourceFiles: pkg.SourceFiles,
	})
}

// AnalyzePyPIPackage analyzes an inspected Python/PyPI package and returns an actionable verdict.
func (e *Engine) AnalyzePyPIPackage(pkg *pypi.Package) (*Verdict, error) {
	return e.Analyze(TargetPackage{
		Ecosystem:   "pypi",
		Path:        pkg.Path,
		Name:        pkg.Name,
		Version:     pkg.Version,
		HasHooks:    pkg.HasHooks,
		HookScripts: pkg.HookScripts,
		SourceFiles: pkg.SourceFiles,
	})
}

// AnalyzePHPPackage analyzes an inspected PHP, Composer, or WordPress plugin/theme package and returns an actionable verdict.
func (e *Engine) AnalyzePHPPackage(pkg *php.Package) (*Verdict, error) {
	return e.Analyze(TargetPackage{
		Ecosystem:   pkg.Type,
		Path:        pkg.Path,
		Name:        pkg.Name,
		Version:     pkg.Version,
		HasHooks:    pkg.HasHooks,
		HookScripts: pkg.HookScripts,
		SourceFiles: pkg.SourceFiles,
	})
}

// Analyze coordinates multi-stage static analysis, heuristic scoring, and neural inference for any package target.
func (e *Engine) Analyze(target TargetPackage) (*Verdict, error) {
	scanner := compiler.NewScanner(e.compiledProg)
	defer scanner.Close()

	verdict := &Verdict{
		PackageName:     target.Name,
		PackageVersion:  target.Version,
		PackagePath:     target.Path,
		Ecosystem:       target.Ecosystem,
		RiskLevel:       RiskBenign,
		Action:          ActionPass,
		HasInstallHooks: target.HasHooks,
		Evidence:        make([]EvidenceItem, 0),
	}

	var fv ml.FeatureVector
	var heuristicScore float64
	hadObfuscation := false
	var totalSourceLen int

	if target.HasHooks {
		fv.HasLifecycleHook = 1.0
	}

	hookOriginFile := "package.json"
	if target.Ecosystem == "pypi" {
		hookOriginFile = "setup.py"
	} else if strings.HasPrefix(target.Ecosystem, "wordpress") || strings.HasPrefix(target.Ecosystem, "composer") || target.Ecosystem == "php" {
		hookOriginFile = "composer.json"
	}

	// 1. Analyze Package Lifecycle Scripts / Setup Hooks
	for hookName, hookCmd := range target.HookScripts {
		if curlRE.MatchString(hookCmd) {
			fv.HookNetworkDownload = 1.0
		}

		// Check for direct shell pipes in install scripts (e.g. curl ... | bash)
		if pipeToShellRE.MatchString(hookCmd) {
			fv.HookPipesToShell = 1.0
			heuristicScore += 0.95
			verdict.Evidence = append(verdict.Evidence, EvidenceItem{
				RuleID:      "Suspicious_Piped_Shell",
				FilePath:    hookOriginFile,
				Severity:    RiskCritical,
				Category:    "dropper",
				Description: fmt.Sprintf("Install hook '%s' pipes remote content directly to shell interpreter: %s", hookName, hookCmd),
				Snippet:     hookCmd,
			})
			continue
		}

		// Disambiguate benign build commands (node-gyp rebuild, cython, composer dump-autoload, console notices)
		if IsBenignBuildHook(hookCmd) {
			continue
		}
	}

	// 2. Scan and Analyze Source Files
	for relPath, rawContent := range target.SourceFiles {
		totalSourceLen += len(rawContent)

		// Feature extraction from source content
		srcStr := string(rawContent)
		if pipeToShellRE.MatchString(srcStr) {
			fv.HookPipesToShell = 1.0
		}
		if evalRE.MatchString(srcStr) {
			fv.DynamicEval = 1.0
		}
		if childProcRE.MatchString(srcStr) {
			fv.ChildProcessExec = 1.0
		}
		if rawIPRE.MatchString(srcStr) {
			fv.NetworkRawIP = 1.0
		}
		if webhookRE.MatchString(srcStr) {
			fv.WebhookExfiltration = 1.0
		}
		if sensitiveRE.MatchString(srcStr) {
			fv.SensitivePathAccess = 1.0
		}

		// Normalization & De-obfuscation
		normRes := deobfuscate.Normalize(srcStr)
		if normRes.HadUnicodeTrap {
			fv.UnicodeObfuscation += 1.0
			hadObfuscation = true
		}
		if normRes.HadStringConcat {
			fv.StringConcatDensity += 1.0
			hadObfuscation = true
		}
		if len(normRes.DecodedPayloads) > 0 {
			fv.Base64PayloadCount += float64(len(normRes.DecodedPayloads))
			hadObfuscation = true
		}
		if normRes.HadXORLoop {
			hadObfuscation = true
			fv.UnicodeObfuscation += 1.0
		}

		// Disambiguate legitimate binary downloaders (esbuild, sharp, python/php prebuilt binaries)
		if IsBenignBinaryFetcher(normRes.NormalizedCode) {
			fv.ChecksumValidation = 1.0
			fv.TrustedCDNSource = 1.0
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
				heuristicScore += 0.90
				fv.YARAMatchWeight += 1.0
			case RiskHigh:
				heuristicScore += 0.60
				fv.YARAMatchWeight += 0.6
			case RiskMedium:
				heuristicScore += 0.35
				fv.YARAMatchWeight += 0.3
			default:
				heuristicScore += 0.10
				fv.YARAMatchWeight += 0.1
			}
		}
	}

	verdict.HadObfuscation = hadObfuscation
	if hadObfuscation && len(verdict.Evidence) > 0 {
		heuristicScore += 0.20
	}

	if totalSourceLen > 0 {
		hookLen := 0
		for _, cmd := range target.HookScripts {
			hookLen += len(cmd)
		}
		if hookLen > 0 {
			fv.ScriptSizeRatio = math.Log1p(float64(hookLen)) / math.Log1p(float64(totalSourceLen))
		}
	}

	// 3. Neural Network Inference & Explainability
	pred := e.mlModel.Predict(&fv)
	verdict.MLScore = pred.Probability
	verdict.MLAttributions = pred.Attributions

	// 4. Ensemble Calibrated Score
	var finalScore float64
	switch {
	case heuristicScore >= 0.60 || pred.Probability >= 0.70:
		// High confidence consensus
		finalScore = math.Max(heuristicScore, pred.Probability)
	case fv.ChecksumValidation > 0 && fv.TrustedCDNSource > 0 && !fvHasCriticalThreat(&fv):
		// Benign protected package - attenuate to baseline
		finalScore = math.Min(heuristicScore, pred.Probability)
	default:
		// Weighted ensemble
		finalScore = 0.5*heuristicScore + 0.5*pred.Probability
	}

	if finalScore > 1.0 {
		finalScore = 1.0
	}
	verdict.ConfidenceScore = finalScore

	// Assign final verdict actions
	switch {
	case finalScore >= 0.70:
		verdict.RiskLevel = RiskCritical
		verdict.Action = ActionBlock
	case finalScore >= 0.40:
		verdict.RiskLevel = RiskHigh
		verdict.Action = ActionWarn
	case finalScore >= 0.20:
		verdict.RiskLevel = RiskMedium
		verdict.Action = ActionWarn
	default:
		verdict.RiskLevel = RiskBenign
		verdict.Action = ActionPass
	}

	return verdict, nil
}

func fvHasCriticalThreat(fv *ml.FeatureVector) bool {
	return fv.HookPipesToShell > 0 || fv.NetworkRawIP > 0 || fv.SensitivePathAccess > 0
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
	case "Reverse_Shell_Payload", "Python_Reverse_Shell":
		severity = RiskCritical
		category = "backdoor"
		desc = "Reverse shell network execution payload"
	case "Credential_And_Secret_Harvesting":
		severity = RiskHigh
		category = "credential-theft"
		desc = "Accessing sensitive cloud credentials, private keys, or CMS secrets"
	case "Dynamic_Code_Synthesis", "Python_Obfuscated_Execution":
		severity = RiskHigh
		category = "obfuscation"
		desc = "Dynamic evaluation of decoded byte/base64 payload"
	case "Python_Suspicious_Install_Hook":
		severity = RiskHigh
		category = "install-hook"
		desc = "Python setup.py command override executing subprocess or network requests"
	case "Python_Pth_AutoExec_Hook":
		severity = RiskCritical
		category = "dropper"
		desc = "Python .pth auto-execution file abusing interpreter startup"
	case "PHP_WordPress_SupplyChain_Backdoor":
		severity = RiskCritical
		category = "backdoor"
		desc = "WordPress supply chain backdoor with C2, rogue admin, or core file masquerading"
	case "Web_Server_Config_Hijacking":
		severity = RiskCritical
		category = "persistence"
		desc = "Web server (.htaccess) configuration hijacked to execute non-PHP files as PHP"
	case "Bitwise_XOR_Obfuscated_Execution":
		severity = RiskHigh
		category = "obfuscation"
		desc = "Bitwise XOR decryption loop paired with dynamic code evaluation"
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
			snippet = strings.TrimSpace(content[start:end])
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
