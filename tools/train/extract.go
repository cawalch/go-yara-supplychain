package main

import (
	"fmt"
	"math"
	"regexp"

	"github.com/cawalch/go-yara-supplychain/pkg/analyzer"
	"github.com/cawalch/go-yara-supplychain/pkg/deobfuscate"
	"github.com/cawalch/go-yara-supplychain/pkg/ecosystems/npm"
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

// ProcessedSample contains the ground-truth label and extracted 16-D feature vector.
type ProcessedSample struct {
	ID         string
	Label      int // 0 or 1
	Features   [16]float64
	Provenance string
}

// ExtractCorpusDataset runs multi-stage extraction over all raw samples in the corpus.
func ExtractCorpusDataset(samples []RawSample) ([]ProcessedSample, error) {
	compiledProg, err := rules.GetCompiledRules()
	if err != nil {
		return nil, fmt.Errorf("compiling rules: %w", err)
	}

	dataset := make([]ProcessedSample, 0, len(samples))

	for _, s := range samples {
		pkg, err := npm.ParsePackage("", []byte(s.Manifest))
		if err != nil {
			return nil, fmt.Errorf("parsing manifest for %s: %w", s.ID, err)
		}
		for path, content := range s.Files {
			pkg.SourceFiles[path] = []byte(content)
		}

		fv := extractFeatures(pkg, compiledProg)
		dataset = append(dataset, ProcessedSample{
			ID:         s.ID,
			Label:      s.Label,
			Features:   fv.ToSlice(),
			Provenance: s.Provenance,
		})
	}

	return dataset, nil
}

func extractFeatures(pkg *npm.InspectedPackage, prog *compiler.CompiledProgram) ml.FeatureVector {
	var fv ml.FeatureVector
	var totalSourceLen int

	if pkg.HasHooks {
		fv.HasLifecycleHook = 1.0
	}

	for _, hookCmd := range pkg.HookScripts {
		if curlRE.MatchString(hookCmd) {
			fv.HookNetworkDownload = 1.0
		}
		if pipeToShellRE.MatchString(hookCmd) {
			fv.HookPipesToShell = 1.0
		}
	}

	scanner := compiler.NewScanner(prog)
	defer scanner.Close()

	for _, rawContent := range pkg.SourceFiles {
		totalSourceLen += len(rawContent)
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

		normRes := deobfuscate.Normalize(srcStr)
		if normRes.HadUnicodeTrap {
			fv.UnicodeObfuscation += 1.0
		}
		if normRes.HadStringConcat {
			fv.StringConcatDensity += 1.0
		}
		if len(normRes.DecodedPayloads) > 0 {
			fv.Base64PayloadCount += float64(len(normRes.DecodedPayloads))
		}

		if analyzer.IsBenignBinaryFetcher(normRes.NormalizedCode) {
			fv.ChecksumValidation = 1.0
			fv.TrustedCDNSource = 1.0
			continue
		}

		scanRes, err := scanner.Scan([]byte(normRes.NormalizedCode))
		if err == nil {
			for _, rm := range scanRes.MatchedRules {
				switch rm.Rule {
				case "Suspicious_Piped_Shell", "Reverse_Shell_Payload":
					fv.YARAMatchWeight += 1.0
				case "Credential_And_Secret_Harvesting", "Dynamic_Code_Synthesis":
					fv.YARAMatchWeight += 0.6
				default:
					fv.YARAMatchWeight += 0.3
				}
			}
		}
	}

	if totalSourceLen > 0 {
		hookLen := 0
		for _, cmd := range pkg.HookScripts {
			hookLen += len(cmd)
		}
		if hookLen > 0 {
			fv.ScriptSizeRatio = math.Log1p(float64(hookLen)) / math.Log1p(float64(totalSourceLen))
		}
	}

	return fv
}
