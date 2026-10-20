package main

import (
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/cawalch/go-yara-supplychain/pkg/analyzer"
	"github.com/cawalch/go-yara-supplychain/pkg/ecosystems/npm"
	"github.com/cawalch/go-yara-supplychain/pkg/report"
)

const version = "0.1.0"

type cliConfig struct {
	sarifPath      string
	jsonOutput     bool
	ndjsonOutput   bool
	failOnCritical bool
	failOnWarn     bool
	noColor        bool
	showVersion    bool
	paths          []string
}

func main() {
	cfg := parseFlags(os.Args[1:])
	if cfg.showVersion {
		fmt.Printf("go-yara-supplychain v%s (pure Go, zero CGO)\n", version)
		os.Exit(0)
	}

	exitCode := run(cfg)
	os.Exit(exitCode)
}

func parseFlags(args []string) *cliConfig {
	flagSet := flag.NewFlagSet("go-yara-supplychain", flag.ContinueOnError)

	sarifPath := flagSet.String("sarif", "", "Path to write SARIF 2.1.0 report")
	jsonOutput := flagSet.Bool("json", false, "Output results in JSON format")
	ndjsonOutput := flagSet.Bool("ndjson", false, "Output results in NDJSON format")
	failOnCritical := flagSet.Bool("fail-on-critical", true, "Exit with code 1 if CRITICAL supply chain threats are detected")
	failOnWarn := flagSet.Bool("fail-on-warn", false, "Exit with code 1 if HIGH or MEDIUM threats are detected")
	noColor := flagSet.Bool("no-color", false, "Disable colored terminal output")
	showVersion := flagSet.Bool("version", false, "Print version and exit")

	_ = flagSet.Parse(args)

	targets := flagSet.Args()
	if len(targets) == 0 {
		targets = []string{"."}
	}

	return &cliConfig{
		sarifPath:      *sarifPath,
		jsonOutput:     *jsonOutput,
		ndjsonOutput:   *ndjsonOutput,
		failOnCritical: *failOnCritical,
		failOnWarn:     *failOnWarn,
		noColor:        *noColor,
		showVersion:    *showVersion,
		paths:          targets,
	}
}

func run(cfg *cliConfig) int {
	engine, err := analyzer.NewEngine()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing analyzer engine: %v\n", err)
		return 2
	}

	packageDirs := discoverPackageDirs(cfg.paths)
	if len(packageDirs) == 0 {
		fmt.Fprintf(os.Stderr, "No npm packages (containing package.json) found in specified paths: %v\n", cfg.paths)
		return 0
	}

	verdicts := make([]*analyzer.Verdict, 0, len(packageDirs))
	for _, pDir := range packageDirs {
		pkg, err := npm.ParsePackageDir(pDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed inspecting package at %s: %v\n", pDir, err)
			continue
		}

		verdict, err := engine.AnalyzePackage(pkg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed analyzing package at %s: %v\n", pDir, err)
			continue
		}

		verdicts = append(verdicts, verdict)
	}

	// Write SARIF report if requested
	if cfg.sarifPath != "" {
		if err := report.WriteSARIFToFile(cfg.sarifPath, verdicts); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing SARIF report to %s: %v\n", cfg.sarifPath, err)
		}
	}

	// Output results
	switch {
	case cfg.ndjsonOutput:
		if err := report.WriteNDJSON(os.Stdout, verdicts); err != nil {
			fmt.Fprintf(os.Stderr, "Error encoding NDJSON: %v\n", err)
		}
	case cfg.jsonOutput:
		if err := report.WriteJSON(os.Stdout, verdicts); err != nil {
			fmt.Fprintf(os.Stderr, "Error encoding JSON: %v\n", err)
		}
	default:
		if err := report.WriteTerminal(os.Stdout, verdicts, cfg.noColor); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing terminal output: %v\n", err)
		}
	}

	// Determine exit code
	for _, v := range verdicts {
		if cfg.failOnCritical && (v.RiskLevel == analyzer.RiskCritical || v.Action == analyzer.ActionBlock) {
			return 1
		}
		if cfg.failOnWarn && (v.RiskLevel == analyzer.RiskHigh || v.RiskLevel == analyzer.RiskMedium) {
			return 1
		}
	}

	return 0
}

// discoverPackageDirs inspects inputs and discovers package directories with package.json
func discoverPackageDirs(targets []string) []string {
	seen := make(map[string]bool)
	var dirs []string

	for _, target := range targets {
		info, err := os.Stat(target)
		if err != nil {
			continue
		}

		if !info.IsDir() {
			continue
		}

		// Check if target itself is a package
		pkgJSON := filepath.Join(target, "package.json")
		if _, err := os.Stat(pkgJSON); err == nil {
			abs, _ := filepath.Abs(target)
			if !seen[abs] {
				seen[abs] = true
				dirs = append(dirs, abs)
			}
		}

		// Also check subdirectories (e.g. node_modules, workspaces) up to depth 2
		_ = filepath.WalkDir(target, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				// Don't recurse into .git
				if d.Name() == ".git" {
					return filepath.SkipDir
				}
				pJSON := filepath.Join(path, "package.json")
				if _, err := os.Stat(pJSON); err == nil {
					abs, _ := filepath.Abs(path)
					if !seen[abs] {
						seen[abs] = true
						dirs = append(dirs, abs)
					}
				}
			}
			return nil
		})
	}

	return dirs
}
