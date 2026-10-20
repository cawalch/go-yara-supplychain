package main

import (
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/cawalch/go-yara-supplychain/pkg/analyzer"
	"github.com/cawalch/go-yara-supplychain/pkg/ecosystems/npm"
	"github.com/cawalch/go-yara-supplychain/pkg/ecosystems/php"
	"github.com/cawalch/go-yara-supplychain/pkg/ecosystems/pypi"
	"github.com/cawalch/go-yara-supplychain/pkg/report"
)

var version = "0.2.0"

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

type discoveredTarget struct {
	dir       string
	ecosystem string // "npm", "pypi", or "php"
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

	discovered := discoverPackageDirs(cfg.paths)
	if len(discovered) == 0 {
		fmt.Fprintf(os.Stderr, "No supported packages (npm, Python/PyPI, or PHP/WordPress) found in specified paths: %v\n", cfg.paths)
		return 0
	}

	verdicts := make([]*analyzer.Verdict, 0, len(discovered))
	for _, target := range discovered {
		var verdict *analyzer.Verdict
		var err error

		switch target.ecosystem {
		case "npm":
			pkg, pErr := npm.ParsePackageDir(target.dir)
			if pErr != nil {
				fmt.Fprintf(os.Stderr, "Warning: failed inspecting npm package at %s: %v\n", target.dir, pErr)
				continue
			}
			verdict, err = engine.AnalyzePackage(pkg)
		case "pypi":
			pkg, pErr := pypi.ParsePackageDir(target.dir)
			if pErr != nil {
				fmt.Fprintf(os.Stderr, "Warning: failed inspecting PyPI package at %s: %v\n", target.dir, pErr)
				continue
			}
			verdict, err = engine.AnalyzePyPIPackage(pkg)
		case "php":
			pkg, pErr := php.ParsePackageDir(target.dir)
			if pErr != nil {
				fmt.Fprintf(os.Stderr, "Warning: failed inspecting PHP/WordPress package at %s: %v\n", target.dir, pErr)
				continue
			}
			verdict, err = engine.AnalyzePHPPackage(pkg)
		}

		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed analyzing package at %s: %v\n", target.dir, err)
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

// discoverPackageDirs inspects inputs and discovers package directories with package.json (npm),
// setup.py / pyproject.toml / setup.cfg (Python / PyPI), or composer.json / WordPress plugin headers (PHP).
func discoverPackageDirs(targets []string) []discoveredTarget {
	seen := make(map[string]bool)
	var discovered []discoveredTarget

	inspectDir := func(dPath string) {
		abs, err := filepath.Abs(dPath)
		if err != nil {
			return
		}

		// Check npm
		pkgJSON := filepath.Join(abs, "package.json")
		if _, err := os.Stat(pkgJSON); err == nil {
			key := "npm:" + abs
			if !seen[key] {
				seen[key] = true
				discovered = append(discovered, discoveredTarget{dir: abs, ecosystem: "npm"})
			}
		}

		// Check PyPI
		isPy := false
		for _, pyManifest := range []string{"pyproject.toml", "setup.py", "setup.cfg"} {
			if _, err := os.Stat(filepath.Join(abs, pyManifest)); err == nil {
				isPy = true
				break
			}
		}
		if isPy {
			key := "pypi:" + abs
			if !seen[key] {
				seen[key] = true
				discovered = append(discovered, discoveredTarget{dir: abs, ecosystem: "pypi"})
			}
		}

		// Check PHP / Composer / WordPress
		isPhp := false
		if _, err := os.Stat(filepath.Join(abs, "composer.json")); err == nil {
			isPhp = true
		} else if _, err := os.Stat(filepath.Join(abs, "style.css")); err == nil {
			isPhp = true
		} else {
			entries, _ := os.ReadDir(abs)
			for _, entry := range entries {
				if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".php") {
					isPhp = true
					break
				}
			}
		}
		if isPhp {
			key := "php:" + abs
			if !seen[key] {
				seen[key] = true
				discovered = append(discovered, discoveredTarget{dir: abs, ecosystem: "php"})
			}
		}
	}

	for _, target := range targets {
		info, err := os.Stat(target)
		if err != nil {
			continue
		}

		if !info.IsDir() {
			continue
		}

		// Check target itself
		inspectDir(target)

		// Walk subdirectories (e.g. node_modules, wp-content/plugins, workspaces, sub-packages)
		_ = filepath.WalkDir(target, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				// Don't recurse into .git, .venv, etc.
				name := d.Name()
				if name == ".git" || name == ".venv" || name == "__pycache__" || name == "vendor" {
					return filepath.SkipDir
				}
				if path != target {
					inspectDir(path)
				}
			}
			return nil
		})
	}

	return discovered
}
