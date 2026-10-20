// Package npm provides parsing and inspection logic for Node.js / npm packages.
package npm

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// PackageJSON represents standard npm package.json manifest fields relevant to security analysis.
type PackageJSON struct {
	Name            string            `json:"name"`
	Version         string            `json:"version"`
	Description     string            `json:"description"`
	Main            string            `json:"main"`
	Scripts         map[string]string `json:"scripts"`
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
	Bin             any               `json:"bin"` // string or map[string]string
}

// InspectedPackage represents a parsed npm package with extracted script files.
type InspectedPackage struct {
	Path        string
	Manifest    PackageJSON
	HookScripts map[string]string // hookName -> command string
	SourceFiles map[string][]byte // relative path -> file content
	HasHooks    bool
}

// LifecycleHooks lists npm scripts executed automatically without explicit user invocation.
var LifecycleHooks = map[string]bool{
	"preinstall":     true,
	"install":        true,
	"postinstall":    true,
	"preuninstall":   true,
	"postuninstall":  true,
	"prepublish":     true,
	"prepare":        true,
	"prepublishOnly": true,
	"prepack":        true,
	"postpack":       true,
	"dependencies":   true,
}

// ParsePackageDir parses a directory containing a package.json and associated scripts.
func ParsePackageDir(dir string) (*InspectedPackage, error) {
	manifestPath := filepath.Join(dir, "package.json")
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("reading package.json: %w", err)
	}

	return ParsePackageManifest(data, dir)
}

// ParsePackage parses package manifest data with an optional baseDir.
func ParsePackage(baseDir string, manifestData []byte) (*InspectedPackage, error) {
	return ParsePackageManifest(manifestData, baseDir)
}

// ParsePackageManifest parses the raw bytes of a package.json and scans the given base directory for source files.
func ParsePackageManifest(manifestData []byte, baseDir string) (*InspectedPackage, error) {
	var manifest PackageJSON
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		return nil, fmt.Errorf("parsing package.json: %w", err)
	}

	pkg := &InspectedPackage{
		Path:        baseDir,
		Manifest:    manifest,
		HookScripts: make(map[string]string),
		SourceFiles: make(map[string][]byte),
	}

	// 1. Identify active lifecycle hooks
	for scriptName, scriptCmd := range manifest.Scripts {
		if LifecycleHooks[scriptName] {
			pkg.HookScripts[scriptName] = scriptCmd
			pkg.HasHooks = true
		}
	}

	// 2. Add manifest itself
	pkg.SourceFiles["package.json"] = manifestData

	// 3. Scan baseDir for script and source files
	if baseDir != "" {
		collectPackageFiles(baseDir, pkg.SourceFiles)
	}

	return pkg, nil
}

func collectPackageFiles(baseDir string, out map[string][]byte) {
	_ = filepath.WalkDir(baseDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if (d.Name() == "node_modules" && path != baseDir) || d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}

		if !isTargetFile(d.Name()) {
			return nil
		}

		rel, err := filepath.Rel(baseDir, path)
		if err != nil {
			return nil
		}

		content, err := os.ReadFile(path)
		if err == nil && len(content) < 5*1024*1024 { // max 5MB per file
			out[rel] = content
		}
		return nil
	})
}

func isTargetFile(name string) bool {
	lower := strings.ToLower(name)
	switch {
	case strings.HasSuffix(lower, ".js"),
		strings.HasSuffix(lower, ".mjs"),
		strings.HasSuffix(lower, ".cjs"),
		strings.HasSuffix(lower, ".ts"),
		strings.HasSuffix(lower, ".sh"),
		strings.HasSuffix(lower, ".py"),
		lower == "package.json":
		return true
	default:
		return false
	}
}
