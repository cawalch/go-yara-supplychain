// Package php provides parsing and inspection logic for PHP, Composer, and WordPress plugin/theme packages.
package php

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	wpPluginNameRE  = regexp.MustCompile(`(?i)\bPlugin\s+Name\s*:\s*([^\r\n*]+)`)
	wpPluginVerRE   = regexp.MustCompile(`(?i)\bVersion\s*:\s*([0-9A-Za-z.\-_+]+)`)
	wpThemeNameRE   = regexp.MustCompile(`(?i)\bTheme\s+Name\s*:\s*([^\r\n*]+)`)
	htaccessPhpRE   = regexp.MustCompile(`(?i)(AddType|AddHandler|SetHandler)\s+application/x-httpd-php\b`)
	suspiciousPhpRE = regexp.MustCompile(`(?i)\b(proc_open|shell_exec|passthru|popen|eval\s*\(|base64_decode|assert\s*\(|fsockopen|curl_exec)\b`)
)

// ComposerJSON represents standard Composer manifest fields relevant to security analysis.
type ComposerJSON struct {
	Name        string            `json:"name"`
	Version     string            `json:"version"`
	Description string            `json:"description"`
	Type        string            `json:"type"`
	Scripts     map[string]any    `json:"scripts"` // script name -> string or []string
	Require     map[string]string `json:"require"`
}

// Package represents a parsed PHP, Composer, or WordPress plugin/theme package.
type Package struct {
	Path        string
	Name        string
	Version     string
	Type        string            // "composer", "wordpress-plugin", "wordpress-theme"
	HasHooks    bool              // Composer lifecycle scripts or top-level installer execution
	HookScripts map[string]string // hookName -> command
	SourceFiles map[string][]byte // relative path -> file content
}

// MaxFileSize represents the maximum size of a single source file to read into memory (5MB).
const MaxFileSize = 5 * 1024 * 1024

// MaxFilesToScan caps the total number of files scanned in a single package.
const MaxFilesToScan = 500

// ParsePackageDir inspects a directory for Composer (composer.json) or WordPress plugin/theme manifests
// and extracts executable scripts and metadata.
func ParsePackageDir(dir string) (*Package, error) {
	composerPath := filepath.Join(dir, "composer.json")
	styleCssPath := filepath.Join(dir, "style.css")

	pkgName := filepath.Base(dir)
	pkgVer := "0.0.0"
	pkgType := "php"
	hasHooks := false
	hookScripts := make(map[string]string)
	sourceFiles := make(map[string][]byte)

	isComposer := false
	isWordPress := false

	// 1. Inspect composer.json if present
	if cData, err := os.ReadFile(composerPath); err == nil && len(cData) <= MaxFileSize {
		isComposer = true
		pkgType = "composer"
		sourceFiles["composer.json"] = cData

		var cjson ComposerJSON
		if err := json.Unmarshal(cData, &cjson); err == nil {
			if cjson.Name != "" {
				pkgName = cjson.Name
			}
			if cjson.Version != "" {
				pkgVer = cjson.Version
			}
			if cjson.Type != "" {
				pkgType = "composer:" + cjson.Type
			}

			// Composer lifecycle hooks executed automatically during install/update
			lifecycleHooks := map[string]bool{
				"pre-install-cmd":           true,
				"post-install-cmd":          true,
				"pre-update-cmd":            true,
				"post-update-cmd":           true,
				"pre-autoload-dump":         true,
				"post-autoload-dump":        true,
				"post-root-package-install": true,
				"post-create-project-cmd":   true,
			}

			for hName, hVal := range cjson.Scripts {
				if lifecycleHooks[strings.ToLower(hName)] {
					hasHooks = true
					switch v := hVal.(type) {
					case string:
						hookScripts[hName] = v
					case []any:
						var cmds []string
						for _, item := range v {
							if s, ok := item.(string); ok {
								cmds = append(cmds, s)
							}
						}
						hookScripts[hName] = strings.Join(cmds, " && ")
					}
				}
			}
		}
	}

	// 2. Inspect style.css for WordPress Themes
	if sData, err := os.ReadFile(styleCssPath); err == nil && len(sData) <= MaxFileSize {
		s := string(sData)
		if m := wpThemeNameRE.FindStringSubmatch(s); len(m) > 1 {
			isWordPress = true
			pkgType = "wordpress-theme"
			pkgName = strings.TrimSpace(m[1])
			sourceFiles["style.css"] = sData
			if vm := wpPluginVerRE.FindStringSubmatch(s); len(vm) > 1 {
				pkgVer = strings.TrimSpace(vm[1])
			}
		}
	}

	// 3. Scan directory files (.php, .inc, .htaccess, .sh) and detect WordPress plugin headers
	fileCount := 0
	errWalk := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			name := d.Name()
			if strings.HasPrefix(name, ".") ||
				name == "vendor" ||
				name == "node_modules" ||
				name == "cache" ||
				name == "build" ||
				name == "dist" {
				return filepath.SkipDir
			}
			return nil
		}

		if fileCount >= MaxFilesToScan {
			return filepath.SkipAll
		}

		baseName := d.Name()
		ext := strings.ToLower(filepath.Ext(path))
		isHtaccess := baseName == ".htaccess" || strings.HasSuffix(baseName, ".htaccess")

		if ext == ".php" || ext == ".inc" || ext == ".phtml" || ext == ".sh" || isHtaccess {
			rel, err := filepath.Rel(dir, path)
			if err != nil {
				return nil
			}

			info, err := d.Info()
			if err != nil || info.Size() > MaxFileSize {
				return nil
			}

			content, err := os.ReadFile(path)
			if err != nil {
				return nil
			}

			sourceFiles[rel] = content
			fileCount++

			// Check for WordPress Plugin Header in root or 1st-level PHP files
			if (ext == ".php") && !strings.Contains(rel, string(filepath.Separator)) {
				s := string(content)
				if m := wpPluginNameRE.FindStringSubmatch(s); len(m) > 1 {
					isWordPress = true
					if pkgType == "php" || pkgType == "composer" {
						pkgType = "wordpress-plugin"
					}
					pkgName = strings.TrimSpace(m[1])
					if vm := wpPluginVerRE.FindStringSubmatch(s); len(vm) > 1 {
						pkgVer = strings.TrimSpace(vm[1])
					}
				}
			}

			// Detect .htaccess execution mapping (forcing non-PHP files to execute as PHP)
			if isHtaccess {
				s := string(content)
				if htaccessPhpRE.MatchString(s) {
					hasHooks = true
					hookScripts[rel+":handler_override"] = strings.TrimSpace(s)
				}
			}
		}

		return nil
	})

	if errWalk != nil && !errors.Is(errWalk, filepath.SkipAll) {
		return nil, fmt.Errorf("walking PHP package dir %s: %w", dir, errWalk)
	}

	if !isComposer && !isWordPress && len(sourceFiles) == 0 {
		return nil, fmt.Errorf("no PHP, Composer, or WordPress package manifest found in %s", dir)
	}

	return &Package{
		Path:        dir,
		Name:        pkgName,
		Version:     pkgVer,
		Type:        pkgType,
		HasHooks:    hasHooks,
		HookScripts: hookScripts,
		SourceFiles: sourceFiles,
	}, nil
}
