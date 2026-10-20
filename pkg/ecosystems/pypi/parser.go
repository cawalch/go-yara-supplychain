// Package pypi provides parsing and inspection logic for Python / PyPI packages.
package pypi

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	// Manifest & hook detection regexes
	setupNameRE        = regexp.MustCompile(`(?i)\bname\s*=\s*['"]([^'"]+)['"]`)
	setupVersionRE     = regexp.MustCompile(`(?i)\bversion\s*=\s*['"]([^'"]+)['"]`)
	pyprojectNameRE    = regexp.MustCompile(`(?m)^\s*name\s*=\s*['"]([^'"]+)['"]`)
	pyprojectVerRE     = regexp.MustCompile(`(?m)^\s*version\s*=\s*['"]([^'"]+)['"]`)
	cmdclassOverrideRE = regexp.MustCompile(`(?i)\bcmdclass\s*=\s*\{[^}]*['"](install|develop|build_py|egg_info|bdist_wheel)['"]\s*:\s*([a-zA-Z0-9_]+)`)
	suspiciousExecRE   = regexp.MustCompile(`(?i)\b(os\.system|subprocess\.(Popen|run|call|check_output)|exec\s*\(|eval\s*\(|base64\.b64decode|urllib\.request|requests\.(get|post)|socket\.socket)\b`)
	benignSetupCallRE  = regexp.MustCompile(`(?i)^\s*(from\s+setuptools\s+import|import\s+setuptools|setup\s*\()`)
)

// Package represents a parsed Python / PyPI package directory.
type Package struct {
	Path         string
	Name         string
	Version      string
	HasSetupPy   bool
	HasPyProject bool
	HasHooks     bool              // If setup.py contains custom cmdclass or active executable hooks
	HookScripts  map[string]string // hookName -> snippet/code
	SourceFiles  map[string][]byte // relative path -> file content
}

// MaxFileSize represents the maximum size of a single source file to read into memory (5MB).
const MaxFileSize = 5 * 1024 * 1024

// MaxFilesToScan caps the total number of files scanned in a single package.
const MaxFilesToScan = 500

// ParsePackageDir inspects a directory for Python package manifests (pyproject.toml, setup.py, setup.cfg)
// and extracts executable scripts and metadata.
func ParsePackageDir(dir string) (*Package, error) {
	setupPyPath := filepath.Join(dir, "setup.py")
	pyprojectPath := filepath.Join(dir, "pyproject.toml")
	setupCfgPath := filepath.Join(dir, "setup.cfg")

	_, errSetup := os.Stat(setupPyPath)
	_, errPyproj := os.Stat(pyprojectPath)
	_, errCfg := os.Stat(setupCfgPath)

	if os.IsNotExist(errSetup) && os.IsNotExist(errPyproj) && os.IsNotExist(errCfg) {
		return nil, fmt.Errorf("no python package manifest (setup.py, pyproject.toml, or setup.cfg) found in %s", dir)
	}

	pkgName := filepath.Base(dir)
	pkgVer := "0.0.0"
	hasSetupPy := false
	hasPyProject := false
	hasHooks := false
	hookScripts := make(map[string]string)
	sourceFiles := make(map[string][]byte)

	// 1. Inspect pyproject.toml if present
	if errPyproj == nil {
		hasPyProject = true
		content, err := os.ReadFile(pyprojectPath)
		if err == nil && len(content) <= MaxFileSize {
			sourceFiles["pyproject.toml"] = content
			s := string(content)
			if m := pyprojectNameRE.FindStringSubmatch(s); len(m) > 1 {
				pkgName = m[1]
			}
			if m := pyprojectVerRE.FindStringSubmatch(s); len(m) > 1 {
				pkgVer = m[1]
			}
		}
	}

	// 2. Inspect setup.cfg if present
	if errCfg == nil {
		content, err := os.ReadFile(setupCfgPath)
		if err == nil && len(content) <= MaxFileSize {
			sourceFiles["setup.cfg"] = content
			s := string(content)
			if m := pyprojectNameRE.FindStringSubmatch(s); len(m) > 1 && pkgName == filepath.Base(dir) {
				pkgName = m[1]
			}
			if m := pyprojectVerRE.FindStringSubmatch(s); len(m) > 1 && pkgVer == "0.0.0" {
				pkgVer = m[1]
			}
		}
	}

	// 3. Inspect setup.py if present (primary execution vector during package installation)
	if errSetup == nil {
		hasSetupPy = true
		content, err := os.ReadFile(setupPyPath)
		if err == nil && len(content) <= MaxFileSize {
			sourceFiles["setup.py"] = content
			s := string(content)

			if m := setupNameRE.FindStringSubmatch(s); len(m) > 1 {
				pkgName = m[1]
			}
			if m := setupVersionRE.FindStringSubmatch(s); len(m) > 1 {
				pkgVer = m[1]
			}

			// Check for cmdclass overrides (e.g. cmdclass={'install': CustomInstall})
			if match := cmdclassOverrideRE.FindStringSubmatch(s); len(match) > 1 {
				hasHooks = true
				hookScripts["cmdclass:"+match[1]] = match[0]
			}

			// Check for suspicious execution directly in setup.py
			if suspiciousExecRE.MatchString(s) {
				hasHooks = true
				matches := suspiciousExecRE.FindAllString(s, 3)
				hookScripts["setup.py:active_code"] = strings.Join(matches, ", ")
			}
		}
	}

	// 4. Walk directory and collect Python source and script files
	fileCount := 0
	errWalk := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			name := d.Name()
			if strings.HasPrefix(name, ".") ||
				name == "__pycache__" ||
				name == "node_modules" ||
				name == "venv" ||
				name == ".venv" ||
				name == "build" ||
				name == "dist" ||
				strings.HasSuffix(name, ".egg-info") {
				return filepath.SkipDir
			}
			return nil
		}

		if fileCount >= MaxFilesToScan {
			return filepath.SkipAll
		}

		ext := strings.ToLower(filepath.Ext(path))
		if ext == ".py" || ext == ".sh" || ext == ".bash" {
			rel, err := filepath.Rel(dir, path)
			if err != nil {
				return nil
			}

			// Already read setup.py
			if rel == "setup.py" {
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
		}
		return nil
	})

	if errWalk != nil && !errors.Is(errWalk, filepath.SkipAll) {
		return nil, fmt.Errorf("walking package dir %s: %w", dir, errWalk)
	}

	return &Package{
		Path:         dir,
		Name:         pkgName,
		Version:      pkgVer,
		HasSetupPy:   hasSetupPy,
		HasPyProject: hasPyProject,
		HasHooks:     hasHooks,
		HookScripts:  hookScripts,
		SourceFiles:  sourceFiles,
	}, nil
}
