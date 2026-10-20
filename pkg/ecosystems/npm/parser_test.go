package npm

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParsePackageDir(t *testing.T) {
	tmpDir := t.TempDir()
	pkgJSON := `{
		"name": "test-pkg",
		"version": "1.0.0",
		"scripts": {
			"postinstall": "node install.js",
			"test": "jest"
		}
	}`
	installJS := `console.log("running install");`

	if err := os.WriteFile(filepath.Join(tmpDir, "package.json"), []byte(pkgJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "install.js"), []byte(installJS), 0o600); err != nil {
		t.Fatal(err)
	}

	pkg, err := ParsePackageDir(tmpDir)
	if err != nil {
		t.Fatalf("ParsePackageDir failed: %v", err)
	}

	if pkg.Manifest.Name != "test-pkg" {
		t.Fatalf("expected name 'test-pkg', got %q", pkg.Manifest.Name)
	}
	if !pkg.HasHooks {
		t.Fatal("expected HasHooks = true")
	}
	if pkg.HookScripts["postinstall"] != "node install.js" {
		t.Fatalf("unexpected postinstall script: %q", pkg.HookScripts["postinstall"])
	}
	if len(pkg.SourceFiles) != 2 {
		t.Fatalf("expected 2 source files, got %d", len(pkg.SourceFiles))
	}
}
