package analyzer

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cawalch/go-yara-supplychain/pkg/ecosystems/npm"
)

func TestMinifiedBundledPackages(t *testing.T) {
	engine, err := NewEngine()
	if err != nil {
		t.Fatalf("failed initializing engine: %v", err)
	}

	fixtures := []struct {
		name         string
		fixtureFile  string
		manifestName string
	}{
		{
			name:         "react-dom-production-bundle",
			fixtureFile:  "react-dom.production.min.js",
			manifestName: "react-dom",
		},
		{
			name:         "lodash-minified-bundle",
			fixtureFile:  "lodash.min.js",
			manifestName: "lodash",
		},
		{
			name:         "webpack-bundle-with-data-uri",
			fixtureFile:  "bundle-with-data-uri.js",
			manifestName: "app-bundle",
		},
	}

	for _, fix := range fixtures {
		t.Run(fix.name, func(t *testing.T) {
			fixturePath := filepath.Join("..", "..", "testdata", "fixtures", fix.fixtureFile)
			content, err := os.ReadFile(fixturePath)
			if err != nil {
				t.Fatalf("reading fixture %s: %v", fixturePath, err)
			}

			manifest := `{"name":"` + fix.manifestName + `","version":"1.0.0"}`
			pkg, err := npm.ParsePackage("", []byte(manifest))
			if err != nil {
				t.Fatalf("ParsePackage failed: %v", err)
			}
			pkg.SourceFiles[fix.fixtureFile] = content

			verdict, err := engine.AnalyzePackage(pkg)
			if err != nil {
				t.Fatalf("AnalyzePackage failed: %v", err)
			}

			if verdict.RiskLevel != RiskBenign || verdict.Action != ActionPass {
				t.Errorf("FALSE POSITIVE on minified fixture %s! Risk: %s, Action: %s, Score: %.2f (ML: %.2f), Evidence: %+v",
					fix.name, verdict.RiskLevel, verdict.Action, verdict.ConfidenceScore, verdict.MLScore, verdict.Evidence)
			}

			if verdict.ConfidenceScore > 0.10 {
				t.Errorf("Score too high for clean minified package %s: got %.2f, expected <= 0.10",
					fix.name, verdict.ConfidenceScore)
			}
		})
	}
}
