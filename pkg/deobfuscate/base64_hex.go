package deobfuscate

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"
)

var (
	// Matches Buffer.from('...', 'base64') or Buffer.from("...", "base64")
	bufferFromB64RE = regexp.MustCompile(`Buffer\.from\s*\(\s*['"]([A-Za-z0-9+/=]{16,})['"]\s*,\s*['"]base64['"]\s*\)`)

	// Matches atob('...')
	atobRE = regexp.MustCompile(`atob\s*\(\s*['"]([A-Za-z0-9+/=]{16,})['"]\s*\)`)

	// Matches general base64 string literals
	genericB64StringRE = regexp.MustCompile(`['"]([A-Za-z0-9+/=]{24,})['"]`)
)

// UnpackBase64Payloads searches for embedded Base64 strings in script code, decodes them,
// and appends the decoded text as annotated comment blocks so pattern rules can inspect the inner payload.
func UnpackBase64Payloads(content string) (unpacked string, payloads []string) {
	var decodedPayloads []string
	seen := map[string]bool{}

	candidates := make([]string, 0)

	// Explicit base64 decoding calls
	for _, sub := range bufferFromB64RE.FindAllStringSubmatch(content, -1) {
		if len(sub) == 2 {
			candidates = append(candidates, sub[1])
		}
	}
	for _, sub := range atobRE.FindAllStringSubmatch(content, -1) {
		if len(sub) == 2 {
			candidates = append(candidates, sub[1])
		}
	}
	for _, sub := range genericB64StringRE.FindAllStringSubmatch(content, -1) {
		if len(sub) == 2 {
			candidates = append(candidates, sub[1])
		}
	}

	for _, cand := range candidates {
		if seen[cand] {
			continue
		}
		seen[cand] = true

		raw, err := base64.StdEncoding.DecodeString(cand)
		if err != nil {
			continue
		}

		// Verify that decoded data is genuine executable code payload (not inlined SVG or font assets)
		if isLikelyCodePayload(raw) {
			decodedPayloads = append(decodedPayloads, string(raw))
		}
	}

	if len(decodedPayloads) == 0 {
		return content, nil
	}

	var sb strings.Builder
	sb.WriteString(content)
	sb.WriteString("\n\n// --- DEOBFUSCATED PAYLOADS ---\n")
	for i, p := range decodedPayloads {
		fmt.Fprintf(&sb, "// [DECODED_BASE64_BLOCK_%d]:\n", i+1)
		sb.WriteString(p)
		sb.WriteString("\n")
	}

	return sb.String(), decodedPayloads
}

func isLikelyCodePayload(b []byte) bool {
	if !isPrintableText(b) {
		return false
	}

	s := strings.TrimSpace(string(b))

	// Filter out non-code assets (SVGs, XML, CSS, HTML snippets) common in bundled web applications
	if strings.HasPrefix(s, "<svg") || strings.HasPrefix(s, "<?xml") ||
		strings.HasPrefix(s, "<!DOCTYPE") || strings.HasPrefix(s, "data:") {
		return false
	}

	// Must contain recognizable script primitives, shell keywords, or execution calls
	codeIndicators := []string{
		"require(", "require (",
		"import ", "export ",
		"function", "=>",
		"var ", "const ", "let ",
		"eval(", "Function(", "vm.runIn",
		"child_process", "exec(", "spawn(", "execSync(",
		"process.env", "process.platform",
		"net.connect", "net.Socket",
		"http.request", "https.request",
		"curl ", "wget ", "chmod ",
		"/bin/sh", "/bin/bash", "cmd.exe", "powershell",
	}

	for _, kw := range codeIndicators {
		if strings.Contains(s, kw) {
			return true
		}
	}

	return false
}

func isPrintableText(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	if !utf8.Valid(b) {
		return false
	}
	printable := 0
	for _, r := range string(b) {
		if r == '\n' || r == '\r' || r == '\t' || (r >= 32 && r <= 126) {
			printable++
		}
	}
	return float64(printable)/float64(len(b)) >= 0.85
}
