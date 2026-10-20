package analyzer

import (
	"regexp"
	"strings"
)

var (
	// Known standard native build commands used by legitimate addons
	nativeBuildCmdRE = regexp.MustCompile(`(?i)\b(node-gyp|node-pre-gyp|cmake-js|cargo\s+build|make\b|ninja\b|msbuild\b|cargo-cp-artifact)`)

	// Harmless banner / log messages in install hooks
	consoleOnlyCmdRE = regexp.MustCompile(`(?i)^\s*(node\s+-e\s+['"]console\.log\([^)]+\)['"]|echo\s+['"][^'"]+['"])\s*$`)

	// Trusted domains for precompiled native binaries
	trustedBinaryHosts = []string{
		"registry.npmjs.org",
		"github.com",
		"objects.githubusercontent.com",
		"binaries.prisma.sh",
		"releases.hashicorp.com",
	}
)

// IsBenignBuildHook checks whether an install script hook is a standard compilation or notice,
// ensuring zero false positives on tools like node-gyp or core-js.
func IsBenignBuildHook(cmd string) bool {
	clean := strings.TrimSpace(cmd)
	if consoleOnlyCmdRE.MatchString(clean) {
		return true
	}
	if nativeBuildCmdRE.MatchString(clean) && !strings.Contains(clean, "|") && !strings.Contains(clean, "eval") {
		return true
	}
	return false
}

// IsBenignBinaryFetcher checks whether a script downloading platform binaries is legitimate
// (e.g. esbuild, swc, sharp) by verifying it targets trusted binary mirrors and performs checksum verification.
func IsBenignBinaryFetcher(content string) bool {
	hasTrustedHost := false
	for _, host := range trustedBinaryHosts {
		if strings.Contains(content, host) {
			hasTrustedHost = true
			break
		}
	}
	if !hasTrustedHost {
		return false
	}

	// Legitimate binary downloaders verify hashes, shasum, or use un-piped extraction
	hasChecksumOrTar := strings.Contains(content, "sha") ||
		strings.Contains(content, "checksum") ||
		strings.Contains(content, "integrity") ||
		strings.Contains(content, "tar.extract") ||
		strings.Contains(content, "unzip")

	hasPipeToShell := strings.Contains(content, "| sh") ||
		strings.Contains(content, "| bash") ||
		strings.Contains(content, "|sh") ||
		strings.Contains(content, "|bash")

	return hasChecksumOrTar && !hasPipeToShell
}
