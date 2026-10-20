package deobfuscate

import "regexp"

var xorLoopRE = regexp.MustCompile(`(?i)(ord\([^)]+\)\s*\^\s*ord\([^)]+\)|\$\w+\[\$\w+\]\s*\^=\s*|charCodeAt\([^)]+\)\s*\^\s*\w+|\w+\s*\^\s*\w+\[\w+\s*%\s*len\(|bytes\(\[[^\]]+\^\s*[^\]]+\]\))`)

// DetectXORLoop checks if content contains bitwise XOR decryption loops commonly used to evade static analysis.
func DetectXORLoop(code string) bool {
	return xorLoopRE.MatchString(code)
}
