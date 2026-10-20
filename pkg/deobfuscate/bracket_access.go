package deobfuscate

import (
	"regexp"
)

var (
	// Matches property access via bracket string literal, e.g. window['eval'] or process['env']
	bracketPropRE = regexp.MustCompile(`([a-zA-Z0-9_$]+(?:\.[a-zA-Z0-9_$]+)*)\s*\[\s*['"]([a-zA-Z_$][a-zA-Z0-9_$]*)['"]\s*\]`)
)

// NormalizeBracketAccess converts bracket notation object access with string literals
// (e.g., window['eval'], process['env']['AWS_KEY'], global['require']) into dot notation
// (window.eval, process.env.AWS_KEY, global.require) so pattern rules match unified syntax.
func NormalizeBracketAccess(content string) (string, bool) {
	res := content
	changed := false

	// Iterate up to 4 passes to handle chained access like obj['a']['b']['c']
	for range 4 {
		next := bracketPropRE.ReplaceAllString(res, "$1.$2")
		if next == res {
			break
		}
		changed = true
		res = next
	}

	return res, changed
}
