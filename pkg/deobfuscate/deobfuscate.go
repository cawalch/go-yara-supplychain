package deobfuscate

// Result holds the normalized code along with metadata about what was uncovered.
type Result struct {
	NormalizedCode   string
	DecodedPayloads  []string
	HadUnicodeTrap   bool
	HadStringConcat  bool
	HadStringArrays  bool
	HadBracketAccess bool
	HadXORLoop       bool
}

// Normalize runs the full de-obfuscation pipeline:
// 1. Unicode zero-width and BiDi Trojan Source stripping.
// 2. String literal constant folding and hex escape expansion.
// 3. String array dictionary lookup resolution (e.g. _tab[0] -> "eval").
// 4. Bracket property access normalization (e.g. window['eval'] -> window.eval).
// 5. Base64 payload extraction and decoding (literals, comments, template strings).
// 6. Bitwise XOR decryption loop pattern detection.
func Normalize(raw string) Result {
	// Step 1: Strip invisible Unicode
	cleanUnicode := StripInvisibleUnicode(raw)
	hadUnicode := cleanUnicode != raw

	// Step 2: Constant folding & hex escape expansion
	folded := FoldStringConstants(cleanUnicode)
	hadConcat := folded != cleanUnicode

	// Step 3: Resolve string array lookups (_tab[0] -> literal)
	resolvedArrays, hadArrays := ResolveStringArrays(folded)
	if hadArrays {
		// Re-fold in case array substitutions introduced concatenations
		resolvedArrays = FoldStringConstants(resolvedArrays)
	}

	// Step 4: Normalize bracket property access (obj['prop'] -> obj.prop)
	normalizedBrackets, hadBrackets := NormalizeBracketAccess(resolvedArrays)

	// Step 5: Base64 unpacking
	unpacked, decoded := UnpackBase64Payloads(normalizedBrackets)

	// Step 6: XOR loop heuristic check
	hadXOR := DetectXORLoop(unpacked)

	return Result{
		NormalizedCode:   unpacked,
		DecodedPayloads:  decoded,
		HadUnicodeTrap:   hadUnicode,
		HadStringConcat:  hadConcat,
		HadStringArrays:  hadArrays,
		HadBracketAccess: hadBrackets,
		HadXORLoop:       hadXOR,
	}
}
