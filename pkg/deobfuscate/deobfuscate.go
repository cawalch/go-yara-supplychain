package deobfuscate

// Result holds the normalized code along with metadata about what was uncovered.
type Result struct {
	NormalizedCode  string
	DecodedPayloads []string
	HadUnicodeTrap  bool
	HadStringConcat bool
}

// Normalize runs the full de-obfuscation pipeline:
// 1. Unicode zero-width and BiDi Trojan Source stripping.
// 2. String literal constant folding and hex escape expansion.
// 3. Base64 payload extraction and decoding.
func Normalize(raw string) Result {
	// Step 1: Strip invisible Unicode
	cleanUnicode := StripInvisibleUnicode(raw)
	hadUnicode := cleanUnicode != raw

	// Step 2: Constant folding & hex escape expansion
	folded := FoldStringConstants(cleanUnicode)
	hadConcat := folded != cleanUnicode

	// Step 3: Base64 unpacking
	unpacked, decoded := UnpackBase64Payloads(folded)

	return Result{
		NormalizedCode:  unpacked,
		DecodedPayloads: decoded,
		HadUnicodeTrap:  hadUnicode,
		HadStringConcat: hadConcat,
	}
}
