// Package deobfuscate provides multi-layer string and code de-obfuscation
// to uncover hidden payloads before signature and semantic analysis.
package deobfuscate

import (
	"strings"
	"unicode"
)

// StripInvisibleUnicode removes zero-width characters, bidirectional overrides (Trojan Source),
// and non-printable control characters that attackers use to evade regex/string matching.
func StripInvisibleUnicode(s string) string {
	var b strings.Builder
	b.Grow(len(s))

	for _, r := range s {
		// Zero-width characters & joiners
		switch r {
		case '\u200B', // zero-width space
			'\u200C',                                         // zero-width non-joiner
			'\u200D',                                         // zero-width joiner
			'\uFEFF',                                         // zero-width no-break space / byte order mark
			'\u2060',                                         // word joiner
			'\u202A', '\u202B', '\u202C', '\u202D', '\u202E', // bidirectional overrides (Trojan Source)
			'\u2066', '\u2067', '\u2068', '\u2069':
			continue
		}

		// Keep standard whitespace (space, tab, newline, carriage return)
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			b.WriteRune(r)
			continue
		}

		// Keep standard printable ASCII and valid printable unicode
		if unicode.IsPrint(r) {
			b.WriteRune(r)
		}
	}

	return b.String()
}
