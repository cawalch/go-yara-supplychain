package deobfuscate

import (
	"regexp"
	"strconv"
	"strings"
)

var (
	// Matches string concatenation like "a" + "b" or 'a' + 'b'
	concatDoubleRE = regexp.MustCompile(`"([^"\\]*)"\s*\+\s*"([^"\\]*)"`)
	concatSingleRE = regexp.MustCompile(`'([^'\\]*)'\s*\+\s*'([^'\\]*)'`)

	// Matches hex escape sequences like \x65\x76\x61\x6c
	hexEscapeRE = regexp.MustCompile(`\\x([0-9a-fA-F]{2})`)

	// Matches String.fromCharCode(99, 117, 114, 108)
	fromCharCodeRE = regexp.MustCompile(`String\.fromCharCode\s*\(\s*([0-9,\s]+)\s*\)`)

	// Matches simple array joins: ['c','u','r','l'].join('')
	arrayJoinRE = regexp.MustCompile(`\[\s*((?:'[^']+'|"[^"]+")(?:\s*,\s*(?:'[^']+'|"[^"]+"))*)\s*\]\.join\s*\(\s*['"]{2}\s*\)`)
)

// FoldStringConstants simplifies concatenated string literals, resolves hex escapes,
// and decodes String.fromCharCode calls so hidden API calls and URLs become visible to YARA.
func FoldStringConstants(content string) string {
	res := content

	// 1. Resolve Hex Escapes (\x65 -> e)
	res = hexEscapeRE.ReplaceAllStringFunc(res, func(m string) string {
		sub := hexEscapeRE.FindStringSubmatch(m)
		if len(sub) == 2 {
			val, err := strconv.ParseUint(sub[1], 16, 8)
			if err == nil && val >= 32 && val <= 126 {
				return string(rune(val))
			}
		}
		return m
	})

	// 2. Resolve String Concatenation ("a" + "b" -> "ab") iteratively
	for i := 0; i < 5; i++ {
		prev := res
		res = concatDoubleRE.ReplaceAllString(res, `"$1$2"`)
		res = concatSingleRE.ReplaceAllString(res, `'$1$2'`)
		if res == prev {
			break
		}
	}

	// 3. Resolve String.fromCharCode(99, 117, 114, 108) -> "curl"
	res = fromCharCodeRE.ReplaceAllStringFunc(res, func(m string) string {
		sub := fromCharCodeRE.FindStringSubmatch(m)
		if len(sub) == 2 {
			parts := strings.Split(sub[1], ",")
			var sb strings.Builder
			for _, p := range parts {
				n, err := strconv.Atoi(strings.TrimSpace(p))
				if err != nil || n < 32 || n > 126 {
					return m // unprintable or invalid, keep original
				}
				sb.WriteByte(byte(n))
			}
			return `"` + sb.String() + `"`
		}
		return m
	})

	// 4. Resolve ['c','u','r','l'].join('') -> "curl"
	res = arrayJoinRE.ReplaceAllStringFunc(res, func(m string) string {
		sub := arrayJoinRE.FindStringSubmatch(m)
		if len(sub) == 2 {
			parts := strings.Split(sub[1], ",")
			var sb strings.Builder
			for _, p := range parts {
				clean := strings.Trim(strings.TrimSpace(p), `'"`)
				sb.WriteString(clean)
			}
			return `"` + sb.String() + `"`
		}
		return m
	})

	return res
}
