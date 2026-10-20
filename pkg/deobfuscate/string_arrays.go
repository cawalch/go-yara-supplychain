package deobfuscate

import (
	"regexp"
	"strconv"
	"strings"
)

var (
	// Matches array literal declarations of string elements:
	// var _0x1234 = ['foo', "bar", 'baz']; or const table = ["a", "b"];
	stringArrayDeclRE = regexp.MustCompile(`(?m)\b(?:var|let|const)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*\[\s*([^\]\n]+)\s*\]\s*;?`)

	// Matches array index lookup: _0x1234[0] or table[0x1]
	arrayLookupRE = regexp.MustCompile(`\b([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\[\s*(0x[0-9a-fA-F]+|\d+)\s*\]`)
)

func parseQuotedStringElement(s string) (string, bool) {
	trimmed := strings.TrimSpace(s)
	if len(trimmed) >= 2 {
		if (trimmed[0] == '\'' && trimmed[len(trimmed)-1] == '\'') ||
			(trimmed[0] == '"' && trimmed[len(trimmed)-1] == '"') {
			return trimmed, true
		}
	}
	return "", false
}

// ResolveStringArrays finds string array declarations (e.g. var _tab = ['eval', 'http://...'])
// and substitutes numeric index accesses (_tab[0], _tab[0x1]) with the corresponding literal.
func ResolveStringArrays(content string) (string, bool) {
	tables := make(map[string][]string)

	for _, match := range stringArrayDeclRE.FindAllStringSubmatch(content, -1) {
		if len(match) < 3 {
			continue
		}
		varName := match[1]
		rawElements := match[2]

		parts := strings.Split(rawElements, ",")
		elements := make([]string, 0, len(parts))
		allQuoted := true

		for _, p := range parts {
			quoted, ok := parseQuotedStringElement(p)
			if ok {
				elements = append(elements, quoted)
			} else {
				allQuoted = false
				break
			}
		}

		if allQuoted && len(elements) > 0 {
			tables[varName] = elements
		}
	}

	if len(tables) == 0 {
		return content, false
	}

	changed := false
	res := arrayLookupRE.ReplaceAllStringFunc(content, func(m string) string {
		sub := arrayLookupRE.FindStringSubmatch(m)
		if len(sub) == 3 {
			ident := sub[1]
			idxStr := sub[2]
			if elements, ok := tables[ident]; ok {
				idx, err := strconv.ParseInt(idxStr, 0, 64)
				if err == nil && idx >= 0 && int(idx) < len(elements) {
					changed = true
					return elements[idx]
				}
			}
		}
		return m
	})

	return res, changed
}
