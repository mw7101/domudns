package dns

import "strings"

// CharClass is a small rune allowlist: a composable description of which
// character categories (lowercase/uppercase letters, digits) plus which
// individually-listed extra runes are accepted. It exists so the handful of
// packages that validate a name/filename one rune at a time (DNS labels,
// sanitized filenames, split-horizon view names) share one implementation
// instead of each hand-rolling the same range checks.
type CharClass struct {
	Lower bool   // a-z
	Upper bool   // A-Z
	Digit bool   // 0-9
	Extra string // additional individually-allowed runes
}

// Allows reports whether c is permitted by cc.
func (cc CharClass) Allows(c rune) bool {
	switch {
	case cc.Lower && c >= 'a' && c <= 'z':
		return true
	case cc.Upper && c >= 'A' && c <= 'Z':
		return true
	case cc.Digit && c >= '0' && c <= '9':
		return true
	default:
		return strings.ContainsRune(cc.Extra, c)
	}
}

// labelCharClass matches the characters allowed in a DNS label apart from
// '_', which isValidLabelChar only allows when allowUnderscore is set.
var labelCharClass = CharClass{Lower: true, Upper: true, Digit: true, Extra: "-*"}

// isValidLabelChar reports whether c may appear in a DNS label: a-z, A-Z,
// 0-9, '-', '*' (wildcard records), and — when allowUnderscore is set —
// '_' (DHCP-registered hostnames like ESP_CC8108 and service labels like
// _sip._tcp).
func isValidLabelChar(c rune, allowUnderscore bool) bool {
	return labelCharClass.Allows(c) || (allowUnderscore && c == '_')
}

// FilenameCharClass matches the characters allowed in a sanitized domain
// filename (path-traversal protection): a-z, 0-9, '.', '-', '_'.
var FilenameCharClass = CharClass{Lower: true, Digit: true, Extra: ".-_"}

// ViewNameCharClass matches the characters allowed in a split-horizon view
// name: a-z, 0-9, '_', '-'.
var ViewNameCharClass = CharClass{Lower: true, Digit: true, Extra: "_-"}

// IsValidViewName checks whether a view name is valid: only characters in
// ViewNameCharClass, max 64 characters. Shared by filestore (zone filenames)
// and the caddy/api zones handlers (request validation) so the rule can't
// drift between where a view name is accepted and where it's persisted.
func IsValidViewName(name string) bool {
	if len(name) == 0 || len(name) > 64 {
		return false
	}
	for _, c := range name {
		if !ViewNameCharClass.Allows(c) {
			return false
		}
	}
	return true
}
