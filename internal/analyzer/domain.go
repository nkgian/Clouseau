package analyzer

import (
	"fmt"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

type DomainAnalyzer struct{}

type DomainResult struct {
	Host        string   `json:"host"`
	UnicodeHost string   `json:"unicode_host,omitempty"`
	Punycode    bool     `json:"punycode"`
	Scripts     []string `json:"scripts,omitempty"`
	MixedScript bool     `json:"mixed_script"`
	Warnings    []string `json:"warnings,omitempty"`
}

func (d *DomainAnalyzer) Run(target string, params map[string]interface{}) (interface{}, error) {
	host := hostFromURL(target)
	if host == "" {
		return nil, fmt.Errorf("invalid url %q", target)
	}

	result := &DomainResult{Host: host}

	check := host
	if unicodeHost, ok := decodePunycodeHost(host); ok {
		result.UnicodeHost = unicodeHost
		result.Punycode = true
		result.Warnings = append(result.Warnings, "internationalized domain name (punycode)")
		check = unicodeHost
	}

	result.Scripts = hostScripts(check)
	if len(result.Scripts) > 1 && containsValue(result.Scripts, "Latin") {
		result.MixedScript = true
		result.Warnings = append(result.Warnings,
			fmt.Sprintf("mixed-script host (%s, possible homoglyph)", strings.Join(result.Scripts, " + ")))
	}

	return result, nil
}

func (r *DomainResult) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "[domain_scan] %s\n", r.Host)
	if r.UnicodeHost != "" {
		fmt.Fprintf(&b, "  unicode: %s\n", r.UnicodeHost)
	}
	if len(r.Scripts) > 0 {
		fmt.Fprintf(&b, "  scripts: %s\n", strings.Join(r.Scripts, ", "))
	}
	for _, warning := range r.Warnings {
		fmt.Fprintf(&b, "  ! %s\n", warning)
	}
	return b.String()
}

func hostScripts(host string) []string {
	seen := map[string]bool{}
	var scripts []string
	for _, r := range host {
		script := runeScript(r)
		if script == "" || seen[script] {
			continue
		}
		seen[script] = true
		scripts = append(scripts, script)
	}
	sort.Strings(scripts)
	return scripts
}

func runeScript(r rune) string {
	switch {
	case unicode.Is(unicode.Latin, r):
		return "Latin"
	case unicode.Is(unicode.Cyrillic, r):
		return "Cyrillic"
	case unicode.Is(unicode.Greek, r):
		return "Greek"
	case unicode.Is(unicode.Arabic, r):
		return "Arabic"
	case unicode.Is(unicode.Hebrew, r):
		return "Hebrew"
	case unicode.Is(unicode.Han, r):
		return "Han"
	case unicode.Is(unicode.Hiragana, r):
		return "Hiragana"
	case unicode.Is(unicode.Katakana, r):
		return "Katakana"
	case unicode.Is(unicode.Hangul, r):
		return "Hangul"
	case unicode.Is(unicode.Devanagari, r):
		return "Devanagari"
	default:
		return ""
	}
}

func decodePunycodeHost(host string) (string, bool) {
	labels := strings.Split(host, ".")
	changed := false

	for i, label := range labels {
		if !strings.HasPrefix(strings.ToLower(label), "xn--") {
			continue
		}
		decoded, ok := decodePunycode(strings.ToLower(label)[4:])
		if !ok {
			return "", false
		}
		labels[i] = string(decoded)
		changed = true
	}

	if !changed {
		return "", false
	}
	return strings.Join(labels, "."), true
}

const (
	punyBase        = 36
	punyTMin        = 1
	punyTMax        = 26
	punySkew        = 38
	punyDamp        = 700
	punyInitialBias = 72
	punyInitialN    = 128
)

func decodePunycode(encoded string) ([]rune, bool) {
	if encoded == "" {
		return nil, false
	}

	var output []rune
	n, i, bias := punyInitialN, 0, punyInitialBias

	if index := strings.LastIndex(encoded, "-"); index >= 0 {
		for _, r := range encoded[:index] {
			if r >= utf8.RuneSelf {
				return nil, false
			}
			output = append(output, r)
		}
		encoded = encoded[index+1:]
	}

	position := 0
	for position < len(encoded) {
		oldi := i
		weight := 1
		for k := punyBase; ; k += punyBase {
			if position >= len(encoded) {
				return nil, false
			}
			r, size := utf8.DecodeRuneInString(encoded[position:])
			position += size

			digit, ok := punyDecodeDigit(r)
			if !ok {
				return nil, false
			}
			i += digit * weight
			if i > 1<<24 {
				return nil, false
			}

			threshold := punyTMin
			switch {
			case k <= bias:
				threshold = punyTMin
			case k >= bias+punyTMax:
				threshold = punyTMax
			default:
				threshold = k - bias
			}
			if digit < threshold {
				break
			}
			weight *= punyBase - threshold
		}

		length := len(output) + 1
		bias = punyAdapt(i-oldi, length, oldi == 0)
		n += i / length
		i %= length

		if n > utf8.MaxRune {
			return nil, false
		}
		output = append(output, 0)
		copy(output[i+1:], output[i:])
		output[i] = rune(n)
		i++
	}

	return output, true
}

func punyDecodeDigit(r rune) (int, bool) {
	switch {
	case r >= 'a' && r <= 'z':
		return int(r - 'a'), true
	case r >= 'A' && r <= 'Z':
		return int(r - 'A'), true
	case r >= '0' && r <= '9':
		return int(r-'0') + 26, true
	}
	return 0, false
}

func punyAdapt(delta, numPoints int, firstTime bool) int {
	if firstTime {
		delta /= punyDamp
	} else {
		delta /= 2
	}
	delta += delta / numPoints

	k := 0
	for delta > ((punyBase-punyTMin)*punyTMax)/2 {
		delta /= punyBase - punyTMin
		k += punyBase
	}
	return k + (punyBase-punyTMin+1)*delta/(delta+punySkew)
}

func containsValue(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
