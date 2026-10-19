package submodules

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

type FormInfo struct {
	Action         string `json:"action,omitempty"`
	Method         string `json:"method,omitempty"`
	CrossOrigin    bool   `json:"cross_origin,omitempty"`
	PasswordFields int    `json:"password_fields,omitempty"`
	HiddenFields   int    `json:"hidden_fields,omitempty"`
}

type FormResult struct {
	Forms            []FormInfo `json:"forms,omitempty"`
	PasswordForms    int        `json:"password_forms,omitempty"`
	CrossOriginForms int        `json:"cross_origin_forms,omitempty"`
	MetaRefresh      bool       `json:"meta_refresh,omitempty"`
}

var (
	formTagPattern      = regexp.MustCompile(`(?is)<form\b[^>]*>`)
	formEndPattern      = regexp.MustCompile(`(?i)</form\s*>`)
	formActionPattern   = regexp.MustCompile(`(?i)\baction\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))`)
	formMethodPattern   = regexp.MustCompile(`(?i)\bmethod\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))`)
	formPasswordPattern = regexp.MustCompile(`(?i)<input\b[^>]*\btype\s*=\s*["']?password`)
	formHiddenPattern   = regexp.MustCompile(`(?i)<input\b[^>]*\btype\s*=\s*["']?hidden`)
	formMetaRefresh     = regexp.MustCompile(`(?i)<meta\b[^>]*\bhttp-equiv\s*=\s*["']?refresh`)
)

func ParseForms(body []byte, pageURL string) *FormResult {
	text := string(body)
	result := &FormResult{MetaRefresh: formMetaRefresh.MatchString(text)}

	page, _ := url.Parse(pageURL)
	seen := map[string]bool{}

	for _, location := range formTagPattern.FindAllStringIndex(text, -1) {
		tag := text[location[0]:location[1]]
		content := ""
		if end := formEndPattern.FindStringIndex(text[location[1]:]); end != nil {
			content = text[location[1] : location[1]+end[0]]
		}

		form := FormInfo{
			Action:         firstRegexGroup(formActionPattern, tag),
			Method:         strings.ToUpper(firstRegexGroup(formMethodPattern, tag)),
			PasswordFields: len(formPasswordPattern.FindAllString(content, -1)),
			HiddenFields:   len(formHiddenPattern.FindAllString(content, -1)),
		}
		if form.Method == "" {
			form.Method = "GET"
		}
		if form.Action != "" && page != nil {
			if reference, err := url.Parse(strings.TrimSpace(form.Action)); err == nil {
				resolved := page.ResolveReference(reference)
				form.CrossOrigin = resolved.Host != "" &&
					!strings.EqualFold(resolved.Hostname(), page.Hostname())
			}
		}

		key := form.Method + " " + form.Action
		if seen[key] {
			continue
		}
		seen[key] = true
		result.Forms = append(result.Forms, form)
		if form.PasswordFields > 0 {
			result.PasswordForms++
		}
		if form.CrossOrigin {
			result.CrossOriginForms++
		}
	}

	if len(result.Forms) == 0 && !result.MetaRefresh {
		return nil
	}
	return result
}

func (r *FormResult) Merge(other *FormResult) {
	if other == nil {
		return
	}
	r.MetaRefresh = r.MetaRefresh || other.MetaRefresh

	seen := map[string]bool{}
	for _, form := range r.Forms {
		seen[form.Method+" "+form.Action] = true
	}
	for _, form := range other.Forms {
		key := form.Method + " " + form.Action
		if seen[key] {
			continue
		}
		seen[key] = true
		r.Forms = append(r.Forms, form)
		if form.PasswordFields > 0 {
			r.PasswordForms++
		}
		if form.CrossOrigin {
			r.CrossOriginForms++
		}
	}
}

func (r *FormResult) String() string {
	var b strings.Builder
	if len(r.Forms) > 0 {
		fmt.Fprintf(&b, "  forms: %d (%d password, %d cross-origin)\n",
			len(r.Forms), r.PasswordForms, r.CrossOriginForms)
		for _, form := range r.Forms {
			action := form.Action
			if action == "" {
				action = "(self)"
			}
			fmt.Fprintf(&b, "    %s %s", form.Method, action)
			if form.CrossOrigin {
				b.WriteString(" [cross-origin]")
			}
			if form.PasswordFields > 0 {
				fmt.Fprintf(&b, " password-fields=%d", form.PasswordFields)
			}
			if form.HiddenFields > 0 {
				fmt.Fprintf(&b, " hidden-fields=%d", form.HiddenFields)
			}
			b.WriteString("\n")
		}
	}
	if r.MetaRefresh {
		b.WriteString("  meta refresh: yes\n")
	}
	return b.String()
}

func firstRegexGroup(pattern *regexp.Regexp, value string) string {
	match := pattern.FindStringSubmatch(value)
	if match == nil {
		return ""
	}
	for _, group := range match[1:] {
		if group != "" {
			return group
		}
	}
	return ""
}
