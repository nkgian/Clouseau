package analyzer

import (
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type HeadersAnalyzer struct{}

type HeaderCheck struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Note   string `json:"note,omitempty"`
}

type CookieFlag struct {
	Name     string `json:"name"`
	Secure   bool   `json:"secure"`
	HttpOnly bool   `json:"http_only"`
	SameSite string `json:"same_site,omitempty"`
}

type CORSInfo struct {
	ProbeOrigin      string `json:"probe_origin"`
	AllowOrigin      string `json:"allow_origin,omitempty"`
	AllowCredentials bool   `json:"allow_credentials"`
	ReflectsOrigin   bool   `json:"reflects_origin"`
}

type RedirectHop struct {
	URL    string `json:"url"`
	Status int    `json:"status,omitempty"`
}

type HeadersResult struct {
	URL       string        `json:"url"`
	Status    int           `json:"status"`
	Server    string        `json:"server,omitempty"`
	PoweredBy string        `json:"powered_by,omitempty"`
	Redirects []RedirectHop `json:"redirects,omitempty"`
	Checks    []HeaderCheck `json:"checks"`
	Cookies   []CookieFlag  `json:"cookies,omitempty"`
	CORS      *CORSInfo     `json:"cors,omitempty"`
}

const (
	headerStatusOK      = "ok"
	headerStatusWeak    = "weak"
	headerStatusMissing = "missing"
	corsProbeOrigin     = "https://clouseau.example"
	hstsMinMaxAge       = 15552000
	headerRedirectLimit = 10
)

var hstsMaxAgePattern = regexp.MustCompile(`(?i)max-age\s*=\s*(\d+)`)

func (h *HeadersAnalyzer) Run(target string, params map[string]interface{}) (interface{}, error) {
	parsed, err := url.Parse(normalizeURL(target))
	if err != nil || parsed.Host == "" {
		return nil, fmt.Errorf("invalid url %q", target)
	}

	request, err := http.NewRequest(http.MethodGet, parsed.String(), nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("User-Agent", "clouseau/1.0")
	request.Header.Set("Origin", corsProbeOrigin)

	hops := []RedirectHop{{URL: parsed.String()}}
	client := &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= headerRedirectLimit {
				return fmt.Errorf("stopped after %d redirects", headerRedirectLimit)
			}
			hops[len(hops)-1].Status = req.Response.StatusCode
			hops = append(hops, RedirectHop{URL: req.URL.String()})
			return nil
		},
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	hops[len(hops)-1].Status = response.StatusCode

	result := &HeadersResult{
		URL:       response.Request.URL.String(),
		Status:    response.StatusCode,
		Server:    response.Header.Get("Server"),
		PoweredBy: response.Header.Get("X-Powered-By"),
	}
	if len(hops) > 1 {
		result.Redirects = hops
	}

	hsts := response.Header.Get("Strict-Transport-Security")
	csp := response.Header.Get("Content-Security-Policy")

	result.Checks = append(result.Checks,
		checkHSTS(hsts),
		checkCSP(csp),
		checkXFrameOptions(response.Header.Get("X-Frame-Options"), csp),
		checkContentTypeOptions(response.Header.Get("X-Content-Type-Options")),
		checkReferrerPolicy(response.Header.Get("Referrer-Policy")),
		checkPermissionsPolicy(response.Header.Get("Permissions-Policy")),
	)

	for _, raw := range response.Header.Values("Set-Cookie") {
		if cookie := parseCookieFlags(raw); cookie != nil {
			result.Cookies = append(result.Cookies, *cookie)
		}
	}

	if allowOrigin := response.Header.Get("Access-Control-Allow-Origin"); allowOrigin != "" {
		result.CORS = &CORSInfo{
			ProbeOrigin:      corsProbeOrigin,
			AllowOrigin:      allowOrigin,
			AllowCredentials: strings.EqualFold(response.Header.Get("Access-Control-Allow-Credentials"), "true"),
			ReflectsOrigin:   allowOrigin == corsProbeOrigin,
		}
	}

	return result, nil
}

func (r *HeadersResult) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "[headers_scan] %s (status %d)\n", r.URL, r.Status)
	if r.Server != "" {
		fmt.Fprintf(&b, "  server: %s\n", r.Server)
	}
	if r.PoweredBy != "" {
		fmt.Fprintf(&b, "  powered by: %s\n", r.PoweredBy)
	}

	if len(r.Redirects) > 1 {
		fmt.Fprintf(&b, "  redirects: %d hop(s)\n", len(r.Redirects)-1)
		for _, hop := range r.Redirects {
			fmt.Fprintf(&b, "    %d %s\n", hop.Status, hop.URL)
		}
	}

	if len(r.Checks) > 0 {
		ok, weak, missing := 0, 0, 0
		for _, check := range r.Checks {
			switch check.Status {
			case headerStatusOK:
				ok++
			case headerStatusWeak:
				weak++
			default:
				missing++
			}
		}
		fmt.Fprintf(&b, "  security headers: %d ok, %d weak, %d missing\n", ok, weak, missing)
		for _, check := range r.Checks {
			fmt.Fprintf(&b, "    %s: %s", check.Name, check.Status)
			if check.Note != "" {
				fmt.Fprintf(&b, " (%s)", check.Note)
			}
			b.WriteString("\n")
		}
	}

	if len(r.Cookies) > 0 {
		fmt.Fprintf(&b, "  cookies: %d\n", len(r.Cookies))
		for _, cookie := range r.Cookies {
			fmt.Fprintf(&b, "    %s: secure=%s, httponly=%s", cookie.Name, yesNo(cookie.Secure), yesNo(cookie.HttpOnly))
			if cookie.SameSite != "" {
				fmt.Fprintf(&b, ", samesite=%s", cookie.SameSite)
			}
			b.WriteString("\n")
		}
	}

	if r.CORS != nil {
		fmt.Fprintf(&b, "  cors: allow-origin %s (credentials: %s)\n",
			r.CORS.AllowOrigin, yesNo(r.CORS.AllowCredentials))
		if r.CORS.ReflectsOrigin {
			b.WriteString("    reflects the probe origin\n")
		}
	}

	return b.String()
}

func checkHSTS(value string) HeaderCheck {
	check := HeaderCheck{Name: "Strict-Transport-Security", Status: headerStatusMissing}
	if value == "" {
		return check
	}

	check.Status = headerStatusOK
	match := hstsMaxAgePattern.FindStringSubmatch(value)
	if match == nil {
		check.Status = headerStatusWeak
		check.Note = "missing max-age"
		return check
	}
	if seconds, err := strconv.Atoi(match[1]); err == nil && seconds < hstsMinMaxAge {
		check.Status = headerStatusWeak
		check.Note = fmt.Sprintf("max-age %d is shorter than 6 months", seconds)
	}
	return check
}

func checkCSP(value string) HeaderCheck {
	check := HeaderCheck{Name: "Content-Security-Policy", Status: headerStatusMissing}
	if value == "" {
		return check
	}

	check.Status = headerStatusOK
	lower := strings.ToLower(value)
	var weak []string
	if strings.Contains(lower, "'unsafe-inline'") {
		weak = append(weak, "'unsafe-inline'")
	}
	if strings.Contains(lower, "'unsafe-eval'") {
		weak = append(weak, "'unsafe-eval'")
	}
	if len(weak) > 0 {
		check.Status = headerStatusWeak
		check.Note = "allows " + strings.Join(weak, ", ")
	}
	return check
}

func checkXFrameOptions(value, csp string) HeaderCheck {
	check := HeaderCheck{Name: "X-Frame-Options", Status: headerStatusMissing}
	if value != "" {
		check.Status = headerStatusOK
		check.Note = strings.ToUpper(value)
		return check
	}
	if strings.Contains(strings.ToLower(csp), "frame-ancestors") {
		check.Status = headerStatusOK
		check.Note = "via CSP frame-ancestors"
	}
	return check
}

func checkContentTypeOptions(value string) HeaderCheck {
	check := HeaderCheck{Name: "X-Content-Type-Options", Status: headerStatusMissing}
	if value == "" {
		return check
	}
	if strings.EqualFold(value, "nosniff") {
		check.Status = headerStatusOK
		return check
	}
	check.Status = headerStatusWeak
	check.Note = fmt.Sprintf("unexpected value %q", value)
	return check
}

func checkReferrerPolicy(value string) HeaderCheck {
	check := HeaderCheck{Name: "Referrer-Policy", Status: headerStatusMissing}
	if value == "" {
		return check
	}
	check.Status = headerStatusOK
	check.Note = value
	if strings.EqualFold(value, "unsafe-url") {
		check.Status = headerStatusWeak
	}
	return check
}

func checkPermissionsPolicy(value string) HeaderCheck {
	check := HeaderCheck{Name: "Permissions-Policy", Status: headerStatusMissing}
	if value != "" {
		check.Status = headerStatusOK
	}
	return check
}

func parseCookieFlags(raw string) *CookieFlag {
	parts := strings.Split(raw, ";")
	name := strings.TrimSpace(strings.SplitN(parts[0], "=", 2)[0])
	if name == "" {
		return nil
	}

	cookie := &CookieFlag{Name: name}
	for _, attribute := range parts[1:] {
		key, value, _ := strings.Cut(strings.TrimSpace(attribute), "=")
		switch {
		case strings.EqualFold(key, "secure"):
			cookie.Secure = true
		case strings.EqualFold(key, "httponly"):
			cookie.HttpOnly = true
		case strings.EqualFold(key, "samesite"):
			cookie.SameSite = value
		}
	}
	return cookie
}

func yesNo(value bool) string {
	if value {
		return "yes"
	}
	return "no"
}
