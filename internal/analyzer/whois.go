package analyzer

import (
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"time"
)

type WhoisAnalyzer struct{}

type WhoisResult struct {
	Domain    string            `json:"domain"`
	Server    string            `json:"server"`
	CreatedAt string            `json:"created_at,omitempty"`
	AgeDays   int               `json:"domain_age_days,omitempty"`
	NewDomain bool              `json:"new_domain,omitempty"`
	Fields    map[string]string `json:"fields"`
	Raw       string            `json:"raw"`
}

const newDomainDays = 90

var (
	whoisCreatedKeys = []string{
		"Creation Date", "Created On", "Created", "created", "created_at",
		"Creation Time", "Registered On", "Registration Date",
		"Domain Registration Date", "created date", "Created Date",
	}
	whoisDateLayouts = []string{
		time.RFC3339,
		"2006-01-02T15:04:05Z",
		"2006-01-02T15:04:05.000Z",
		"2006-01-02 15:04:05",
		"2006-01-02",
		"02-Jan-2006",
		"2006.01.02",
		"January 2 2006",
	}
)

func (r *WhoisResult) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "[whois_lookup] %s (server: %s)\n", r.Domain, r.Server)

	if r.AgeDays > 0 {
		fmt.Fprintf(&b, "  domain age: %d days\n", r.AgeDays)
	}
	if r.NewDomain {
		fmt.Fprintf(&b, "  ! recently registered domain (< %d days)\n", newDomainDays)
	}

	keys := make([]string, 0, len(r.Fields))
	for k := range r.Fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(&b, "  %s: %s\n", k, r.Fields[k])
	}

	fmt.Fprintln(&b, "  --- raw response ---")
	for _, line := range strings.Split(strings.TrimRight(r.Raw, "\r\n"), "\n") {
		fmt.Fprintf(&b, "  %s\n", strings.TrimRight(line, "\r"))
	}
	return b.String()
}

func (w *WhoisAnalyzer) Run(url string, params map[string]interface{}) (interface{}, error) {
	domain := hostFromURL(url)
	if domain == "" {
		return nil, fmt.Errorf("invalid url %q", url)
	}

	server := stringParam(params, "server")
	if server == "" {
		discovered, err := discoverWhoisServer(domain)
		if err != nil {
			return nil, err
		}
		server = discovered
	}

	raw, err := queryWhois(server, domain)
	if err != nil {
		return nil, fmt.Errorf("whois query to %s for %s failed: %w", server, domain, err)
	}

	fields := parseWhoisFields(raw)
	result := &WhoisResult{
		Domain: domain,
		Server: server,
		Fields: fields,
		Raw:    raw,
	}
	if created, ok := whoisCreatedAt(fields); ok {
		result.CreatedAt = created.Format("2006-01-02")
		if days := int(time.Since(created).Hours() / 24); days >= 0 {
			result.AgeDays = days
			result.NewDomain = days < newDomainDays
		}
	}
	return result, nil
}

func whoisCreatedAt(fields map[string]string) (time.Time, bool) {
	for _, key := range whoisCreatedKeys {
		value, exists := fields[key]
		if !exists {
			continue
		}
		value = strings.TrimSpace(strings.Trim(value, "\"'"))
		for _, layout := range whoisDateLayouts {
			if parsed, err := time.Parse(layout, value); err == nil {
				return parsed, true
			}
		}
	}
	return time.Time{}, false
}

func queryWhois(server, query string) (string, error) {
	conn, err := net.DialTimeout("tcp", whoisAddress(server), 10*time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		return "", err
	}

	if _, err := fmt.Fprintf(conn, "%s\r\n", query); err != nil {
		return "", err
	}

	data, err := io.ReadAll(io.LimitReader(conn, 64<<10))
	if len(data) == 0 && err != nil {
		return "", err
	}
	return string(data), nil
}

func whoisAddress(server string) string {
	if _, _, err := net.SplitHostPort(server); err == nil {
		return server
	}
	return net.JoinHostPort(server, "43")
}

func discoverWhoisServer(domain string) (string, error) {
	idx := strings.LastIndex(domain, ".")
	if idx <= 0 || idx == len(domain)-1 {
		return "", fmt.Errorf("cannot determine tld for %q", domain)
	}
	tld := domain[idx+1:]

	response, err := queryWhois("whois.iana.org", tld)
	if err != nil {
		return "", fmt.Errorf("whois server discovery for .%s failed: %w", tld, err)
	}

	for _, line := range strings.Split(response, "\n") {
		line = strings.TrimSpace(line)
		if len(line) > 6 && strings.EqualFold(line[:6], "whois:") {
			fields := strings.Fields(line[6:])
			if len(fields) > 0 {
				return fields[0], nil
			}
		}
	}
	return "", fmt.Errorf("no whois server registered for .%s", tld)
}

func parseWhoisFields(raw string) map[string]string {
	fields := map[string]string{}
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(strings.TrimRight(line, "\r"))
		// fix for whois lokkups with inconvenient formatting, e.g. ">>> Last update of whois database": "2026-10-19T16:47:19Z <<<""
		if line == "" || strings.HasPrefix(line, "%") || strings.HasPrefix(line, "#") ||
			strings.HasPrefix(line, ">>>") || strings.HasPrefix(line, "<<<") {
			continue
		}

		idx := strings.Index(line, ":")
		if idx <= 0 {
			continue
		}

		key := strings.TrimSpace(line[:idx])
		value := strings.TrimSpace(line[idx+1:])
		if key == "" || value == "" || strings.ContainsAny(key, "/\\") || strings.HasPrefix(value, "//") {
			continue
		}

		if previous, exists := fields[key]; exists {
			fields[key] = previous + ", " + value
		} else {
			fields[key] = value
		}
	}
	return fields
}
