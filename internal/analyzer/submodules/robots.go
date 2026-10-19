package submodules

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

type RobotsGroup struct {
	UserAgents []string `json:"user_agents,omitempty"`
	Disallow   []string `json:"disallow,omitempty"`
	Allow      []string `json:"allow,omitempty"`
	CrawlDelay string   `json:"crawl_delay,omitempty"`
}

type SitemapSummary struct {
	URL    string `json:"url"`
	Status int    `json:"status,omitempty"`
	URLs   int    `json:"urls,omitempty"`
	Error  string `json:"error,omitempty"`
}

type RobotsResult struct {
	URL          string           `json:"url"`
	Status       int              `json:"status"`
	Groups       []RobotsGroup    `json:"groups,omitempty"`
	Sitemaps     []string         `json:"sitemaps,omitempty"`
	SitemapFiles []SitemapSummary `json:"sitemap_files,omitempty"`
	TotalURLs    int              `json:"total_urls,omitempty"`
	Sensitive    []string         `json:"sensitive,omitempty"`
}

const sitemapsMax = 5

var (
	robotsSensitivePatterns = []string{
		"admin", "login", "backup", "config", "private", "secret", "internal",
		"staging", "tmp", "sql", "db", ".git", ".env", "password", "phpmyadmin",
	}
	sitemapLocPattern = regexp.MustCompile(`(?i)<loc>\s*([^<\s]+)\s*</loc>`)
)

func (r *RobotsResult) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "[robots_scan] %s (status %d)\n", r.URL, r.Status)

	if len(r.Groups) > 0 {
		fmt.Fprintf(&b, "  groups: %d\n", len(r.Groups))
		for _, group := range r.Groups {
			fmt.Fprintf(&b, "    %s: %d disallow, %d allow\n",
				strings.Join(group.UserAgents, ", "), len(group.Disallow), len(group.Allow))
			if group.CrawlDelay != "" {
				fmt.Fprintf(&b, "      crawl-delay: %s\n", group.CrawlDelay)
			}
		}
	}
	if len(r.Sitemaps) > 0 {
		fmt.Fprintf(&b, "  sitemaps: %d\n", len(r.Sitemaps))
		for _, sitemap := range r.Sitemaps {
			fmt.Fprintf(&b, "    %s\n", sitemap)
		}
	}
	if len(r.SitemapFiles) > 0 {
		fmt.Fprintf(&b, "  sitemaps fetched: %d (%d URLs)\n", len(r.SitemapFiles), r.TotalURLs)
		for _, file := range r.SitemapFiles {
			if file.Error != "" {
				fmt.Fprintf(&b, "    %s: error (%s)\n", file.URL, file.Error)
				continue
			}
			fmt.Fprintf(&b, "    %s: status %d, %d URLs\n", file.URL, file.Status, file.URLs)
		}
	}
	if len(r.Sensitive) > 0 {
		fmt.Fprintf(&b, "  sensitive paths: %d\n", len(r.Sensitive))
		for _, path := range r.Sensitive {
			fmt.Fprintf(&b, "    %s\n", path)
		}
	}

	return b.String()
}

func FetchRobots(baseURL string) *RobotsResult {
	target := strings.TrimSuffix(baseURL, "/") + "/robots.txt"

	client := &http.Client{Timeout: probeTimeout}
	status, body, _, err := httpGet(client, target)
	if err != nil {
		return nil
	}

	result := &RobotsResult{URL: target, Status: status}
	if status != http.StatusOK {
		return result
	}

	parsed := ParseRobots(string(body))
	result.Groups = parsed.Groups
	result.Sitemaps = parsed.Sitemaps
	result.Sensitive = parsed.Sensitive
	result.SitemapFiles, result.TotalURLs = inspectSitemaps(client, parsed.Sitemaps)
	return result
}

func inspectSitemaps(client *http.Client, sitemaps []string) ([]SitemapSummary, int) {
	var files []SitemapSummary
	total := 0

	for _, sitemapURL := range sitemaps {
		if len(files) >= sitemapsMax {
			break
		}

		summary := SitemapSummary{URL: sitemapURL}
		status, body, _, err := httpGet(client, sitemapURL)
		if err != nil {
			summary.Error = err.Error()
			files = append(files, summary)
			continue
		}
		summary.Status = status
		if status == http.StatusOK {
			summary.URLs = len(sitemapLocPattern.FindAll(body, -1))
			total += summary.URLs
		}
		files = append(files, summary)
	}

	return files, total
}

func ParseRobots(content string) *RobotsResult {
	result := &RobotsResult{}
	var current *RobotsGroup
	lastWasAgent := false

	for _, raw := range strings.Split(content, "\n") {
		line := raw
		if index := strings.Index(line, "#"); index >= 0 {
			line = line[:index]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		key, value := splitRobotsField(line)
		switch strings.ToLower(key) {
		case "user-agent":
			if current == nil || !lastWasAgent {
				result.Groups = append(result.Groups, RobotsGroup{})
				current = &result.Groups[len(result.Groups)-1]
			}
			current.UserAgents = append(current.UserAgents, value)
			lastWasAgent = true
		case "disallow":
			if current != nil {
				current.Disallow = append(current.Disallow, value)
			}
			lastWasAgent = false
		case "allow":
			if current != nil {
				current.Allow = append(current.Allow, value)
			}
			lastWasAgent = false
		case "crawl-delay":
			if current != nil {
				current.CrawlDelay = value
			}
			lastWasAgent = false
		case "sitemap":
			if value != "" {
				result.Sitemaps = append(result.Sitemaps, value)
			}
			lastWasAgent = false
		}
	}

	result.Sitemaps = uniqueSorted(result.Sitemaps)

	var sensitive []string
	for _, group := range result.Groups {
		for _, path := range group.Disallow {
			if path != "" && robotsIsSensitive(path) {
				sensitive = append(sensitive, path)
			}
		}
	}
	result.Sensitive = uniqueSorted(sensitive)

	return result
}

func splitRobotsField(line string) (string, string) {
	index := strings.Index(line, ":")
	if index < 0 {
		return line, ""
	}
	return strings.TrimSpace(line[:index]), strings.TrimSpace(line[index+1:])
}

func robotsIsSensitive(path string) bool {
	lower := strings.ToLower(path)
	for _, pattern := range robotsSensitivePatterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
}
