package tests

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"clouseau/internal/analyzer"
	"clouseau/internal/analyzer/submodules"
)

func TestParseRobotsGroups(t *testing.T) {
	content := `# example robots.txt
User-agent: *
Disallow: /wp-admin/
Disallow: /backup/
Allow: /wp-admin/admin-ajax.php
Crawl-delay: 5

User-agent: Googlebot
User-agent: Bingbot
Disallow: /private/

Sitemap: https://example.com/sitemap_index.xml
Sitemap: https://example.com/news-sitemap.xml
`

	result := submodules.ParseRobots(content)

	if len(result.Groups) != 2 {
		t.Fatalf("groups = %d, want 2: %+v", len(result.Groups), result.Groups)
	}

	first := result.Groups[0]
	if len(first.UserAgents) != 1 || first.UserAgents[0] != "*" {
		t.Fatalf("first group agents = %v, want [*]", first.UserAgents)
	}
	if len(first.Disallow) != 2 {
		t.Fatalf("first group disallow = %v, want 2 entries", first.Disallow)
	}
	if len(first.Allow) != 1 || first.Allow[0] != "/wp-admin/admin-ajax.php" {
		t.Fatalf("first group allow = %v, want [/wp-admin/admin-ajax.php]", first.Allow)
	}
	if first.CrawlDelay != "5" {
		t.Fatalf("first group crawl-delay = %q, want 5", first.CrawlDelay)
	}

	second := result.Groups[1]
	if len(second.UserAgents) != 2 || second.UserAgents[0] != "Googlebot" || second.UserAgents[1] != "Bingbot" {
		t.Fatalf("second group agents = %v, want [Googlebot Bingbot]", second.UserAgents)
	}
	if len(second.Disallow) != 1 || second.Disallow[0] != "/private/" {
		t.Fatalf("second group disallow = %v, want [/private/]", second.Disallow)
	}

	if len(result.Sitemaps) != 2 {
		t.Fatalf("sitemaps = %v, want 2 entries", result.Sitemaps)
	}
}

func TestParseRobotsSensitivePaths(t *testing.T) {
	content := `User-agent: *
Disallow:
Disallow: /TMP-files/
Disallow: /.env
Disallow: /assets/images/
`

	result := submodules.ParseRobots(content)

	if len(result.Sensitive) != 2 {
		t.Fatalf("sensitive = %v, want 2 entries", result.Sensitive)
	}
	if !wordpressContains(result.Sensitive, "/TMP-files/") {
		t.Fatalf("sensitive missing /TMP-files/: %v", result.Sensitive)
	}
	if !wordpressContains(result.Sensitive, "/.env") {
		t.Fatalf("sensitive missing /.env: %v", result.Sensitive)
	}
	if wordpressContains(result.Sensitive, "/assets/images/") {
		t.Fatalf("sensitive should not contain /assets/images/: %v", result.Sensitive)
	}
}

func TestFetchRobots(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/robots.txt" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		fmt.Fprint(w, "User-agent: *\nDisallow: /secret/\nSitemap: https://example.com/sitemap.xml\n")
	}))
	defer server.Close()

	result := submodules.FetchRobots(server.URL + "/")

	if result == nil {
		t.Fatal("expected robots result, got nil")
	}
	if result.Status != http.StatusOK {
		t.Fatalf("status = %d, want 200", result.Status)
	}
	if result.URL != server.URL+"/robots.txt" {
		t.Fatalf("url = %q, want %s", result.URL, server.URL+"/robots.txt")
	}
	if len(result.Groups) != 1 {
		t.Fatalf("groups = %+v, want 1 entry", result.Groups)
	}
	if !wordpressContains(result.Sensitive, "/secret/") {
		t.Fatalf("sensitive missing /secret/: %v", result.Sensitive)
	}
	if len(result.Sitemaps) != 1 || result.Sitemaps[0] != "https://example.com/sitemap.xml" {
		t.Fatalf("sitemaps = %v, want [https://example.com/sitemap.xml]", result.Sitemaps)
	}
}

func TestFetchRobotsMissing(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	result := submodules.FetchRobots(server.URL)

	if result == nil {
		t.Fatal("expected robots result, got nil")
	}
	if result.Status != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", result.Status)
	}
	if len(result.Groups) != 0 || len(result.Sitemaps) != 0 || len(result.Sensitive) != 0 {
		t.Fatalf("expected empty parsing for missing robots.txt: %+v", result)
	}
}

func TestFetchRobotsUnreachable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := server.URL
	server.Close()

	if result := submodules.FetchRobots(url); result != nil {
		t.Fatalf("expected nil for unreachable host, got %+v", result)
	}
}

func TestRobotsAnalyzerRun(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "User-agent: *\nDisallow: /admin/\n")
	}))
	defer server.Close()

	result, err := (&analyzer.RobotsAnalyzer{}).Run(server.URL, nil)
	if err != nil {
		t.Fatalf("Run returned unexpected error: %v", err)
	}

	robots, ok := result.(*submodules.RobotsResult)
	if !ok {
		t.Fatalf("Run returned %T, want *submodules.RobotsResult", result)
	}
	if robots.Status != http.StatusOK {
		t.Fatalf("status = %d, want 200", robots.Status)
	}
	if !wordpressContains(robots.Sensitive, "/admin/") {
		t.Fatalf("sensitive missing /admin/: %v", robots.Sensitive)
	}
}

func TestRobotsAnalyzerRunInvalidURL(t *testing.T) {
	if _, err := (&analyzer.RobotsAnalyzer{}).Run("://bad", nil); err == nil {
		t.Fatal("expected error for invalid url, got nil")
	}
}

func TestRobotsAnalyzerRunUnreachable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := server.URL
	server.Close()

	if _, err := (&analyzer.RobotsAnalyzer{}).Run(url, nil); err == nil {
		t.Fatal("expected error for unreachable host, got nil")
	}
}
