package tests

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"clouseau/internal/analyzer/submodules"
)

func wordpressContains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func wordpressHasEndpoint(result *submodules.WordPressResult, path string, status int) bool {
	for _, endpoint := range result.Endpoints {
		if endpoint.Path == path && endpoint.Status == status {
			return true
		}
	}
	return false
}

func TestDetectWordPress(t *testing.T) {
	body := []byte(`<html>
<head><meta name="generator" content="WordPress 6.4.3"></head>
<body>
<a href="/wp-admin/">admin</a>
<link rel="stylesheet" href="/wp-content/themes/twentytwentyfour/style.css">
<script src="/wp-content/plugins/contact-form-7/includes/js/script.js"></script>
</body></html>`)

	detection := submodules.DetectWordPress(body)
	if detection == nil {
		t.Fatal("expected wordpress detection, got nil")
	}
	if detection.Version != "6.4.3" {
		t.Fatalf("version = %q, want 6.4.3", detection.Version)
	}
	if !wordpressContains(detection.Evidence, "/wp-admin/") {
		t.Fatalf("evidence missing /wp-admin/: %v", detection.Evidence)
	}
	if !wordpressContains(detection.Evidence, "/wp-content/") {
		t.Fatalf("evidence missing /wp-content/: %v", detection.Evidence)
	}
	if !wordpressContains(detection.Evidence, "meta generator") {
		t.Fatalf("evidence missing meta generator: %v", detection.Evidence)
	}
	if !wordpressContains(detection.Themes, "twentytwentyfour") {
		t.Fatalf("themes = %v, want twentytwentyfour", detection.Themes)
	}
	if !wordpressContains(detection.Plugins, "contact-form-7") {
		t.Fatalf("plugins = %v, want contact-form-7", detection.Plugins)
	}
}

func TestDetectWordPressGeneratorContentFirst(t *testing.T) {
	body := []byte(`<html><head><meta content="WordPress 6.2.1" name="generator"></head></html>`)

	detection := submodules.DetectWordPress(body)
	if detection == nil {
		t.Fatal("expected wordpress detection, got nil")
	}
	if detection.Version != "6.2.1" {
		t.Fatalf("version = %q, want 6.2.1", detection.Version)
	}
}

func TestDetectWordPressRejectsNonWordPress(t *testing.T) {
	body := []byte(`<html><head><title>Plain site</title></head><body><p>hello</p></body></html>`)

	if detection := submodules.DetectWordPress(body); detection != nil {
		t.Fatalf("expected nil detection, got %+v", detection)
	}
}

func TestWordPressDetectionMerge(t *testing.T) {
	first := &submodules.WordPressDetection{
		Evidence: []string{"/wp-content/"},
		Plugins:  []string{"akismet"},
	}
	second := &submodules.WordPressDetection{
		Version:  "6.4.3",
		Evidence: []string{"/wp-content/", "/wp-admin/"},
		Themes:   []string{"theme-a"},
		Plugins:  []string{"akismet", "jetpack"},
	}

	first.Merge(second)
	first.Merge(nil)

	if len(first.Evidence) != 2 {
		t.Fatalf("evidence = %v, want 2 deduplicated entries", first.Evidence)
	}
	if len(first.Plugins) != 2 {
		t.Fatalf("plugins = %v, want 2 deduplicated entries", first.Plugins)
	}
	if len(first.Themes) != 1 || first.Themes[0] != "theme-a" {
		t.Fatalf("themes = %v, want [theme-a]", first.Themes)
	}
	if first.Version != "6.4.3" {
		t.Fatalf("version = %q, want 6.4.3", first.Version)
	}
}

func TestInspectWordPressCollectsData(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/readme.html", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<h1>WordPress</h1><br /> Version 6.4.3")
	})
	mux.HandleFunc("/wp-login.php", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<form id="loginform"><input name="log" id="user_login"></form>`)
	})
	mux.HandleFunc("/xmlrpc.php", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusMethodNotAllowed)
		fmt.Fprint(w, "XML-RPC server accepts POST requests only.")
	})
	mux.HandleFunc("/wp-json/wp/v2/users", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `[{"id":1,"name":"Admin","slug":"admin"},{"id":2,"name":"","slug":"editor"}]`)
	})
	mux.HandleFunc("/wp-json/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"name":"Test Site","namespaces":["wp/v2","jetpack/v4"]}`)
	})
	mux.HandleFunc("/wp-sitemap.xml", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<urlset></urlset>")
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("author") == "1" {
			http.Redirect(w, r, "/author/jane/", http.StatusMovedPermanently)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	detection := &submodules.WordPressDetection{
		Evidence: []string{"/wp-content/"},
		Themes:   []string{"twentytwentyfour"},
		Plugins:  []string{"contact-form-7"},
	}
	result := submodules.InspectWordPress(server.URL, detection)

	if result.Version != "6.4.3" || result.VersionSource != "readme.html" {
		t.Fatalf("version = %q (%s), want 6.4.3 (readme.html)", result.Version, result.VersionSource)
	}
	if !result.Login {
		t.Error("login = false, want true")
	}
	if !result.REST {
		t.Error("rest = false, want true")
	}
	if !result.XMLRPC {
		t.Error("xmlrpc = false, want true")
	}
	if !result.Sitemap {
		t.Error("sitemap = false, want true")
	}
	if result.SiteName != "Test Site" {
		t.Fatalf("site name = %q, want Test Site", result.SiteName)
	}
	if !wordpressContains(result.Namespaces, "jetpack/v4") {
		t.Fatalf("namespaces = %v, want jetpack/v4", result.Namespaces)
	}
	if len(result.Users) != 2 {
		t.Fatalf("users = %+v, want 2 entries", result.Users)
	}
	if result.Users[0].Slug != "admin" || result.Users[1].Slug != "editor" {
		t.Fatalf("users = %+v, want admin and editor slugs", result.Users)
	}
	if len(result.Authors) != 1 || result.Authors[0] != "jane" {
		t.Fatalf("authors = %v, want [jane]", result.Authors)
	}
	if !wordpressContains(result.Themes, "twentytwentyfour") {
		t.Fatalf("themes = %v, want twentytwentyfour", result.Themes)
	}
	if !wordpressContains(result.Plugins, "contact-form-7") {
		t.Fatalf("plugins = %v, want contact-form-7", result.Plugins)
	}
	if !wordpressHasEndpoint(result, "/wp-json/", http.StatusOK) {
		t.Fatalf("missing /wp-json/ 200 endpoint: %+v", result.Endpoints)
	}
	if !wordpressHasEndpoint(result, "/xmlrpc.php", http.StatusMethodNotAllowed) {
		t.Fatalf("missing /xmlrpc.php 405 endpoint: %+v", result.Endpoints)
	}
}

func TestInspectWordPressUsesRESTAndFeedFallbacks(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/feed/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<rss><channel><generator>https://wordpress.org/?v=6.5.2</generator></channel></rss>`)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("rest_route") {
		case "/":
			fmt.Fprint(w, `{"name":"Fallback Site","namespaces":["wp/v2"]}`)
		case "/wp/v2/users":
			fmt.Fprint(w, `[{"id":7,"name":"Jane","slug":"jane"}]`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	detection := &submodules.WordPressDetection{Evidence: []string{"/wp-content/"}}
	result := submodules.InspectWordPress(server.URL, detection)

	if result.Version != "6.5.2" || result.VersionSource != "feed" {
		t.Fatalf("version = %q (%s), want 6.5.2 (feed)", result.Version, result.VersionSource)
	}
	if !result.REST {
		t.Error("rest = false, want true via /?rest_route=/")
	}
	if !wordpressHasEndpoint(result, "/?rest_route=/", http.StatusOK) {
		t.Fatalf("missing /?rest_route=/ fallback endpoint: %+v", result.Endpoints)
	}
	if len(result.Users) != 1 || result.Users[0].Slug != "jane" {
		t.Fatalf("users = %+v, want jane", result.Users)
	}
}

func TestInspectWordPressWithoutReachableEndpoints(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	detection := &submodules.WordPressDetection{
		Version:  "6.0",
		Evidence: []string{"/wp-content/"},
	}
	result := submodules.InspectWordPress(server.URL, detection)

	if result.Version != "6.0" || result.VersionSource != "meta generator" {
		t.Fatalf("version = %q (%s), want 6.0 (meta generator)", result.Version, result.VersionSource)
	}
	if result.Login || result.REST || result.XMLRPC || result.Sitemap {
		t.Fatalf("expected all probes to fail: %+v", result)
	}
	if len(result.Users) != 0 || len(result.Authors) != 0 {
		t.Fatalf("expected no users/authors: %+v", result)
	}
	if len(result.Endpoints) == 0 {
		t.Fatal("expected attempted endpoints to be recorded")
	}
	if !wordpressHasEndpoint(result, "/readme.html", http.StatusNotFound) {
		t.Fatalf("missing /readme.html 404 endpoint: %+v", result.Endpoints)
	}
}

func TestInspectWordPressHandlesBlockedUsers(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/wp-json/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"name":"Blocked Site","namespaces":["wp/v2"]}`)
	})
	mux.HandleFunc("/wp-json/wp/v2/users", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `{"code":"rest_cannot_list_users"}`)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	result := submodules.InspectWordPress(server.URL, &submodules.WordPressDetection{Evidence: []string{"/wp-content/"}})

	if !result.REST {
		t.Error("rest = false, want true")
	}
	if len(result.Users) != 0 {
		t.Fatalf("users = %+v, want none", result.Users)
	}
	if !wordpressHasEndpoint(result, "/wp-json/wp/v2/users", http.StatusForbidden) {
		t.Fatalf("missing blocked users endpoint: %+v", result.Endpoints)
	}
}
