package submodules

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

const (
	wpProbeTimeout = 8 * time.Second
	wpProbeBytes   = 1 << 20
	wpAuthorPages  = 3
)

type WordPressDetection struct {
	Evidence []string `json:"evidence,omitempty"`
	Version  string   `json:"version,omitempty"`
	Themes   []string `json:"themes,omitempty"`
	Plugins  []string `json:"plugins,omitempty"`
}

type WPUser struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
	Slug string `json:"slug"`
}

type WPEndpoint struct {
	Path   string `json:"path"`
	Status int    `json:"status,omitempty"`
}

type WordPressResult struct {
	Version       string       `json:"version,omitempty"`
	VersionSource string       `json:"version_source,omitempty"`
	SiteName      string       `json:"site_name,omitempty"`
	Namespaces    []string     `json:"rest_namespaces,omitempty"`
	Evidence      []string     `json:"evidence,omitempty"`
	Themes        []string     `json:"themes,omitempty"`
	Plugins       []string     `json:"plugins,omitempty"`
	Login         bool         `json:"login"`
	REST          bool         `json:"rest"`
	XMLRPC        bool         `json:"xmlrpc"`
	Sitemap       bool         `json:"sitemap"`
	Users         []WPUser     `json:"users,omitempty"`
	Authors       []string     `json:"authors,omitempty"`
	Endpoints     []WPEndpoint `json:"endpoints,omitempty"`
}

var (
	wpSignatures = []string{
		"/wp-admin/",
		"/wp-content/",
		"/wp-includes/",
		"/wp-login.php",
		"/wp-json/",
		"wp-emoji-release.min.js",
		"wp-embed.min.js",
		"wp-block-library",
		"xmlrpc.php",
		"wp-cron.php",
		"api.w.org",
	}

	wpGeneratorPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?is)<meta[^>]+name\s*=\s*["']generator["'][^>]*content\s*=\s*["']WordPress\s*([^"']+)["']`),
		regexp.MustCompile(`(?is)<meta[^>]+content\s*=\s*["']WordPress\s*([^"']+)["'][^>]*name\s*=\s*["']generator["']`),
	}

	wpVersionPrefix    = regexp.MustCompile(`^[0-9]+(?:\.[0-9]+)+`)
	wpComponentPattern = regexp.MustCompile(`(?i)/wp-content/(plugins|themes)/([a-z0-9][a-z0-9._-]*)`)
	wpReadmeVersion    = regexp.MustCompile(`(?i)Version\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)`)
	wpFeedVersion      = regexp.MustCompile(`(?is)<generator>[^<]*wordpress[^<]*\?v=([0-9]+(?:\.[0-9]+)+)`)
	wpAuthorLocation   = regexp.MustCompile(`(?i)/author/([^/?#]+)`)
)

type wpRESTIndex struct {
	Name       string   `json:"name"`
	Namespaces []string `json:"namespaces"`
}

func DetectWordPress(body []byte) *WordPressDetection {
	text := string(body)
	lower := strings.ToLower(text)

	detection := &WordPressDetection{}
	for _, signature := range wpSignatures {
		if strings.Contains(lower, signature) {
			detection.Evidence = append(detection.Evidence, signature)
		}
	}

	for _, pattern := range wpGeneratorPatterns {
		match := pattern.FindStringSubmatch(text)
		if match == nil {
			continue
		}
		detection.Evidence = append(detection.Evidence, "meta generator")
		if detection.Version == "" {
			detection.Version = wpVersionPrefix.FindString(strings.TrimSpace(match[1]))
		}
		break
	}

	for _, match := range wpComponentPattern.FindAllStringSubmatch(text, -1) {
		kind := strings.ToLower(match[1])
		slug := strings.ToLower(match[2])
		if kind == "plugins" {
			detection.Plugins = append(detection.Plugins, slug)
		} else {
			detection.Themes = append(detection.Themes, slug)
		}
	}

	if len(detection.Evidence) == 0 && len(detection.Plugins) == 0 && len(detection.Themes) == 0 {
		return nil
	}

	detection.Evidence = uniqueSorted(detection.Evidence)
	detection.Themes = uniqueSorted(detection.Themes)
	detection.Plugins = uniqueSorted(detection.Plugins)
	return detection
}

func (d *WordPressDetection) Merge(other *WordPressDetection) {
	if other == nil {
		return
	}
	d.Evidence = uniqueSorted(append(d.Evidence, other.Evidence...))
	d.Themes = uniqueSorted(append(d.Themes, other.Themes...))
	d.Plugins = uniqueSorted(append(d.Plugins, other.Plugins...))
	if d.Version == "" {
		d.Version = other.Version
	}
}

func InspectWordPress(baseURL string, detection *WordPressDetection) *WordPressResult {
	result := &WordPressResult{
		Version:  detection.Version,
		Evidence: detection.Evidence,
		Themes:   detection.Themes,
		Plugins:  detection.Plugins,
	}
	if result.Version != "" {
		result.VersionSource = "meta generator"
	}

	client := &http.Client{
		Timeout: wpProbeTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	base := strings.TrimSuffix(baseURL, "/")

	probeReadme(client, base, result)
	probeLogin(client, base, result)
	probeXMLRPC(client, base, result)
	if restPath := probeREST(client, base, result); restPath != "" {
		probeUsers(client, base, restPath, result)
	}
	probeSitemap(client, base, result)
	probeFeed(client, base, result)
	probeAuthors(client, base, result)

	return result
}

func probeReadme(client *http.Client, base string, result *WordPressResult) {
	status, body, _, err := wpGet(client, base+"/readme.html")
	if err != nil {
		return
	}
	result.Endpoints = append(result.Endpoints, WPEndpoint{Path: "/readme.html", Status: status})
	if status == http.StatusOK && result.Version == "" {
		if match := wpReadmeVersion.FindSubmatch(body); match != nil {
			result.Version = string(match[1])
			result.VersionSource = "readme.html"
		}
	}
}

func probeLogin(client *http.Client, base string, result *WordPressResult) {
	status, body, _, err := wpGet(client, base+"/wp-login.php")
	if err != nil {
		return
	}
	result.Endpoints = append(result.Endpoints, WPEndpoint{Path: "/wp-login.php", Status: status})
	page := string(body)
	result.Login = status == http.StatusOK &&
		(strings.Contains(page, "user_login") || strings.Contains(page, `id="loginform"`))
}

func probeXMLRPC(client *http.Client, base string, result *WordPressResult) {
	status, body, _, err := wpGet(client, base+"/xmlrpc.php")
	if err != nil {
		return
	}
	result.Endpoints = append(result.Endpoints, WPEndpoint{Path: "/xmlrpc.php", Status: status})
	result.XMLRPC = status == http.StatusMethodNotAllowed ||
		strings.Contains(string(body), "XML-RPC server accepts POST requests only")
}

func probeREST(client *http.Client, base string, result *WordPressResult) string {
	for _, path := range []string{"/wp-json/", "/?rest_route=/"} {
		status, body, _, err := wpGet(client, base+path)
		if err != nil {
			continue
		}
		result.Endpoints = append(result.Endpoints, WPEndpoint{Path: path, Status: status})
		if status != http.StatusOK {
			continue
		}

		var index wpRESTIndex
		if json.Unmarshal(body, &index) != nil {
			continue
		}
		if index.Name == "" && len(index.Namespaces) == 0 {
			continue
		}

		result.REST = true
		result.SiteName = index.Name
		result.Namespaces = uniqueSorted(index.Namespaces)
		return path
	}
	return ""
}

func probeUsers(client *http.Client, base, restPath string, result *WordPressResult) {
	path := "/wp-json/wp/v2/users"
	if restPath != "/wp-json/" {
		path = "/?rest_route=/wp/v2/users"
	}

	status, body, _, err := wpGet(client, base+path)
	if err != nil {
		return
	}
	result.Endpoints = append(result.Endpoints, WPEndpoint{Path: path, Status: status})
	if status != http.StatusOK {
		return
	}

	var users []WPUser
	if json.Unmarshal(body, &users) != nil {
		return
	}
	for _, user := range users {
		if user.Name != "" || user.Slug != "" {
			result.Users = append(result.Users, user)
		}
	}
}

func probeSitemap(client *http.Client, base string, result *WordPressResult) {
	for _, path := range []string{"/wp-sitemap.xml", "/sitemap_index.xml"} {
		status, _, _, err := wpGet(client, base+path)
		if err != nil {
			continue
		}
		result.Endpoints = append(result.Endpoints, WPEndpoint{Path: path, Status: status})
		if status == http.StatusOK {
			result.Sitemap = true
			return
		}
	}
}

func probeFeed(client *http.Client, base string, result *WordPressResult) {
	if result.Version != "" {
		return
	}

	status, body, _, err := wpGet(client, base+"/feed/")
	if err != nil {
		return
	}
	result.Endpoints = append(result.Endpoints, WPEndpoint{Path: "/feed/", Status: status})
	if status != http.StatusOK {
		return
	}
	if match := wpFeedVersion.FindSubmatch(body); match != nil {
		result.Version = string(match[1])
		result.VersionSource = "feed"
	}
}

func probeAuthors(client *http.Client, base string, result *WordPressResult) {
	var authors []string
	for id := 1; id <= wpAuthorPages; id++ {
		status, _, location, err := wpGet(client, fmt.Sprintf("%s/?author=%d", base, id))
		if err != nil || status < 300 || status >= 400 || location == "" {
			continue
		}
		if match := wpAuthorLocation.FindStringSubmatch(location); match != nil {
			authors = append(authors, match[1])
		}
	}
	result.Authors = uniqueSorted(authors)
}

func wpGet(client *http.Client, target string) (int, []byte, string, error) {
	request, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		return 0, nil, "", err
	}
	request.Header.Set("User-Agent", "clouseau/1.0")

	response, err := client.Do(request)
	if err != nil {
		return 0, nil, "", err
	}
	defer response.Body.Close()

	body, err := io.ReadAll(io.LimitReader(response.Body, wpProbeBytes))
	if err != nil {
		return response.StatusCode, nil, response.Header.Get("Location"), err
	}
	return response.StatusCode, body, response.Header.Get("Location"), nil
}

func (r *WordPressResult) String() string {
	var b strings.Builder
	b.WriteString("  wordpress:\n")

	if r.Version != "" {
		fmt.Fprintf(&b, "    version: %s (%s)\n", r.Version, r.VersionSource)
	}
	if r.SiteName != "" {
		fmt.Fprintf(&b, "    site: %s\n", r.SiteName)
	}
	if len(r.Evidence) > 0 {
		fmt.Fprintf(&b, "    detected by: %s\n", strings.Join(r.Evidence, ", "))
	}
	if len(r.Themes) > 0 {
		fmt.Fprintf(&b, "    themes: %s\n", strings.Join(r.Themes, ", "))
	}
	if len(r.Plugins) > 0 {
		fmt.Fprintf(&b, "    plugins: %s\n", strings.Join(r.Plugins, ", "))
	}
	if len(r.Namespaces) > 0 {
		fmt.Fprintf(&b, "    rest namespaces: %s\n", strings.Join(r.Namespaces, ", "))
	}

	fmt.Fprintf(&b, "    login: %s | rest: %s | xmlrpc: %s | sitemap: %s\n",
		yesNo(r.Login), yesNo(r.REST), yesNo(r.XMLRPC), yesNo(r.Sitemap))

	for _, user := range r.Users {
		name := user.Name
		if name == "" {
			name = user.Slug
		}
		fmt.Fprintf(&b, "    user: %s (id %d, slug %s)\n", name, user.ID, user.Slug)
	}
	for _, author := range r.Authors {
		fmt.Fprintf(&b, "    author: %s\n", author)
	}

	if len(r.Endpoints) > 0 {
		b.WriteString("    endpoints:\n")
		for _, endpoint := range r.Endpoints {
			fmt.Fprintf(&b, "      %s %d\n", endpoint.Path, endpoint.Status)
		}
	}

	return b.String()
}

func yesNo(value bool) string {
	if value {
		return "yes"
	}
	return "no"
}
