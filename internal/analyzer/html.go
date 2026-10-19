package analyzer

import (
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"clouseau/internal/analyzer/submodules"
)

type HTMLAnalyzer struct{}

type HTMLPage struct {
	URL          string   `json:"url"`
	Status       int      `json:"status"`
	Title        string   `json:"title,omitempty"`
	ContentType  string   `json:"content_type,omitempty"`
	Bytes        int      `json:"bytes"`
	SHA256       string   `json:"sha256,omitempty"`
	EvidenceFile string   `json:"evidence_file,omitempty"`
	Links        []string `json:"links,omitempty"`
}

type HTMLResult struct {
	StartURL       string                       `json:"start_url"`
	Pages          []HTMLPage                   `json:"pages"`
	Links          []string                     `json:"links,omitempty"`
	Cloaking       *submodules.CloakingResult   `json:"cloaking,omitempty"`
	Forms          *submodules.FormResult       `json:"forms,omitempty"`
	Identifiers    *submodules.IdentifierResult `json:"identifiers,omitempty"`
	WordPress      *submodules.WordPressResult  `json:"wordpress,omitempty"`
	EvidenceDir    string                       `json:"evidence_dir,omitempty"`
	EvidenceErrors []string                     `json:"evidence_errors,omitempty"`
}

type htmlOptions struct {
	maxDepth     int
	extractLinks bool
	wordpress    bool
	cloaking     bool
	evidenceDir  string
}

const (
	maxHTMLPages    = 25
	maxHTMLBytes    = 2 << 20
	maxHTMLTitle    = 120
	maxHTMLRedirect = 5
)

var (
	titlePattern = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
	linkPattern  = regexp.MustCompile(`(?i)\b(?:href|src)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))`)
)

func (r *HTMLResult) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "[html_scan] %s (%d page(s))\n", r.StartURL, len(r.Pages))
	for _, page := range r.Pages {
		fmt.Fprintf(&b, "  %d %s (%d bytes)\n", page.Status, page.URL, page.Bytes)
		if page.Title != "" {
			fmt.Fprintf(&b, "      title: %s\n", page.Title)
		}
		if len(page.Links) > 0 {
			fmt.Fprintf(&b, "      links: %d\n", len(page.Links))
		}
	}
	if len(r.Links) > 0 {
		fmt.Fprintf(&b, "  unique links found: %d\n", len(r.Links))
		for _, link := range r.Links {
			fmt.Fprintf(&b, "    %s\n", link)
		}
	}
	if r.Cloaking != nil {
		b.WriteString(r.Cloaking.String())
	}
	if r.Forms != nil {
		b.WriteString(r.Forms.String())
	}
	if r.Identifiers != nil {
		b.WriteString(r.Identifiers.String())
	}
	if r.WordPress != nil {
		b.WriteString(r.WordPress.String())
	}
	for _, err := range r.EvidenceErrors {
		fmt.Fprintf(&b, "  ! evidence: %s\n", err)
	}
	if r.EvidenceDir != "" {
		saved := 0
		for _, page := range r.Pages {
			if page.EvidenceFile != "" {
				saved++
			}
		}
		fmt.Fprintf(&b, "  evidence: %d page(s) saved to %s\n", saved, r.EvidenceDir)
	}
	return b.String()
}

func (w *HTMLAnalyzer) Run(url string, params map[string]interface{}) (interface{}, error) {
	options := htmlOptions{
		maxDepth:     intParam(params, "max_depth", 1),
		extractLinks: boolParam(params, "extract_links", true),
		wordpress:    !boolParam(params, "skip_wordpress", false),
		cloaking:     !boolParam(params, "skip_cloaking", false),
		evidenceDir:  stringParam(params, "evidence_dir"),
	}
	if options.maxDepth < 0 {
		options.maxDepth = 0
	}

	result, err := crawlHTML(url, options)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func crawlHTML(start string, options htmlOptions) (*HTMLResult, error) {
	base, err := url.Parse(normalizeURL(start))
	if err != nil || base.Host == "" {
		return nil, fmt.Errorf("invalid url %q", start)
	}

	client := &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxHTMLRedirect {
				return fmt.Errorf("stopped after %d redirects", maxHTMLRedirect)
			}
			return nil
		},
	}

	type queueItem struct {
		url   string
		depth int
	}

	result := &HTMLResult{StartURL: start}
	visited := map[string]bool{}
	seenLinks := map[string]bool{}
	queue := []queueItem{{normalizeURL(start), 0}}
	var (
		wpDetection *submodules.WordPressDetection
		identifiers *submodules.IdentifierResult
		forms       *submodules.FormResult
	)

	stamp := time.Now().Format("20060102-150405")
	if options.evidenceDir != "" {
		if err := os.MkdirAll(options.evidenceDir, 0o755); err != nil {
			return nil, fmt.Errorf("cannot create evidence directory: %w", err)
		}
		result.EvidenceDir = options.evidenceDir
	}

	for len(queue) > 0 && len(result.Pages) < maxHTMLPages {
		current := queue[0]
		queue = queue[1:]
		if visited[current.url] {
			continue
		}
		visited[current.url] = true

		fetch, err := fetchHTMLPage(client, current.url, options.wordpress)
		if err != nil {
			if current.depth == 0 {
				return nil, err
			}
			continue
		}
		if fetch.wordpress != nil {
			if wpDetection == nil {
				wpDetection = &submodules.WordPressDetection{}
			}
			wpDetection.Merge(fetch.wordpress)
		}
		if fetch.identifiers != nil {
			if identifiers == nil {
				identifiers = &submodules.IdentifierResult{}
			}
			identifiers.Merge(fetch.identifiers)
		}
		if fetch.forms != nil {
			if forms == nil {
				forms = &submodules.FormResult{}
			}
			forms.Merge(fetch.forms)
		}

		page := fetch.page
		if options.extractLinks {
			page.Links = fetch.links
		}
		result.Pages = append(result.Pages, *page)

		if options.evidenceDir != "" {
			index := len(result.Pages) - 1
			name := fmt.Sprintf("%s-page-%03d.html", stamp, index+1)
			path := filepath.Join(options.evidenceDir, name)
			if err := os.WriteFile(path, fetch.body, 0o644); err != nil {
				result.EvidenceErrors = append(result.EvidenceErrors, err.Error())
			} else {
				result.Pages[index].EvidenceFile = path
			}
		}

		for _, link := range fetch.links {
			seenLinks[link] = true
		}

		if current.depth >= options.maxDepth {
			continue
		}
		for _, link := range fetch.links {
			if visited[link] {
				continue
			}
			reference, err := url.Parse(link)
			if err != nil || !strings.EqualFold(reference.Hostname(), base.Hostname()) {
				continue
			}
			queue = append(queue, queueItem{link, current.depth + 1})
		}
	}

	if options.extractLinks {
		result.Links = make([]string, 0, len(seenLinks))
		for link := range seenLinks {
			result.Links = append(result.Links, link)
		}
		sort.Strings(result.Links)
	}

	if identifiers != nil {
		result.Identifiers = identifiers
	}
	if forms != nil {
		result.Forms = forms
	}
	if wpDetection != nil {
		result.WordPress = submodules.InspectWordPress(base.Scheme+"://"+base.Host, wpDetection)
	}
	if options.cloaking {
		result.Cloaking = submodules.DetectCloaking(normalizeURL(start))
	}

	return result, nil
}

type pageFetch struct {
	page        *HTMLPage
	links       []string
	body        []byte
	wordpress   *submodules.WordPressDetection
	identifiers *submodules.IdentifierResult
	forms       *submodules.FormResult
}

func fetchHTMLPage(client *http.Client, pageURL string, wordpress bool) (*pageFetch, error) {
	request, err := http.NewRequest(http.MethodGet, pageURL, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("User-Agent", "clouseau/1.0")

	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	body, err := io.ReadAll(io.LimitReader(response.Body, maxHTMLBytes))
	if err != nil {
		return nil, err
	}

	fetch := &pageFetch{
		page: &HTMLPage{
			URL:         response.Request.URL.String(),
			Status:      response.StatusCode,
			ContentType: response.Header.Get("Content-Type"),
			Bytes:       len(body),
			SHA256:      fmt.Sprintf("%x", sha256.Sum256(body)),
		},
		body: body,
	}

	if !isHTMLContent(fetch.page.ContentType) {
		return fetch, nil
	}

	if wordpress {
		fetch.wordpress = submodules.DetectWordPress(body)
	}
	fetch.identifiers = submodules.DetectIdentifiers(body)
	fetch.forms = submodules.ParseForms(body, fetch.page.URL)

	if match := titlePattern.FindSubmatch(body); match != nil {
		fetch.page.Title = truncate(strings.Join(strings.Fields(string(match[1])), " "), maxHTMLTitle)
	}

	pageBase, err := url.Parse(fetch.page.URL)
	if err != nil {
		return fetch, nil
	}

	seen := map[string]bool{}
	for _, match := range linkPattern.FindAllSubmatch(body, -1) {
		rawReference := ""
		for _, group := range match[1:] {
			if len(group) > 0 {
				rawReference = string(group)
				break
			}
		}
		if rawReference == "" {
			continue
		}

		reference, err := url.Parse(strings.TrimSpace(rawReference))
		if err != nil {
			continue
		}
		absolute := pageBase.ResolveReference(reference)
		absolute.Fragment = ""
		if (absolute.Scheme != "http" && absolute.Scheme != "https") || absolute.Host == "" {
			continue
		}
		link := absolute.String()
		if seen[link] {
			continue
		}
		seen[link] = true
		fetch.links = append(fetch.links, link)
	}

	return fetch, nil
}

func isHTMLContent(contentType string) bool {
	contentType = strings.ToLower(contentType)
	return contentType == "" || strings.Contains(contentType, "html") || strings.Contains(contentType, "xml")
}

func truncate(value string, max int) string {
	if len(value) <= max {
		return value
	}
	return value[:max-3] + "..."
}
