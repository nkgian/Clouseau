package analyzer

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

type HTMLAnalyzer struct{}

type HTMLPage struct {
	URL         string
	Status      int
	Title       string
	ContentType string
	Bytes       int
	Links       []string
}

type HTMLResult struct {
	StartURL string
	Pages    []HTMLPage
	Links    []string
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
	return b.String()
}

func (w *HTMLAnalyzer) Run(url string, params map[string]interface{}) (interface{}, error) {
	maxDepth := intParam(params, "max_depth", 1)
	if maxDepth < 0 {
		maxDepth = 0
	}
	extractLinks := boolParam(params, "extract_links", true)

	result, err := crawlHTML(url, maxDepth, extractLinks)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func crawlHTML(start string, maxDepth int, extractLinks bool) (*HTMLResult, error) {
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

	for len(queue) > 0 && len(result.Pages) < maxHTMLPages {
		current := queue[0]
		queue = queue[1:]
		if visited[current.url] {
			continue
		}
		visited[current.url] = true

		page, links, err := fetchHTMLPage(client, current.url)
		if err != nil {
			if current.depth == 0 {
				return nil, err
			}
			continue
		}
		if extractLinks {
			page.Links = links
		}
		result.Pages = append(result.Pages, *page)

		for _, link := range links {
			seenLinks[link] = true
		}

		if current.depth >= maxDepth {
			continue
		}
		for _, link := range links {
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

	if extractLinks {
		result.Links = make([]string, 0, len(seenLinks))
		for link := range seenLinks {
			result.Links = append(result.Links, link)
		}
		sort.Strings(result.Links)
	}

	return result, nil
}

func fetchHTMLPage(client *http.Client, pageURL string) (*HTMLPage, []string, error) {
	request, err := http.NewRequest(http.MethodGet, pageURL, nil)
	if err != nil {
		return nil, nil, err
	}
	request.Header.Set("User-Agent", "clouseau/1.0")

	response, err := client.Do(request)
	if err != nil {
		return nil, nil, err
	}
	defer response.Body.Close()

	body, err := io.ReadAll(io.LimitReader(response.Body, maxHTMLBytes))
	if err != nil {
		return nil, nil, err
	}

	page := &HTMLPage{
		URL:         response.Request.URL.String(),
		Status:      response.StatusCode,
		ContentType: response.Header.Get("Content-Type"),
		Bytes:       len(body),
	}

	if !isHTMLContent(page.ContentType) {
		return page, nil, nil
	}

	if match := titlePattern.FindSubmatch(body); match != nil {
		page.Title = truncate(strings.Join(strings.Fields(string(match[1])), " "), maxHTMLTitle)
	}

	pageBase, err := url.Parse(page.URL)
	if err != nil {
		return page, nil, nil
	}

	seen := map[string]bool{}
	var links []string
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
		links = append(links, link)
	}

	return page, links, nil
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
