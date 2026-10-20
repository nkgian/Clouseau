package analyzer

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type ThreatAnalyzer struct{}

type ThreatSource struct {
	Source string   `json:"source"`
	Status string   `json:"status"`
	Detail string   `json:"detail,omitempty"`
	URLs   []string `json:"urls,omitempty"`
}

type ThreatResult struct {
	Host      string         `json:"host"`
	FirstSeen string         `json:"wayback_first_seen,omitempty"`
	Sources   []ThreatSource `json:"sources"`
}

const (
	threatFound = "found"
	threatClear = "clear"
	threatError = "error"

	defaultOpenPhishURL = "https://openphish.com/feed.txt"
	defaultURLhausURL   = "https://urlhaus-api.abuse.ch/v1/host/"
	defaultWaybackURL   = "https://web.archive.org/cdx/search/cdx"

	threatURLsMax  = 5
	threatBytesMax = 4 << 20
)

func (t *ThreatAnalyzer) Run(target string, params map[string]interface{}) (interface{}, error) {
	host := hostFromURL(target)
	if host == "" {
		return nil, fmt.Errorf("invalid url %q", target)
	}

	openPhishURL := endpointParam(params, "openphish_url", defaultOpenPhishURL)
	urlhausURL := endpointParam(params, "urlhaus_url", defaultURLhausURL)
	waybackURL := endpointParam(params, "wayback_url", defaultWaybackURL)
	urlhausKey := stringParam(params, "urlhaus_key")

	client := &http.Client{Timeout: 20 * time.Second}

	var (
		openPhish ThreatSource
		urlhaus   ThreatSource
		wayback   ThreatSource
		wg        sync.WaitGroup
	)
	wg.Add(3)
	go func() { defer wg.Done(); openPhish = checkOpenPhish(client, openPhishURL, host) }()
	go func() { defer wg.Done(); urlhaus = checkURLhaus(client, urlhausURL, host, urlhausKey) }()
	go func() { defer wg.Done(); wayback = checkWayback(client, waybackURL, host) }()
	wg.Wait()

	result := &ThreatResult{
		Host:    host,
		Sources: []ThreatSource{openPhish, urlhaus, wayback},
	}
	if wayback.Status == threatFound {
		result.FirstSeen = wayback.Detail
	}
	return result, nil
}

func (r *ThreatResult) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "[threat_lookup] %s\n", r.Host)
	if r.FirstSeen != "" {
		fmt.Fprintf(&b, "  wayback first seen: %s\n", r.FirstSeen)
	}
	for _, source := range r.Sources {
		fmt.Fprintf(&b, "  %s: %s", source.Source, source.Status)
		if source.Detail != "" {
			fmt.Fprintf(&b, " (%s)", source.Detail)
		}
		b.WriteString("\n")
		for _, url := range source.URLs {
			fmt.Fprintf(&b, "    %s\n", url)
		}
	}
	return b.String()
}

func checkOpenPhish(client *http.Client, endpoint, host string) ThreatSource {
	source := ThreatSource{Source: "openphish"}

	status, body, err := fetchExternal(client, http.MethodGet, endpoint, nil, nil)
	if err != nil {
		source.Status = threatError
		source.Detail = err.Error()
		return source
	}
	if status != http.StatusOK {
		source.Status = threatError
		source.Detail = fmt.Sprintf("unexpected status %d", status)
		return source
	}

	var matches []string
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parsed, err := url.Parse(line)
		if err != nil {
			continue
		}
		if strings.EqualFold(parsed.Hostname(), host) {
			matches = append(matches, line)
			if len(matches) >= threatURLsMax {
				break
			}
		}
	}

	if len(matches) > 0 {
		source.Status = threatFound
		source.Detail = fmt.Sprintf("%d matching url(s)", len(matches))
		source.URLs = matches
		return source
	}
	source.Status = threatClear
	return source
}

func checkURLhaus(client *http.Client, endpoint, host, key string) ThreatSource {
	source := ThreatSource{Source: "urlhaus"}

	form := url.Values{"host": {host}}
	headers := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
	if key != "" {
		headers["Auth-Key"] = key
	}

	status, body, err := fetchExternal(client, http.MethodPost, endpoint, strings.NewReader(form.Encode()), headers)
	if err != nil {
		source.Status = threatError
		source.Detail = err.Error()
		return source
	}
	if status != http.StatusOK {
		source.Status = threatError
		if status == http.StatusUnauthorized || status == http.StatusForbidden {
			source.Detail = "auth key required; set urlhaus_key"
			return source
		}
		source.Detail = fmt.Sprintf("unexpected status %d", status)
		return source
	}

	var response struct {
		QueryStatus string `json:"query_status"`
		URLs        []struct {
			URL string `json:"url"`
		} `json:"urls"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		source.Status = threatError
		source.Detail = "invalid response"
		return source
	}

	switch response.QueryStatus {
	case "ok":
		source.Status = threatFound
		for _, entry := range response.URLs {
			if entry.URL != "" {
				source.URLs = append(source.URLs, entry.URL)
			}
			if len(source.URLs) >= threatURLsMax {
				break
			}
		}
	case "no_results":
		source.Status = threatClear
	default:
		// rate_limited, invalid_auth_key, missing_params, ... must never read as clear
		source.Status = threatError
		source.Detail = fmt.Sprintf("unexpected query_status %q", response.QueryStatus)
	}
	return source
}

func checkWayback(client *http.Client, endpoint, host string) ThreatSource {
	source := ThreatSource{Source: "wayback"}

	query := endpoint + "?url=" + url.QueryEscape(host) + "&output=json&limit=1&fl=timestamp"
	status, body, err := fetchExternal(client, http.MethodGet, query, nil, nil)
	if err != nil {
		source.Status = threatError
		source.Detail = err.Error()
		return source
	}
	if status != http.StatusOK {
		source.Status = threatError
		source.Detail = fmt.Sprintf("unexpected status %d", status)
		return source
	}

	var rows [][]string
	if err := json.Unmarshal(body, &rows); err != nil {
		source.Status = threatError
		source.Detail = "invalid response"
		return source
	}
	if len(rows) >= 2 && len(rows[1]) > 0 && rows[1][0] != "" {
		source.Status = threatFound
		source.Detail = formatWaybackTimestamp(rows[1][0])
		return source
	}

	source.Status = threatClear
	return source
}

func formatWaybackTimestamp(timestamp string) string {
	timestamp = strings.TrimSpace(timestamp)
	if len(timestamp) < 8 {
		return timestamp
	}
	return timestamp[:4] + "-" + timestamp[4:6] + "-" + timestamp[6:8]
}

func fetchExternal(client *http.Client, method, endpoint string, body io.Reader, headers map[string]string) (int, []byte, error) {
	request, err := http.NewRequest(method, endpoint, body)
	if err != nil {
		return 0, nil, err
	}
	request.Header.Set("User-Agent", "clouseau/1.0")
	for key, value := range headers {
		request.Header.Set(key, value)
	}

	response, err := client.Do(request)
	if err != nil {
		return 0, nil, err
	}
	defer response.Body.Close()

	data, err := io.ReadAll(io.LimitReader(response.Body, threatBytesMax))
	if err != nil {
		return response.StatusCode, nil, err
	}
	return response.StatusCode, data, nil
}

func endpointParam(params map[string]interface{}, key, fallback string) string {
	if value := stringParam(params, key); value != "" {
		return value
	}
	return fallback
}
