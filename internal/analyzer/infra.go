package analyzer

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"clouseau/internal/analyzer/submodules"
)

type InfraAnalyzer struct{}

type InfraResult struct {
	Host           string                  `json:"host"`
	Domains        []string                `json:"certificate_domains,omitempty"`
	DomainTotal    int                     `json:"certificate_domain_total,omitempty"`
	CertificateErr string                  `json:"certificate_error,omitempty"`
	Favicon        *submodules.FaviconInfo `json:"favicon,omitempty"`
}

const (
	defaultCrtURL = "https://crt.sh/"
	ctDomainLimit = 100
)

func (i *InfraAnalyzer) Run(target string, params map[string]interface{}) (interface{}, error) {
	parsed, err := url.Parse(normalizeURL(target))
	if err != nil || parsed.Host == "" {
		return nil, fmt.Errorf("invalid url %q", target)
	}
	host := strings.ToLower(parsed.Hostname())

	crtURL := endpointParam(params, "crt_url", defaultCrtURL)

	var (
		domains []string
		ctErr   error
		favicon *submodules.FaviconInfo
		wg      sync.WaitGroup
	)
	wg.Add(2)
	go func() { defer wg.Done(); domains, ctErr = fetchCertificateDomains(crtURL, host) }()
	go func() { defer wg.Done(); favicon = submodules.FetchFavicon(parsed.Scheme + "://" + parsed.Host) }()
	wg.Wait()

	result := &InfraResult{Host: host, Favicon: favicon}
	if ctErr != nil {
		result.CertificateErr = ctErr.Error()
		return result, nil
	}

	result.DomainTotal = len(domains)
	if len(domains) > ctDomainLimit {
		domains = domains[:ctDomainLimit]
	}
	result.Domains = domains
	return result, nil
}

func (r *InfraResult) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "[infra_scan] %s\n", r.Host)

	if r.CertificateErr != "" {
		fmt.Fprintf(&b, "  certificate domains: error (%s)\n", r.CertificateErr)
	} else if r.DomainTotal > 0 {
		fmt.Fprintf(&b, "  certificate domains: %d\n", r.DomainTotal)
		for _, domain := range r.Domains {
			fmt.Fprintf(&b, "    %s\n", domain)
		}
	} else {
		b.WriteString("  certificate domains: none\n")
	}

	if r.Favicon != nil {
		if r.Favicon.Error != "" {
			fmt.Fprintf(&b, "  favicon: error (%s)\n", r.Favicon.Error)
		} else {
			fmt.Fprintf(&b, "  favicon: %d bytes\n", r.Favicon.Bytes)
			fmt.Fprintf(&b, "    mmh3: %d\n", r.Favicon.MMH3)
			fmt.Fprintf(&b, "    sha256: %s\n", r.Favicon.SHA256)
		}
	}

	return b.String()
}

func fetchCertificateDomains(endpoint, host string) ([]string, error) {
	client := &http.Client{Timeout: 30 * time.Second}

	query := endpoint + "?q=" + url.QueryEscape("%."+host) + "&output=json"
	status, body, err := fetchExternal(client, http.MethodGet, query, nil, nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d", status)
	}

	var certificates []struct {
		CommonName string `json:"common_name"`
		NameValue  string `json:"name_value"`
	}
	if err := json.Unmarshal(body, &certificates); err != nil {
		return nil, fmt.Errorf("invalid certificate response: %w", err)
	}

	seen := map[string]bool{}
	var domains []string
	add := func(name string) {
		name = strings.ToLower(strings.TrimSpace(name))
		name = strings.TrimPrefix(name, "*.")
		if name == "" || strings.ContainsAny(name, " \t") {
			return
		}
		if name != host && !strings.HasSuffix(name, "."+host) {
			return
		}
		if seen[name] {
			return
		}
		seen[name] = true
		domains = append(domains, name)
	}

	for _, certificate := range certificates {
		add(certificate.CommonName)
		for _, name := range strings.Split(certificate.NameValue, "\n") {
			add(name)
		}
	}

	sort.Strings(domains)
	return domains, nil
}
