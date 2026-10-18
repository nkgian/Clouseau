package analyzer

import (
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
)

type OriginCandidate struct {
	Subdomain string   `json:"subdomain"`
	IPs       []string `json:"ips"`
}

type CloudflareOriginResult struct {
	Domain     string            `json:"domain"`
	Checked    int               `json:"checked"`
	Candidates []OriginCandidate `json:"candidates,omitempty"`
}

func (r *CloudflareOriginResult) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "[cloudflare_ip_lookup] %s (%d subdomains resolved)\n", r.Domain, r.Checked)

	if len(r.Candidates) == 0 {
		fmt.Fprintln(&b, "  no potential origin candidates found")
		return b.String()
	}

	fmt.Fprintln(&b, "  potential origins (not behind Cloudflare):")
	for _, candidate := range r.Candidates {
		fmt.Fprintf(&b, "    %s -> %s\n", candidate.Subdomain, strings.Join(candidate.IPs, ", "))
	}
	return b.String()
}

func lookupCloudflareOrigins(host string, params map[string]interface{}) (*CloudflareOriginResult, error) {
	domain := baseDomain(host)
	names, err := cloudflareSubdomains(params)
	if err != nil {
		return nil, err
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("no subdomains to check for %s", domain)
	}

	type resolution struct {
		fqdn string
		ips  []string
	}
	resolutions := make([]resolution, len(names))
	semaphore := make(chan struct{}, 20)
	var wg sync.WaitGroup

	for i, name := range names {
		wg.Add(1)
		go func(i int, name string) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			fqdn := name + "." + domain
			ips, err := net.LookupHost(fqdn)
			if err != nil || len(ips) == 0 {
				return
			}
			resolutions[i] = resolution{fqdn: fqdn, ips: uniqueSorted(ips)}
		}(i, name)
	}
	wg.Wait()

	candidates := make([]IPAddress, 0, len(resolutions))
	for _, item := range resolutions {
		for _, ip := range item.ips {
			candidates = append(candidates, IPAddress{IP: ip, Scope: "public"})
		}
	}

	asnInfo, err := lookupASN(candidates)
	if err != nil {
		return nil, fmt.Errorf("asn classification for %s failed: %w", domain, err)
	}

	result := &CloudflareOriginResult{Domain: domain}

	for _, item := range resolutions {
		if item.fqdn == "" {
			continue
		}
		result.Checked++

		var originIPs []string
		for _, ip := range item.ips {
			if !isCloudflareAddress(ip, asnInfo) {
				originIPs = append(originIPs, ip)
			}
		}
		if len(originIPs) > 0 {
			result.Candidates = append(result.Candidates, OriginCandidate{Subdomain: item.fqdn, IPs: originIPs})
		}
	}

	sort.Slice(result.Candidates, func(i, j int) bool {
		return result.Candidates[i].Subdomain < result.Candidates[j].Subdomain
	})

	return result, nil
}

// Using same subdomain list as https://github.com/bimantaraz/bypass-cloudflare-get-real-IP
func cloudflareSubdomains(params map[string]interface{}) ([]string, error) {
	path := stringParam(params, "subdomains_file")
	if path == "" {
		path = "cloudflare_subdomains.txt"
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read subdomains file %s: %w", path, err)
	}

	seen := map[string]bool{}
	var names []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.ToLower(strings.TrimSpace(line))
		if line == "" || strings.HasPrefix(line, "#") || seen[line] {
			continue
		}
		seen[line] = true
		names = append(names, line)
	}
	return names, nil
}

func baseDomain(host string) string {
	labels := strings.Split(host, ".")
	if len(labels) > 2 {
		switch labels[0] {
		case "www", "ww1", "ww2", "web", "m":
			return strings.Join(labels[1:], ".")
		}
	}
	return host
}

func isCloudflareAddress(rawIP string, asnInfo map[string]ASInfo) bool {
	info, ok := asnInfo[rawIP]
	if !ok {
		return false
	}
	if info.ASN == "13335" {
		return true
	}
	return strings.Contains(strings.ToLower(info.Name), "cloudflare")
}

func uniqueSorted(values []string) []string {
	seen := map[string]bool{}
	sorted := make([]string, 0, len(values))
	for _, value := range values {
		if !seen[value] {
			seen[value] = true
			sorted = append(sorted, value)
		}
	}
	sort.Strings(sorted)
	return sorted
}
