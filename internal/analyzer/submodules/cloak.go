package submodules

import (
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

type CloakProbe struct {
	Profile  string `json:"profile"`
	Status   int    `json:"status,omitempty"`
	FinalURL string `json:"final_url,omitempty"`
	Bytes    int    `json:"bytes,omitempty"`
	Title    string `json:"title,omitempty"`
	SHA256   string `json:"sha256,omitempty"`
	Error    string `json:"error,omitempty"`
}

type CloakingResult struct {
	Probes  []CloakProbe `json:"probes"`
	Differs bool         `json:"differs"`
	Reasons []string     `json:"reasons,omitempty"`
}

type cloakProfile struct {
	Name      string
	UserAgent string
	Language  string
}

var cloakTitlePattern = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

var cloakProfiles = []cloakProfile{
	{
		Name:      "browser",
		UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		Language:  "en-US,en;q=0.9",
	},
	{
		Name:      "googlebot",
		UserAgent: "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
		Language:  "en-US,en;q=0.9",
	},
	{
		Name:      "curl",
		UserAgent: "curl/8.5.0",
	},
}

const cloakLengthRatio = 0.2

func DetectCloaking(target string) *CloakingResult {
	result := &CloakingResult{Probes: make([]CloakProbe, len(cloakProfiles))}

	var wg sync.WaitGroup
	for index, profile := range cloakProfiles {
		wg.Add(1)
		go func(index int, profile cloakProfile) {
			defer wg.Done()
			result.Probes[index] = probeCloaking(target, profile)
		}(index, profile)
	}
	wg.Wait()

	baseline := result.Probes[0]
	if baseline.Error != "" {
		return result
	}

	for _, probe := range result.Probes[1:] {
		if probe.Error != "" {
			continue
		}
		if probe.Status != baseline.Status {
			result.Reasons = append(result.Reasons, fmt.Sprintf("%s: status %d vs browser %d",
				probe.Profile, probe.Status, baseline.Status))
		}
		if probe.FinalURL != baseline.FinalURL {
			result.Reasons = append(result.Reasons, fmt.Sprintf("%s: final url %s vs %s",
				probe.Profile, probe.FinalURL, baseline.FinalURL))
		}
		if probe.Title != baseline.Title {
			result.Reasons = append(result.Reasons, fmt.Sprintf("%s: title %q vs %q",
				probe.Profile, probe.Title, baseline.Title))
		}
		if percent := cloakLengthDelta(baseline.Bytes, probe.Bytes); percent > cloakLengthRatio {
			result.Reasons = append(result.Reasons, fmt.Sprintf("%s: body size differs by %.0f%% (%d vs %d bytes)",
				probe.Profile, percent*100, probe.Bytes, baseline.Bytes))
		}
	}

	result.Differs = len(result.Reasons) > 0
	return result
}

func (r *CloakingResult) String() string {
	var b strings.Builder
	if r.Differs {
		b.WriteString("  cloaking: YES (content differs per client)\n")
	} else {
		b.WriteString("  cloaking: no\n")
	}
	for _, probe := range r.Probes {
		if probe.Error != "" {
			fmt.Fprintf(&b, "    %s: error (%s)\n", probe.Profile, probe.Error)
			continue
		}
		fmt.Fprintf(&b, "    %s: status %d, %d bytes\n", probe.Profile, probe.Status, probe.Bytes)
	}
	for _, reason := range r.Reasons {
		fmt.Fprintf(&b, "    ! %s\n", reason)
	}
	return b.String()
}

func probeCloaking(target string, profile cloakProfile) CloakProbe {
	probe := CloakProbe{Profile: profile.Name}

	request, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		probe.Error = err.Error()
		return probe
	}
	request.Header.Set("User-Agent", profile.UserAgent)
	request.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	if profile.Language != "" {
		request.Header.Set("Accept-Language", profile.Language)
	}

	client := &http.Client{Timeout: 15 * time.Second}
	response, err := client.Do(request)
	if err != nil {
		probe.Error = err.Error()
		return probe
	}
	defer response.Body.Close()

	body, err := io.ReadAll(io.LimitReader(response.Body, probeBytes))
	if err != nil {
		probe.Error = err.Error()
		return probe
	}

	probe.Status = response.StatusCode
	probe.FinalURL = response.Request.URL.String()
	probe.Bytes = len(body)
	probe.SHA256 = fmt.Sprintf("%x", sha256.Sum256(body))
	if match := cloakTitlePattern.FindSubmatch(body); match != nil {
		probe.Title = strings.Join(strings.Fields(string(match[1])), " ")
	}
	return probe
}

func cloakLengthDelta(first, second int) float64 {
	largest := first
	if second > largest {
		largest = second
	}
	if largest == 0 {
		return 0
	}
	delta := first - second
	if delta < 0 {
		delta = -delta
	}
	return float64(delta) / float64(largest)
}
