package analyzer

import (
	"fmt"
	"net/url"

	"clouseau/internal/analyzer/submodules"
)

type RobotsAnalyzer struct{}

func (r *RobotsAnalyzer) Run(target string, params map[string]interface{}) (interface{}, error) {
	base, err := url.Parse(normalizeURL(target))
	if err != nil || base.Host == "" {
		return nil, fmt.Errorf("invalid url %q", target)
	}

	result := submodules.FetchRobots(base.Scheme + "://" + base.Host)
	if result == nil {
		return nil, fmt.Errorf("could not fetch robots.txt for %s", base.Host)
	}
	return result, nil
}
