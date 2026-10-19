package analyzer

import (
	"net/url"
	"strings"
)

type Analyzer interface {
	Run(url string, params map[string]interface{}) (interface{}, error)
}

var Registry = map[string]Analyzer{
	"ip_lookup":    &IpLookup{},
	"whois_lookup": &WhoisAnalyzer{},
	"html_scan":    &HTMLAnalyzer{},
	"robots_scan":  &RobotsAnalyzer{},
}

func normalizeURL(raw string) string {
	if !strings.Contains(raw, "://") {
		return "http://" + raw
	}
	return raw
}

func hostFromURL(raw string) string {
	parsed, err := url.Parse(normalizeURL(raw))
	if err != nil || parsed.Hostname() == "" {
		return strings.ToLower(raw)
	}
	return strings.ToLower(parsed.Hostname())
}

func stringParam(params map[string]interface{}, key string) string {
	if v, ok := params[key].(string); ok {
		return v
	}
	return ""
}

func intParam(params map[string]interface{}, key string, fallback int) int {
	switch v := params[key].(type) {
	case int:
		return v
	case int64:
		return int(v)
	case uint64:
		return int(v)
	case float64:
		return int(v)
	default:
		return fallback
	}
}

func boolParam(params map[string]interface{}, key string, fallback bool) bool {
	if v, ok := params[key].(bool); ok {
		return v
	}
	return fallback
}

func intListParam(params map[string]interface{}, key string) []int {
	list, ok := params[key].([]interface{})
	if !ok {
		return nil
	}
	values := make([]int, 0, len(list))
	for _, item := range list {
		switch v := item.(type) {
		case int:
			values = append(values, v)
		case int64:
			values = append(values, int(v))
		case uint64:
			values = append(values, int(v))
		case float64:
			values = append(values, int(v))
		}
	}
	return values
}
