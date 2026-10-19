package tests

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"clouseau/internal/analyzer"
)

func newThreatServer(t *testing.T) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()
	mux.HandleFunc("/feed.txt", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "https://evil.example/one\nhttps://other.example/x\nhttps://evil.example/two\n")
	})
	mux.HandleFunc("/urlhaus/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		_ = r.ParseForm()
		if r.PostFormValue("host") == "evil.example" {
			fmt.Fprint(w, `{"query_status":"ok","urls":[{"url":"https://evil.example/payload"}]}`)
			return
		}
		fmt.Fprint(w, `{"query_status":"no_results"}`)
	})
	mux.HandleFunc("/cdx", func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.RawQuery, "clean.example") {
			fmt.Fprint(w, `[]`)
			return
		}
		fmt.Fprint(w, `[["timestamp"],["20150312010203"]]`)
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server
}

func threatParams(server *httptest.Server) map[string]interface{} {
	return map[string]interface{}{
		"openphish_url": server.URL + "/feed.txt",
		"urlhaus_url":   server.URL + "/urlhaus/",
		"wayback_url":   server.URL + "/cdx",
	}
}

func TestThreatRunFindsListedHost(t *testing.T) {
	server := newThreatServer(t)

	result, err := (&analyzer.ThreatAnalyzer{}).Run("https://evil.example/login", threatParams(server))
	if err != nil {
		t.Fatalf("Run returned unexpected error: %v", err)
	}
	threat, ok := result.(*analyzer.ThreatResult)
	if !ok {
		t.Fatalf("Run returned %T, want *analyzer.ThreatResult", result)
	}

	bySource := map[string]analyzer.ThreatSource{}
	for _, source := range threat.Sources {
		bySource[source.Source] = source
	}

	openPhish := bySource["openphish"]
	if openPhish.Status != "found" || len(openPhish.URLs) != 2 {
		t.Fatalf("openphish = %+v, want found with 2 urls", openPhish)
	}
	urlhaus := bySource["urlhaus"]
	if urlhaus.Status != "found" || len(urlhaus.URLs) != 1 || urlhaus.URLs[0] != "https://evil.example/payload" {
		t.Fatalf("urlhaus = %+v, want found with payload url", urlhaus)
	}
	if threat.FirstSeen != "2015-03-12" {
		t.Fatalf("first seen = %q, want 2015-03-12", threat.FirstSeen)
	}
}

func TestThreatRunClearsCleanHost(t *testing.T) {
	server := newThreatServer(t)

	result, err := (&analyzer.ThreatAnalyzer{}).Run("https://clean.example", threatParams(server))
	if err != nil {
		t.Fatalf("Run returned unexpected error: %v", err)
	}
	threat := result.(*analyzer.ThreatResult)

	for _, source := range threat.Sources {
		if source.Status != "clear" {
			t.Fatalf("source %s = %+v, want clear", source.Source, source)
		}
	}
	if threat.FirstSeen != "" {
		t.Fatalf("first seen = %q, want empty", threat.FirstSeen)
	}
}

func TestThreatRunInvalidURL(t *testing.T) {
	if _, err := (&analyzer.ThreatAnalyzer{}).Run("://bad", nil); err == nil {
		t.Fatal("expected error for invalid url, got nil")
	}
}
