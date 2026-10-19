package tests

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"clouseau/internal/analyzer"
	"clouseau/internal/analyzer/submodules"
)

func TestMurmur3KnownVectors(t *testing.T) {
	if got := int32(submodules.Murmur3Sum32([]byte("foo"), 0)); got != -156908512 {
		t.Fatalf("Murmur3Sum32(foo, 0) = %d, want -156908512", got)
	}
	if got := submodules.Murmur3Sum32(nil, 0); got != 0 {
		t.Fatalf("Murmur3Sum32(empty, 0) = %d, want 0", got)
	}
	if submodules.Murmur3Sum32([]byte("foo"), 0) == submodules.Murmur3Sum32([]byte("foo"), 42) {
		t.Fatal("Murmur3Sum32 ignores the seed")
	}
}

func TestInfraRunCollectsFaviconAndCertificateDomains(t *testing.T) {
	favicon := []byte{0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x10, 0x10, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00}

	var serverURL string
	mux := http.NewServeMux()
	mux.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/x-icon")
		w.Write(favicon)
	})
	mux.HandleFunc("/crt", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `[
			{"common_name":"%[1]s","name_value":"%[1]s\nsub.%[1]s\nevil.example.org\n*.%[1]s"}
		]`, hostOf(serverURL))
	})

	server := httptest.NewServer(mux)
	defer server.Close()
	serverURL = server.URL

	result, err := (&analyzer.InfraAnalyzer{}).Run(server.URL, map[string]interface{}{"crt_url": server.URL + "/crt"})
	if err != nil {
		t.Fatalf("Run returned unexpected error: %v", err)
	}
	infra, ok := result.(*analyzer.InfraResult)
	if !ok {
		t.Fatalf("Run returned %T, want *analyzer.InfraResult", result)
	}

	host := hostOf(server.URL)
	if infra.DomainTotal != 2 {
		t.Fatalf("domain total = %d, want 2: %v", infra.DomainTotal, infra.Domains)
	}
	if !wordpressContains(infra.Domains, host) || !wordpressContains(infra.Domains, "sub."+host) {
		t.Fatalf("domains = %v, want %s and sub.%s", infra.Domains, host, host)
	}

	if infra.Favicon == nil || infra.Favicon.Error != "" {
		t.Fatalf("favicon = %+v, want successful fetch", infra.Favicon)
	}
	if infra.Favicon.Bytes != len(favicon) {
		t.Fatalf("favicon bytes = %d, want %d", infra.Favicon.Bytes, len(favicon))
	}
	if infra.Favicon.MMH3 != submodules.ShodanFaviconHash(favicon) {
		t.Fatalf("favicon mmh3 = %d, want shodan hash %d", infra.Favicon.MMH3, submodules.ShodanFaviconHash(favicon))
	}
	if infra.Favicon.SHA256 == "" {
		t.Fatal("favicon sha256 is empty")
	}
}

func TestInfraRunReportsCertificateError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/crt" {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	result, err := (&analyzer.InfraAnalyzer{}).Run(server.URL, map[string]interface{}{"crt_url": server.URL + "/crt"})
	if err != nil {
		t.Fatalf("Run returned unexpected error: %v", err)
	}
	infra := result.(*analyzer.InfraResult)

	if infra.CertificateErr == "" {
		t.Fatal("certificate error is empty, want an error")
	}
	if infra.Favicon == nil || infra.Favicon.Error == "" {
		t.Fatalf("favicon = %+v, want an error for missing favicon", infra.Favicon)
	}
}

func hostOf(rawURL string) string {
	parsed := strings.TrimPrefix(rawURL, "http://")
	if index := strings.IndexAny(parsed, "/:"); index >= 0 {
		return parsed[:index]
	}
	return parsed
}
