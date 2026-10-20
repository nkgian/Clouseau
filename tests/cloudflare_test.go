package tests

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"clouseau/internal/analyzer/submodules"
)

func writeSubdomains(t *testing.T, content string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "subdomains.txt")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write subdomains file: %v", err)
	}
	return path
}

func staticResolver(hosts map[string][]string) submodules.Resolver {
	return func(host string) ([]string, error) {
		if ips, ok := hosts[host]; ok {
			return ips, nil
		}
		return nil, errors.New("no such host")
	}
}

func TestBaseDomainRegisteredDomain(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"www.example.com", "example.com"},
		{"shop.example.co.uk", "example.co.uk"},
		{"m.example.co.uk", "example.co.uk"},
		{"example.github.io", "example.github.io"},
		{"example.com", "example.com"},
		{"EXAMPLE.COM", "example.com"},
		{"localhost", "localhost"},
		{"co.uk", "co.uk"},
		{"127.0.0.1", "127.0.0.1"},
	}
	for _, tc := range cases {
		if got := submodules.BaseDomain(tc.in); got != tc.want {
			t.Errorf("BaseDomain(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestLookupOriginsFindsOriginCandidates(t *testing.T) {
	path := writeSubdomains(t, "# comment\nwww\nmail\napi\ncdn\nmail\n\n")
	resolver := staticResolver(map[string][]string{
		"www.example.com":  {"104.16.1.2", "104.16.1.1"},
		"mail.example.com": {"203.0.113.10"},
		"api.example.com":  {"104.16.1.1", "198.51.100.7"},
		"cdn.example.com":  {"192.0.2.55"},
	})

	var classifiedInput []string
	classifier := func(ips []string) (map[string]bool, error) {
		classifiedInput = append([]string(nil), ips...)
		return map[string]bool{
			"104.16.1.1":   true,
			"104.16.1.2":   true,
			"203.0.113.10": false,
			"198.51.100.7": false,
		}, nil
	}

	result, err := submodules.LookupOrigins("www.example.com", map[string]interface{}{"subdomains_file": path}, classifier, resolver)
	if err != nil {
		t.Fatalf("LookupOrigins returned unexpected error: %v", err)
	}

	if result.Domain != "example.com" {
		t.Errorf("Domain = %q, want %q", result.Domain, "example.com")
	}
	if result.Checked != 4 {
		t.Errorf("Checked = %d, want 4", result.Checked)
	}

	want := []submodules.OriginCandidate{
		{Subdomain: "api.example.com", IPs: []string{"198.51.100.7"}},
		{Subdomain: "mail.example.com", IPs: []string{"203.0.113.10"}},
	}
	if !reflect.DeepEqual(result.Candidates, want) {
		t.Errorf("Candidates = %#v, want %#v", result.Candidates, want)
	}

	wantClassified := []string{"104.16.1.1", "104.16.1.2", "192.0.2.55", "198.51.100.7", "203.0.113.10"}
	if !reflect.DeepEqual(classifiedInput, wantClassified) {
		t.Errorf("classifier received %v, want %v", classifiedInput, wantClassified)
	}

	text := result.String()
	for _, wantLine := range []string{
		"[cloudflare_ip_lookup] example.com (4 subdomains resolved)",
		"api.example.com -> 198.51.100.7",
		"mail.example.com -> 203.0.113.10",
	} {
		if !strings.Contains(text, wantLine) {
			t.Errorf("String() missing %q:\n%s", wantLine, text)
		}
	}
}

func TestLookupOriginsNoCandidates(t *testing.T) {
	path := writeSubdomains(t, "www\nmail\n")
	resolver := staticResolver(map[string][]string{
		"www.example.com":  {"104.16.1.1"},
		"mail.example.com": {"104.16.1.2"},
	})
	classifier := func(ips []string) (map[string]bool, error) {
		return map[string]bool{"104.16.1.1": true, "104.16.1.2": true}, nil
	}

	result, err := submodules.LookupOrigins("example.com", map[string]interface{}{"subdomains_file": path}, classifier, resolver)
	if err != nil {
		t.Fatalf("LookupOrigins returned unexpected error: %v", err)
	}
	if result.Checked != 2 {
		t.Errorf("Checked = %d, want 2", result.Checked)
	}
	if len(result.Candidates) != 0 {
		t.Errorf("Candidates = %#v, want none", result.Candidates)
	}
	if !strings.Contains(result.String(), "no potential origin candidates found") {
		t.Errorf("String() = %q, want no-candidates message", result.String())
	}
}

func TestLookupOriginsClassifierError(t *testing.T) {
	path := writeSubdomains(t, "www\n")
	resolver := staticResolver(map[string][]string{"www.example.com": {"104.16.1.1"}})
	classifier := func(ips []string) (map[string]bool, error) {
		return nil, errors.New("asn service unavailable")
	}

	_, err := submodules.LookupOrigins("example.com", map[string]interface{}{"subdomains_file": path}, classifier, resolver)
	if err == nil {
		t.Fatal("LookupOrigins returned nil error, want classification failure")
	}
	if !strings.Contains(err.Error(), "asn classification") {
		t.Errorf("error = %q, want it to mention asn classification", err)
	}
}

func TestLookupOriginsMissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.txt")
	_, err := submodules.LookupOrigins("example.com", map[string]interface{}{"subdomains_file": path}, nil, nil)
	if err == nil {
		t.Fatal("LookupOrigins returned nil error, want missing-file failure")
	}
	if !strings.Contains(err.Error(), "cannot read subdomains file") {
		t.Errorf("error = %q, want missing-file message", err)
	}
}

func TestLookupOriginsEmptyFile(t *testing.T) {
	path := writeSubdomains(t, "# only comments\n\n")
	failIfCalled := func(string) ([]string, error) {
		t.Fatal("resolver called for empty subdomain list")
		return nil, nil
	}
	_, err := submodules.LookupOrigins("example.com", map[string]interface{}{"subdomains_file": path}, nil, failIfCalled)
	if err == nil {
		t.Fatal("LookupOrigins returned nil error, want empty-list failure")
	}
	if !strings.Contains(err.Error(), "no subdomains to check") {
		t.Errorf("error = %q, want no-subdomains message", err)
	}
}
