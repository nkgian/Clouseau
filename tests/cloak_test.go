package tests

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"clouseau/internal/analyzer/submodules"
)

func TestDetectCloakingDiffersByUserAgent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.Header.Get("User-Agent"), "Googlebot") {
			fmt.Fprint(w, `<html><head><title>Clean page</title></head><body>welcome</body></html>`)
			return
		}
		fmt.Fprint(w, `<html><head><title>Free crypto giveaway</title></head><body>connect your wallet now</body></html>`)
	}))
	defer server.Close()

	result := submodules.DetectCloaking(server.URL)
	if result == nil {
		t.Fatal("expected cloaking result, got nil")
	}
	if len(result.Probes) != 3 {
		t.Fatalf("probes = %d, want 3", len(result.Probes))
	}
	if !result.Differs {
		t.Fatal("differs = false, want true for user-agent cloaking")
	}
	joined := strings.Join(result.Reasons, "; ")
	if !strings.Contains(joined, "googlebot") {
		t.Fatalf("reasons = %v, want googlebot difference", result.Reasons)
	}
}

func TestDetectCloakingUniformContent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html><head><title>Same</title></head><body>same body for everyone</body></html>`)
	}))
	defer server.Close()

	result := submodules.DetectCloaking(server.URL)
	if result.Differs {
		t.Fatalf("differs = true, want false for uniform content: %v", result.Reasons)
	}
}
