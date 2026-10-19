package tests

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"clouseau/internal/analyzer"
)

func TestHTMLScanCollectsIndicatorsAndEvidence(t *testing.T) {
	page := `<html><head><title>Giveaway</title></head><body>
<form action="https://collect.example/p" method="post"><input type="password" name="p"></form>
<script>var t="G-ABC123XY";</script>
<a href="https://t.me/scamchannel">telegram</a>
</body></html>`

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, page)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	dir := t.TempDir()
	result, err := (&analyzer.HTMLAnalyzer{}).Run(server.URL, map[string]interface{}{
		"max_depth":     0,
		"extract_links": false,
		"evidence_dir":  dir,
	})
	if err != nil {
		t.Fatalf("Run returned unexpected error: %v", err)
	}

	html, ok := result.(*analyzer.HTMLResult)
	if !ok {
		t.Fatalf("Run returned %T, want *analyzer.HTMLResult", result)
	}
	if len(html.Pages) != 1 {
		t.Fatalf("pages = %d, want 1", len(html.Pages))
	}
	if html.Pages[0].SHA256 == "" {
		t.Fatal("page sha256 is empty")
	}

	evidence := html.Pages[0].EvidenceFile
	if evidence == "" {
		t.Fatal("evidence file is empty")
	}
	content, err := os.ReadFile(evidence)
	if err != nil {
		t.Fatalf("cannot read evidence file: %v", err)
	}
	if string(content) != page {
		t.Fatal("evidence file content does not match served page")
	}
	if !strings.HasPrefix(evidence, dir) {
		t.Fatalf("evidence file %q not inside %q", evidence, dir)
	}

	if html.Identifiers == nil {
		t.Fatal("identifiers = nil, want analytics and telegram")
	}
	if !wordpressContains(html.Identifiers.Analytics, "G-ABC123XY") {
		t.Fatalf("analytics = %v, want G-ABC123XY", html.Identifiers.Analytics)
	}
	if !wordpressContains(html.Identifiers.Telegram, "scamchannel") {
		t.Fatalf("telegram = %v, want scamchannel", html.Identifiers.Telegram)
	}

	if html.Forms == nil || html.Forms.PasswordForms != 1 || html.Forms.CrossOriginForms != 1 {
		t.Fatalf("forms = %+v, want 1 password and 1 cross-origin form", html.Forms)
	}

	if html.Cloaking == nil {
		t.Fatal("cloaking = nil, want probe results")
	}
	if html.Cloaking.Differs {
		t.Fatalf("cloaking differs = true, want false for uniform content: %v", html.Cloaking.Reasons)
	}
}

func TestHTMLScanSkipsCloakingWhenDisabled(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<html><body>plain</body></html>")
	}))
	defer server.Close()

	result, err := (&analyzer.HTMLAnalyzer{}).Run(server.URL, map[string]interface{}{
		"max_depth":     0,
		"extract_links": false,
		"skip_cloaking": true,
	})
	if err != nil {
		t.Fatalf("Run returned unexpected error: %v", err)
	}
	html := result.(*analyzer.HTMLResult)

	if html.Cloaking != nil {
		t.Fatalf("cloaking = %+v, want nil when disabled", html.Cloaking)
	}
}
