package tests

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"clouseau/internal/analyzer"
)

func findHeaderCheck(result *analyzer.HeadersResult, name string) *analyzer.HeaderCheck {
	for i := range result.Checks {
		if result.Checks[i].Name == name {
			return &result.Checks[i]
		}
	}
	return nil
}

func findCookie(result *analyzer.HeadersResult, name string) *analyzer.CookieFlag {
	for i := range result.Cookies {
		if result.Cookies[i].Name == name {
			return &result.Cookies[i]
		}
	}
	return nil
}

func TestHeadersRunAuditsResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'self'; script-src 'unsafe-inline'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Server", "test-server/1.0")
		w.Header().Set("X-Powered-By", "Go")
		w.Header().Add("Set-Cookie", "session=abc; Path=/; HttpOnly; SameSite=Lax")
		w.Header().Add("Set-Cookie", "prefs=1; Secure; SameSite=Strict")
		w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
		w.Header().Set("Access-Control-Allow-Credentials", "true")
	}))
	defer server.Close()

	result, err := (&analyzer.HeadersAnalyzer{}).Run(server.URL, nil)
	if err != nil {
		t.Fatalf("Run returned unexpected error: %v", err)
	}

	headers, ok := result.(*analyzer.HeadersResult)
	if !ok {
		t.Fatalf("Run returned %T, want *analyzer.HeadersResult", result)
	}
	if headers.Status != http.StatusOK {
		t.Fatalf("status = %d, want 200", headers.Status)
	}
	if headers.Server != "test-server/1.0" {
		t.Fatalf("server = %q, want test-server/1.0", headers.Server)
	}
	if headers.PoweredBy != "Go" {
		t.Fatalf("powered_by = %q, want Go", headers.PoweredBy)
	}

	if len(headers.Checks) != 6 {
		t.Fatalf("checks = %d, want 6: %+v", len(headers.Checks), headers.Checks)
	}
	if check := findHeaderCheck(headers, "Strict-Transport-Security"); check == nil || check.Status != "ok" {
		t.Fatalf("HSTS check = %+v, want ok", check)
	}
	if check := findHeaderCheck(headers, "Content-Security-Policy"); check == nil || check.Status != "weak" {
		t.Fatalf("CSP check = %+v, want weak", check)
	}
	if check := findHeaderCheck(headers, "X-Frame-Options"); check == nil || check.Status != "ok" {
		t.Fatalf("X-Frame-Options check = %+v, want ok via CSP frame-ancestors", check)
	}
	if check := findHeaderCheck(headers, "X-Content-Type-Options"); check == nil || check.Status != "ok" {
		t.Fatalf("X-Content-Type-Options check = %+v, want ok", check)
	}
	if check := findHeaderCheck(headers, "Referrer-Policy"); check == nil || check.Status != "ok" {
		t.Fatalf("Referrer-Policy check = %+v, want ok", check)
	}
	if check := findHeaderCheck(headers, "Permissions-Policy"); check == nil || check.Status != "missing" {
		t.Fatalf("Permissions-Policy check = %+v, want missing", check)
	}

	if len(headers.Cookies) != 2 {
		t.Fatalf("cookies = %+v, want 2 entries", headers.Cookies)
	}
	session := findCookie(headers, "session")
	if session == nil || session.Secure || !session.HttpOnly || session.SameSite != "Lax" {
		t.Fatalf("session cookie = %+v, want secure=false httponly=true samesite=Lax", session)
	}
	prefs := findCookie(headers, "prefs")
	if prefs == nil || !prefs.Secure || prefs.HttpOnly || prefs.SameSite != "Strict" {
		t.Fatalf("prefs cookie = %+v, want secure=true httponly=false samesite=Strict", prefs)
	}

	if headers.CORS == nil {
		t.Fatal("cors = nil, want reflection details")
	}
	if !headers.CORS.ReflectsOrigin {
		t.Fatalf("cors = %+v, want reflected probe origin", headers.CORS)
	}
	if !headers.CORS.AllowCredentials {
		t.Fatalf("cors = %+v, want allow_credentials", headers.CORS)
	}
}

func TestHeadersRunFlagsWeakValues(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=300")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("X-Content-Type-Options", "sniff")
		w.Header().Set("Referrer-Policy", "unsafe-url")
		w.Header().Set("Permissions-Policy", "geolocation=()")
	}))
	defer server.Close()

	result, err := (&analyzer.HeadersAnalyzer{}).Run(server.URL, nil)
	if err != nil {
		t.Fatalf("Run returned unexpected error: %v", err)
	}
	headers := result.(*analyzer.HeadersResult)

	if check := findHeaderCheck(headers, "Strict-Transport-Security"); check == nil || check.Status != "weak" {
		t.Fatalf("HSTS check = %+v, want weak", check)
	}
	if check := findHeaderCheck(headers, "Content-Security-Policy"); check == nil || check.Status != "ok" {
		t.Fatalf("CSP check = %+v, want ok", check)
	}
	if check := findHeaderCheck(headers, "X-Frame-Options"); check == nil || check.Status != "missing" {
		t.Fatalf("X-Frame-Options check = %+v, want missing", check)
	}
	if check := findHeaderCheck(headers, "X-Content-Type-Options"); check == nil || check.Status != "weak" {
		t.Fatalf("X-Content-Type-Options check = %+v, want weak", check)
	}
	if check := findHeaderCheck(headers, "Referrer-Policy"); check == nil || check.Status != "weak" {
		t.Fatalf("Referrer-Policy check = %+v, want weak", check)
	}
	if check := findHeaderCheck(headers, "Permissions-Policy"); check == nil || check.Status != "ok" {
		t.Fatalf("Permissions-Policy check = %+v, want ok", check)
	}
	if len(headers.Cookies) != 0 {
		t.Fatalf("cookies = %+v, want none", headers.Cookies)
	}
	if headers.CORS != nil {
		t.Fatalf("cors = %+v, want nil", headers.CORS)
	}
}

func TestHeadersRunInvalidURL(t *testing.T) {
	if _, err := (&analyzer.HeadersAnalyzer{}).Run("://bad", nil); err == nil {
		t.Fatal("expected error for invalid url, got nil")
	}
}

func TestHeadersRunUnreachable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	url := server.URL
	server.Close()

	if _, err := (&analyzer.HeadersAnalyzer{}).Run(url, nil); err == nil {
		t.Fatal("expected error for unreachable host, got nil")
	}
}
