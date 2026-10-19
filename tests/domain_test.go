package tests

import (
	"testing"

	"clouseau/internal/analyzer"
)

func TestDomainRunFlagsPunycode(t *testing.T) {
	result, err := (&analyzer.DomainAnalyzer{}).Run("https://xn--e1afmkfd.xn--p1ai", nil)
	if err != nil {
		t.Fatalf("Run returned unexpected error: %v", err)
	}

	domain, ok := result.(*analyzer.DomainResult)
	if !ok {
		t.Fatalf("Run returned %T, want *analyzer.DomainResult", result)
	}
	if !domain.Punycode {
		t.Error("punycode = false, want true")
	}
	if domain.UnicodeHost != "пример.рф" {
		t.Fatalf("unicode host = %q, want пример.рф", domain.UnicodeHost)
	}
	if len(domain.Warnings) == 0 {
		t.Fatal("warnings = none, want punycode warning")
	}
}

func TestDomainRunFlagsMixedScript(t *testing.T) {
	result, err := (&analyzer.DomainAnalyzer{}).Run("https://аpple.com", nil)
	if err != nil {
		t.Fatalf("Run returned unexpected error: %v", err)
	}
	domain := result.(*analyzer.DomainResult)

	if !domain.MixedScript {
		t.Fatalf("mixed script = false, want true: scripts=%v", domain.Scripts)
	}
	if !wordpressContains(domain.Scripts, "Latin") || !wordpressContains(domain.Scripts, "Cyrillic") {
		t.Fatalf("scripts = %v, want Latin and Cyrillic", domain.Scripts)
	}
}

func TestDomainRunCleanDomain(t *testing.T) {
	result, err := (&analyzer.DomainAnalyzer{}).Run("https://www.example.com/path", nil)
	if err != nil {
		t.Fatalf("Run returned unexpected error: %v", err)
	}
	domain := result.(*analyzer.DomainResult)

	if domain.Punycode || domain.MixedScript {
		t.Fatalf("result = %+v, want clean domain", domain)
	}
	if len(domain.Warnings) != 0 {
		t.Fatalf("warnings = %v, want none", domain.Warnings)
	}
}
