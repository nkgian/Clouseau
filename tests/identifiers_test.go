package tests

import (
	"testing"

	"clouseau/internal/analyzer/submodules"
)

func TestDetectIdentifiers(t *testing.T) {
	body := []byte(`<html><head><style>.logo{background:url(img@2x.png)}</style></head><body>
<script>
var classic = "UA-123456-7";
gtag('config', 'G-ABC123XY');
fbq('init', '123456789012345');
ym(34567890, "init");
</script>
<a href="https://t.me/durov">telegram</a>
<a href="https://wa.me/15551234567">whatsapp</a>
<a href="mailto:contact@scam.example">mail</a>
<span>eth: 0x52908400098527886E0F7030069857D2E4169EE7</span>
<span>btc: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa</span>
</body></html>`)

	result := submodules.DetectIdentifiers(body)
	if result == nil {
		t.Fatal("expected identifiers, got nil")
	}

	for _, want := range []string{"UA-123456-7", "G-ABC123XY", "fbq 123456789012345", "ym 34567890"} {
		if !wordpressContains(result.Analytics, want) {
			t.Fatalf("analytics = %v, want %s", result.Analytics, want)
		}
	}
	if len(result.Analytics) != 4 {
		t.Fatalf("analytics = %v, want 4 entries", result.Analytics)
	}
	if !wordpressContains(result.Telegram, "durov") {
		t.Fatalf("telegram = %v, want durov", result.Telegram)
	}
	if !wordpressContains(result.WhatsApp, "15551234567") {
		t.Fatalf("whatsapp = %v, want 15551234567", result.WhatsApp)
	}
	if !wordpressContains(result.Wallets, "0x52908400098527886E0F7030069857D2E4169EE7") {
		t.Fatalf("wallets = %v, want the ethereum address", result.Wallets)
	}
	if !wordpressContains(result.Wallets, "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa") {
		t.Fatalf("wallets = %v, want the bitcoin address", result.Wallets)
	}
	if len(result.Emails) != 1 || result.Emails[0] != "contact@scam.example" {
		t.Fatalf("emails = %v, want [contact@scam.example]", result.Emails)
	}
}

func TestDetectIdentifiersNone(t *testing.T) {
	body := []byte(`<html><body><p>Nothing to see here.</p></body></html>`)

	if result := submodules.DetectIdentifiers(body); result != nil {
		t.Fatalf("expected nil identifiers, got %+v", result)
	}
}

func TestIdentifierMerge(t *testing.T) {
	first := &submodules.IdentifierResult{Analytics: []string{"G-AAA111"}, Emails: []string{"a@x.example"}}
	second := &submodules.IdentifierResult{Analytics: []string{"G-AAA111", "G-BBB222"}}

	first.Merge(second)
	first.Merge(nil)

	if len(first.Analytics) != 2 {
		t.Fatalf("analytics = %v, want 2 deduplicated entries", first.Analytics)
	}
	if len(first.Emails) != 1 {
		t.Fatalf("emails = %v, want 1 entry", first.Emails)
	}
}
