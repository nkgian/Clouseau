package submodules

import (
	"fmt"
	"regexp"
	"strings"
)

type IdentifierResult struct {
	Analytics []string `json:"analytics,omitempty"`
	Telegram  []string `json:"telegram,omitempty"`
	WhatsApp  []string `json:"whatsapp,omitempty"`
	Wallets   []string `json:"wallets,omitempty"`
	Emails    []string `json:"emails,omitempty"`
}

var (
	identifierClassicAnalytics = regexp.MustCompile(`\bUA-\d{4,}-\d+\b`)
	identifierGoogleTag        = regexp.MustCompile(`\b(?:G|GT|AW)-[A-Z0-9]{4,}\b`)
	identifierTagManager       = regexp.MustCompile(`\bGTM-[A-Z0-9]{4,}\b`)
	identifierAdSense          = regexp.MustCompile(`\bca-pub-\d{10,}\b`)
	identifierFacebookPixel    = regexp.MustCompile(`fbq\(\s*['"]init['"]\s*,\s*['"](\d{8,})['"]`)
	identifierYandexMetrica    = regexp.MustCompile(`\bym\(\s*(\d{6,})`)
	identifierTelegram         = regexp.MustCompile(`(?:t\.me|telegram\.me)/([A-Za-z0-9_]{4,})`)
	identifierWhatsApp         = regexp.MustCompile(`(?:wa\.me/|api\.whatsapp\.com/send\?phone=|whatsapp://send\?phone=)(\+?\d{6,})`)
	identifierBitcoin          = regexp.MustCompile(`\b(?:bc1[a-z0-9]{25,39}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b`)
	identifierEthereum         = regexp.MustCompile(`\b0x[a-fA-F0-9]{40}\b`)
	identifierEmail            = regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`)
)

var identifierEmailNoise = []string{
	".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico",
	".css", ".js", ".woff", ".woff2", ".ttf",
}

func DetectIdentifiers(body []byte) *IdentifierResult {
	text := string(body)
	result := &IdentifierResult{}

	result.Analytics = append(result.Analytics, identifierClassicAnalytics.FindAllString(text, -1)...)
	result.Analytics = append(result.Analytics, identifierGoogleTag.FindAllString(text, -1)...)
	result.Analytics = append(result.Analytics, identifierTagManager.FindAllString(text, -1)...)
	result.Analytics = append(result.Analytics, identifierAdSense.FindAllString(text, -1)...)
	for _, match := range identifierFacebookPixel.FindAllStringSubmatch(text, -1) {
		result.Analytics = append(result.Analytics, "fbq "+match[1])
	}
	for _, match := range identifierYandexMetrica.FindAllStringSubmatch(text, -1) {
		result.Analytics = append(result.Analytics, "ym "+match[1])
	}

	for _, match := range identifierTelegram.FindAllStringSubmatch(text, -1) {
		result.Telegram = append(result.Telegram, match[1])
	}
	for _, match := range identifierWhatsApp.FindAllStringSubmatch(text, -1) {
		result.WhatsApp = append(result.WhatsApp, match[1])
	}

	result.Wallets = append(result.Wallets, identifierBitcoin.FindAllString(text, -1)...)
	result.Wallets = append(result.Wallets, identifierEthereum.FindAllString(text, -1)...)

	for _, email := range identifierEmail.FindAllString(text, -1) {
		lower := strings.ToLower(email)
		if identifierEmailIsNoise(lower) {
			continue
		}
		result.Emails = append(result.Emails, lower)
	}

	result.Analytics = uniqueSorted(result.Analytics)
	result.Telegram = uniqueSorted(result.Telegram)
	result.WhatsApp = uniqueSorted(result.WhatsApp)
	result.Wallets = uniqueSorted(result.Wallets)
	result.Emails = uniqueSorted(result.Emails)

	if len(result.Analytics) == 0 && len(result.Telegram) == 0 && len(result.WhatsApp) == 0 &&
		len(result.Wallets) == 0 && len(result.Emails) == 0 {
		return nil
	}
	return result
}

func (r *IdentifierResult) Merge(other *IdentifierResult) {
	if other == nil {
		return
	}
	r.Analytics = uniqueSorted(append(r.Analytics, other.Analytics...))
	r.Telegram = uniqueSorted(append(r.Telegram, other.Telegram...))
	r.WhatsApp = uniqueSorted(append(r.WhatsApp, other.WhatsApp...))
	r.Wallets = uniqueSorted(append(r.Wallets, other.Wallets...))
	r.Emails = uniqueSorted(append(r.Emails, other.Emails...))
}

func (r *IdentifierResult) String() string {
	var b strings.Builder
	b.WriteString("  identifiers:\n")
	if len(r.Analytics) > 0 {
		fmt.Fprintf(&b, "    analytics: %s\n", strings.Join(r.Analytics, ", "))
	}
	if len(r.Telegram) > 0 {
		fmt.Fprintf(&b, "    telegram: %s\n", strings.Join(r.Telegram, ", "))
	}
	if len(r.WhatsApp) > 0 {
		fmt.Fprintf(&b, "    whatsapp: %s\n", strings.Join(r.WhatsApp, ", "))
	}
	if len(r.Wallets) > 0 {
		fmt.Fprintf(&b, "    wallets: %s\n", strings.Join(r.Wallets, ", "))
	}
	if len(r.Emails) > 0 {
		fmt.Fprintf(&b, "    emails: %s\n", strings.Join(r.Emails, ", "))
	}
	return b.String()
}

func identifierEmailIsNoise(email string) bool {
	for _, suffix := range identifierEmailNoise {
		if strings.HasSuffix(email, suffix) {
			return true
		}
	}
	return false
}
