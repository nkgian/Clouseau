package analyzer

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"
)

type IpLookup struct{}

type IPAddress struct {
	IP       string   `json:"ip"`
	Version  int      `json:"version"`
	Scope    string   `json:"scope"`
	PTR      []string `json:"ptr,omitempty"`
	ASN      string   `json:"asn,omitempty"`
	ASName   string   `json:"as_name,omitempty"`
	Country  string   `json:"country,omitempty"`
	Prefix   string   `json:"prefix,omitempty"`
	Provider []string `json:"provider,omitempty"`
	DNSBL    []string `json:"dnsbl,omitempty"`
}

type DNSRecords struct {
	A     []string `json:"a,omitempty"`
	AAAA  []string `json:"aaaa,omitempty"`
	MX    []string `json:"mx,omitempty"`
	NS    []string `json:"ns,omitempty"`
	TXT   []string `json:"txt,omitempty"`
	CNAME string   `json:"cname,omitempty"`
}

type TLSInfo struct {
	ServerName  string    `json:"server_name,omitempty"`
	Version     string    `json:"version"`
	CipherSuite string    `json:"cipher_suite"`
	Subject     string    `json:"subject"`
	Issuer      string    `json:"issuer"`
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
	DaysLeft    int       `json:"days_left"`
	DNSNames    []string  `json:"dns_names,omitempty"`
	SelfSigned  bool      `json:"self_signed"`
}

type IPResult struct {
	Host      string      `json:"host"`
	Records   DNSRecords  `json:"records"`
	Addresses []IPAddress `json:"addresses"`
	TLS       *TLSInfo    `json:"tls,omitempty"`
	Warnings  []string    `json:"warnings,omitempty"`
}

type ASInfo struct {
	ASN     string
	Prefix  string
	Country string
	Name    string
}

type providerSignature struct {
	pattern string
	label   string
}

var providerSignatures = []providerSignature{
	{"cloudflare", "Cloudflare"},
	{"akamai", "Akamai"},
	{"edgesuite", "Akamai"},
	{"edgekey", "Akamai"},
	{"fastly", "Fastly"},
	{"cloudfront", "AWS CloudFront"},
	{"amazon", "Amazon AWS"},
	{"microsoft", "Microsoft Azure"},
	{"azure", "Microsoft Azure"},
	{"msedge", "Microsoft Azure"},
	{"google", "Google Cloud"},
	{"googleusercontent", "Google Cloud"},
	{"1e100", "Google Cloud"},
	{"gvt1", "Google Cloud"},
	{"imperva", "Imperva"},
	{"incapsula", "Imperva"},
	{"sucuri", "Sucuri"},
	{"zscaler", "Zscaler"},
	{"stackpath", "StackPath"},
	{"highwinds", "StackPath"},
	{"hwcdn", "StackPath"},
	{"bunnycdn", "Bunny CDN"},
	{"b-cdn", "Bunny CDN"},
	{"cdn77", "CDN77"},
	{"gcore", "Gcore"},
	{"gcdn", "Gcore"},
	{"limelight", "Limelight"},
	{"llnwd", "Limelight"},
	{"cachefly", "CacheFly"},
	{"keycdn", "KeyCDN"},
	{"kxcdn", "KeyCDN"},
	{"digitalocean", "DigitalOcean"},
	{"linode", "Linode"},
	{"vultr", "Vultr"},
	{"hetzner", "Hetzner"},
	{"ovh", "OVH"},
	{"contabo", "Contabo"},
	{"leaseweb", "Leaseweb"},
	{"oracle", "Oracle Cloud"},
	{"vercel", "Vercel"},
	{"netlify", "Netlify"},
	{"heroku", "Heroku"},
	{"shopify", "Shopify"},
	{"squarespace", "Squarespace"},
	{"wix", "Wix"},
	{"github", "GitHub"},
	{"tor-exit", "Tor exit node"},
	{"torexit", "Tor exit node"},
}

// for dnsbl rep lookup. see: https://www.dnsbl.info/
var dnsblZones = []string{
	"zen.spamhaus.org",
	"bl.spamcop.net",
	"dnsbl.sorbs.net",
	"b.barracudacentral.org",
	"dnsbl-1.uceprotect.net",
}

func (r *IPResult) warnf(format string, args ...interface{}) {
	r.Warnings = append(r.Warnings, fmt.Sprintf(format, args...))
}

func (r *IPResult) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "[ip_lookup] %s\n", r.Host)

	if r.Records.CNAME != "" {
		fmt.Fprintf(&b, "  CNAME: %s\n", strings.TrimSuffix(r.Records.CNAME, "."))
	}
	printValues(&b, "  ", "A", r.Records.A)
	printValues(&b, "  ", "AAAA", r.Records.AAAA)
	printValues(&b, "  ", "NS", r.Records.NS)
	printValues(&b, "  ", "MX", r.Records.MX)
	if len(r.Records.TXT) > 0 {
		fmt.Fprintln(&b, "  TXT:")
		for _, txt := range r.Records.TXT {
			fmt.Fprintf(&b, "    %s\n", truncate(txt, 250))
		}
	}

	if r.TLS != nil {
		fmt.Fprintf(&b, "  TLS: %s %s\n", r.TLS.Version, r.TLS.CipherSuite)
		fmt.Fprintf(&b, "    subject: %s\n", r.TLS.Subject)
		fmt.Fprintf(&b, "    issuer:  %s\n", r.TLS.Issuer)
		fmt.Fprintf(&b, "    valid:   %s -> %s (%d days left)\n",
			r.TLS.NotBefore.Format(time.RFC3339), r.TLS.NotAfter.Format(time.RFC3339), r.TLS.DaysLeft)
		if r.TLS.SelfSigned {
			fmt.Fprintln(&b, "    self-signed: yes")
		}
		if len(r.TLS.DNSNames) > 0 {
			fmt.Fprintf(&b, "    san: %s\n", strings.Join(r.TLS.DNSNames, ", "))
		}
	}

	for _, addr := range r.Addresses {
		fmt.Fprintf(&b, "  -- %s (IPv%d, %s) --\n", addr.IP, addr.Version, addr.Scope)
		printValues(&b, "    ", "PTR", addr.PTR)
		if addr.ASN != "" {
			fmt.Fprintf(&b, "    ASN: AS%s %s (%s) %s\n", addr.ASN, addr.ASName, addr.Country, addr.Prefix)
		}
		printValues(&b, "    ", "provider", addr.Provider)
		printValues(&b, "    ", "dnsbl", addr.DNSBL)
	}

	if len(r.Warnings) > 0 {
		fmt.Fprintln(&b, "  warnings:")
		for _, warning := range r.Warnings {
			fmt.Fprintf(&b, "    %s\n", warning)
		}
	}

	return b.String()
}

func printValues(b *strings.Builder, indent, label string, values []string) {
	if len(values) == 0 {
		return
	}
	fmt.Fprintf(b, "%s%s: %s\n", indent, label, strings.Join(values, ", "))
}

func (w *IpLookup) Run(url string, params map[string]interface{}) (interface{}, error) {
	host := hostFromURL(url)

	ips, err := net.LookupHost(host)
	if err != nil {
		return nil, fmt.Errorf("host lookup for %s failed: %w", host, err)
	}

	result := &IPResult{Host: host}

	if cname, err := net.LookupCNAME(host); err != nil {
		result.warnf("cname lookup: %v", err)
	} else {
		result.Records.CNAME = cname
	}

	addresses, v4, v6 := classifyAddresses(ips)
	sort.Strings(v4)
	sort.Strings(v6)
	result.Records.A = v4
	result.Records.AAAA = v6

	result.Records.NS = lookupNS(host)
	result.Records.MX = lookupMX(host)
	result.Records.TXT = lookupTXT(host)

	for i := range addresses {
		if names, err := net.LookupAddr(addresses[i].IP); err == nil {
			for j, name := range names {
				names[j] = strings.TrimSuffix(name, ".")
			}
			sort.Strings(names)
			addresses[i].PTR = names
		}
	}

	asnInfo, err := lookupASN(addresses)
	if err != nil {
		result.warnf("asn lookup: %v", err)
	}

	for i := range addresses {
		if info, ok := asnInfo[addresses[i].IP]; ok {
			addresses[i].ASN = info.ASN
			addresses[i].ASName = info.Name
			addresses[i].Country = info.Country
			addresses[i].Prefix = info.Prefix
		}
		haystack := strings.Join([]string{
			result.Records.CNAME,
			strings.Join(addresses[i].PTR, " "),
			addresses[i].ASName,
			addresses[i].Prefix,
		}, " ")
		addresses[i].Provider = detectProviders(haystack)
	}

	if boolParam(params, "dnsbl", false) {
		for i := range addresses {
			if addresses[i].Scope == "public" {
				addresses[i].DNSBL = checkDNSBL(addresses[i].IP)
			}
		}
	}

	if boolParam(params, "tls", false) {
		info, err := inspectTLS(host, intParam(params, "tls_port", 443))
		if err != nil {
			result.warnf("tls inspection: %v", err)
		} else {
			result.TLS = info
		}
	}

	result.Addresses = addresses
	return result, nil
}

func classifyAddresses(ips []string) ([]IPAddress, []string, []string) {
	addresses := make([]IPAddress, 0, len(ips))
	seen := map[string]bool{}
	var v4, v6 []string

	for _, raw := range ips {
		ip := net.ParseIP(raw)
		if ip == nil || seen[raw] {
			continue
		}
		seen[raw] = true

		version := 6
		if ip.To4() != nil {
			version = 4
			v4 = append(v4, raw)
		} else {
			v6 = append(v6, raw)
		}

		addresses = append(addresses, IPAddress{
			IP:      raw,
			Version: version,
			Scope:   ipScope(ip),
		})
	}

	sort.Slice(addresses, func(i, j int) bool {
		if addresses[i].Version != addresses[j].Version {
			return addresses[i].Version < addresses[j].Version
		}
		return addresses[i].IP < addresses[j].IP
	})

	return addresses, v4, v6
}

func ipScope(ip net.IP) string {
	switch {
	case ip.IsUnspecified():
		return "unspecified"
	case ip.IsLoopback():
		return "loopback"
	case ip.IsMulticast():
		return "multicast"
	case ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast():
		return "link-local"
	case ip.IsInterfaceLocalMulticast():
		return "interface-local"
	case ip.IsPrivate():
		return "private"
	default:
		return "public"
	}
}

func lookupNS(host string) []string {
	records, err := net.LookupNS(host)
	if err != nil {
		return nil
	}
	names := make([]string, 0, len(records))
	for _, record := range records {
		names = append(names, strings.TrimSuffix(record.Host, "."))
	}
	sort.Strings(names)
	return names
}

func lookupMX(host string) []string {
	records, err := net.LookupMX(host)
	if err != nil {
		return nil
	}
	names := make([]string, 0, len(records))
	for _, record := range records {
		target := strings.TrimSuffix(record.Host, ".")
		if target == "" {
			target = "(null MX)"
		}
		names = append(names, fmt.Sprintf("%d %s", record.Pref, target))
	}
	return names
}

func lookupTXT(host string) []string {
	records, err := net.LookupTXT(host)
	if err != nil {
		return nil
	}
	sort.Strings(records)
	return records
}

func lookupASN(addresses []IPAddress) (map[string]ASInfo, error) {
	queries := make([]string, 0, len(addresses))
	for _, addr := range addresses {
		if addr.Scope == "public" {
			queries = append(queries, addr.IP)
		}
	}
	if len(queries) == 0 {
		return nil, nil
	}

	query := "begin\nverbose\n" + strings.Join(queries, "\n") + "\nend"
	response, err := queryWhois("whois.cymru.com", query)
	if err != nil {
		return nil, err
	}

	info := map[string]ASInfo{}
	for _, line := range strings.Split(response, "\n") {
		parts := strings.Split(line, "|")
		if len(parts) < 7 {
			continue
		}
		asn := strings.TrimSpace(parts[0])
		if _, err := strconv.Atoi(asn); err != nil {
			continue
		}
		ip := strings.TrimSpace(parts[1])
		if ip == "" {
			continue
		}
		country := strings.TrimSpace(parts[3])
		name := strings.TrimSpace(parts[6])
		if country != "" && country != "NA" {
			name = strings.TrimSuffix(name, ", "+country)
		}
		info[ip] = ASInfo{
			ASN:     asn,
			Prefix:  strings.TrimSpace(parts[2]),
			Country: country,
			Name:    name,
		}
	}
	return info, nil
}

func detectProviders(haystack string) []string {
	haystack = strings.ToLower(haystack)
	seen := map[string]bool{}
	var found []string
	for _, signature := range providerSignatures {
		if strings.Contains(haystack, signature.pattern) && !seen[signature.label] {
			seen[signature.label] = true
			found = append(found, signature.label)
		}
	}
	return found
}

func checkDNSBL(rawIP string) []string {
	ip := net.ParseIP(rawIP)
	v4 := ip.To4()
	if v4 == nil {
		return nil
	}

	reversed := fmt.Sprintf("%d.%d.%d.%d", v4[3], v4[2], v4[1], v4[0])
	var listed []string
	for _, zone := range dnsblZones {
		answers, err := net.LookupHost(reversed + "." + zone)
		if err != nil {
			continue
		}
		for _, answer := range answers {
			if strings.HasPrefix(answer, "127.255.255.") {
				continue
			}
			if strings.HasPrefix(answer, "127.") {
				listed = append(listed, zone)
				break
			}
		}
	}
	return listed
}

func inspectTLS(host string, port int) (*TLSInfo, error) {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(host, strconv.Itoa(port)), &tls.Config{ServerName: host})
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no certificate presented by %s", host)
	}
	leaf := state.PeerCertificates[0]

	return &TLSInfo{
		ServerName:  state.ServerName,
		Version:     tls.VersionName(state.Version),
		CipherSuite: tls.CipherSuiteName(state.CipherSuite),
		Subject:     leaf.Subject.String(),
		Issuer:      leaf.Issuer.String(),
		NotBefore:   leaf.NotBefore,
		NotAfter:    leaf.NotAfter,
		DaysLeft:    int(time.Until(leaf.NotAfter).Hours() / 24),
		DNSNames:    leaf.DNSNames,
		SelfSigned:  bytes.Equal(leaf.RawIssuer, leaf.RawSubject),
	}, nil
}
