package analyzer

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"clouseau/internal/analyzer/submodules"
)

type IpLookup struct{}

type IPAddress struct {
	IP               string        `json:"ip"`
	Version          int           `json:"version"`
	Scope            string        `json:"scope"`
	PTR              []string      `json:"ptr,omitempty"`
	ForwardConfirmed bool          `json:"forward_confirmed,omitempty"`
	ASN              string        `json:"asn,omitempty"`
	ASName           string        `json:"as_name,omitempty"`
	Country          string        `json:"country,omitempty"`
	Prefix           string        `json:"prefix,omitempty"`
	Provider         []string      `json:"provider,omitempty"`
	TorExit          bool          `json:"tor_exit,omitempty"`
	OpenPorts        []int         `json:"open_ports,omitempty"`
	Netblock         *NetblockInfo `json:"netblock,omitempty"`
	DNSBL            []string      `json:"dnsbl,omitempty"`
}

type NetblockInfo struct {
	Server       string   `json:"server"`
	Organization string   `json:"organization,omitempty"`
	AbuseEmails  []string `json:"abuse_emails,omitempty"`
}

type EmailSecurity struct {
	SPF         []string `json:"spf,omitempty"`
	DMARC       string   `json:"dmarc,omitempty"`
	DMARCPolicy string   `json:"dmarc_policy,omitempty"`
	BIMI        string   `json:"bimi,omitempty"`
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
	Verified    bool      `json:"verified"`
	VerifyError string    `json:"verify_error,omitempty"`
}

type IPResult struct {
	Host             string                   `json:"host"`
	Records          DNSRecords               `json:"records"`
	Email            EmailSecurity            `json:"email_security"`
	Addresses        []IPAddress              `json:"addresses"`
	TLS              *TLSInfo                 `json:"tls,omitempty"`
	CloudflareOrigin *submodules.OriginResult `json:"cloudflare_origin,omitempty"`
	Warnings         []string                 `json:"warnings,omitempty"`
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

var defaultPorts = []int{21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443, 27017}

var emailPattern = regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`)

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

	if len(r.Email.SPF) > 0 {
		printValues(&b, "  ", "SPF", r.Email.SPF)
	}
	if r.Email.DMARC != "" {
		policy := r.Email.DMARCPolicy
		if policy == "" {
			policy = "none"
		}
		fmt.Fprintf(&b, "  DMARC: %s (policy: %s)\n", truncate(r.Email.DMARC, 250), policy)
	}
	if r.Email.BIMI != "" {
		fmt.Fprintf(&b, "  BIMI: %s\n", truncate(r.Email.BIMI, 250))
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
		if r.TLS.Verified {
			fmt.Fprintln(&b, "    verified: yes")
		} else {
			fmt.Fprintf(&b, "    verified: no (%s)\n", r.TLS.VerifyError)
		}
		if len(r.TLS.DNSNames) > 0 {
			fmt.Fprintf(&b, "    san: %s\n", strings.Join(r.TLS.DNSNames, ", "))
		}
	}

	if r.CloudflareOrigin != nil {
		fmt.Fprintf(&b, "  cloudflare origin candidates (%d subdomains resolved):\n", r.CloudflareOrigin.Checked)
		if len(r.CloudflareOrigin.Candidates) == 0 {
			fmt.Fprintln(&b, "    none found")
		}
		for _, candidate := range r.CloudflareOrigin.Candidates {
			fmt.Fprintf(&b, "    %s -> %s\n", candidate.Subdomain, strings.Join(candidate.IPs, ", "))
		}
	}

	for _, addr := range r.Addresses {
		fmt.Fprintf(&b, "  -- %s (IPv%d, %s) --\n", addr.IP, addr.Version, addr.Scope)
		printValues(&b, "    ", "PTR", addr.PTR)
		if len(addr.PTR) > 0 && !addr.ForwardConfirmed {
			fmt.Fprintln(&b, "    forward-confirmed PTR: no")
		}
		if addr.ASN != "" {
			fmt.Fprintf(&b, "    ASN: AS%s %s (%s) %s\n", addr.ASN, addr.ASName, addr.Country, addr.Prefix)
		}
		printValues(&b, "    ", "provider", addr.Provider)
		if addr.TorExit {
			fmt.Fprintln(&b, "    tor exit node: yes")
		}
		if len(addr.OpenPorts) > 0 {
			fmt.Fprintf(&b, "    open ports: %s\n", joinInts(addr.OpenPorts))
		}
		if addr.Netblock != nil {
			fmt.Fprintf(&b, "    netblock: %s (via %s)\n", addr.Netblock.Organization, addr.Netblock.Server)
			printValues(&b, "      ", "abuse", addr.Netblock.AbuseEmails)
		}
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

	if net.ParseIP(host) == nil {
		if cname, err := net.LookupCNAME(host); err != nil {
			result.warnf("cname lookup: %v", err)
		} else {
			result.Records.CNAME = cname
		}
	}

	addresses, v4, v6 := classifyAddresses(ips)
	sort.Strings(v4)
	sort.Strings(v6)
	result.Records.A = v4
	result.Records.AAAA = v6

	result.Records.NS = lookupNS(host)
	result.Records.MX = lookupMX(host)
	result.Records.TXT = lookupTXT(host)

	emailDomain := submodules.BaseDomain(host)
	emailTXT := result.Records.TXT
	if emailDomain != host {
		emailTXT = lookupTXT(emailDomain)
	}
	result.Email = lookupEmailSecurity(emailDomain, emailTXT)

	for i := range addresses {
		if names, err := net.LookupAddr(addresses[i].IP); err == nil {
			for j, name := range names {
				names[j] = strings.TrimSuffix(name, ".")
			}
			sort.Strings(names)
			addresses[i].PTR = names
			addresses[i].ForwardConfirmed = forwardConfirmed(addresses[i].IP, names)
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

	if boolParam(params, "tor", false) {
		exits, err := lookupTorExits(addresses)
		if err != nil {
			result.warnf("tor exit check: %v", err)
		} else {
			for i := range addresses {
				addresses[i].TorExit = exits[addresses[i].IP]
			}
		}
	}

	if boolParam(params, "netblock", false) {
		for i := range addresses {
			if addresses[i].Scope != "public" {
				continue
			}
			info, err := lookupNetblock(addresses[i].IP)
			if err != nil {
				result.warnf("netblock lookup for %s: %v", addresses[i].IP, err)
				continue
			}
			addresses[i].Netblock = info
		}
	}

	if boolParam(params, "scan_ports", false) {
		ports := intListParam(params, "ports")
		if len(ports) == 0 {
			ports = defaultPorts
		}
		timeout := time.Duration(intParam(params, "port_timeout_ms", 2000)) * time.Millisecond
		for i := range addresses {
			if !scannableScope(addresses[i].Scope) {
				continue
			}
			addresses[i].OpenPorts = scanPorts(addresses[i].IP, ports, timeout)
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

	if !boolParam(params, "skip_origin_lookup", false) && net.ParseIP(host) == nil && hasProvider(addresses, "Cloudflare") {
		origin, err := submodules.LookupOrigins(host, params, classifyCloudflareIPs)
		if err != nil {
			result.warnf("cloudflare origin lookup: %v", err)
		} else {
			result.CloudflareOrigin = origin
		}
	}

	result.Addresses = addresses
	return result, nil
}

func hasProvider(addresses []IPAddress, label string) bool {
	for _, addr := range addresses {
		for _, provider := range addr.Provider {
			if provider == label {
				return true
			}
		}
	}
	return false
}

func classifyCloudflareIPs(ips []string) (map[string]bool, error) {
	addresses := make([]IPAddress, 0, len(ips))
	for _, ip := range ips {
		addresses = append(addresses, IPAddress{IP: ip, Scope: "public"})
	}

	info, err := lookupASN(addresses)
	if err != nil {
		return nil, err
	}

	classified := make(map[string]bool, len(ips))
	for _, ip := range ips {
		asn, ok := info[ip]
		if !ok {
			continue
		}
		classified[ip] = asn.ASN == "13335" || strings.Contains(strings.ToLower(asn.Name), "cloudflare")
	}
	return classified, nil
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
	conn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(host, strconv.Itoa(port)), &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
	})
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no certificate presented by %s", host)
	}
	leaf := state.PeerCertificates[0]

	info := &TLSInfo{
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
	}

	options := x509.VerifyOptions{
		DNSName:       host,
		Intermediates: x509.NewCertPool(),
	}
	for _, certificate := range state.PeerCertificates[1:] {
		options.Intermediates.AddCert(certificate)
	}
	if _, err := leaf.Verify(options); err != nil {
		info.VerifyError = err.Error()
	} else {
		info.Verified = true
	}

	return info, nil
}

func lookupEmailSecurity(host string, txtRecords []string) EmailSecurity {
	security := EmailSecurity{}

	for _, txt := range txtRecords {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(txt)), "v=spf1") {
			security.SPF = append(security.SPF, txt)
		}
	}

	if records, err := net.LookupTXT("_dmarc." + host); err == nil {
		for _, txt := range records {
			if strings.HasPrefix(strings.ToLower(strings.TrimSpace(txt)), "v=dmarc1") {
				security.DMARC = txt
				security.DMARCPolicy = dmarcPolicy(txt)
				break
			}
		}
	}

	if records, err := net.LookupTXT("default._bimi." + host); err == nil {
		for _, txt := range records {
			if strings.HasPrefix(strings.ToLower(strings.TrimSpace(txt)), "v=bimi1") {
				security.BIMI = txt
				break
			}
		}
	}

	return security
}

func dmarcPolicy(record string) string {
	for _, part := range strings.Split(record, ";") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(strings.ToLower(part), "p=") {
			return strings.TrimSpace(part[2:])
		}
	}
	return ""
}

func forwardConfirmed(rawIP string, names []string) bool {
	ip := net.ParseIP(rawIP)
	if ip == nil {
		return false
	}
	for _, name := range names {
		answers, err := net.LookupHost(name)
		if err != nil {
			continue
		}
		for _, answer := range answers {
			if parsed := net.ParseIP(answer); parsed != nil && parsed.Equal(ip) {
				return true
			}
		}
	}
	return false
}

func lookupNetblock(rawIP string) (*NetblockInfo, error) {
	referral, err := queryWhois("whois.iana.org", rawIP)
	if err != nil {
		return nil, err
	}

	server := referralServer(referral)
	if server == "" {
		return nil, fmt.Errorf("no whois referral found for %s", rawIP)
	}

	response, err := queryWhois(server, rawIP)
	if err != nil {
		return nil, err
	}

	if next := referralServer(response); next != "" && !strings.EqualFold(next, server) {
		if second, err := queryWhois(next, rawIP); err == nil {
			server = next
			response = second
		}
	}

	return &NetblockInfo{
		Server:       server,
		Organization: netblockOrg(response),
		AbuseEmails:  abuseEmails(response),
	}, nil
}

func referralServer(response string) string {
	for _, line := range strings.Split(response, "\n") {
		key, value := fieldValue(strings.TrimRight(line, "\r"))
		switch strings.ToLower(key) {
		case "refer", "whois":
			host := firstField(value)
			if host != "" && strings.Contains(host, ".") && !strings.ContainsAny(host, "/\\") {
				return host
			}
		}
	}
	return ""
}

func firstField(value string) string {
	fields := strings.Fields(value)
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}

func fieldValue(line string) (string, string) {
	idx := strings.Index(line, ":")
	if idx <= 0 {
		return "", ""
	}
	return strings.TrimSpace(line[:idx]), strings.TrimSpace(line[idx+1:])
}

func netblockOrg(response string) string {
	values := map[string]string{}
	for _, line := range strings.Split(response, "\n") {
		key, value := fieldValue(strings.TrimRight(line, "\r"))
		if key == "" || value == "" {
			continue
		}
		lower := strings.ToLower(key)
		if _, exists := values[lower]; !exists {
			values[lower] = value
		}
	}

	for _, key := range []string{"orgname", "org-name", "organisation", "organization", "owner", "descr"} {
		if value := values[key]; value != "" {
			return value
		}
	}
	return ""
}

func abuseEmails(response string) []string {
	seen := map[string]bool{}
	var emails []string
	for _, line := range strings.Split(response, "\n") {
		key, value := fieldValue(strings.TrimRight(line, "\r"))
		if key == "" || !strings.Contains(strings.ToLower(key), "abuse") {
			continue
		}
		for _, email := range emailPattern.FindAllString(value, -1) {
			if !seen[email] {
				seen[email] = true
				emails = append(emails, email)
			}
		}
	}
	sort.Strings(emails)
	return emails
}

func lookupTorExits(addresses []IPAddress) (map[string]bool, error) {
	needed := false
	for _, addr := range addresses {
		if addr.Scope == "public" {
			needed = true
			break
		}
	}
	if !needed {
		return nil, nil
	}

	client := &http.Client{Timeout: 20 * time.Second}
	response, err := client.Get("https://check.torproject.org/torbulkexitlist")
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("tor exit list returned %s", response.Status)
	}

	body, err := io.ReadAll(io.LimitReader(response.Body, 4<<20))
	if err != nil {
		return nil, err
	}

	exits := map[string]bool{}
	for _, line := range strings.Split(string(body), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			exits[line] = true
		}
	}
	return exits, nil
}

func scanPorts(rawIP string, ports []int, timeout time.Duration) []int {
	var (
		mu   sync.Mutex
		wg   sync.WaitGroup
		open []int
	)
	semaphore := make(chan struct{}, 32)

	for _, port := range ports {
		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			conn, err := net.DialTimeout("tcp", net.JoinHostPort(rawIP, strconv.Itoa(port)), timeout)
			if err != nil {
				return
			}
			conn.Close()

			mu.Lock()
			open = append(open, port)
			mu.Unlock()
		}(port)
	}

	wg.Wait()
	sort.Ints(open)
	return open
}

func scannableScope(scope string) bool {
	switch scope {
	case "public", "private", "loopback":
		return true
	default:
		return false
	}
}

func joinInts(values []int) string {
	parts := make([]string, len(values))
	for i, value := range values {
		parts[i] = strconv.Itoa(value)
	}
	return strings.Join(parts, ", ")
}
