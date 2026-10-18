package analyzer

import (
	"fmt"
	"net"
	"strings"
)

type IpLookup struct{}

type IPResult struct {
	Host  string
	IPs   []string
	CNAME string
}

func (r *IPResult) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "[ip_lookup] %s\n", r.Host)
	for _, ip := range r.IPs {
		fmt.Fprintf(&b, "  [HOST]:%s\n", ip)
	}
	if r.CNAME != "" {
		fmt.Fprintf(&b, "  [CNAME]%s\n", r.CNAME)
	}
	return b.String()
}

func (w *IpLookup) Run(url string, params map[string]interface{}) (interface{}, error) {
	host := hostFromURL(url)

	ips, err := net.LookupHost(host)
	if err != nil {
		return nil, fmt.Errorf("host lookup for %s failed: %w", host, err)
	}

	cname, err := net.LookupCNAME(host)
	if err != nil {
		return nil, fmt.Errorf("cname lookup for %s failed: %w", host, err)
	}

	return &IPResult{Host: host, IPs: ips, CNAME: cname}, nil
}
