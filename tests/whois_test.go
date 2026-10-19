package tests

import (
	"bufio"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"clouseau/internal/analyzer"
)

func startFakeWhoisServer(t *testing.T, response string) (string, <-chan string) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start fake whois server: %v", err)
	}
	t.Cleanup(func() { listener.Close() })

	queries := make(chan string, 8)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				query, err := bufio.NewReader(conn).ReadString('\n')
				if err != nil {
					return
				}
				queries <- strings.TrimSpace(query)
				io.WriteString(conn, response)
			}(conn)
		}
	}()

	return listener.Addr().String(), queries
}

func runWhois(t *testing.T, target, server string) *analyzer.WhoisResult {
	t.Helper()

	result, err := (&analyzer.WhoisAnalyzer{}).Run(target, map[string]interface{}{"server": server})
	if err != nil {
		t.Fatalf("Run(%q) returned unexpected error: %v", target, err)
	}

	whois, ok := result.(*analyzer.WhoisResult)
	if !ok {
		t.Fatalf("Run(%q) returned %T, want *analyzer.WhoisResult", target, result)
	}
	return whois
}

func TestWhoisRunReturnsParsedResult(t *testing.T) {
	response := strings.Join([]string{
		"Domain Name: EXAMPLE.COM",
		"Registrar: Example Registrar, Inc.",
		"Name Server: NS1.EXAMPLE.COM",
		"Name Server: NS2.EXAMPLE.COM",
		"Creation Date: 1995-08-14T04:00:00Z",
	}, "\r\n") + "\r\n"

	server, _ := startFakeWhoisServer(t, response)
	whois := runWhois(t, "example.com", server)

	if whois.Domain != "example.com" {
		t.Errorf("Domain = %q, want %q", whois.Domain, "example.com")
	}
	if whois.Server != server {
		t.Errorf("Server = %q, want %q", whois.Server, server)
	}
	if whois.Raw != response {
		t.Errorf("Raw = %q, want %q", whois.Raw, response)
	}
	if got := whois.Fields["Registrar"]; got != "Example Registrar, Inc." {
		t.Errorf("Fields[Registrar] = %q, want %q", got, "Example Registrar, Inc.")
	}
	if got := whois.Fields["Name Server"]; got != "NS1.EXAMPLE.COM, NS2.EXAMPLE.COM" {
		t.Errorf("Fields[Name Server] = %q, want %q", got, "NS1.EXAMPLE.COM, NS2.EXAMPLE.COM")
	}
	if got := whois.Fields["Creation Date"]; got != "1995-08-14T04:00:00Z" {
		t.Errorf("Fields[Creation Date] = %q, want %q", got, "1995-08-14T04:00:00Z")
	}
}

func TestWhoisRunStripsURLToHost(t *testing.T) {
	server, queries := startFakeWhoisServer(t, "Domain Name: WWW.EXAMPLE.COM\r\n")
	runWhois(t, "https://www.example.com/some/path?q=1", server)

	select {
	case query := <-queries:
		if query != "www.example.com" {
			t.Errorf("query sent to whois server = %q, want %q", query, "www.example.com")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for whois query")
	}
}

func TestWhoisRunNormalizesQueryCase(t *testing.T) {
	server, queries := startFakeWhoisServer(t, "Domain Name: EXAMPLE.COM\r\n")
	runWhois(t, "EXAMPLE.COM", server)

	select {
	case query := <-queries:
		if query != "example.com" {
			t.Errorf("query sent to whois server = %q, want %q", query, "example.com")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for whois query")
	}
}

func TestWhoisRunHandlesNoMatch(t *testing.T) {
	response := "% No match for \"DOES-NOT-EXIST.EXAMPLE\".\r\n"
	server, _ := startFakeWhoisServer(t, response)
	whois := runWhois(t, "does-not-exist.example", server)

	if len(whois.Fields) != 0 {
		t.Errorf("Fields = %v, want empty for a no-match response", whois.Fields)
	}
	if !strings.Contains(whois.Raw, "No match") {
		t.Errorf("Raw = %q, want it to contain %q", whois.Raw, "No match")
	}
}

func TestWhoisRunIgnoresNonFieldLines(t *testing.T) {
	response := strings.Join([]string{
		"% comment line",
		"",
		"https://example.com/whois",
		"Registrar: Example",
	}, "\r\n") + "\r\n"

	server, _ := startFakeWhoisServer(t, response)
	whois := runWhois(t, "example.com", server)

	if _, exists := whois.Fields["https"]; exists {
		t.Errorf("Fields = %v, want URL lines to be ignored", whois.Fields)
	}
	if _, exists := whois.Fields["% comment line"]; exists {
		t.Errorf("Fields = %v, want comment lines to be ignored", whois.Fields)
	}
	if got := whois.Fields["Registrar"]; got != "Example" {
		t.Errorf("Fields[Registrar] = %q, want %q", got, "Example")
	}
}

func TestWhoisRunIgnoresDatabaseMarkerLines(t *testing.T) {
	response := strings.Join([]string{
		"Domain Name: EXAMPLE.COM",
		">>> Last update of whois database: 2026-10-19T16:47:19Z <<<",
		"Registrar: Example",
	}, "\r\n") + "\r\n"

	server, _ := startFakeWhoisServer(t, response)
	whois := runWhois(t, "example.com", server)

	for key, value := range whois.Fields {
		if strings.Contains(key, ">>>") || strings.Contains(value, "<<<") {
			t.Errorf("Fields = %v, want database marker lines to be ignored", whois.Fields)
		}
	}
	if got := whois.Fields["Registrar"]; got != "Example" {
		t.Errorf("Fields[Registrar] = %q, want %q", got, "Example")
	}
}

func TestWhoisRunErrorsWhenServerUnreachable(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to reserve a port: %v", err)
	}
	server := listener.Addr().String()
	listener.Close()

	if _, err := (&analyzer.WhoisAnalyzer{}).Run("example.com", map[string]interface{}{"server": server}); err == nil {
		t.Fatal("Run() returned nil error, want an error for an unreachable whois server")
	}
}
