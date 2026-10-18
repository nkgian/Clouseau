package tests

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"net"
	"testing"
	"time"

	"clouseau/internal/analyzer"
)

func runIPLookup(t *testing.T, target string, params map[string]interface{}) *analyzer.IPResult {
	t.Helper()

	result, err := (&analyzer.IpLookup{}).Run(target, params)
	if err != nil {
		t.Fatalf("Run(%q) returned unexpected error: %v", target, err)
	}

	lookup, ok := result.(*analyzer.IPResult)
	if !ok {
		t.Fatalf("Run(%q) returned %T, want *analyzer.IPResult", target, result)
	}
	return lookup
}

func findAddress(result *analyzer.IPResult, ip string) *analyzer.IPAddress {
	for i := range result.Addresses {
		if result.Addresses[i].IP == ip {
			return &result.Addresses[i]
		}
	}
	return nil
}

func startTCPListener(t *testing.T) int {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start local tcp listener: %v", err)
	}
	t.Cleanup(func() { listener.Close() })

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	return listener.Addr().(*net.TCPAddr).Port
}

func closedLocalPort(t *testing.T) int {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to reserve a local port: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	return port
}

func startTLSListener(t *testing.T) int {
	t.Helper()

	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{selfSignedCertificate(t)}})
	if err != nil {
		t.Fatalf("failed to start local tls listener: %v", err)
	}
	t.Cleanup(func() { listener.Close() })

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				if tlsConn, ok := conn.(*tls.Conn); ok {
					tlsConn.Handshake()
				}
			}(conn)
		}
	}()

	return listener.Addr().(*net.TCPAddr).Port
}

func selfSignedCertificate(t *testing.T) tls.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate certificate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(48 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost"},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create self-signed certificate: %v", err)
	}

	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func TestIPLookupRunResolvesLocalhost(t *testing.T) {
	result := runIPLookup(t, "localhost", map[string]interface{}{})

	if result.Host != "localhost" {
		t.Errorf("Host = %q, want %q", result.Host, "localhost")
	}

	loopback := findAddress(result, "127.0.0.1")
	if loopback == nil {
		t.Fatalf("Addresses = %v, want an entry for 127.0.0.1", result.Addresses)
	}
	if loopback.Version != 4 {
		t.Errorf("Version = %d, want 4", loopback.Version)
	}
	if loopback.Scope != "loopback" {
		t.Errorf("Scope = %q, want %q", loopback.Scope, "loopback")
	}
	if len(result.Records.A) == 0 {
		t.Error("Records.A is empty, want 127.0.0.1")
	}
}

func TestIPLookupRunScansOpenPorts(t *testing.T) {
	openPort := startTCPListener(t)
	closedPort := closedLocalPort(t)

	result := runIPLookup(t, "127.0.0.1", map[string]interface{}{
		"scan_ports":      true,
		"ports":           []interface{}{openPort, closedPort},
		"port_timeout_ms": 1500,
	})

	address := findAddress(result, "127.0.0.1")
	if address == nil {
		t.Fatalf("Addresses = %v, want an entry for 127.0.0.1", result.Addresses)
	}
	if len(address.OpenPorts) != 1 || address.OpenPorts[0] != openPort {
		t.Errorf("OpenPorts = %v, want [%d]", address.OpenPorts, openPort)
	}
}

func TestIPLookupRunInspectsTLS(t *testing.T) {
	port := startTLSListener(t)

	result := runIPLookup(t, "127.0.0.1", map[string]interface{}{
		"tls":      true,
		"tls_port": port,
	})

	if result.TLS == nil {
		t.Fatalf("TLS is nil, warnings: %v", result.Warnings)
	}
	if !result.TLS.SelfSigned {
		t.Error("SelfSigned = false, want true for a self-signed certificate")
	}
	if result.TLS.Verified {
		t.Error("Verified = true, want false for a self-signed certificate")
	}
	if result.TLS.VerifyError == "" {
		t.Error("VerifyError is empty, want the verification failure reason")
	}
	if result.TLS.Version == "" {
		t.Error("Version is empty, want a TLS version")
	}
	if result.TLS.DaysLeft <= 0 {
		t.Errorf("DaysLeft = %d, want > 0", result.TLS.DaysLeft)
	}
	if result.TLS.CipherSuite == "" {
		t.Error("CipherSuite is empty, want a cipher suite name")
	}
}

func TestIPLookupRunSkipsExternalOptInsForNonPublicAddress(t *testing.T) {
	result := runIPLookup(t, "127.0.0.1", map[string]interface{}{
		"dnsbl":    true,
		"tor":      true,
		"netblock": true,
	})

	address := findAddress(result, "127.0.0.1")
	if address == nil {
		t.Fatalf("Addresses = %v, want an entry for 127.0.0.1", result.Addresses)
	}
	if address.TorExit {
		t.Error("TorExit = true, want false")
	}
	if address.Netblock != nil {
		t.Errorf("Netblock = %+v, want nil for a non-public address", address.Netblock)
	}
	if len(address.DNSBL) != 0 {
		t.Errorf("DNSBL = %v, want none for a non-public address", address.DNSBL)
	}
	if len(result.Warnings) != 0 {
		t.Errorf("Warnings = %v, want none", result.Warnings)
	}
}

func TestIPLookupRunErrorsOnUnresolvableHost(t *testing.T) {
	if _, err := (&analyzer.IpLookup{}).Run("does-not-exist-xyz123.invalid", map[string]interface{}{}); err == nil {
		t.Fatal("Run() returned nil error, want an error for an unresolvable host")
	}
}

func TestIPLookupResultJSONShape(t *testing.T) {
	result := runIPLookup(t, "127.0.0.1", map[string]interface{}{})

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("failed to marshal result: %v", err)
	}

	var payload map[string]json.RawMessage
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("failed to unmarshal result: %v", err)
	}

	for _, key := range []string{"host", "records", "email_security", "addresses"} {
		if _, exists := payload[key]; !exists {
			t.Errorf("JSON is missing key %q", key)
		}
	}

	var addresses []map[string]json.RawMessage
	if err := json.Unmarshal(payload["addresses"], &addresses); err != nil {
		t.Fatalf("failed to unmarshal addresses: %v", err)
	}
	if len(addresses) == 0 {
		t.Fatal("JSON addresses is empty")
	}
	for _, key := range []string{"ip", "version", "scope"} {
		if _, exists := addresses[0][key]; !exists {
			t.Errorf("JSON address is missing key %q", key)
		}
	}
}
