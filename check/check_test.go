package check

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

type spec struct {
	names    []string
	notAfter time.Time
	rsaBits  int
	selfSign bool
}

// serve starts a TLS listener with a freshly generated certificate and returns the address plus a pool trusting it.
func serve(t *testing.T, s spec, maxVersion uint16) (string, *x509.CertPool) {
	t.Helper()
	var key any
	var pub any
	if s.rsaBits > 0 {
		k, err := rsa.GenerateKey(rand.Reader, s.rsaBits)
		if err != nil {
			t.Fatal(err)
		}
		key, pub = k, &k.PublicKey
	} else {
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		key, pub = k, &k.PublicKey
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "tls-expiry-test"},
		NotBefore:    time.Now().Add(-48 * time.Hour),
		NotAfter:     s.notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:         true, BasicConstraintsValid: true,
		DNSNames:    s.names,
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	cfg := &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	if maxVersion != 0 {
		cfg.MinVersion, cfg.MaxVersion = tls.VersionTLS10, maxVersion
	}
	l, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { _ = c.(*tls.Conn).Handshake(); c.Close() }()
		}
	}()
	return l.Addr().String(), pool
}

func codes(r Result) string {
	var c []string
	for _, f := range r.Findings {
		c = append(c, f.Code)
	}
	return strings.Join(c, ",")
}

func TestHealthyCertificate(t *testing.T) {
	addr, pool := serve(t, spec{names: []string{"localhost"}, notAfter: time.Now().Add(200 * 24 * time.Hour)}, 0)
	r := Endpoint(addr, Options{Roots: pool})
	if r.Error != "" || !r.Trusted || len(r.Findings) != 0 || r.DaysLeft < 190 {
		t.Fatalf("unexpected %+v", r)
	}
	if r.TLSVersion != "TLS 1.3" {
		t.Fatalf("version %s", r.TLSVersion)
	}
}

func TestExpiryBuckets(t *testing.T) {
	for _, c := range []struct {
		days int
		code string
	}{{-3, "EXPIRED"}, {5, "EXPIRES_SOON"}, {20, "EXPIRING"}} {
		addr, pool := serve(t, spec{notAfter: time.Now().Add(time.Duration(c.days) * 24 * time.Hour)}, 0)
		r := Endpoint(addr, Options{Roots: pool})
		if !strings.Contains(codes(r), c.code) {
			t.Errorf("days=%d want %s got %q (err %s)", c.days, c.code, codes(r), r.Error)
		}
	}
}

func TestUntrustedSelfSignedAndHostnameMismatch(t *testing.T) {
	addr, _ := serve(t, spec{names: []string{"localhost"}, notAfter: time.Now().Add(100 * 24 * time.Hour)}, 0)
	r := Endpoint(addr, Options{Roots: x509.NewCertPool()})
	if r.Trusted || !strings.Contains(codes(r), "SELF_SIGNED") {
		t.Fatalf("want SELF_SIGNED, got %q", codes(r))
	}
	// host given as a name the certificate does not carry
	addr2, pool2 := serve(t, spec{names: []string{"other.example"}, notAfter: time.Now().Add(100 * 24 * time.Hour)}, 0)
	_, port, _ := net.SplitHostPort(addr2)
	r2 := Endpoint("localhost:"+port, Options{Roots: pool2})
	if !strings.Contains(codes(r2), "HOSTNAME_MISMATCH") {
		t.Fatalf("want HOSTNAME_MISMATCH, got %q (err %s)", codes(r2), r2.Error)
	}
}

func TestWeakRSAKey(t *testing.T) {
	addr, pool := serve(t, spec{notAfter: time.Now().Add(100 * 24 * time.Hour), rsaBits: 1024}, 0)
	r := Endpoint(addr, Options{Roots: pool})
	if !strings.Contains(codes(r), "WEAK_KEY") {
		t.Fatalf("got %q (err %s)", codes(r), r.Error)
	}
}

func TestDeterministicClock(t *testing.T) {
	addr, pool := serve(t, spec{notAfter: time.Now().Add(100 * 24 * time.Hour)}, 0)
	r := Endpoint(addr, Options{Roots: pool, Now: time.Now().Add(95 * 24 * time.Hour)})
	if !strings.Contains(codes(r), "EXPIRES_SOON") {
		t.Fatalf("fake clock ignored: %q", codes(r))
	}
}

func TestConnectionErrorsAndTargetParsing(t *testing.T) {
	if r := Endpoint("127.0.0.1:1", Options{Timeout: time.Second}); r.Error == "" {
		t.Fatal("expected a connection error")
	}
	for in, want := range map[string]string{"example.org": "example.org:443", "https://example.org/": "example.org:443", "example.org:8443": "example.org:8443", "[::1]:9443": "::1:9443"} {
		h, p, err := SplitTarget(in)
		if err != nil || h+":"+p != want {
			t.Errorf("%s -> %s:%s %v", in, h, p, err)
		}
	}
	for _, bad := range []string{"", "host:0", "host:99999", "host:abc"} {
		if _, _, err := SplitTarget(bad); err == nil {
			t.Errorf("expected error for %q", bad)
		}
	}
}

func TestWorst(t *testing.T) {
	if Worst(nil) != 0 {
		t.Fatal("empty")
	}
	rs := []Result{{Findings: []Finding{{Severity: "medium"}}}, {Findings: []Finding{{Severity: "critical"}}}}
	if Worst(rs) != 4 || Worst([]Result{{Error: "x"}}) != 3 {
		t.Fatal("ranking wrong")
	}
}
