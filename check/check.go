// Package check inspects the TLS endpoint of a host: certificate validity, chain trust, hostname match,
// protocol version and weak cryptography.
package check

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// Finding is one problem discovered on an endpoint.
type Finding struct {
	Severity string `json:"severity"`
	Code     string `json:"code"`
	Message  string `json:"message"`
}

// Result is the full report for one endpoint.
type Result struct {
	Target     string    `json:"target"`
	TLSVersion string    `json:"tls_version,omitempty"`
	Cipher     string    `json:"cipher,omitempty"`
	Subject    string    `json:"subject,omitempty"`
	Issuer     string    `json:"issuer,omitempty"`
	NotBefore  time.Time `json:"not_before,omitzero"`
	NotAfter   time.Time `json:"not_after,omitzero"`
	DaysLeft   int       `json:"days_left"`
	SANs       []string  `json:"sans,omitempty"`
	Trusted    bool      `json:"trusted"`
	Findings   []Finding `json:"findings"`
	Error      string    `json:"error,omitempty"`
}

// Options tune a check. Roots and Now exist mainly so tests are deterministic; zero values mean "system roots, now".
type Options struct {
	Timeout      time.Duration
	WarnDays     int
	CriticalDays int
	Roots        *x509.CertPool
	Now          time.Time
}

// SplitTarget accepts host, host:port, [v6]:port and returns host and port (default 443).
func SplitTarget(t string) (string, string, error) {
	t = strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(t, "https://"), "http://"))
	t = strings.TrimSuffix(t, "/")
	if t == "" {
		return "", "", fmt.Errorf("empty target")
	}
	if h, p, err := net.SplitHostPort(t); err == nil {
		if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
			return "", "", fmt.Errorf("invalid port %q", p)
		}
		return h, p, nil
	}
	return strings.Trim(t, "[]"), "443", nil
}

func versionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	}
	return fmt.Sprintf("0x%04x", v)
}

// Endpoint connects to target and evaluates it.
func Endpoint(target string, o Options) Result {
	if o.Timeout <= 0 {
		o.Timeout = 8 * time.Second
	}
	if o.WarnDays <= 0 {
		o.WarnDays = 30
	}
	if o.CriticalDays <= 0 {
		o.CriticalDays = 14
	}
	if o.Now.IsZero() {
		o.Now = time.Now()
	}
	res := Result{Target: target, Findings: []Finding{}}
	host, port, err := SplitTarget(target)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	d := &net.Dialer{Timeout: o.Timeout}
	// Certificates are collected without verification, then verified explicitly so that an invalid
	// certificate can still be reported in full instead of aborting the handshake.
	cfg := &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10, ServerName: host} //nolint:gosec
	conn, err := tls.DialWithDialer(d, "tcp", net.JoinHostPort(host, port), cfg)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	defer conn.Close()
	st := conn.ConnectionState()
	res.TLSVersion = versionName(st.Version)
	res.Cipher = tls.CipherSuiteName(st.CipherSuite)
	if len(st.PeerCertificates) == 0 {
		res.Error = "server presented no certificate"
		return res
	}
	leaf := st.PeerCertificates[0]
	res.Subject, res.Issuer = leaf.Subject.String(), leaf.Issuer.String()
	res.NotBefore, res.NotAfter = leaf.NotBefore, leaf.NotAfter
	res.DaysLeft = int(leaf.NotAfter.Sub(o.Now).Hours() / 24)
	res.SANs = append(append([]string{}, leaf.DNSNames...), ipStrings(leaf.IPAddresses)...)

	add := func(sev, code, msg string) { res.Findings = append(res.Findings, Finding{sev, code, msg}) }

	switch {
	case o.Now.After(leaf.NotAfter):
		add("critical", "EXPIRED", fmt.Sprintf("certificate expired %d day(s) ago", -res.DaysLeft))
	case o.Now.Before(leaf.NotBefore):
		add("high", "NOT_YET_VALID", "certificate is not valid yet")
	case res.DaysLeft < o.CriticalDays:
		add("high", "EXPIRES_SOON", fmt.Sprintf("expires in %d day(s)", res.DaysLeft))
	case res.DaysLeft < o.WarnDays:
		add("medium", "EXPIRING", fmt.Sprintf("expires in %d day(s)", res.DaysLeft))
	}

	inter := x509.NewCertPool()
	for _, c := range st.PeerCertificates[1:] {
		inter.AddCert(c)
	}
	_, verr := leaf.Verify(x509.VerifyOptions{DNSName: host, Intermediates: inter, Roots: o.Roots, CurrentTime: o.Now})
	res.Trusted = verr == nil
	if verr != nil && !o.Now.After(leaf.NotAfter) && !o.Now.Before(leaf.NotBefore) {
		switch verr.(type) {
		case x509.HostnameError:
			add("high", "HOSTNAME_MISMATCH", verr.Error())
		case x509.UnknownAuthorityError:
			if leaf.Subject.String() == leaf.Issuer.String() {
				add("medium", "SELF_SIGNED", "self-signed certificate is not trusted by clients")
			} else {
				add("high", "UNTRUSTED_CHAIN", verr.Error())
			}
		default:
			add("high", "VERIFY_FAILED", verr.Error())
		}
	}

	if st.Version < tls.VersionTLS12 {
		add("high", "OLD_TLS", res.TLSVersion+" is deprecated (RFC 8996); require TLS 1.2 or newer")
	}
	if k, ok := leaf.PublicKey.(*rsa.PublicKey); ok && k.N.BitLen() < 2048 {
		add("high", "WEAK_KEY", fmt.Sprintf("RSA key of %d bits", k.N.BitLen()))
	}
	switch leaf.SignatureAlgorithm {
	case x509.SHA1WithRSA, x509.ECDSAWithSHA1, x509.MD5WithRSA:
		add("high", "WEAK_SIGNATURE", "signed with "+leaf.SignatureAlgorithm.String())
	}
	if life := leaf.NotAfter.Sub(leaf.NotBefore); life > 398*24*time.Hour && leaf.NotBefore.After(time.Date(2020, 9, 1, 0, 0, 0, 0, time.UTC)) {
		add("low", "LONG_LIFETIME", fmt.Sprintf("validity of %d days exceeds the 398 day browser limit", int(life.Hours()/24)))
	}
	return res
}

func ipStrings(ips []net.IP) []string {
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	return out
}

// Worst returns the highest severity rank among findings (0 none, 1 low, 2 medium, 3 high, 4 critical).
func Worst(rs []Result) int {
	rank := map[string]int{"low": 1, "medium": 2, "high": 3, "critical": 4}
	w := 0
	for _, r := range rs {
		if r.Error != "" && w < 3 {
			w = 3
		}
		for _, f := range r.Findings {
			if rank[f.Severity] > w {
				w = rank[f.Severity]
			}
		}
	}
	return w
}
