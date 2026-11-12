package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCLIAgainstLocalTLSServer(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "https://")

	var out, errb bytes.Buffer
	// the test server's certificate is untrusted by system roots: medium severity, so default threshold fails
	if code := run([]string{addr}, &out, &errb); code != 2 {
		t.Fatalf("want exit 2, got %d\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), addr) {
		t.Fatalf("target missing from output: %s", out.String())
	}
	if code := run([]string{"-fail-on", "critical", addr}, &out, &errb); code != 0 {
		t.Fatalf("critical threshold should pass, got %d", code)
	}
	out.Reset()
	if code := run([]string{"-json", "-fail-on", "critical", addr}, &out, &errb); code != 0 {
		t.Fatalf("json run exit %d", code)
	}
	var rs []map[string]any
	if err := json.Unmarshal(out.Bytes(), &rs); err != nil || len(rs) != 1 || rs[0]["tls_version"] == "" {
		t.Fatalf("bad JSON %v: %s", err, out.String())
	}
}

func TestCLIUsageAndErrors(t *testing.T) {
	var out, errb bytes.Buffer
	if run(nil, &out, &errb) != 2 || run([]string{"-fail-on", "nope", "x"}, &out, &errb) != 2 || run([]string{"-bogus"}, &out, &errb) != 2 {
		t.Fatal("usage errors must exit 2")
	}
	out.Reset()
	if code := run([]string{"-t", "1s", "127.0.0.1:1"}, &out, &errb); code != 2 || !strings.Contains(out.String(), "ERROR") {
		t.Fatalf("unreachable host should fail: %d %s", code, out.String())
	}
}
