package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/jvch0512/tls-expiry/check"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, out, errw io.Writer) int {
	fs := flag.NewFlagSet("tls-expiry", flag.ContinueOnError)
	fs.SetOutput(errw)
	warn := fs.Int("warn", 30, "warn when fewer days remain")
	crit := fs.Int("crit", 14, "high severity when fewer days remain")
	timeout := fs.Duration("t", 8*time.Second, "connect timeout")
	asJSON := fs.Bool("json", false, "JSON output")
	failOn := fs.String("fail-on", "medium", "exit 2 at this severity or worse: low|medium|high|critical")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() == 0 {
		fmt.Fprintln(errw, "usage: tls-expiry [flags] host[:port] ...")
		return 2
	}
	threshold := map[string]int{"low": 1, "medium": 2, "high": 3, "critical": 4}[*failOn]
	if threshold == 0 {
		fmt.Fprintln(errw, "invalid -fail-on")
		return 2
	}
	results := make([]check.Result, fs.NArg())
	var wg sync.WaitGroup
	for i, t := range fs.Args() {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i] = check.Endpoint(t, check.Options{Timeout: *timeout, WarnDays: *warn, CriticalDays: *crit})
		}()
	}
	wg.Wait()
	if *asJSON {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		_ = enc.Encode(results)
	} else {
		for _, r := range results {
			if r.Error != "" {
				fmt.Fprintf(out, "%-30s ERROR %s\n", r.Target, r.Error)
				continue
			}
			fmt.Fprintf(out, "%-30s %s  %3d days left  trusted=%v  %s\n", r.Target, r.TLSVersion, r.DaysLeft, r.Trusted, r.Subject)
			for _, f := range r.Findings {
				fmt.Fprintf(out, "    [%s] %s: %s\n", f.Severity, f.Code, f.Message)
			}
		}
	}
	if check.Worst(results) >= threshold {
		return 2
	}
	return 0
}
