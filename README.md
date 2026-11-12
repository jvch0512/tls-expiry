# tls-expiry

Go CLI that checks the **TLS certificate health of many endpoints at once**: expiry buckets, chain trust, hostname match, protocol version, weak keys and signatures. Standard library only, concurrent, JSON output and a CI-friendly exit code, so it fits a cron job or a pipeline that guards against surprise certificate outages.

> Built with AI assistance (Claude) as a portfolio project. Review the code before relying on it.

## Usage

```bash
go install github.com/jvch0512/tls-expiry@latest
tls-expiry example.org api.example.org:8443
tls-expiry -warn 45 -crit 21 -json $(cat hosts.txt)
tls-expiry -fail-on high example.org          # exit 2 only for high or critical findings
```

```
example.org:443   TLS 1.3   64 days left  trusted=true  CN=example.org
    [medium] EXPIRING: expires in 28 day(s)
```
(illustrative output)

## What it reports

| Code | Severity | Meaning |
|------|----------|---------|
| `EXPIRED` | critical | certificate is past its end date |
| `EXPIRES_SOON` / `EXPIRING` | high / medium | under `-crit` / `-warn` days left |
| `NOT_YET_VALID` | high | start date in the future (often clock skew) |
| `HOSTNAME_MISMATCH` | high | name not covered by the certificate SANs |
| `UNTRUSTED_CHAIN` / `SELF_SIGNED` | high / medium | not chained to a trusted root |
| `OLD_TLS` | high | negotiated TLS 1.0 or 1.1 |
| `WEAK_KEY` | high | RSA below 2048 bits |
| `WEAK_SIGNATURE` | high | SHA-1 or MD5 signature |
| `LONG_LIFETIME` | low | validity above the 398-day browser limit |

## Design notes

* The handshake runs with verification disabled **on purpose**, then the chain is verified explicitly. That way an expired or untrusted certificate is still reported in full instead of dying as a connection error
* The clock and root pool are injectable, so tests are deterministic and need no network: they generate real certificates on the fly (valid, expired, expiring, 1024-bit RSA, wrong hostname, self-signed) and serve them on loopback
* Targets are checked in parallel, output order matches input order

Only scan hosts you own or are authorised to test.

## Development

```bash
go vet ./... && go test -race ./...
```

MIT licensed.
