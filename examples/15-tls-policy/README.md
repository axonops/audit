[← Back to examples](../README.md)

> **Previous:** [14 — Loki Output](../14-loki-output/) |
> **Next:** [16 — Buffering](../16-buffering/)

# Example 15: TLS Policy

Demonstrates how to configure global and per-output TLS policy in
go-audit. TLS policy controls the minimum TLS version and allowed
cipher suites for all TLS-enabled outputs (syslog TCP+TLS, webhook
HTTPS, loki HTTPS).

## What You'll Learn

1. Why go-audit defaults to **TLS 1.3 only** and when to change this
2. How to set a **global TLS policy** that applies to all outputs
3. How to **override per-output** for legacy infrastructure
4. What `allow_tls12` and `allow_weak_ciphers` actually do
5. How to configure **mTLS** (mutual TLS) with client certificates

## Prerequisites

None — this example uses stdout output to demonstrate the TLS policy
configuration without requiring actual TLS connections. This example is
most useful after reading [06 — Syslog Output](../06-syslog-output/) or
[07 — Webhook Output](../07-webhook-output/), which show the outputs
that TLS policy applies to.

## Files

| File | Purpose |
|------|---------|
| [`main.go`](main.go) | Loads config with TLS policy, demonstrates all 4 policy scenarios programmatically |
| [`outputs.yaml`](outputs.yaml) | YAML config showing global tls_policy with commented production examples |
| [`taxonomy.yaml`](taxonomy.yaml) | Simple 2-event taxonomy |
| [`audit_generated.go`](audit_generated.go) | Generated typed builders |

## Running the Example

```bash
go run .
```

**Output** (2 JSON events on stdout + TLS policy demonstration on
stderr):

```
--- TLS Policy Demonstration ---

  Default (nil policy):
    MinVersion: TLS 1.3
    CipherSuites: Go defaults

  TLS 1.3 only (explicit):
    MinVersion: TLS 1.3
    CipherSuites: Go defaults

  TLS 1.2 allowed, secure ciphers:
    MinVersion: TLS 1.2
    CipherSuites: secure suites only

  TLS 1.2 allowed, weak ciphers (NOT recommended):
    MinVersion: TLS 1.2
    CipherSuites: Go defaults
    WARNING: audit: weak ciphers permitted; consider restricting to TLS 1.3 only
```

## Key Concepts

### Why TLS 1.3 Only by Default?

go-audit enforces [TLS 1.3](https://datatracker.ietf.org/doc/html/rfc8446)
by default for all TLS-enabled outputs. This is the most secure
configuration:

- **No known vulnerabilities** — TLS 1.3 removes support for weak
  algorithms and patterns that led to BEAST, POODLE, and DROWN attacks
  in TLS 1.0/1.1
- **Simplified handshake** — fewer round trips, reduced attack surface
- **Mandatory forward secrecy** — all TLS 1.3 cipher suites provide
  forward secrecy by design
- **Cipher suite selection is not configurable** in Go for TLS 1.3 —
  this prevents misconfiguration

If you don't set any `tls_policy`, or set it to the zero value, you
get TLS 1.3 only. This is the correct default for new deployments.

### The Four TLS Policy Configurations

| Configuration | `allow_tls12` | `allow_weak_ciphers` | MinVersion | Cipher filtering | When to use |
|--------------|--------------|---------------------|------------|-----------------|-------------|
| **Default** | `false` | `false` | TLS 1.3 | Go defaults (not configurable for TLS 1.3) | New deployments, modern infrastructure |
| **Explicit TLS 1.3** | `false` | `false` | TLS 1.3 | Same as default | Documenting the policy explicitly |
| **TLS 1.2 fallback** | `true` | `false` | TLS 1.2 | Secure suites from `tls.CipherSuites()` | Legacy syslog/webhook servers that don't support TLS 1.3 |
| **Weak ciphers** | `true` | `true` | TLS 1.2 | Go full defaults (may include weak suites) | **NOT recommended.** Last resort for very old infrastructure |

**Note:** `allow_weak_ciphers` has no effect when `allow_tls12` is
`false`, because TLS 1.3 cipher suites are not configurable in Go.

### Global vs Per-Output Policy

```yaml
# Global policy — applies to ALL TLS-enabled outputs by default
tls_policy:
  allow_tls12: false
  allow_weak_ciphers: false

outputs:
  # This output inherits the global policy (TLS 1.3 only)
  modern_siem:
    type: syslog
    syslog:
      network: "tcp+tls"
      address: "modern-syslog.internal:6514"

  # This output OVERRIDES the global policy
  legacy_siem:
    type: syslog
    syslog:
      network: "tcp+tls"
      address: "legacy-syslog.internal:6514"
      tls_policy:
        allow_tls12: true           # allow TLS 1.2 for this output only
        allow_weak_ciphers: false   # still use only secure ciphers
```

The per-output `tls_policy` block completely replaces the global
policy for that output — it does not merge fields. If you set
`tls_policy.allow_tls12: true` on an output, you must also set
`allow_weak_ciphers` (or it defaults to `false`).

### mTLS (Mutual TLS) with Client Certificates

For environments that require client certificate authentication, all
TLS-enabled outputs support `tls_cert` and `tls_key`:

```yaml
outputs:
  secure_siem:
    type: syslog
    syslog:
      network: "tcp+tls"
      address: "syslog.internal:6514"
      tls_ca: "/etc/audit/tls/ca.pem"          # verify server certificate
      tls_cert: "/etc/audit/tls/client.pem"     # present client certificate
      tls_key: "/etc/audit/tls/client-key.pem"  # client private key
```

Both `tls_cert` and `tls_key` MUST be set together. The server must be
configured to require and verify client certificates.

### Which Outputs Support TLS?

| Output | TLS transport | TLS policy | Client certs (mTLS) |
|--------|--------------|------------|---------------------|
| **Syslog** | `network: "tcp+tls"` | Yes | Yes |
| **Webhook** | `url: "https://..."` | Yes | Yes |
| **Loki** | `url: "https://..."` | Yes | Yes |
| **File** | N/A (local filesystem) | No | No |
| **Stdout** | N/A (process stdout) | No | No |

### Security Implications

> **Warning:** `allow_tls12: true` widens the attack surface. TLS 1.2
> supports older cipher suites and lacks the mandatory forward secrecy
> of TLS 1.3. Only enable this when the remote endpoint genuinely does
> not support TLS 1.3.

> **Warning:** `allow_weak_ciphers: true` MUST NOT be used in
> production. It disables cipher suite filtering, potentially allowing
> suites with known weaknesses. This exists only as a last resort for
> extremely old infrastructure.

TLS certificates are loaded **once** at output construction time.
Certificate rotation requires restarting the application. There is
no automatic hot-reload of certificate files.

## Further Reading

- [Output Configuration YAML](../../docs/output-configuration.md) — TLS policy field reference
- [Output Types Overview](../../docs/outputs.md) — all five output types with TLS support notes
- [Loki Output Reference](../../docs/loki-output.md) — loki TLS configuration examples
- [RFC 8446: TLS 1.3](https://datatracker.ietf.org/doc/html/rfc8446) — the TLS 1.3 specification
- [Go `crypto/tls` package](https://pkg.go.dev/crypto/tls) — Go's TLS implementation
