[← Back to examples](../README.md)

> **Previous:** [13 — HMAC Integrity](../13-hmac-integrity/) |
> **Next:** [15 — Buffering](../15-buffering/)
# Example 14: TLS

Demonstrates how to configure per-output TLS in audit. The single
`tls:` block on each TLS-capable output groups the cert material
(CA, cert, key) and the policy flags (TLS version, weak ciphers)
together. Defaults to TLS 1.3 only.

## What You'll Learn

1. Why audit defaults to **TLS 1.3 only** and when to change this
2. How to configure **per-output TLS** inside each output's `tls:` block
3. Why there is **no root-level `tls:` key**
4. What `allow_tls12` and `allow_weak_ciphers` actually do
5. How to configure **mTLS** (mutual TLS) with client certificates

## Prerequisites

None — this example uses stdout output to demonstrate the TLS
configuration without requiring actual TLS connections. This example is
most useful after reading [06 — Syslog Output](../06-syslog-output/) or
[07 — Webhook Output](../07-webhook-output/), which show the outputs
that TLS applies to.

## Files

| File | Purpose |
|------|---------|
| [`main.go`](main.go) | Loads config with TLS policy, demonstrates all 4 policy scenarios programmatically |
| [`outputs.yaml`](outputs.yaml) | YAML config showing per-output `tls:` block with commented production examples |
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
    CipherSuites: secure suites only (13 suites)

  TLS 1.2 allowed, weak ciphers (NOT recommended):
    MinVersion: TLS 1.2
    CipherSuites: Go defaults
    WARNING: audit: weak ciphers permitted; consider restricting to TLS 1.3 only
```

## Key Concepts

### Why TLS 1.3 Only by Default?

audit enforces [TLS 1.3](https://datatracker.ietf.org/doc/html/rfc8446)
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

If an output or provider omits the `tls:` block — or sets it without
`allow_tls12: true` — you get TLS 1.3 only. This is the correct
default for new deployments.

### The Four TLS Policy Configurations

| Configuration | `allow_tls12` | `allow_weak_ciphers` | MinVersion | Cipher filtering | When to use |
|--------------|--------------|---------------------|------------|-----------------|-------------|
| **Default** | `false` | `false` | TLS 1.3 | Go defaults (not configurable for TLS 1.3) | New deployments, modern infrastructure |
| **Explicit TLS 1.3** | `false` | `false` | TLS 1.3 | Same as default | Documenting the policy explicitly |
| **TLS 1.2 fallback** | `true` | `false` | TLS 1.2 | Secure suites from `tls.CipherSuites()` | Legacy syslog/webhook servers that don't support TLS 1.3 |
| **Weak ciphers** | `true` | `true` | TLS 1.2 | Go full defaults (may include weak suites) | **NOT recommended.** Last resort for very old infrastructure |

**Note:** `allow_weak_ciphers` has no effect when `allow_tls12` is
`false`, because TLS 1.3 cipher suites are not configurable in Go.

### Per-Output `tls:` Block

The `tls:` block is configured inside each TLS-capable output —
`syslog:` (when `network: tcp+tls`), `webhook:` (when `https://`),
`loki:` (when `https://`), `splunk:` (when `https://`) — and inside
each secret provider (`vault:`, `openbao:`). Each block stands
alone; there is no shared root-level default. Cert material and
policy flags live together inside one block:

```yaml
outputs:
  # No tls block → defaults to TLS 1.3 only.
  modern_siem:
    type: syslog
    syslog:
      network: "tcp+tls"
      address: "modern-syslog.internal:6514"

  # Per-output tls block for a legacy target.
  legacy_siem:
    type: syslog
    syslog:
      network: "tcp+tls"
      address: "legacy-syslog.internal:6514"
      tls:
        ca: "/etc/audit/tls/ca.pem"
        allow_tls12: true           # allow TLS 1.2 for this output only
        allow_weak_ciphers: false   # still use only secure ciphers
```

### Why No Root-Level `tls:`?

Earlier versions allowed a root-level `tls_policy:` that would
inherit into every output and provider. That was removed because it
created a privilege-escalation surface: a permissive policy set for a
legacy syslog target would silently downgrade the TLS posture of
secret-provider connections carrying bootstrap credentials.

Setting `tls:` (or the legacy `tls_policy:`) at the top level of
`outputs.yaml` now fails at startup with an "unknown top-level key"
error. Configure the `tls:` block inside each affected output or
provider block instead.

### mTLS (Mutual TLS) with Client Certificates

For environments that require client certificate authentication, all
TLS-enabled outputs accept `cert:` and `key:` inside the `tls:`
block:

```yaml
outputs:
  secure_siem:
    type: syslog
    syslog:
      network: "tcp+tls"
      address: "syslog.internal:6514"
      tls:
        ca: "/etc/audit/tls/ca.pem"          # verify server certificate
        cert: "/etc/audit/tls/client.pem"    # present client certificate
        key: "/etc/audit/tls/client-key.pem" # client private key
```

Both `tls.cert` and `tls.key` MUST be set together. The server must
be configured to require and verify client certificates.

### Encrypted Private Keys (`tls.key_password`)

When the client private key is a PKCS#8 v2 `ENCRYPTED PRIVATE KEY`
PEM block, supply the password via `tls.key_password`. The library
decrypts with AES-128/192/256-CBC + PBKDF2-HMAC-SHA1/SHA256/SHA512
(RFC 8018) or scrypt (RFC 7914).

```yaml
outputs:
  secure_siem:
    type: syslog
    syslog:
      network: "tcp+tls"
      address: "syslog.internal:6514"
      tls:
        ca: "/etc/audit/tls/ca.pem"
        cert: "/etc/audit/tls/client.pem"
        key: "/etc/audit/tls/client.encrypted.key"
        # Recommended: pull from a secret provider.
        key_password: ref+openbao://kv/data/audit#tls_key_password
        # Or env substitution:
        # key_password: "${TLS_KEY_PASSWORD}"
        # Or plain (dev only):
        # key_password: "hunter2"
```

**Generate an encrypted PKCS#8 key:**

```
openssl pkcs8 -topk8 -v2 aes256 -in client.unencrypted.key -out client.encrypted.key
```

**Legacy keys refused.** PKCS#1 PEM blocks with the
`Proc-Type: 4,ENCRYPTED` header (the `openssl genrsa -des3`
output) are refused with the sentinel `audit.ErrLegacyEncryptedPEMKey`.
Go's `x509.DecryptPEMBlock` is deprecated since 1.16 — we never
invoke it. Rewrap legacy keys with the openssl command above and
configure `tls.key_password` for the new key.

**Mismatches refused.** An encrypted key with an empty password,
or an unencrypted key with a non-empty password, is rejected
loudly rather than silently downgrading the TLS posture.

**Redaction.** The password is `[REDACTED]` in every
`Config.String()` / `%v` / `%+v` / `%#v` representation and never
appears in error chains.

### Which Outputs Support TLS?

| Output | TLS transport | TLS block | Client certs (mTLS) |
|--------|--------------|-----------|---------------------|
| **Syslog** | `network: "tcp+tls"` | Yes | Yes |
| **Webhook** | `url: "https://..."` | Yes | Yes |
| **Loki** | `url: "https://..."` | Yes | Yes |
| **Splunk** | `url: "https://..."` | Yes | Yes |
| **File** | N/A (local filesystem) | No | No |
| **Stdout** | N/A (process stdout) | No | No |

### What's NOT in the `tls:` Block

`allow_insecure_http` and `allow_private_ranges` stay at each
output's top level — they are HTTP/network policy, not TLS:

```yaml
outputs:
  ingest:
    type: webhook
    webhook:
      url: "http://internal-collector:8080"
      allow_insecure_http: true    # top level — not TLS
      allow_private_ranges: true   # top level — SSRF/egress, not TLS
      tls:
        ca: "/etc/audit/ca.pem"    # still used if you switch to https://
```

`allow_insecure_http` is the *negation* of TLS; nesting it inside
`tls:` would be a category error. `allow_private_ranges` is an
SSRF/egress policy that applies equally to plain HTTP and HTTPS.

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

- [Output Configuration YAML](../../docs/output-configuration.md) — `tls:` block field reference
- [Output Types Overview](../../docs/outputs.md) — all five output types with TLS support notes
- [Loki Output Reference](../../docs/loki-output.md) — loki TLS configuration examples
- [RFC 8446: TLS 1.3](https://datatracker.ietf.org/doc/html/rfc8446) — the TLS 1.3 specification
- [Go `crypto/tls` package](https://pkg.go.dev/crypto/tls) — Go's TLS implementation
