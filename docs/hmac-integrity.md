[&larr; Back to README](../README.md)

# 🔐 HMAC Integrity Verification

- [What Is HMAC?](#what-is-hmac)
- [Why Use It?](#why-use-it)
- [What HMAC Does NOT Protect Against](#what-hmac-does-not-protect-against)
- [Performance Impact](#performance-impact)
- [Configuration](#configuration)
- [Supported Algorithms](#supported-algorithms)
- [Salt Management](#salt-management)
- [Verification](#verification)
- [Alternative Approaches](#alternative-approaches)

## What Is HMAC?

HMAC (Hash-based Message Authentication Code) is a cryptographic
function that produces a fixed-size hash from a message and a secret
key (salt). When appended to an audit event, it allows anyone with the
salt to verify the event has not been modified since it was written.

audit computes the HMAC over the **complete serialised payload** —
including all fields, sensitivity label filtering, and the
`event_category` — and appends it as the last field in the output.

## Why Use It?

Audit logs must be trustworthy. In regulated industries, you need to
prove records have not been modified after writing. Per-event HMAC
provides **tamper detection** — if the HMAC doesn't match the payload,
the event has been altered.

**Compliance frameworks:** PCI-DSS (Req 10.5.5), SOC 2 (CC7.2),
SOX (Sections 302/404), HIPAA (§164.312(c)(1)), FedRAMP/NIST 800-53
(AU-9/AU-10), GDPR (Art 5(1)(f)), ISO 27001 (A.12.4.2).

## What HMAC Does NOT Protect Against

- **Event deletion** — missing events are not detected by HMAC
- **Replay attacks** — old events can be re-submitted
- **Salt compromise** — if an attacker has the salt, they can forge HMACs
- **Key management** — the library does not manage salts; that is the consumer's responsibility

## ⚠️ Performance Impact

> **HMAC computation has a CPU cost.** Every event delivered to an
> HMAC-enabled output pays for a cryptographic hash computation.

**Use selectively:**
- Don't enable HMAC on every output if you don't need it
- Use [event routing](event-routing.md) to send only security-critical
  events to HMAC-enabled outputs
- Verbose read events can go to non-HMAC outputs with zero crypto cost
- If your SIEM provides its own integrity verification, HMAC may be
  redundant

**Benchmark data (AMD Ryzen 9 7950X):**

| Operation | Time | Allocations |
|-----------|------|-------------|
| HMAC-SHA-256 (~110 byte event) | ~300 ns | 4 allocs |
| HMAC-SHA-512 (~110 byte event) | ~400 ns | 4 allocs |
| No HMAC (baseline) | 0 ns | 0 allocs |

## ⚙️ Configuration

HMAC is configured **per-output** in the output YAML:

```yaml
outputs:
  # HMAC-enabled output — only security events
  secure_log:
    type: file
    hmac:
      enabled: true
      salt:
        version: "2026-Q1"
        value: "${HMAC_SALT}"           # env var — never hardcode salts
      hash: HMAC-SHA-256
    file:
      path: "./secure-audit.log"
    route:
      include_categories: [security]

  # No HMAC — all events, no crypto overhead
  verbose_log:
    type: file
    file:
      path: "./verbose.log"
```

| Field | Required | Description |
|-------|----------|-------------|
| `hmac.enabled` | No | Default: `false`. Must be explicitly `true`. |
| `hmac.salt.version` | Yes (when enabled) | User-defined version identifier for the salt. Included in output for rotation support. |
| `hmac.salt.value` | Yes (when enabled) | The salt value. Min 16 bytes (128 bits). Supports `${VAR}` env vars. |
| `hmac.hash` | Yes (when enabled) | Hash algorithm. See [Supported Algorithms](#supported-algorithms). |

## 📋 Supported Algorithms

Per **NIST SP 800-224**, only approved cryptographic hash functions
are supported. SHA-1 and MD5 are explicitly **not supported**.

### SHA-2 Family

| Config Value | Output Size | Security Strength |
|-------------|-------------|-------------------|
| `HMAC-SHA-256` | 256-bit | 128-bit |
| `HMAC-SHA-384` | 384-bit | 192-bit |
| `HMAC-SHA-512` | 512-bit | 256-bit |

### SHA-3 Family

| Config Value | Output Size |
|-------------|-------------|
| `HMAC-SHA3-256` | 256-bit |
| `HMAC-SHA3-384` | 384-bit |
| `HMAC-SHA3-512` | 512-bit |

**Recommendation:** `HMAC-SHA-256` for most applications — widely
supported, 128-bit security, used by TLS 1.3, JWT (HS256), and most
API authentication schemes.

## 🔑 Salt Management

### Why Salt Is Mandatory

Without a salt, anyone with access to the audit log can recompute the
HMAC for a modified event. The salt provides a shared secret — only
parties who know the salt can compute or verify HMACs.

### Salt Versioning

The `salt.version` field is included in every HMAC'd event. This
supports salt rotation:

1. Configure a new salt with a new version identifier
2. All subsequent events carry the new version
3. Previously signed events remain verifiable — the consumer reads
   the version and looks up the corresponding salt

The library does NOT manage salt storage or version-to-salt mapping.
Use Vault, KMS, or your own key management system.

### Salt Best Practices

- **Never hardcode salts** — use `${VAR}` environment variable substitution
- **Minimum 16 bytes** (128 bits) — enforced by the library
- **Rotate periodically** — use the version field to track rotations
- **Don't reuse** — use different salts for different purposes

## ✅ Verification

The library provides exported functions for HMAC verification:

```go
// Verify an event's HMAC
ok, err := audit.VerifyHMAC(
    payloadBytes,    // serialised event excluding _hmac and _hmac_v
    hmacValue,       // the _hmac field value (lowercase hex)
    salt,            // the salt bytes (looked up by _hmac_v version)
    "HMAC-SHA-256",  // the algorithm
)
```

### Output Format

**JSON:**
```json
{"timestamp":"...","event_type":"auth_failure","severity":8,"app_name":"my-service","host":"prod-01","timezone":"UTC","pid":12345,"outcome":"failure","event_category":"security","_hmac":"a1b2c3d4...","_hmac_v":"2026-Q1"}
```

**CEF:**
```
CEF:0|...|8|... outcome=failure cat=security _hmac=a1b2c3d4... _hmacVersion=2026-Q1
```

The HMAC is always the last field. `_hmac` is lowercase hex-encoded.
`_hmac_v` is the salt version string.

### Interaction with Other Features

- **Sensitivity labels:** HMAC is computed AFTER field stripping. Same
  event on different outputs with different `exclude_labels` produces
  different HMACs.
- **Event category:** HMAC covers the `event_category` field when present.
- **Framework fields:** HMAC covers `app_name`, `host`, `timezone`, and
  `pid` when present. These fields are part of the serialised payload
  before HMAC computation.
- **Format cache:** The base serialised event is cached. HMAC is
  computed per-delivery (after event_category + field stripping).

## 🔄 Alternative Approaches

### Hash Chaining

Hash chaining (each event includes the previous event's hash) provides
stronger tamper evidence — deleting a single event breaks the chain.
However, hash chaining:
- Requires sequential processing (breaks async fan-out)
- Makes recovery after failure complex
- Is not compatible with multi-output architectures

audit uses per-event HMAC as a simpler, stateless alternative.

### Storage-Layer Verification

Some SIEM appliances and audit systems verify integrity at the storage
layer (e.g., WORM storage, append-only databases). Per-event HMAC is
complementary — it proves integrity at the **source** (your
application), while storage verification proves integrity at the
**destination**.

## 📚 Further Reading

- [Progressive Example: HMAC Integrity](../examples/12-hmac-integrity/) — per-output HMAC with selective routing
- [Output Configuration YAML](output-configuration.md) — full HMAC config reference
- [Event Routing](event-routing.md) — selective HMAC via routing
- [Sensitivity Labels](sensitivity-labels.md) — interaction with field stripping
- [API Reference: VerifyHMAC](https://pkg.go.dev/github.com/axonops/audit#VerifyHMAC)
- [RFC 2104: HMAC](https://datatracker.ietf.org/doc/html/rfc2104) — the HMAC specification
- [NIST FIPS 198-1](https://csrc.nist.gov/pubs/fips/198-1/final) — HMAC standard
- [NIST SP 800-224](https://csrc.nist.gov/pubs/sp/800/224/final) — approved hash functions
