# HMAC Integrity Example

Per-output tamper detection using HMAC. This example shows two HMAC
patterns side by side: **selective** (only security events) and
**global** (all events). A plain stdout output shows the contrast.

## What You'll Learn

- Configuring HMAC on specific outputs
- Selective HMAC via category routing (only security events pay crypto cost)
- Global HMAC without routing (every event gets tamper detection)
- Comparing the same event across outputs with and without HMAC
- Understanding `_hmac` and `_hmac_v` fields in the output
- How to verify event integrity

## Prerequisites

- Go 1.26+
- Completed: [Sensitivity Labels](../06-sensitivity-labels/)

## Files

| File | Purpose |
|------|---------|
| `taxonomy.yaml` | Event definitions with security and write categories |
| `outputs.yaml` | Three outputs: selective HMAC, global HMAC, plain stdout |
| `audit_generated.go` | Generated typed builders and constants |
| `main.go` | Emits security and write events, displays all outputs |

## Key Concepts

### What Is HMAC?

HMAC (Hash-based Message Authentication Code) computes a cryptographic
hash over the event payload using a secret key (salt). If anyone modifies
the event after it was written, the HMAC won't match — proving tampering.

### Selective vs Global HMAC

HMAC has a CPU cost (~300 ns per event for SHA-256). You have two options:

**Selective HMAC** — combine HMAC with routing so only specific events
pay the crypto cost. Use this when tamper detection only matters for
compliance-relevant events (security, financial):

```yaml
secure_log:
  type: file
  hmac:
    enabled: true
    salt:
      version: "2026-Q1"
      value: "${HMAC_SALT:-default-example-salt!}"
    hash: HMAC-SHA-256
  file:
    path: "./secure-audit.log"
  route:
    include_categories: [security]    # only security events
```

**Global HMAC** — enable HMAC without routing, so every event gets
tamper detection. Use this when you need to prove no audit event was
modified, regardless of category:

```yaml
tamperproof_log:
  type: file
  hmac:
    enabled: true
    salt:
      version: "2026-Q1"
      value: "${HMAC_SALT:-default-example-salt!}"
    hash: HMAC-SHA-256
  file:
    path: "./all-audit.log"
  # No route — all events are delivered with HMAC
```

**No HMAC** — outputs without an `hmac:` block have zero crypto
overhead:

```yaml
console:
  type: stdout
  # No hmac block — no crypto cost
```

### How Routing Interacts with HMAC

The same event can appear on multiple outputs with different HMAC
treatment. In this example, an `auth_failure` event lands on all three
outputs:

| Output | Has HMAC? | Why? |
|--------|-----------|------|
| `secure_log` | Yes | Route includes `security` category + HMAC enabled |
| `tamperproof_log` | Yes | No route filter (receives all) + HMAC enabled |
| `console` (stdout) | No | No `hmac:` block configured |

A `user_create` event (category `write`) lands on two outputs:

| Output | Has HMAC? | Why? |
|--------|-----------|------|
| `secure_log` | Skipped | Route excludes `write` category |
| `tamperproof_log` | Yes | No route filter + HMAC enabled |
| `console` (stdout) | No | No `hmac:` block configured |

### Salt Requirements

The salt MUST be at least 16 bytes (128 bits), per NIST SP 800-224.
`ValidateHMACConfig` enforces this — `NewLogger` returns an error if
the salt is too short.

Never hardcode salts in production — use `${ENV_VAR}` substitution.

### Salt Versioning

The `version` field is included in every HMAC'd event as `_hmac_v`.
When you rotate salts, change the version so verifiers know which
salt to use for each event.

### Verifying Events

Use the exported `audit.VerifyHMAC` function:

```go
// payloadBytes is the raw JSON line with _hmac and _hmac_v removed.
// hmacValue is the string value of the _hmac field (lowercase hex).
// salt is []byte loaded from your key store, looked up by _hmac_v.
ok, err := audit.VerifyHMAC(payloadBytes, hmacValue, salt, "HMAC-SHA-256")
if err != nil {
    log.Printf("hmac verify: %v", err)
}
if !ok {
    // payload has been tampered with
}
```

### Supported Algorithms

| Algorithm | Security Strength | Config Value |
|-----------|-------------------|--------------|
| SHA-256 | 128-bit | `HMAC-SHA-256` |
| SHA-384 | 192-bit | `HMAC-SHA-384` |
| SHA-512 | 256-bit | `HMAC-SHA-512` |
| SHA3-256 | 128-bit | `HMAC-SHA3-256` |
| SHA3-384 | 192-bit | `HMAC-SHA3-384` |
| SHA3-512 | 256-bit | `HMAC-SHA3-512` |

All NIST SP 800-224 approved. SHA-1 and MD5 are not supported.

## Run It

```bash
go run .
```

## Expected Output

```
INFO audit: logger created buffer_size=10000 drain_timeout=5s validation_mode=strict outputs=3
--- Security event ---

--- Write event ---

--- Compare the three outputs below ---
INFO audit: shutdown started
{"timestamp":"...","event_type":"auth_failure","severity":8,...,"event_category":"security"}
{"timestamp":"...","event_type":"user_create","severity":4,...,"event_category":"write"}
INFO audit: shutdown complete duration=...

--- secure-audit.log ---
{"timestamp":"...","event_type":"auth_failure",...,"_hmac":"<hex-64-chars>","_hmac_v":"2026-Q1"}

--- all-audit.log ---
{"timestamp":"...","event_type":"auth_failure",...,"_hmac":"<same-hex>","_hmac_v":"2026-Q1"}
{"timestamp":"...","event_type":"user_create",...,"_hmac":"<different-hex>","_hmac_v":"2026-Q1"}
```

Notice the three contrasts:

- **stdout** — both events, no `_hmac` fields (zero crypto cost)
- **secure-audit.log** — only `auth_failure` (security category), with HMAC
- **all-audit.log** — both events, both with HMAC (global tamper detection)

The `auth_failure` event has the same HMAC value in both files because
the same salt and payload produce the same hash. The `user_create` event
only appears in `all-audit.log` because `secure_log` routes by category.

## Further Reading

- [HMAC Integrity](../../docs/hmac-integrity.md) — full guide: algorithms, salt management, verification, performance
- [Event Routing](../../docs/event-routing.md) — how routing controls which events reach HMAC-enabled outputs
- [Sensitivity Labels](../../docs/sensitivity-labels.md) — field stripping that changes the HMAC payload
- [Output Configuration YAML](../../docs/output-configuration.md) — hmac: block syntax

## Previous

[Sensitivity Labels](../06-sensitivity-labels/) — per-output field
stripping with PII and financial labels.

## Next

[Formatters](../08-formatters/) — JSON vs CEF formatters for SIEM
integration.
