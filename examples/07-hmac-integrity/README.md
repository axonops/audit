# HMAC Integrity Example

Per-output tamper detection using HMAC. Security events go to a file
with HMAC enabled; all events go to stdout without HMAC overhead.

## What You'll Learn

- Configuring HMAC on a specific output
- Using event routing so only security events pay the crypto cost
- Understanding `_hmac` and `_hmac_v` fields in the output
- How to verify event integrity

## Prerequisites

- Go 1.26+
- Completed: [Sensitivity Labels](../06-sensitivity-labels/)

## Files

| File | Purpose |
|------|---------|
| `taxonomy.yaml` | Event definitions with security and write categories |
| `outputs.yaml` | Two outputs: HMAC-enabled file (security only) + plain stdout |
| `audit_generated.go` | Generated typed builders and constants |
| `main.go` | Emits security and write events |

## Key Concepts

### What Is HMAC?

HMAC (Hash-based Message Authentication Code) computes a cryptographic
hash over the event payload using a secret salt. If anyone modifies the
event after it was written, the HMAC won't match — proving tampering.

### Why Per-Output?

HMAC has a CPU cost (~400ns per event for SHA-256). You don't want to
pay this for every event on every output. By configuring HMAC only on
the `secure_log` output and routing only security events there, you
get tamper detection where it matters without slowing down verbose
logging.

### YAML Configuration

```yaml
outputs:
  secure_log:
    type: file
    hmac:
      enabled: true
      salt:
        version: "2026-Q1"                        # for salt rotation
        value: "${HMAC_SALT:-default-example-salt!}" # env var recommended
      hash: HMAC-SHA-256
    file:
      path: "./secure-audit.log"
    route:
      include_categories: [security]              # only security events
```

### Salt Is Mandatory

Without a salt, anyone can recompute the HMAC for a modified event.
The salt is the shared secret that makes HMAC meaningful. Never
hardcode it in production — use `${ENV_VAR}` substitution.

### Salt Versioning

The `version` field is included in every HMAC'd event as `_hmac_v`.
When you rotate salts, change the version so verifiers know which
salt to use for each event.

### Output Format

Events in `secure-audit.log` include HMAC fields:

```json
{"timestamp":"...","event_type":"auth_failure","severity":8,"actor_id":"unknown","outcome":"failure","reason":"invalid credentials","source_ip":"192.168.1.100","event_category":"security","_hmac":"a1b2c3d4...","_hmac_v":"2026-Q1"}
```

Events on stdout do NOT include HMAC (no crypto cost):

```json
{"timestamp":"...","event_type":"auth_failure","severity":8,"actor_id":"unknown","outcome":"failure","reason":"invalid credentials","source_ip":"192.168.1.100","event_category":"security"}
```

### Verifying Events

Use the exported `audit.VerifyHMAC` function:

```go
// Extract payload (everything except _hmac and _hmac_v)
// Extract the _hmac value and _hmac_v version
// Look up the salt for that version
ok, err := audit.VerifyHMAC(payload, hmacValue, salt, "HMAC-SHA-256")
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
cat secure-audit.log
```

## Expected Output

**stdout** (all events, no HMAC):

```
--- Security event (HMAC in secure_log, plain on stdout) ---
{"timestamp":"...","event_type":"auth_failure","severity":8,"actor_id":"unknown","outcome":"failure","reason":"invalid credentials","source_ip":"192.168.1.100","event_category":"security"}

--- Write event (stdout only, no HMAC cost) ---
{"timestamp":"...","event_type":"user_create","severity":4,"actor_id":"admin","outcome":"success","target_id":"user-42","event_category":"write"}

--- Check secure-audit.log for HMAC fields (_hmac, _hmac_v) ---
```

**secure-audit.log** (security events only, with HMAC):

```json
{"timestamp":"...","event_type":"auth_failure","severity":8,"actor_id":"unknown","outcome":"failure","reason":"invalid credentials","source_ip":"192.168.1.100","event_category":"security","_hmac":"a1b2c3...","_hmac_v":"2026-Q1"}
```

Only the security event appears in the file. The write event (`user_create`)
is excluded by the route. The `_hmac` field is a hex-encoded HMAC-SHA-256
digest, and `_hmac_v` is the salt version for key lookup during verification.

## Previous

[Sensitivity Labels](../06-sensitivity-labels/) — per-output field
stripping with PII and financial labels.

## Next

[Formatters](../08-formatters/) — JSON vs CEF formatters for SIEM
integration.
