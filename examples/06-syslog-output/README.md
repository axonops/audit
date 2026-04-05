[← Back to examples](../README.md)

> **Previous:** [05 — File Output](../05-file-output/) |
> **Next:** [08 — Loki Output](../08-loki-output/)

# Example 06: Syslog Output

Sends audit events to a syslog server as
[RFC 5424](https://datatracker.ietf.org/doc/html/rfc5424) structured
syslog messages over TCP. The example embeds a local TCP receiver so
it's fully self-contained — no external syslog server or Docker needed.

## What You'll Learn

1. How audit events are formatted as **RFC 5424 syslog messages**
2. How the syslog output handles **transport options** (TCP, UDP,
   TCP+TLS)
3. What the **facility** and **APP-NAME** header fields mean
4. How **automatic reconnection** works when the syslog server is
   temporarily unavailable
5. How to pair syslog with the **CEF formatter** for SIEM integration

## Prerequisites

None — the example embeds its own TCP syslog receiver.

For a real deployment, you'd point the output at your syslog
infrastructure (rsyslog, syslog-ng, Splunk, Graylog, or any
RFC 5424-compatible receiver).

## Files

| File | Purpose |
|------|---------|
| [`main.go`](main.go) | Creates a logger with syslog output, starts a local TCP receiver, emits 4 events |
| [`outputs.yaml`](outputs.yaml) | Syslog output YAML configuration |
| [`taxonomy.yaml`](taxonomy.yaml) | 4 event types across 2 categories (security and write) |
| [`audit_generated.go`](audit_generated.go) | Generated typed builders |

## Running the Example

```bash
go run .
```

**Output** (4 RFC 5424 messages received by the embedded syslog server):

```
--- RFC 5424 messages received by syslog server ---

[Message 1]
<134>1 2026-04-05T12:00:00+02:00 dev-machine audit-example 12345 audit-example - {"timestamp":"...","event_type":"auth_login","severity":5,"app_name":"syslog-example","host":"dev-machine",...,"actor_id":"alice","outcome":"success","event_category":"security"}

[Message 2]
<134>1 2026-04-05T12:00:00+02:00 dev-machine audit-example 12345 audit-example - {"timestamp":"...","event_type":"user_create",...,"actor_id":"bob","outcome":"success","event_category":"write"}

[Message 3]
<134>1 2026-04-05T12:00:00+02:00 dev-machine audit-example 12345 audit-example - {"timestamp":"...","event_type":"auth_failure","severity":8,...,"actor_id":"mallory","outcome":"failure","reason":"invalid_password","event_category":"security"}

[Message 4]
<134>1 2026-04-05T12:00:00+02:00 dev-machine audit-example 12345 audit-example - {"timestamp":"...","event_type":"config_change","severity":7,...,"actor_id":"alice","outcome":"success","setting":"max_retries","old_value":"3","new_value":"5","event_category":"write"}

Total: 4 RFC 5424 messages received
```

## Key Concepts

### Understanding the RFC 5424 Message Format

Each syslog message follows the
[RFC 5424](https://datatracker.ietf.org/doc/html/rfc5424) structure:

```
<PRIORITY>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD MSG
```

Breaking down a real message from this example:

```
<134>1 2026-04-05T12:00:00+02:00 dev-machine audit-example 12345 audit-example - {...JSON...}
 │   │ │                         │            │             │     │              │ └─ MSG: the audit event JSON
 │   │ │                         │            │             │     │              └── SD: no structured data ("-")
 │   │ │                         │            │             │     └───────────────── MSGID: same as APP-NAME
 │   │ │                         │            │             └─────────────────────── PROCID: process ID
 │   │ │                         │            └───────────────────────────────────── APP-NAME: from config
 │   │ │                         └────────────────────────────────────────────────── HOSTNAME: from outputs.yaml
 │   │ └──────────────────────────────────────────────────────────────────────────── TIMESTAMP: RFC 3339
 │   └────────────────────────────────────────────────────────────────────────────── VERSION: always 1
 └────────────────────────────────────────────────────────────────────────────────── PRIORITY: facility × 8 + severity
```

**Priority calculation:** `<134>` = facility `local0` (16) × 8 +
severity `informational` (6) = 134. The syslog severity bits are always
`informational` (6), hardcoded at construction — the audit event's
`severity` field (e.g., 8 for `auth_failure`) does NOT affect the
syslog priority. The event severity is preserved in the JSON payload.

### Transport Options

| Transport | YAML `network:` | Use case | Reliability |
|-----------|-----------------|----------|-------------|
| **TCP** | `"tcp"` | Default. Reliable delivery with connection-oriented transport | Connection-based; reconnects on failure |
| **UDP** | `"udp"` | Fire-and-forget. No connection overhead, but messages may be silently lost or truncated | No delivery guarantee; messages > ~2048 bytes may be truncated ([RFC 5424 §6.1](https://datatracker.ietf.org/doc/html/rfc5424#section-6.1)) |
| **TCP+TLS** | `"tcp+tls"` | Encrypted transport. Required for compliance (PCI DSS, SOC 2) when events cross network boundaries | TLS 1.3 by default; supports mTLS with client certificates |

### Facility Values

The `facility` field identifies the type of program generating the
message. For audit logging, `local0` through `local7` are recommended
(they're reserved for local use):

| Facility | Numeric | Common use |
|----------|---------|------------|
| `local0` | 16 | **Default.** General audit logging |
| `local1`–`local7` | 17–23 | Additional audit streams or application tiers |
| `auth` | 4 | Authentication subsystem |
| `authpriv` | 10 | Private authentication messages |
| `daemon` | 3 | System daemons |

Full list: `kern`, `user`, `mail`, `daemon`, `auth`, `syslog`, `lpr`,
`news`, `uucp`, `cron`, `authpriv`, `ftp`, `local0`–`local7`.

### Automatic Reconnection

If the syslog server becomes unavailable, the output automatically
reconnects with bounded exponential backoff:

- **Base delay:** 100ms
- **Maximum delay:** 30s
- **Backoff factor:** 2× with random jitter ([0.5, 1.0) multiplier)
- **Max attempts:** Configurable via `max_retries` (default: 10)

During reconnection, the mutex is released so `logger.Close()` can
interrupt the backoff sleep. The event that triggered the reconnection
is retried once on the new connection.

### YAML Configuration Explained

```yaml
outputs:
  siem:
    type: syslog               # Register with: import _ "github.com/axonops/go-audit/syslog"
    syslog:
      network: "tcp"           # Transport: "tcp" (default), "udp", or "tcp+tls"
      address: "localhost:1514" # Required: host:port of the syslog server
      app_name: "audit-example" # RFC 5424 APP-NAME (default: "audit")
      facility: "local0"       # Syslog facility (default: "local0")
      max_retries: 3           # Reconnection attempts (default: 10)
```

### CEF Formatter Pairing

Syslog + CEF is the standard pattern for SIEM integration. The CEF
(Common Event Format) formatter produces messages that tools like
ArcSight, Splunk, and QRadar can parse natively:

```yaml
outputs:
  siem:
    type: syslog
    syslog:
      network: "tcp+tls"
      address: "siem.internal:6514"
      facility: "local0"
    formatter:
      type: cef
      vendor: "MyCompany"
      product: "MyApp"
      version: "1.0"
```

See [Example 14: Formatters](../14-formatters/) for JSON vs CEF
comparison.

## Blank Import Required

Unlike stdout (which is built-in), syslog requires a blank import to
register its factory:

```go
import _ "github.com/axonops/go-audit/syslog"
```

This is needed because the syslog output lives in a separate module
(`github.com/axonops/go-audit/syslog`) that depends on the
`github.com/axonops/srslog` library for RFC 5424 formatting. The blank
import triggers the `init()` function that registers the `"syslog"`
output factory.

## Further Reading

- [Syslog Output Reference](../../docs/syslog-output.md) — complete configuration, TLS, reconnection, production patterns
- [RFC 5424: The Syslog Protocol](https://datatracker.ietf.org/doc/html/rfc5424) — the standard this output implements
- [RFC 5425: TLS Transport Mapping for Syslog](https://datatracker.ietf.org/doc/html/rfc5425) — TLS transport standard
- [Output Types Overview](../../docs/outputs.md) — all five output types
- [Example 14: Formatters](../14-formatters/) — JSON vs CEF side-by-side
- [Output Configuration YAML](../../docs/output-configuration.md) — full YAML reference
