[&larr; Back to README](../README.md)

# Output Configuration YAML Reference

The output configuration is a YAML file that defines where your audit
events are sent: which outputs to use, how to format events, how to
route events per-output, and which sensitive fields to strip.

This is a complete reference for everything that can go in an
`outputs.yaml` file.

## Complete Schema

```yaml
version: 1

# ── Default Formatter (optional) ───────────────────────────
# Applies to all outputs that don't specify their own formatter.
# If omitted, JSON with RFC 3339 nanosecond timestamps is used.

default_formatter:
  type: json                       # "json" or "cef"
  timestamp: rfc3339nano           # "rfc3339nano" (default) or "unix_ms"
  omit_empty: false                # true to skip fields with zero values

# ── Outputs ─────────────────────────────────────────────────
# Map of named outputs. Each output has a type, optional config,
# optional formatter override, optional event route, and optional
# sensitivity label exclusions.

outputs:

  # ── Stdout Output ─────────────────────────────────────────
  console:
    type: stdout
    # No additional config needed. Writes to os.Stdout.

  # ── File Output ───────────────────────────────────────────
  audit_file:
    type: file
    enabled: true                  # optional, default true — set false to disable
    file:
      path: "${AUDIT_LOG_DIR:-/var/log/audit}/events.log"   # env vars supported
      max_size_mb: 100             # rotate at this size (default: 100)
      max_backups: 5               # keep this many rotated files (default: 5)
      max_age_days: 30             # delete files older than this (default: 30)
      permissions: "0600"          # file permissions (default: "0600")
      compress: true               # gzip rotated files (default: true)
    route:
      exclude_categories:
        - read                     # don't write verbose read events to this file
    exclude_labels:
      - pii                        # strip PII fields before writing

  # ── Syslog Output ─────────────────────────────────────────
  siem:
    type: syslog
    syslog:
      network: "tcp+tls"           # "tcp" (default), "udp", or "tcp+tls"
      address: "${SYSLOG_HOST}:6514"
      app_name: "myapp"            # RFC 5424 APP-NAME (default: "audit")
      tls_ca: "/etc/audit/ca.pem"
      tls_cert: "/etc/audit/client-cert.pem"   # for mTLS
      tls_key: "/etc/audit/client-key.pem"     # for mTLS
      max_retries: 10              # reconnection attempts (default: 10)
    formatter:
      type: cef                    # SIEM-native format
      vendor: "MyCompany"
      product: "MyApp"
      version: "1.0"
    route:
      include_categories:
        - security                 # only security events to SIEM

  # ── Webhook Output ────────────────────────────────────────
  alerts:
    type: webhook
    webhook:
      url: "https://ingest.example.com/audit"
      batch_size: 50               # events per batch (default: 100)
      flush_interval: "5s"         # time-based flush (default: "5s")
      timeout: "10s"               # HTTP request timeout (default: "10s")
      max_retries: 3               # retry attempts (default: 3)
      # headers:                   # custom HTTP headers
      #   Authorization: "Bearer ${AUDIT_TOKEN}"
      # allow_insecure_http: true  # MUST NOT be true in production
      # allow_private_ranges: true # disable SSRF protection (dev only)
    route:
      min_severity: 7              # only high-severity events
    exclude_labels:
      - pii
      - financial                  # strip sensitive fields
```

## Top-Level Fields

| Field | Required | Description |
|-------|----------|-------------|
| `version` | Yes | Must be `1`. Schema version for future migration. |
| `default_formatter` | No | Default formatter for all outputs. JSON if omitted. |
| `outputs` | Yes | Map of named outputs. At least one must be defined. |

## Output Block

Every output has these fields:

| Field | Required | Description |
|-------|----------|-------------|
| `type` | Yes | Output type: `"stdout"`, `"file"`, `"syslog"`, or `"webhook"` |
| `enabled` | No | `true` (default) or `false`. Disabled outputs are skipped. |
| `[type_name]` | Depends | Type-specific config block. Key must match `type`. Not needed for `stdout`. |
| `formatter` | No | Per-output formatter override. Uses `default_formatter` if omitted. |
| `route` | No | Per-output event filter. Receives all events if omitted. |
| `exclude_labels` | No | List of sensitivity labels to strip from events before delivery. |

## Formatter Configuration

```yaml
formatter:
  type: json                       # "json" or "cef"

  # JSON-specific fields:
  timestamp: rfc3339nano           # "rfc3339nano" or "unix_ms"
  omit_empty: false                # skip zero-value fields

  # CEF-specific fields:
  vendor: "MyCompany"              # CEF header: vendor name
  product: "MyApp"                 # CEF header: product name
  version: "1.0"                   # CEF header: product version
  omit_empty: false                # skip zero-value extension fields
```

| Field | Applies To | Default | Description |
|-------|-----------|---------|-------------|
| `type` | Both | `"json"` | Format type |
| `timestamp` | JSON only | `"rfc3339nano"` | Timestamp format: `"rfc3339nano"` or `"unix_ms"` |
| `omit_empty` | Both | `false` | Skip fields with zero values |
| `vendor` | CEF only | — | Required for CEF. Organisation name. |
| `product` | CEF only | — | Required for CEF. Application name. |
| `version` | CEF only | — | Required for CEF. Application version. |

## Event Route Configuration

Routes control which events reach an output. Include and exclude
modes are mutually exclusive.

```yaml
route:
  # Include mode — only matching events delivered:
  include_categories: [security]
  include_event_types: [auth_failure]

  # Exclude mode — all events except matching:
  exclude_categories: [read]
  exclude_event_types: [health_check]

  # Severity filtering (can combine with either mode):
  min_severity: 7                  # minimum severity (0-10)
  max_severity: 10                 # maximum severity (0-10)
```

| Field | Description |
|-------|-------------|
| `include_categories` | Only deliver events in these categories |
| `include_event_types` | Only deliver these specific event types |
| `exclude_categories` | Deliver everything except events in these categories |
| `exclude_event_types` | Deliver everything except these specific event types |
| `min_severity` | Minimum severity threshold (0-10 inclusive) |
| `max_severity` | Maximum severity threshold (0-10 inclusive) |

See [Event Routing](event-routing.md) for details and examples.

## Sensitivity Label Exclusion

```yaml
exclude_labels:
  - pii                            # strip all PII-labeled fields
  - financial                      # strip all financial-labeled fields
```

Labels are defined in the taxonomy YAML (see [Taxonomy Reference](taxonomy-validation.md#sensitivity-labels)).
Framework fields (`timestamp`, `event_type`, `severity`, `duration_ms`)
are never stripped.

See [Sensitivity Labels](sensitivity-labels.md) for details.

## File Output Fields

| Field | Default | Description |
|-------|---------|-------------|
| `path` | (required) | File path. Supports `${VAR}` substitution. Parent directory must exist. |
| `max_size_mb` | `100` | Rotate when file reaches this size in MB. |
| `max_backups` | `5` | Number of rotated files to keep. |
| `max_age_days` | `30` | Delete rotated files older than this. |
| `permissions` | `"0600"` | File permissions (octal string, must be quoted). |
| `compress` | `true` | Gzip compress rotated files. |

## Syslog Output Fields

| Field | Default | Description |
|-------|---------|-------------|
| `network` | `"tcp"` | Transport: `"tcp"`, `"udp"`, or `"tcp+tls"`. |
| `address` | (required) | Host:port. Supports `${VAR}` substitution. |
| `app_name` | `"audit"` | RFC 5424 APP-NAME field. |
| `facility` | `"local0"` | Syslog facility. |
| `tls_ca` | — | CA certificate path for TLS verification. |
| `tls_cert` | — | Client certificate path for mTLS. |
| `tls_key` | — | Client key path for mTLS. |
| `max_retries` | `10` | Reconnection attempts before giving up. |

## Webhook Output Fields

| Field | Default | Description |
|-------|---------|-------------|
| `url` | (required) | HTTPS endpoint. Must be `https://` unless `allow_insecure_http` is set. |
| `batch_size` | `100` | Events per batch. |
| `flush_interval` | `"5s"` | Flush after this duration even if batch is not full. |
| `timeout` | `"10s"` | HTTP request timeout. |
| `max_retries` | `3` | Retry attempts with exponential backoff. |
| `headers` | — | Map of custom HTTP headers added to every request. |
| `tls_ca` | — | CA certificate path for TLS verification. |
| `tls_cert` | — | Client certificate path for mTLS. |
| `tls_key` | — | Client key path for mTLS. |
| `allow_insecure_http` | `false` | Allow `http://` URLs. MUST NOT be `true` in production. |
| `allow_private_ranges` | `false` | Allow private/loopback IP ranges. Disables SSRF protection. |

## Environment Variable Substitution

Values support `${VAR}` and `${VAR:-default}` syntax:

```yaml
file:
  path: "${AUDIT_LOG_DIR:-/var/log/audit}/events.log"
syslog:
  address: "${SYSLOG_HOST}:${SYSLOG_PORT:-6514}"
```

Expansion happens after YAML parsing for injection safety — the raw
YAML structure is validated first, then string values are expanded.

## Factory Registry

Output types must be registered before `Load` can create them.
Registration happens via blank imports in your application:

```go
import (
    _ "github.com/axonops/go-audit/file"
    _ "github.com/axonops/go-audit/syslog"
    _ "github.com/axonops/go-audit/webhook"
)
```

If an output type's module is not imported, `Load` returns an error
— no output is silently dropped. The `stdout` type is always
available (built into core).

## Loading Output Configuration

```go
//go:embed outputs.yaml
var outputsYAML []byte

result, err := outputconfig.Load(outputsYAML, &taxonomy, metrics)
if err != nil {
    log.Fatal(err)  // fail hard — partial configs are never returned
}

opts := []audit.Option{audit.WithTaxonomy(taxonomy)}
opts = append(opts, result.Options...)
logger, err := audit.NewLogger(cfg, opts...)
```

## Further Reading

- [Progressive Example: File Output](../examples/03-file-output/) — file-specific configuration
- [Progressive Example: Multi-Output](../examples/04-multi-output/) — multiple outputs in one YAML
- [Progressive Example: CRUD API](../examples/09-crud-api/) — five outputs in a production-like setup
- [Outputs](outputs.md) — output types and fan-out architecture
- [Event Routing](event-routing.md) — per-output event filtering
- [Sensitivity Labels](sensitivity-labels.md) — per-output field stripping
- [API Reference: outputconfig.Load](https://pkg.go.dev/github.com/axonops/go-audit/outputconfig#Load)
