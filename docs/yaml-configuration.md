[&larr; Back to README](../README.md)

# YAML Output Configuration

## What Is outputconfig?

The `outputconfig` package loads output configuration from a YAML file
and returns ready-to-use options for `audit.NewLogger`. It decouples
your output destinations from your application code — change where
events go without recompiling.

## Why YAML Configuration?

Hardcoding output destinations in Go means recompiling and redeploying
to change a syslog address or add a new output. YAML configuration
lets operations teams manage audit destinations independently:

- Add a new output destination without code changes
- Change file rotation settings per environment
- Route events differently in staging vs production
- Inject secrets via environment variables

## YAML Schema

```yaml
version: 1

default_formatter:              # optional, applies to all outputs
  type: json                    # "json" or "cef"
  timestamp: rfc3339nano        # "rfc3339nano" or "unix_ms"

outputs:
  audit_file:
    type: file
    enabled: true               # optional, default true
    file:
      path: "${AUDIT_LOG_DIR}/events.log"
      max_size_mb: 100
      max_backups: 10
      max_age_days: 90
      permissions: "0600"
      compress: true

  siem:
    type: syslog
    syslog:
      network: "tcp+tls"
      address: "${SYSLOG_HOST}:6514"
      tls_ca: "/etc/audit/ca.pem"
    formatter:                  # per-output formatter override
      type: cef
      vendor: "MyCompany"
      product: "MyApp"
      version: "1.0"
    route:                      # per-output event filter
      include_categories: [security]
    exclude_labels: [pii]       # strip PII before delivery

  alerts:
    type: webhook
    webhook:
      url: "https://ingest.example.com/audit"
      batch_size: 50
      timeout: 15s
    route:
      min_severity: 7
```

## Environment Variable Substitution

Values support `${VAR}` and `${VAR:-default}` syntax:

```yaml
file:
  path: "${AUDIT_LOG_DIR:-/var/log/audit}/events.log"
syslog:
  address: "${SYSLOG_HOST}:${SYSLOG_PORT:-6514}"
```

Expansion happens after YAML parsing — the raw YAML structure is
validated first, then string values are expanded. This prevents YAML
injection via environment variables.

## Factory Registry

Output types are registered via blank imports. The consumer controls
which output types are available:

```go
import (
    _ "github.com/axonops/go-audit/file"
    _ "github.com/axonops/go-audit/syslog"
    _ "github.com/axonops/go-audit/webhook"
)
```

If an output type's module is not blank-imported, `Load` returns an
error for that output — no output is silently dropped.

## Usage

```go
//go:embed outputs.yaml
var outputsYAML []byte

result, err := outputconfig.Load(outputsYAML, &taxonomy, metrics)
if err != nil {
    log.Fatal(err) // fail hard — partial configs are never returned
}

opts := []audit.Option{audit.WithTaxonomy(taxonomy)}
opts = append(opts, result.Options...)
logger, err := audit.NewLogger(cfg, opts...)
```

## Further Reading

- [Progressive Example: Code Generation](../examples/02-code-generation/) — YAML outputs with go:embed
- [Progressive Example: File Output](../examples/03-file-output/) — file-specific configuration
- [Progressive Example: Multi-Output](../examples/04-multi-output/) — multiple outputs from YAML
- [Outputs](outputs.md) — output types and capabilities
- [API Reference: outputconfig.Load](https://pkg.go.dev/github.com/axonops/go-audit/outputconfig#Load)
