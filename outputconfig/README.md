# outputconfig — YAML loader for audit outputs

[![Go Reference][godoc-badge]][godoc]

Loads an `outputs.yaml` file at process start, validates it, constructs
every configured output via the registry, and returns a ready-to-use
[`*audit.Auditor`][audit-godoc] (or the underlying [`audit.Option`][option-godoc]
slice) for you to wire into the rest of your application.

> **Module path**: `github.com/axonops/audit/outputconfig`
> **Status**: pre-release (v0.x)
> **Documentation**: [Full reference][output-configuration-doc] · [Code-generation example][example-02]

## Why

You have two ways to configure audit outputs:

1. **In Go.** Call `audit.New(audit.WithOutputs(out1, out2), ...)` and
   wire per-output routes via `audit.WithNamedOutput(out, audit.WithRoute(r))`.
   The compiler checks everything, but every output change is a
   recompile + redeploy.
2. **In YAML.** Write an `outputs.yaml` file describing what goes where,
   read it at startup, hand it to this package. Operators reconfigure
   outputs at deploy time — change the SIEM endpoint, add a per-output
   route, rotate an HMAC salt — **without recompiling Go.**

`outputconfig` is option 2. It is the configuration loader; it is not
itself an output. It does not register output types either — those come
from blank-importing the output modules (see below). It just turns YAML
into [`audit.Option`][option-godoc] values.

This separation matters because audit logging is a compliance function:
the destinations, routing, and integrity settings frequently need to
change without a code change going through review.

### What `outputconfig` does NOT do

- It does **not** register output types. The YAML key `type: file`
  resolves to a constructor that the `file` module's `init()` put
  into the registry. If you do not blank-import `github.com/axonops/audit/file`
  (or the umbrella `github.com/axonops/audit/outputs` package),
  `Load()` fails with "unknown output type: file" — no output is ever
  silently dropped.
- It does **not** define a taxonomy. You still write your taxonomy
  separately (typically `taxonomy.yaml`, embedded via `go:embed`),
  parse it with `audit.ParseTaxonomyYAML`, and pass it in.
- It does **not** own the auditor lifecycle. `defer auditor.Close()`
  is still your responsibility.

## Install

```bash
go get github.com/axonops/audit/outputconfig
```

## Quick start

The 80% case is one call: `outputconfig.New`. Parse the taxonomy, load
the outputs YAML, create the auditor.

```go
package main

import (
    "context"
    _ "embed"
    "log"

    "github.com/axonops/audit"
    "github.com/axonops/audit/outputconfig"
    _ "github.com/axonops/audit/outputs" // registers stdout, file, syslog, webhook, loki, splunk
)

//go:embed taxonomy.yaml
var taxonomyYAML []byte

func main() {
    // outputconfig.New(ctx, taxonomyYAML []byte, outputsConfigPath string, opts ...audit.Option)
    auditor, err := outputconfig.New(context.Background(), taxonomyYAML, "outputs.yaml")
    if err != nil {
        log.Fatalf("audit setup: %v", err)
    }
    defer func() { _ = auditor.Close() }()

    _ = auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{
        "actor_id": "alice",
        "outcome":  "success",
    }))
}
```

The blank import `_ "github.com/axonops/audit/outputs"` is the line
that registers `file`, `syslog`, `webhook`, `loki`, `splunk`, and
`stdout` output types with the registry. Without it, only output
types whose modules you imported directly are recognised.

A minimal `outputs.yaml` to go with the above:

```yaml
version: 1
app_name: my-service
host: ${HOSTNAME:-localhost}

outputs:
  console:
    type: stdout
  audit_log:
    type: file
    file:
      path: /var/log/my-service/audit.log
      max_size_mb: 100
```

## The registry pattern

Output types live in their own Go modules so that adopters only pull
in what they use. Each output module registers itself in `init()`:

```go
// inside github.com/axonops/audit/file/init.go (illustrative)
func init() {
    audit.MustRegisterOutputFactory("file", fileFactory)
}
```

`outputconfig.Load` walks your YAML, looks up the factory for each
`type:` string, and calls it. If the factory isn't there, you get a
hard error at startup.

The canonical pattern is:

```go
import (
    "github.com/axonops/audit/outputconfig"
    _ "github.com/axonops/audit/outputs" // pulls in ALL built-in outputs
)
```

For smaller binaries, blank-import only what you use:

```go
import (
    "github.com/axonops/audit/outputconfig"
    _ "github.com/axonops/audit/file"    // type: file
    _ "github.com/axonops/audit/webhook" // type: webhook
)
```

Custom output types you wrote yourself? Either give them an `init()`
that calls `audit.MustRegisterOutputFactory`, or pass
`outputconfig.WithFactory(name, factory)` to `NewWithLoad`.

## Inspecting before constructing

When you want to inspect the parsed outputs before wiring them into
an auditor — for example, to log "starting with N outputs" or to add
extra `audit.Option` values conditionally — call `Load` directly
instead of the `New` facade:

```go
loaded, err := outputconfig.Load(ctx, yamlBytes, taxonomy)
if err != nil {
    return fmt.Errorf("audit config: %w", err)
}

for _, info := range loaded.OutputMetadata() {
    log.Printf("output %s (type=%s)", info.Name, info.Type)
}

opts := append([]audit.Option{audit.WithTaxonomy(taxonomy)}, loaded.Options()...)
opts = append(opts, audit.WithMetrics(myPromMetrics))

auditor, err := audit.New(opts...)
if err != nil {
    _ = loaded.Close() // hand back the outputs Load constructed
    return err
}
```

`Loaded.Options()` is the slice the facade hands to `audit.New`. It
already contains `WithAppName`, `WithHost`, queue size, validation
mode, and one `WithNamedOutput` per configured output. You add
`WithTaxonomy` (because you typically already have it for other
reasons) plus anything else your application needs.

## LoadOption

`Load` and `NewWithLoad` accept `LoadOption` values for advanced
plumbing:

| Option | Purpose |
|---|---|
| `WithSecretProvider(p)` | Register a secrets backend for `ref+vault://…` URIs in the YAML |
| `WithSecretTimeout(d)` | Override the secret-resolution timeout (default 10s) |
| `WithCoreMetrics(m)` | Use a single shared `audit.Metrics` for the auditor (Prometheus, etc.) |
| `WithOutputMetrics(f)` | Per-output metrics factory — gets a fresh `Metrics` for each output, tagged with its name |
| `WithFactory(name, f)` | Register a custom output type without an `init()` blank import |
| `WithDiagnosticLogger(l)` | Send loader lifecycle messages to your `*slog.Logger` |

## YAML schema (overview)

The full reference, with every field, type, default, and validation
rule, lives in [docs/output-configuration.md][output-configuration-doc].
The top-level shape is:

```yaml
version: 1                         # required, must be 1
app_name: my-service               # required, non-empty, max 255 bytes
host: ${HOSTNAME:-localhost}       # required, env vars allowed
timezone: UTC                      # optional, overrides auto-detected zone

auditor:                           # optional core auditor settings
  enabled: true                    # default: true
  queue_size: 10000                # default: 10_000, max 1_000_000
  shutdown_timeout: 5s             # default: 5s, max 60s
  validation_mode: strict          # strict (default) | warn | permissive
  omit_empty: false                # default: false

standard_fields:                   # optional defaults for reserved fields
  env: production
  region: eu-west-1

secrets:                           # optional secret-provider declarations
  providers:
    vault:
      type: vault
      address: https://vault.internal:8200
  timeout: 10s

outputs:                           # required, at least one enabled
  audit_log:                       # output name (1..64 bytes, [a-z0-9_-])
    type: file                     # registered output type
    enabled: true                  # optional, default true
    file:                          # output-specific config block
      path: /var/log/audit.log
      max_size_mb: 100
    formatter:                     # optional per-output formatter override
      type: cef
      vendor: MyCompany
      product: MyApp
    route:                         # optional per-output event filter
      include_categories:
        security: {}
    exclude_labels: [pii]          # optional sensitivity label strip
    hmac:                          # optional per-output HMAC integrity
      enabled: true
      salt:
        version: v1
        value: ${HMAC_SALT}
      algorithm: HMAC-SHA-256
```

TLS, where applicable, is configured **per-output** (under each
output's nested block — e.g. `syslog.tls`, `webhook.tls`,
`loki.tls`, `splunk.tls`) and **per-secret-provider** (under
`secrets.providers.<name>.tls`). Schema is consistent across all of
them:

```yaml
tls:
  ca: /etc/ssl/ca.pem
  cert: /etc/ssl/client.pem
  key: /etc/ssl/client.key
  key_password: ${TLS_KEY_PW}
  allow_tls12: false
```

There is no top-level `tls:` key. See the per-output documentation
for which fields are accepted under each output type.

## Environment variables and secrets

String values support `${VAR}` and `${VAR:-default}` substitution.
Expansion happens **after** YAML parsing so an env var value cannot
inject YAML structure.

For secrets that must not live in env vars or the YAML at all
(database passwords, HMAC salts, API tokens), use the `ref+` URI form
resolved by a registered secrets provider — see
[docs/secrets.md][secrets-doc] for the supported schemes
(`ref+vault://`, `ref+openbao://`, …) and provider configuration.

## Configuration reference

The full field-level reference — every config key, its type, default,
valid range, and boundary behaviour — is in
**[docs/output-configuration.md][output-configuration-doc]**. This
README does not duplicate the field tables.

Per-output reference docs:

- [docs/stdout-output.md][stdout-doc]
- [docs/file-output.md][file-doc]
- [docs/syslog-output.md][syslog-doc]
- [docs/webhook-output.md][webhook-doc]
- [docs/loki-output.md][loki-doc]
- [docs/splunk-output.md][splunk-doc]

## See also

- **[Full output-configuration reference][output-configuration-doc]** — the field-level spec
- **[examples/02-code-generation][example-02]** — the canonical
  `outputconfig.New` + `go:embed` taxonomy + generated builders pattern
- **[examples/10-multi-output][example-10]** — fan-out to multiple
  outputs from a single YAML
- **[examples/11-event-routing][example-11]** — per-output `route:`
  filters in YAML
- **[examples/15-buffering][example-15]** — queue size, drain timeout,
  drop behaviour
- **[github.com/axonops/audit/outputs][outputs-godoc]** — the umbrella
  blank-import package
- **[github.com/axonops/audit/secrets][secrets-godoc]** — secret
  provider plumbing for `ref+` URIs

[godoc]: https://pkg.go.dev/github.com/axonops/audit/outputconfig
[godoc-badge]: https://pkg.go.dev/badge/github.com/axonops/audit/outputconfig.svg
[audit-godoc]: https://pkg.go.dev/github.com/axonops/audit#Auditor
[option-godoc]: https://pkg.go.dev/github.com/axonops/audit#Option
[outputs-godoc]: https://pkg.go.dev/github.com/axonops/audit/outputs
[secrets-godoc]: https://pkg.go.dev/github.com/axonops/audit/secrets
[output-configuration-doc]: https://github.com/axonops/audit/blob/main/docs/output-configuration.md
[stdout-doc]: https://github.com/axonops/audit/blob/main/docs/stdout-output.md
[file-doc]: https://github.com/axonops/audit/blob/main/docs/file-output.md
[syslog-doc]: https://github.com/axonops/audit/blob/main/docs/syslog-output.md
[webhook-doc]: https://github.com/axonops/audit/blob/main/docs/webhook-output.md
[loki-doc]: https://github.com/axonops/audit/blob/main/docs/loki-output.md
[splunk-doc]: https://github.com/axonops/audit/blob/main/docs/splunk-output.md
[secrets-doc]: https://github.com/axonops/audit/blob/main/docs/secrets.md
[example-02]: https://github.com/axonops/audit/tree/main/examples/02-code-generation
[example-10]: https://github.com/axonops/audit/tree/main/examples/10-multi-output
[example-11]: https://github.com/axonops/audit/tree/main/examples/11-event-routing
[example-15]: https://github.com/axonops/audit/tree/main/examples/15-buffering
