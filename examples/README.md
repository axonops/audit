[&larr; Back to project README](../README.md)

# go-audit Examples

Progressive examples from "hello world" to a complete CRUD REST API.
Each example introduces one new concept and builds on the previous.

## Examples

| # | Example | What it teaches |
|---|---------|-----------------|
| 1 | [basic](01-basic/) | Taxonomy, Logger, AuditEvent(), Fields, validation — programmatic setup |
| 2 | [code-generation](02-code-generation/) | YAML taxonomy, audit-gen, typed builders, go:embed, outputconfig.Load |
| 3 | [standard-fields](03-standard-fields/) | Reserved standard fields, framework fields, standard_fields YAML defaults |
| 4 | [stdout-output](04-stdout-output/) | Stdout output for development, debugging, and piping to jq |
| 5 | [file-output](05-file-output/) | File output with rotation and permissions in YAML |
| 6 | [syslog-output](06-syslog-output/) | Syslog output with RFC 5424, TCP/UDP/TLS, facility values |
| 7 | [webhook-output](07-webhook-output/) | Webhook output with NDJSON batching, retry, SSRF protection |
| 8 | [loki-output](08-loki-output/) | Loki output with stream labels, batching, gzip, LogQL queries |
| 9 | [multi-output](09-multi-output/) | Fan-out to multiple outputs from one YAML config |
| 10 | [tls-policy](10-tls-policy/) | Global and per-output TLS policy configuration |
| 11 | [event-routing](11-event-routing/) | Category and severity-based routing in YAML |
| 12 | [sensitivity-labels](12-sensitivity-labels/) | Per-output field stripping with PII and financial labels |
| 13 | [hmac-integrity](13-hmac-integrity/) | Per-output HMAC tamper detection — selective vs global |
| 14 | [formatters](14-formatters/) | JSON vs CEF with category severity levels |
| 15 | [middleware](15-middleware/) | Automatic HTTP audit logging with Hints |
| 16 | [crud-api](16-crud-api/) | Complete REST API with Postgres, four outputs, HMAC, Loki, Grafana |
| 17 | [testing](17-testing/) | Testing audit events with audittest.NewLogger |
| 18 | [buffering](18-buffering/) | Two-level buffering, ErrBufferFull, per-output drops, tuning |

The **basic** example uses the programmatic API to show how the library
works. Every example after that uses YAML files for configuration —
that's how you'd use go-audit in a real application.

### Buffering and Performance

Examples 7 (webhook) and 8 (Loki) use outputs with internal buffers
and batching. Examples 5 (file), 6 (syslog), and 4 (stdout) use
synchronous outputs that write directly from the drain goroutine.
Example 9 (multi-output) demonstrates both synchronous and async
outputs in a single configuration — the most direct illustration of
the two-level buffering model. See
[Two-Level Buffering](../docs/async-delivery.md#two-level-buffering)
for the architecture explanation, memory sizing, and tuning guidance.

## Getting Started

From a fresh clone:

```bash
# Set up the Go workspace (required for multi-module resolution):
make workspace

# Build all examples to verify they compile:
make test-examples

# Run an individual example:
cd examples/01-basic && go run .
```

## For Consumers Outside the Workspace

If you copy an example to your own project, you'll need to initialise
a Go module and fetch the dependencies:

```bash
go mod init myapp

# Core library + output config loader:
go get github.com/axonops/audit
go get github.com/axonops/audit/outputconfig

# Output types you use (blank imports register them):
go get github.com/axonops/audit/file
go get github.com/axonops/audit/syslog
go get github.com/axonops/audit/webhook
go get github.com/axonops/audit/loki

# CRUD API also needs:
go get github.com/lib/pq
go get github.com/prometheus/client_golang
```
