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
| 7 | webhook-output *(coming soon)* | Webhook output with NDJSON batching, retry, SSRF protection |
| 8 | [loki-output](08-loki-output/) | Loki output with stream labels, batching, gzip, LogQL queries |
| 9 | [multi-output](09-multi-output/) | Fan-out to multiple outputs from one YAML config |
| 10 | tls-policy *(coming soon)* | Global and per-output TLS policy configuration |
| 11 | [event-routing](11-event-routing/) | Category and severity-based routing in YAML |
| 12 | [sensitivity-labels](12-sensitivity-labels/) | Per-output field stripping with PII and financial labels |
| 13 | [hmac-integrity](13-hmac-integrity/) | Per-output HMAC tamper detection — selective vs global |
| 14 | [formatters](14-formatters/) | JSON vs CEF with category severity levels |
| 15 | [middleware](15-middleware/) | Automatic HTTP audit logging with Hints |
| 16 | [crud-api](16-crud-api/) | Complete REST API with Postgres, five outputs, Docker |
| 17 | [testing](17-testing/) | Testing audit events with audittest.NewLogger |

The **basic** example uses the programmatic API to show how the library
works. Every example after that uses YAML files for configuration —
that's how you'd use go-audit in a real application.

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
go get github.com/axonops/go-audit
go get github.com/axonops/go-audit/outputconfig

# Output types you use (blank imports register them):
go get github.com/axonops/go-audit/file
go get github.com/axonops/go-audit/syslog
go get github.com/axonops/go-audit/webhook
go get github.com/axonops/go-audit/loki

# CRUD API also needs:
go get github.com/lib/pq
go get github.com/prometheus/client_golang
```
