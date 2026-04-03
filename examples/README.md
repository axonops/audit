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
| 4 | [file-output](04-file-output/) | File output with rotation and permissions in YAML |
| 5 | [multi-output](05-multi-output/) | Fan-out to multiple outputs from one YAML config |
| 6 | [event-routing](06-event-routing/) | Category and severity-based routing in YAML |
| 7 | [sensitivity-labels](07-sensitivity-labels/) | Per-output field stripping with PII and financial labels |
| 8 | [hmac-integrity](08-hmac-integrity/) | Per-output HMAC tamper detection — selective vs global |
| 9 | [formatters](09-formatters/) | JSON vs CEF with category severity levels |
| 10 | [middleware](10-middleware/) | Automatic HTTP audit logging with Hints |
| 11 | [crud-api](11-crud-api/) | Complete REST API with Postgres, five outputs, Docker |
| 12 | [testing](12-testing/) | Testing audit events with audittest.NewLogger |

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

# CRUD API also needs:
go get github.com/lib/pq
go get github.com/prometheus/client_golang
```
