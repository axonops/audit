[&larr; Back to project README](../README.md)

# go-audit Examples

Progressive examples from "hello world" to a complete CRUD REST API.
Each example introduces one new concept and builds on the previous.

## Examples

| # | Example | What it teaches |
|---|---------|-----------------|
| 1 | [basic](01-basic/) | Taxonomy, Logger, AuditEvent(), Fields, validation — programmatic setup |
| 2 | [code-generation](02-code-generation/) | YAML taxonomy, audit-gen, typed builders, go:embed, outputconfig.Load |
| 3 | [file-output](03-file-output/) | File output with rotation and permissions in YAML |
| 4 | [multi-output](04-multi-output/) | Fan-out to multiple outputs from one YAML config |
| 5 | [event-routing](05-event-routing/) | Category and severity-based routing in YAML |
| 6 | [sensitivity-labels](06-sensitivity-labels/) | Per-output field stripping with PII and financial labels |
| 7 | [formatters](07-formatters/) | JSON vs CEF with category severity levels |
| 8 | [middleware](08-middleware/) | Automatic HTTP audit logging with Hints |
| 9 | [crud-api](09-crud-api/) | Complete REST API with Postgres, five outputs, Docker |
| 10 | [testing](10-testing/) | Testing audit events with audittest.NewLogger |
| 11 | [hmac-integrity](11-hmac-integrity/) | Per-output HMAC tamper detection with selective routing |

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
