# go-audit Examples

Progressive examples from "hello world" to a complete CRUD REST API.
Each example introduces one new concept and builds on the previous.

## Examples

| # | Example | What it teaches |
|---|---------|-----------------|
| 1 | [basic](basic/) | Taxonomy, Logger, Audit(), Fields, validation — programmatic setup |
| 2 | [code-generation](code-generation/) | YAML taxonomy, audit-gen, go:embed, outputconfig.Load |
| 3 | [file-output](file-output/) | File output with rotation and permissions in YAML |
| 4 | [multi-output](multi-output/) | Fan-out to multiple outputs from one YAML config |
| 5 | [event-routing](event-routing/) | Per-output routing rules in YAML |
| 6 | [formatters](formatters/) | JSON vs CEF formatters configured in YAML |
| 7 | [middleware](middleware/) | Automatic HTTP audit logging with Hints |
| 8 | [crud-api](crud-api/) | Complete REST API with Postgres, Prometheus, Docker |

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
cd examples/basic && go run .
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
