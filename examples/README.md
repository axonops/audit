# go-audit Examples

Progressive examples from "hello world" to a complete CRUD REST API.
Each example introduces one new concept and builds on the previous.

## Examples

| # | Example | Concepts | Description |
|---|---------|----------|-------------|
| 1 | [basic](basic/) | NewLogger, Taxonomy, Audit, Fields | Minimum viable audit event |
| 2 | [file-output](file-output/) | file.New, rotation, permissions | Write events to a log file |
| 3 | [multi-output](multi-output/) | WithOutputs, fan-out | Send events to multiple outputs |
| 4 | [code-generation](code-generation/) | audit-gen, go:generate, go:embed | Type-safe constants from YAML |
| 5 | [event-routing](event-routing/) | WithNamedOutput, EventRoute | Per-output category filtering |
| 6 | [formatters](formatters/) | JSONFormatter, CEFFormatter | JSON vs CEF side by side |
| 7 | [middleware](middleware/) | Middleware, EventBuilder, Hints | Automatic HTTP audit logging |
| 8 | [crud-api](crud-api/) | All of the above + Postgres, Prometheus | Complete REST API |

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

If you copy an example to your own project:

```bash
# Examples 1-7 need only the core and file modules:
go get github.com/axonops/go-audit
go get github.com/axonops/go-audit/file

# The CRUD API example also needs:
go get github.com/axonops/go-audit/syslog
go get github.com/axonops/go-audit/webhook
go get github.com/lib/pq
go get github.com/prometheus/client_golang
```
