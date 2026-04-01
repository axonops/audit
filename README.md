<p align="center">
  <img src=".github/images/logo-readme.png" alt="go-audit" width="128">
</p>

<h1 align="center">go-audit</h1>

<p align="center">
  Structured, schema-enforced audit logging for Go services.
</p>

<p align="center">
  <a href="https://github.com/axonops/go-audit/actions/workflows/ci.yml"><img src="https://github.com/axonops/go-audit/actions/workflows/ci.yml/badge.svg?branch=main" alt="CI"></a>
  <a href="https://pkg.go.dev/github.com/axonops/go-audit"><img src="https://pkg.go.dev/badge/github.com/axonops/go-audit.svg" alt="Go Reference"></a>
  <a href="https://goreportcard.com/report/github.com/axonops/go-audit"><img src="https://goreportcard.com/badge/github.com/axonops/go-audit" alt="Go Report Card"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-blue.svg" alt="License"></a>
  <img src="https://img.shields.io/badge/status-pre--release-orange" alt="Pre-release">
</p>

---

go-audit is an audit logging library for Go that validates every event
against a consumer-defined schema before delivery. Define your audit
event taxonomy in YAML, generate type-safe Go code from it, and let the
library handle async delivery, multi-output fan-out, and per-output
field filtering. Unlike general-purpose loggers, go-audit enforces that
every audit event has the required fields, rejects unknown event types,
and strips sensitive fields from outputs that shouldn't see them.

## Quick Start

```go
package main

import (
	"fmt"
	"log"

	audit "github.com/axonops/go-audit"
)

func main() {
	stdout, err := audit.NewStdoutOutput(audit.StdoutConfig{})
	if err != nil {
		log.Fatal(err)
	}

	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(audit.Taxonomy{
			Version: 1,
			Categories: map[string]*audit.CategoryDef{
				"write": {Events: []string{"user_create"}},
			},
			Events: map[string]*audit.EventDef{
				"user_create": {Required: []string{"outcome", "actor_id"}},
			},
			DefaultEnabled: []string{"write"},
		}),
		audit.WithOutputs(stdout),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer logger.Close()

	if err := logger.AuditEvent(audit.NewEvent("user_create", audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
	})); err != nil {
		fmt.Println("audit error:", err)
	}
}
```

Output (JSON, one line per event):

```json
{"timestamp":"...","event_type":"user_create","severity":5,"actor_id":"alice","outcome":"success"}
```

In production, define your taxonomy in YAML and generate typed builders
with `audit-gen` — see the [progressive examples](examples/).

## Installation

Requires **Go 1.26+**. The core library includes `StdoutOutput`. Output
backends are separate modules so you import only what you need:

```bash
go get github.com/axonops/go-audit             # core: logger, taxonomy, validation
go get github.com/axonops/go-audit/file         # file output with rotation
go get github.com/axonops/go-audit/syslog       # RFC 5424 syslog (TCP/UDP/TLS/mTLS)
go get github.com/axonops/go-audit/webhook      # batched HTTP webhook with SSRF protection
go get github.com/axonops/go-audit/outputconfig # YAML-based output configuration
```

## Features

- **Schema-enforced events** — define your audit taxonomy in YAML; the library validates every event against it at runtime
- **Type-safe code generation** — `audit-gen` generates per-event builder structs with required-field constructors; typos become compile errors
- **Async delivery** — events enqueue to a buffered channel and drain via a background goroutine; sub-microsecond `AuditEvent()` calls (see [benchmarks](BENCHMARKS.md))
- **Multi-output fan-out** — send events to files, syslog, webhooks, and stdout simultaneously
- **File output** — size-based rotation, gzip compression, backup retention, configurable permissions
- **Syslog output** — RFC 5424 over TCP, UDP, or TLS with mTLS client certificate support
- **Webhook output** — batched HTTP delivery with retry, backoff, and SSRF protection
- **Per-output event routing** — route events by category or severity; security events to SIEM, verbose reads to local files
- **Sensitivity labels** — classify fields as PII, financial, etc. and strip them per-output
- **JSON and CEF formatters** — Common Event Format for SIEM integration
- **HTTP middleware** — captures request metadata (client IP, TLS state, duration, status code) automatically
- **Consumer testing** — [`audittest`](https://pkg.go.dev/github.com/axonops/go-audit/audittest) package (included in core module) provides an in-memory recorder with the same validation as production
- **Pluggable metrics** — bring your own Prometheus (or anything); no metrics dependency in core

## Documentation

| Resource | Description |
|----------|-------------|
| [Progressive Examples](examples/) | 10 examples from "hello world" to a complete CRUD API |
| [API Reference](https://pkg.go.dev/github.com/axonops/go-audit) | pkg.go.dev documentation |
| [Architecture](ARCHITECTURE.md) | Pipeline design, module boundaries, thread safety |
| [Contributing](CONTRIBUTING.md) | Development setup, PR process, code standards |
| [Changelog](CHANGELOG.md) | Release history and breaking changes |
| [Security Policy](SECURITY.md) | Vulnerability reporting |
| [Benchmarks](BENCHMARKS.md) | Performance baseline and methodology |

## Module Structure

| Module | Description |
|--------|-------------|
| `github.com/axonops/go-audit` | Core: Logger, Output interface, taxonomy validation, fan-out, routing, formatters, middleware |
| `github.com/axonops/go-audit/file` | File output with size-based rotation and compression |
| `github.com/axonops/go-audit/syslog` | RFC 5424 syslog output (TCP/UDP/TLS/mTLS) |
| `github.com/axonops/go-audit/webhook` | Batched HTTP webhook with retry and SSRF protection |
| `github.com/axonops/go-audit/outputconfig` | YAML-based output configuration with env var substitution |

Outputs are isolated in separate modules so the core library carries
minimal third-party dependencies (`gopkg.in/yaml.v3` for taxonomy
parsing, `go-syncmap` for lock-free category lookups). Import only the
outputs you use.

## How It Works

```
AuditEvent(event)
    │
    ├── validate against taxonomy (required fields, known event type)
    ├── check category enabled
    └── enqueue to buffered channel ──► drain goroutine
                                            │
                                            ├── serialize (JSON or CEF)
                                            └── fan-out to each output
                                                 ├── per-output routing filter
                                                 ├── per-output sensitivity filter
                                                 └── write
```

The caller goroutine handles validation and enqueuing. A single
background drain goroutine handles serialization and delivery, so
outputs do not need to be thread-safe. Delivery is at-most-once within a
process lifetime. Call `Logger.Close()` to flush pending events before
shutdown — failing to close leaks the drain goroutine and loses buffered
events.

## Status

This library is **pre-release (v0.x)**. The API may change between minor
versions until v1.0.0. Pin your dependency version.

## License

[Apache License 2.0](LICENSE)

Copyright 2026 AxonOps Limited.
