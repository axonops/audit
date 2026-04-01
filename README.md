<div align="center">
  <img src=".github/images/logo-readme.png" alt="go-audit" width="128">

  # go-audit

  **Structured, Schema-Enforced Audit Logging for Go Services**

  [![CI](https://github.com/axonops/go-audit/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/axonops/go-audit/actions/workflows/ci.yml)
  [![Go Reference](https://pkg.go.dev/badge/github.com/axonops/go-audit.svg)](https://pkg.go.dev/github.com/axonops/go-audit)
  [![Go Report Card](https://goreportcard.com/badge/github.com/axonops/go-audit)](https://goreportcard.com/report/github.com/axonops/go-audit)
  [![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
  ![Status](https://img.shields.io/badge/status-pre--release-orange)

  [Getting Started](#-quick-start) | [Documentation](#-documentation) | [Examples](examples/) | [API Reference](https://pkg.go.dev/github.com/axonops/go-audit)
</div>

---

## Overview

go-audit is an audit logging library for Go that validates every event
against a consumer-defined schema, delivers events asynchronously to
multiple outputs, and supports both JSON and
[CEF (Common Event Format)](docs/cef-format.md) for SIEM integration.

Define your audit event types in YAML. Generate type-safe Go code from
them. Let the library handle validation, async delivery, multi-output
fan-out, per-output event routing, and sensitive field stripping.

---

## Why Audit Logging?

Audit logging is not application logging. They serve fundamentally
different purposes:

| | Application Logging | Audit Logging |
|---|---|---|
| **Purpose** | Debugging, troubleshooting, observability | Compliance, forensics, accountability |
| **Audience** | Developers, SREs | Security teams, auditors, legal |
| **Guarantees** | Best-effort — missing a log line is fine | Schema-enforced — missing a required field is a compliance failure |
| **Retention** | Days to weeks | Months to years (regulatory requirements) |
| **Content** | Technical details (errors, stack traces) | Who did what, when, to which resource, and why |
| **Destinations** | Log aggregator (ELK, Datadog) | SIEM (Splunk, ArcSight, QRadar), compliance archives |

If your application handles user data, financial transactions,
authentication, or access control, regulations like SOX, HIPAA, GDPR,
and PCI-DSS require you to maintain audit trails. An application logger
(`log/slog`, `zap`, `zerolog`) does not enforce the structure,
completeness, or delivery guarantees that compliance demands.

---

## Why go-audit?

No existing Go library provides schema-enforced audit logging with
multi-output fan-out and SIEM-native format support. go-audit fills
this gap:

- **Schema enforcement** — every event validated against your taxonomy; missing required fields are rejected, not silently dropped
- **SIEM-native output** — CEF format understood by Splunk, ArcSight, QRadar out of the box, alongside JSON for log aggregators
- **Multi-output fan-out** — send events to files, syslog, webhooks, and stdout simultaneously, each with its own formatter and filters
- **Sensitive field stripping** — classify fields as PII or financial data, strip them per-output for GDPR/PCI compliance
- **Non-blocking** — sub-microsecond `AuditEvent()` calls; async delivery via a background drain goroutine
- **No vendor lock-in** — pluggable metrics interface; no Prometheus, OpenTelemetry, or logging framework dependency in core

---

## Quick Start

go-audit uses a YAML-first workflow: define your events in a taxonomy
file, configure outputs in another, and generate type-safe Go code.

### 1. Define your taxonomy (`taxonomy.yaml`)

```yaml
version: 1

categories:
  write:
    events: [user_create]
  security:
    severity: 8
    events: [auth_failure]

default_enabled: [write, security]

events:
  user_create:
    description: "A new user account was created"
    fields:
      outcome:  { required: true }
      actor_id: { required: true }
      target_id: {}

  auth_failure:
    description: "An authentication attempt failed"
    fields:
      outcome:  { required: true }
      actor_id: { required: true }
      source_ip: {}
```

### 2. Configure outputs (`outputs.yaml`)

```yaml
version: 1
outputs:
  console:
    type: stdout
  siem:
    type: file
    file:
      path: "./audit-cef.log"
    formatter:
      type: cef
      vendor: "MyCompany"
      product: "MyApp"
      version: "1.0"
```

### 3. Generate type-safe code

```bash
go run github.com/axonops/go-audit/cmd/audit-gen \
  -input taxonomy.yaml \
  -output audit_generated.go \
  -package main
```

(`go run` fetches the tool automatically — no separate install needed.)

### 4. Use the generated builders

```go
// Required fields are constructor parameters — typos are compile errors
err := logger.AuditEvent(
    NewUserCreateEvent("alice", "success").
        SetTargetID("user-42"),
)
```

For the complete runnable application (taxonomy loading, output
configuration, logger creation), see
[examples/02-code-generation](examples/02-code-generation/).

### Output

**JSON** (default formatter):
```json
{"timestamp":"...","event_type":"user_create","severity":5,"actor_id":"alice","outcome":"success","target_id":"user-42"}
```

**CEF** (SIEM formatter):
```
CEF:0|MyCompany|MyApp|1.0|user_create|A new user account was created|5|rt=... act=user_create suser=alice outcome=success
```

See the [progressive examples](examples/) for complete working
applications from "hello world" to a full CRUD REST API.

---

## Key Features

<div align="center">

| Feature | Description | Learn More |
|---------|-------------|------------|
| **Taxonomy Validation** | Define event schemas in YAML; every event validated at runtime | [Docs](docs/taxonomy-validation.md) |
| **Code Generation** | `audit-gen` generates typed builders; typos become compile errors | [Docs](docs/code-generation.md) |
| **CEF Format** | Common Event Format for SIEM platforms (Splunk, ArcSight, QRadar) | [Docs](docs/cef-format.md) |
| **Multi-Output Fan-Out** | File, syslog, webhook, stdout — simultaneously with per-output config | [Docs](docs/outputs.md) |
| **Event Routing** | Route events by category or severity to specific outputs | [Docs](docs/event-routing.md) |
| **Sensitivity Labels** | Classify fields as PII/financial; strip per-output for compliance | [Docs](docs/sensitivity-labels.md) |
| **Async Delivery** | Sub-microsecond enqueue; background drain goroutine | [Docs](docs/async-delivery.md) |
| **HTTP Middleware** | Automatic request metadata capture for HTTP audit logging | [Docs](docs/http-middleware.md) |
| **Metrics & Monitoring** | Pluggable interface for tracking drops, errors, and delivery | [Docs](docs/metrics-monitoring.md) |
| **YAML Configuration** | Configure outputs in YAML with env var substitution | [Docs](docs/yaml-configuration.md) |
| **Consumer Testing** | In-memory recorder with same validation as production | [Docs](docs/testing.md) |
| **JSON Format** | Line-delimited JSON with deterministic field order | [API Ref](https://pkg.go.dev/github.com/axonops/go-audit#JSONFormatter) |
| **File Output** | Size-based rotation, gzip compression, backup retention | [Docs](docs/outputs.md#file-output) |
| **Syslog Output** | RFC 5424 over TCP, UDP, or TLS with mTLS support | [Docs](docs/outputs.md#syslog-output) |
| **Webhook Output** | Batched HTTPS with retry, backoff, and SSRF protection | [Docs](docs/outputs.md#webhook-output) |

</div>

---

## Installation

Requires **Go 1.26+**. The core library includes `StdoutOutput`. Output
backends are separate modules — import only what you need:

```bash
go get github.com/axonops/go-audit             # core: logger, taxonomy, validation, formatters
go get github.com/axonops/go-audit/file         # file output with rotation
go get github.com/axonops/go-audit/syslog       # RFC 5424 syslog (TCP/UDP/TLS/mTLS)
go get github.com/axonops/go-audit/webhook      # batched HTTP webhook with SSRF protection
go get github.com/axonops/go-audit/outputconfig # YAML-based output configuration
```

The `audittest` package for testing is included in the core module —
no additional `go get` needed.

---

## Module Structure

| Module | Description |
|--------|-------------|
| `github.com/axonops/go-audit` | Core: Logger, taxonomy validation, formatters (JSON + CEF), middleware, fan-out, routing |
| `github.com/axonops/go-audit/file` | File output with size-based rotation and gzip compression |
| `github.com/axonops/go-audit/syslog` | RFC 5424 syslog output (TCP/UDP/TLS/mTLS) |
| `github.com/axonops/go-audit/webhook` | Batched HTTP webhook with retry and SSRF protection |
| `github.com/axonops/go-audit/outputconfig` | YAML-based output configuration with env var substitution |

Outputs are isolated in separate modules so the core library carries
minimal third-party dependencies. Import only the outputs you use.

---

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

---

## Status

This library is **pre-release (v0.x)**. The API may change between
minor versions until v1.0.0. Pin your dependency version.

## License

[Apache License 2.0](LICENSE) — Copyright 2026 AxonOps Limited.
