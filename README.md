<div align="center">
  <img src=".github/images/logo-readme.png" alt="go-audit" width="128">

  # go-audit

  **Structured, Schema-Enforced Audit Logging for Go Services**

  [![CI](https://github.com/axonops/go-audit/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/axonops/go-audit/actions/workflows/ci.yml)
  [![Go Reference](https://pkg.go.dev/badge/github.com/axonops/go-audit.svg)](https://pkg.go.dev/github.com/axonops/go-audit)
  [![Go Report Card](https://goreportcard.com/badge/github.com/axonops/go-audit)](https://goreportcard.com/report/github.com/axonops/go-audit)
  [![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
  ![Status](https://img.shields.io/badge/status-pre--release-orange)

  [🚀 Quick Start](#-quick-start) | [✨ Features](#-key-features) | [📚 Examples](examples/) | [📖 API Reference](https://pkg.go.dev/github.com/axonops/go-audit)
</div>

---

## 🔍 Overview

go-audit is an audit logging library for Go. Audit logging is different
from application logging — application logs record technical details
for debugging (`log/slog`, `zap`), while audit logs record **who did
what, when, and to which resource** for compliance, forensics, and
accountability. If your application handles user data, authentication,
or financial transactions, regulations like SOX, HIPAA, and GDPR
require structured audit trails that application loggers don't enforce.

go-audit splits audit configuration into two layers:

- **Compile-time (taxonomy):** Your event schema — which event types
  exist, which fields are required, what's optional — is defined in a
  YAML file and embedded into your binary with `go:embed`. A code
  generator (`audit-gen`) produces typed Go builders from this schema,
  so invalid event names and missing required fields are caught by the
  compiler, not at runtime. The taxonomy is your audit contract — it
  ships with the binary and cannot be changed without recompiling.

- **Runtime (outputs):** Where events go — files, syslog, webhooks —
  is configured in a separate YAML file loaded at startup. Output
  destinations, routing filters, formatters, and sensitivity label
  exclusions can all change per environment without rebuilding.

The library validates events against the compiled taxonomy, delivers
them asynchronously to multiple outputs simultaneously, and supports
both [JSON](docs/json-format.md) and
[CEF (Common Event Format)](docs/cef-format.md) for SIEM integration.

---

## ✨ Key Features

<div align="center">

| Feature | Description | Docs |
|---------|-------------|------|
| 📋 **Taxonomy Validation** | Define event schemas in YAML; every event validated at runtime | [Learn more](docs/taxonomy-validation.md) |
| ⚙️ **Code Generation** | `audit-gen` generates typed builders; typos become compile errors | [Learn more](docs/code-generation.md) |
| 🛡️ **CEF Format** | Common Event Format for SIEM platforms (Splunk, ArcSight, QRadar) | [Learn more](docs/cef-format.md) |
| 📄 **JSON Format** | Line-delimited JSON with deterministic field order | [Learn more](docs/json-format.md) |
| 📡 **Multi-Output Fan-Out** | File, syslog, webhook, stdout — simultaneously with per-output config | [Learn more](docs/outputs.md) |
| 🔀 **Event Routing** | Route events by category or severity to specific outputs | [Learn more](docs/event-routing.md) |
| 🔒 **Sensitivity Labels** | Classify fields as PII/financial; strip per-output for compliance | [Learn more](docs/sensitivity-labels.md) |
| ⚡ **Async Delivery** | Sub-microsecond enqueue; background drain goroutine | [Learn more](docs/async-delivery.md) |
| 🌐 **HTTP Middleware** | Automatically captures HTTP request fields for audit logging | [Learn more](docs/http-middleware.md) |
| 📊 **Metrics & Monitoring** | Track dropped events, delivery errors, and output health | [Learn more](docs/metrics-monitoring.md) |
| 📝 **YAML Configuration** | Configure outputs in YAML with environment variable substitution | [Learn more](docs/output-configuration.md) |
| 🔐 **HMAC Integrity** | Per-output tamper detection with NIST-approved algorithms | [Learn more](docs/hmac-integrity.md) |
| 🧪 **Testing Support** | In-memory recorder with same validation as production | [Learn more](docs/testing.md) |

</div>

---

## ❓ Why Audit Logging?

Audit logging is not application logging. They serve fundamentally
different purposes:

| | 🔧 Application Logging | 📋 Audit Logging |
|---|---|---|
| **Purpose** | Debugging, troubleshooting, observability | Compliance, forensics, accountability |
| **Audience** | Developers, SREs | Security teams, auditors, legal |
| **Guarantees** | Best-effort — missing a log line is fine | Schema-enforced — missing a field is a compliance gap |
| **Retention** | Days to weeks | Months to years (regulatory requirements) |
| **Content** | Technical details (errors, stack traces) | Who did what, when, to which resource, and why |
| **Destinations** | Log aggregator (OpenSearch, Datadog, Loki) | SIEM (Splunk, ArcSight, QRadar), compliance archives |

If your application handles user data, financial transactions,
authentication, or access control, regulations like SOX, HIPAA, GDPR,
and PCI-DSS require audit trails. Application loggers (`log/slog`,
`zap`, `zerolog`) do not enforce the structure, completeness, or
delivery guarantees that compliance demands.

---

## 💡 Why go-audit?

No existing Go library provides schema-enforced audit logging with
multi-output fan-out and SIEM-native format support:

- 📋 **Schema enforcement** — every event validated against your taxonomy; missing required fields are rejected, not silently dropped
- 🛡️ **SIEM-native output** — [CEF format](docs/cef-format.md) understood by Splunk, ArcSight, QRadar out of the box, alongside [JSON](docs/json-format.md) for log aggregators
- 📡 **Multi-output fan-out** — send events to [files, syslog, webhooks, and stdout](docs/outputs.md) simultaneously, each with its own formatter and filters
- 🔒 **Sensitive field stripping** — [classify fields as PII or financial](docs/sensitivity-labels.md); strip them per-output for GDPR/PCI compliance
- ⚡ **Non-blocking** — sub-microsecond `AuditEvent()` calls; [async delivery](docs/async-delivery.md) via a background drain goroutine with completeness monitoring
- 🔌 **No vendor lock-in** — [pluggable metrics interface](docs/metrics-monitoring.md); no Prometheus, OpenTelemetry, or logging framework dependency in core

---

## 🚀 Quick Start

go-audit uses a YAML-first workflow: define your events in a taxonomy
file, configure outputs in another, and generate type-safe Go code.

### 1️⃣ Define your taxonomy (`taxonomy.yaml`) - This is your source code. 

```yaml
version: 1

categories:
  write:
    severity: 3
    events:
      - user_create
  security:
    severity: 8
    events:
      - auth_failure

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

### 2️⃣ Configure outputs (`outputs.yaml`) - This is your config. 

```yaml
version: 1
outputs:
  console:
    type: stdout

  siem_log:
    type: file
    file:
      path: "./audit-cef.log"
    formatter:
      type: cef
      vendor: "MyCompany"
      product: "MyApp"
      version: "1.0"
```

### 3️⃣ Generate type-safe code 

```bash
go run github.com/axonops/go-audit/cmd/audit-gen \
  -input taxonomy.yaml \
  -output audit_generated.go \
  -package main
```

> 💡 `go run` fetches the tool automatically — no separate install needed.

### 4️⃣ Use the generated builders

```go
// Required fields are constructor parameters — typos are compile errors
err := logger.AuditEvent(
    NewUserCreateEvent("alice", "success").
        SetTargetID("user-42"),
)
```

> 📚 For the complete runnable application (taxonomy loading, output
> configuration, logger creation), see
> [examples/02-code-generation](examples/02-code-generation/).

### Output

**📄 JSON** (default formatter):
```json
{"timestamp":"...","event_type":"user_create","severity":3,"actor_id":"alice","outcome":"success","target_id":"user-42","event_category":"write"}
```

**🛡️ CEF** (SIEM formatter):
```
CEF:0|MyCompany|MyApp|1.0|user_create|A new user account was created|3|rt=... act=user_create suser=alice outcome=success eventCategory=write
```

---

## 📦 Installation

Requires **Go 1.26+**.

```bash
go get github.com/axonops/go-audit             # core: logger, taxonomy, validation, formatters, stdout output
go get github.com/axonops/go-audit/file         # file output with rotation
go get github.com/axonops/go-audit/syslog       # RFC 5424 syslog (TCP/UDP/TLS/mTLS)
go get github.com/axonops/go-audit/webhook      # batched HTTP webhook with SSRF protection
go get github.com/axonops/go-audit/outputconfig # YAML-based output configuration
```

> 💡 The core module includes `StdoutOutput` (no additional dependency)
> and the `audittest` package for [testing](docs/testing.md).

---

## 🏗️ Module Structure

| Module | Description |
|--------|-------------|
| `github.com/axonops/go-audit` | Core: Logger, taxonomy validation, JSON + CEF formatters, HTTP middleware, stdout output, fan-out, routing, `audittest` |
| `github.com/axonops/go-audit/file` | File output with size-based rotation and gzip compression |
| `github.com/axonops/go-audit/syslog` | RFC 5424 syslog output (TCP/UDP/TLS/mTLS) |
| `github.com/axonops/go-audit/webhook` | Batched HTTP webhook with retry and SSRF protection |
| `github.com/axonops/go-audit/outputconfig` | YAML-based output configuration with env var substitution |

Outputs are isolated in separate modules so the core library carries
minimal third-party dependencies. Import only the outputs you use.

---

## 📚 Documentation

| Resource | Description |
|----------|-------------|
| 📖 [Progressive Examples](examples/) | 10 examples from "hello world" to a [complete CRUD API](examples/09-crud-api/) with five outputs |
| 📘 [API Reference](https://pkg.go.dev/github.com/axonops/go-audit) | pkg.go.dev documentation |
| 🏗️ [Architecture](ARCHITECTURE.md) | Pipeline design, module boundaries, thread safety |
| 🤝 [Contributing](CONTRIBUTING.md) | Development setup, PR process, code standards |
| 📝 [Changelog](CHANGELOG.md) | Release history and breaking changes |
| ❌ [Error Reference](docs/error-reference.md) | Every error explained with recovery guidance |
| 🔧 [Troubleshooting](docs/troubleshooting.md) | Common problems and how to fix them |
| 🔒 [Security Policy](SECURITY.md) | Vulnerability reporting |
| ⚡ [Benchmarks](BENCHMARKS.md) | Performance baseline and methodology |

---

## ⚠️ Status

This library is **pre-release (v0.x)**. The API may change between
minor versions until v1.0.0. Pin your dependency version.

---

## 🙏 Acknowledgements

go-audit builds on excellent open-source projects. See
[ACKNOWLEDGEMENTS.md](ACKNOWLEDGEMENTS.md) for full attribution and
license details.

- [gopkg.in/yaml.v3](https://github.com/go-yaml/yaml) — YAML parsing (MIT / Apache-2.0)
- [github.com/axonops/srslog](https://github.com/axonops/srslog) — RFC 5424 syslog (BSD-3-Clause)
- [github.com/rgooding/go-syncmap](https://github.com/rgooding/go-syncmap) — Generic sync.Map (Apache-2.0)

---

## 📄 License

[Apache License 2.0](LICENSE) — Copyright 2026 AxonOps Limited.

---

<div align="center">
  <sub>Made with ❤️ by <a href="https://axonops.com">AxonOps</a></sub>
</div>
