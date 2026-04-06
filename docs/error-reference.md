[&larr; Back to README](../README.md)

# Error Reference

- [How to Check Errors](#how-to-check-errors)
- [Core Errors](#core-errors)
- [Configuration Errors](#configuration-errors)
- [Output Errors](#output-errors)
- [Taxonomy Errors](#taxonomy-errors)

## How to Check Errors

All go-audit errors are sentinel values. Use `errors.Is` to check
for specific error types — never compare error strings:

```go
err := logger.AuditEvent(event)
if errors.Is(err, audit.ErrBufferFull) {
    // handle buffer full
}
if errors.Is(err, audit.ErrClosed) {
    // logger was already closed
}
```

Errors that wrap a sentinel (e.g., taxonomy validation) include
detail in the message. Use `errors.Is` to check the category, then
read the `.Error()` string for specifics.

---

## ⚡ Core Errors

### `ErrBufferFull`

```
audit: buffer full
```

| | |
|---|---|
| **When** | `AuditEvent()` is called but the async buffer channel is at capacity |
| **Meaning** | The event was **dropped** — it will not be delivered to any output |
| **Transient?** | Yes — resolves when the drain goroutine catches up |
| **What to do** | Log a warning, increment a metric (`RecordBufferDrop` fires automatically). Do NOT retry immediately — the buffer is full and retrying worsens the backlog. If this happens frequently, increase `Config.BufferSize` or investigate slow outputs. |

### `ErrClosed`

```
audit: logger is closed
```

| | |
|---|---|
| **When** | `AuditEvent()` is called after `Logger.Close()` has been called |
| **Meaning** | The logger has been shut down — no more events can be emitted |
| **Transient?** | No — permanent. The logger cannot be reopened. |
| **What to do** | This usually means your shutdown ordering is wrong. Make sure you stop generating events (e.g., stop the HTTP server) before calling `logger.Close()`. See [Graceful Shutdown](async-delivery.md#-graceful-shutdown). |

### `ErrDuplicateDestination`

```
audit: duplicate destination
```

| | |
|---|---|
| **When** | `NewLogger()` is called with two outputs that write to the same destination (e.g., two file outputs with the same path, two syslog outputs with the same address) |
| **Meaning** | Logger creation failed — duplicate outputs would cause data corruption or interleaved writes |
| **Transient?** | No — permanent configuration error |
| **What to do** | Check your output configuration for duplicate paths, addresses, or URLs. Each output must write to a unique destination. |

---

## ⚙️ Configuration Errors

### `ErrConfigInvalid`

```
audit: config validation failed
```

| | |
|---|---|
| **When** | `NewLogger()` is called with an invalid `Config` struct |
| **Meaning** | Logger creation failed — one or more config values are out of range |
| **Transient?** | No — permanent configuration error |
| **What to do** | Check the error message for details. Common causes: `BufferSize` exceeds 1,000,000, `DrainTimeout` exceeds 60 seconds, `Version` is not 1. The wrapped error message tells you which field is invalid. |

### `ErrOutputConfigInvalid`

```
audit: output config validation failed
```

| | |
|---|---|
| **Package** | `github.com/axonops/go-audit/outputconfig` |
| **When** | `outputconfig.Load()` is called with invalid YAML output configuration |
| **Meaning** | Output configuration parsing or validation failed |
| **Transient?** | No — permanent configuration error |
| **What to do** | Check the error message for details. Common causes: unknown output type (forgot a blank import), invalid YAML syntax, missing required fields (e.g., `url` for webhook, `path` for file), unknown YAML keys (check for typos), using removed `default_formatter` key (set `formatter:` on each output instead), non-JSON `formatter` on a Loki output. See [Output Configuration YAML](output-configuration.md). |

---

## 📡 Output Errors

### `ErrOutputClosed`

```
audit: output is closed
```

| | |
|---|---|
| **When** | `Output.Write()` is called after `Output.Close()` |
| **Meaning** | The output has been shut down — it cannot accept more events |
| **Transient?** | No — permanent |
| **What to do** | This is usually an internal library error. If you see it, it likely means `Close()` was called while events were still being processed. Report it as a bug. |

### `ErrHijackNotSupported`

```
audit: underlying ResponseWriter does not support hijacking
```

| | |
|---|---|
| **When** | The HTTP middleware's response writer wrapper receives a `Hijack()` call, but the underlying `http.ResponseWriter` does not implement `http.Hijacker` |
| **Meaning** | WebSocket upgrade or similar hijack operation is not supported by the server's response writer |
| **Transient?** | No — depends on the HTTP server implementation |
| **What to do** | This is rare. It occurs when the audit middleware wraps a response writer that doesn't support hijacking (e.g., HTTP/2 connections). If you need WebSocket support through the audit middleware, ensure your HTTP server supports hijacking. |

---

## 📋 Taxonomy Errors

### `ErrTaxonomyInvalid`

```
audit: taxonomy validation failed
```

| | |
|---|---|
| **When** | `ValidateTaxonomy()` or `WithTaxonomy()` is called with a taxonomy that fails semantic validation |
| **Meaning** | The taxonomy structure is valid YAML but has logical errors |
| **Transient?** | No — permanent. Fix the taxonomy definition. |
| **What to do** | The error message lists all validation failures (one per line). Common causes: category references an event type not defined in `events`, event has a field in both required and optional, severity out of range (0-10), version not 1, reserved standard field declared as bare optional (use `required: true` or add labels), framework field declared as user field. Fix each listed issue in your taxonomy YAML. |

### New validation errors (#237)

```
event "X" field "Y" is a reserved standard field -- it is always available without declaration; to reference it, set required: true or add labels
```

| | |
|---|---|
| **When** | A reserved standard field (actor_id, source_ip, reason, etc.) is declared as a bare optional field in the taxonomy |
| **Meaning** | Reserved standard fields are always available. Bare optional declarations are redundant. |
| **What to do** | Either remove the declaration entirely, add `required: true` to make it mandatory, or add sensitivity labels. |

```
audit: app_name must not be empty
audit: host must not be empty
audit: timezone must not be empty
```

| | |
|---|---|
| **When** | `WithAppName("")`, `WithHost("")`, or `WithTimezone("")` is called |
| **Meaning** | Framework field values cannot be empty strings |
| **What to do** | Provide a non-empty value. In outputs YAML, ensure `app_name` and `host` are set. |

```
audit: standard field default key "X" is not a reserved standard field
```

| | |
|---|---|
| **When** | `WithStandardFieldDefaults` is called with a key that is not one of the 31 reserved standard field names |
| **Meaning** | Only reserved standard fields can have deployment-wide defaults |
| **What to do** | Check the field name against `ReservedStandardFieldNames()`. |

### `ErrInvalidInput`

```
audit: invalid input
```

| | |
|---|---|
| **When** | `ParseTaxonomyYAML()` is called with input that cannot be parsed as valid YAML |
| **Meaning** | The input is structurally invalid — not a YAML problem with your taxonomy, but a YAML syntax or input problem |
| **Transient?** | No — permanent. Fix the input. |
| **What to do** | Common causes: input exceeds 1 MiB limit, input contains multiple YAML documents (separated by `---`), YAML syntax error (bad indentation, tabs instead of spaces), unknown YAML key (typo in field name — the parser rejects unknown keys). The wrapped error message gives the specific parse error. |

### `ErrHandleNotFound`

```
audit: event type not found
```

| | |
|---|---|
| **When** | `Logger.Handle()` or `Logger.MustHandle()` is called with an event type name not registered in the taxonomy |
| **Meaning** | The event type string does not match any event defined in the taxonomy |
| **Transient?** | No — permanent. The event type must exist in the taxonomy. |
| **What to do** | Check for typos in the event type name. Use generated constants (`EventUserCreate`) instead of string literals to catch this at compile time. If using `MustHandle()`, note that it **panics** instead of returning an error — use `Handle()` if you want to handle the error gracefully. |

---

## 📚 Further Reading

- [Async Delivery](async-delivery.md) — buffer sizing, delivery guarantee, graceful shutdown
- [Taxonomy YAML Reference](taxonomy-validation.md) — fixing taxonomy validation errors
- [Output Configuration YAML](output-configuration.md) — fixing output config errors
- [Metrics & Monitoring](metrics-monitoring.md) — tracking errors via the Metrics interface
