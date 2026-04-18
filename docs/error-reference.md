[&larr; Back to README](../README.md)

# Error Reference

- [How to Check Errors](#how-to-check-errors)
- [Core Errors](#core-errors)
- [Configuration Errors](#configuration-errors)
- [Output Errors](#output-errors)
- [Secret Resolution Errors](#secret-resolution-errors)
- [Taxonomy Errors](#taxonomy-errors)

## How to Check Errors

All audit errors are sentinel values. Use `errors.Is` to check
for specific error types — never compare error strings:

```go
err := auditor.AuditEvent(event)
if errors.Is(err, audit.ErrQueueFull) {
    // handle buffer full
}
if errors.Is(err, audit.ErrClosed) {
    // auditor was already closed
}
```

Errors that wrap a sentinel (e.g., taxonomy validation) include
detail in the message. Use `errors.Is` to check the category, then
read the `.Error()` string for specifics.

---

## ⚡ Core Errors

### `ErrQueueFull`

```
audit: queue full
```

| | |
|---|---|
| **When** | `AuditEvent()` is called but the async buffer channel is at capacity |
| **Meaning** | The event was **dropped** — it will not be delivered to any output |
| **Transient?** | Yes — resolves when the drain goroutine catches up |
| **What to do** | Log a warning, increment a metric (`RecordBufferDrop` fires automatically). Do NOT retry immediately — the queue is full and retrying worsens the backlog. If this happens frequently, increase `Config.QueueSize` (or `auditor.queue_size` in YAML) or investigate slow outputs. See [Two-Level Buffering](async-delivery.md#two-level-buffering) for the pipeline architecture. |

### `ErrClosed`

```
audit: auditor is closed
```

| | |
|---|---|
| **When** | `AuditEvent()` is called after `Auditor.Close()` has been called |
| **Meaning** | The auditor has been shut down — no more events can be emitted |
| **Transient?** | No — permanent. The auditor cannot be reopened. |
| **What to do** | This usually means your shutdown ordering is wrong. Make sure you stop generating events (e.g., stop the HTTP server) before calling `auditor.Close()`. See [Graceful Shutdown](async-delivery.md#-graceful-shutdown). |

### `ErrDuplicateDestination`

```
audit: duplicate destination
```

| | |
|---|---|
| **When** | `New()` is called with two outputs that write to the same destination (e.g., two file outputs with the same path, two syslog outputs with the same address) |
| **Meaning** | Auditor creation failed — duplicate outputs would cause data corruption or interleaved writes |
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
| **When** | `New()` is called with an invalid `Config` struct |
| **Meaning** | Auditor creation failed — one or more config values are out of range |
| **Transient?** | No — permanent configuration error |
| **What to do** | Check the error message for details. Common causes: `QueueSize` exceeds 1,000,000, `ShutdownTimeout` exceeds 60 seconds, `Version` is not 1. The wrapped error message tells you which field is invalid. |

### `ErrOutputConfigInvalid`

```
audit: output config validation failed
```

| | |
|---|---|
| **Package** | `github.com/axonops/audit/outputconfig` |
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

## 🔐 HMAC Errors

HMAC validation errors occur when `outputconfig.Load()` encounters an
invalid HMAC configuration on an output, or when the programmatic API
receives invalid HMAC parameters.

| Error (contains) | When |
|------------------|------|
| `hmac salt version is required when hmac is enabled` | `hmac.salt.version` is empty or missing |
| `hmac salt value is required when hmac is enabled` | `hmac.salt.value` is empty or missing |
| `hmac hash algorithm is required when hmac is enabled` | `hmac.hash` is empty or missing |
| `hmac salt must be at least` | Salt is shorter than `audit.MinSaltLength` (currently 16) bytes |
| `unknown hmac algorithm` | Algorithm is not in `audit.SupportedHMACAlgorithms()` (currently: HMAC-SHA-256, HMAC-SHA-384, HMAC-SHA-512, HMAC-SHA3-256, HMAC-SHA3-384, HMAC-SHA3-512) |

All HMAC configuration validation errors (from `ValidateHMACConfig`, `outputconfig.Load()`, and `New`) wrap `audit.ErrConfigInvalid`. Use `errors.Is(err, audit.ErrConfigInvalid)` to detect them programmatically. Errors returned by `ComputeHMAC` and `VerifyHMAC` do not wrap this sentinel and must be handled separately.

---

## 📡 Loki Output Errors

| Error | When |
|-------|------|
| `url must not be empty` | Loki output has no URL configured |
| `must be https` | URL uses HTTP without `allow_insecure_http: true` |
| `must not contain credentials` | URL has embedded user:pass |
| `mutually exclusive` | Both `basic_auth` and `bearer_token` are set |
| `unknown dynamic label` | A `labels.dynamic` key is not one of the valid label names |
| `invalid` static label name | Label name doesn't match `[a-zA-Z_][a-zA-Z0-9_]*` |
| `loki does not support custom formatters` | `formatter: cef` or non-JSON on a Loki output |

---

## 📡 Webhook Output Errors

| Error | When |
|-------|------|
| `url must not be empty` | Webhook has no URL configured |
| `must be https` | URL uses HTTP without `allow_insecure_http: true` |
| `must not contain credentials` | URL has embedded user:pass |
| `batch_size must be at least 1` | Explicit zero or negative `batch_size` |
| `max_retries must be at least 1` | Negative `max_retries` (zero defaults to 3) |
| `buffer_size must be at least 1` | Explicit zero or negative `buffer_size` |
| `batch_size N exceeds maximum` | `batch_size` > 10,000 |
| `max_retries N exceeds maximum` | `max_retries` > 20 |
| `flush_interval must not be negative` | Negative duration |
| `timeout must not be negative` | Negative duration |
| `CR/LF` in header | Header contains carriage return or line feed |

---

## 📡 Syslog Output Errors

| Error | When |
|-------|------|
| `address must not be empty` | No syslog server address |
| `network must be tcp, udp, or tcp+tls` | Invalid transport protocol |
| `unknown syslog facility` | Facility name not in the standard set |
| `max_retries N exceeds maximum 20` | `max_retries` > 20 |
| `tls_cert and tls_key must both be set or both empty` | Only one of cert/key provided |
| `hostname exceeds RFC 5424 maximum` | Hostname > 255 bytes |
| `invalid byte` in hostname | Hostname contains non-PRINTUSASCII characters |

---

## Secret Resolution Errors

Secret resolution errors occur during `outputconfig.Load` when ref+
URIs cannot be resolved. All errors are in `github.com/axonops/audit/secrets`.

### `ErrMalformedRef`

```
secrets: malformed secret reference
```

| | |
|---|---|
| **When** | `ParseRef` encounters a `ref+` URI with structural errors: empty scheme, empty path, empty key, path traversal (`..`), percent-encoded characters, or missing `://` separator |
| **Meaning** | The ref URI syntax is invalid -- the provider is never contacted |
| **Transient?** | No -- fix the ref URI in the YAML configuration |
| **What to do** | Check the exact error message for the specific validation failure. Common causes: missing `#key` fragment, leading `/` in path, consecutive slashes (`//`) in path. See [URI Syntax](secrets.md#uri-syntax). |

### `ErrProviderNotRegistered`

```
secrets: no provider registered for scheme
```

| | |
|---|---|
| **When** | A ref URI references a scheme for which no `WithSecretProvider` was registered |
| **Meaning** | The library cannot resolve this ref because no provider handles the scheme |
| **Transient?** | No -- register the correct provider or fix the scheme in the ref URI |
| **What to do** | The error message includes the scheme and the field path: `secrets: no provider registered for scheme: scheme "openbao" (field outputs.siem.webhook.headers.Authorization)`. Add the missing `outputconfig.WithSecretProvider(provider)` call, or correct the scheme in the ref URI. |

### `ErrSecretNotFound`

```
secrets: secret not found at path
```

| | |
|---|---|
| **When** | The provider received a 404 from the server, or the requested key does not exist at the path |
| **Meaning** | The secret path or key does not exist in the backend |
| **Transient?** | No -- fix the path or key in the ref URI |
| **What to do** | The most common cause is using the CLI path instead of the API path. For KV v2, the CLI path `secret/audit/hmac` maps to API path `secret/data/audit/hmac`. Verify the secret exists with `bao kv get` or `vault kv get`. |

### `ErrSecretResolveFailed`

```
secrets: secret resolution failed
```

| | |
|---|---|
| **When** | Network error, authentication failure (403), unexpected server response, timeout, or response size limit exceeded |
| **Meaning** | The provider contacted the server but the request failed |
| **Transient?** | Possibly -- authentication failures are permanent until the token is rotated; network errors may be transient |
| **What to do** | Check the wrapped error message for specifics: `authentication failed (403)` means the token lacks permission or is expired; `unexpected status N` means the server returned an error; `context deadline exceeded` means the resolution timeout was reached (increase with `WithSecretTimeout`). |

### `ErrUnresolvedRef`

```
secrets: unresolved secret reference in config
```

| | |
|---|---|
| **When** | After all resolution passes, a string value in the config still contains a `ref+` pattern |
| **Meaning** | A ref URI was not resolved -- either no provider was registered, the scheme was wrong, or the ref was embedded in a larger string |
| **Transient?** | No -- fix the configuration or register the required provider |
| **What to do** | The error includes the field path: `field outputs.siem.webhook.headers.Authorization still contains a secret reference`. Check that: (1) a provider for the scheme is registered, (2) the ref is the entire string value (not embedded in a larger string), (3) the `ref+` prefix is exactly lowercase. |

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

### `ErrInvalidTaxonomyName`

```
audit: invalid taxonomy name
```

| | |
|---|---|
| **When** | A category name, event type key, required/optional field name, or sensitivity label name fails the character-set or length rule. |
| **Meaning** | The offending name contains a character outside `[a-z][a-z0-9_]*` or exceeds 128 bytes. Protects downstream log consumers from bidi overrides, Unicode confusables, CEF/JSON metacharacters, and C0/C1 control bytes (issue #477). |
| **Transient?** | No — permanent. Fix the taxonomy definition. |
| **What to do** | Rename the identifier to use only lowercase letters, digits, and underscores, starting with a letter, and keep it under 128 bytes. See [Taxonomy Validation — Name Character Set and Length](taxonomy-validation.md#️-name-character-set-and-length) for the full rule and rationale. |
| **Sentinel behaviour** | Always wrapped alongside `ErrTaxonomyInvalid` via `errors.Join`. Consumers may test either sentinel with `errors.Is`:<br>`errors.Is(err, audit.ErrInvalidTaxonomyName)` → narrow (name-shape only)<br>`errors.Is(err, audit.ErrTaxonomyInvalid)` → any taxonomy error, including name-shape |

Example error message (with bidi bytes rendered as Go escapes):

```
audit: taxonomy validation failed:
- event type name "user\u202eadmin" is invalid: must match ^[a-z][a-z0-9_]*$
audit: invalid taxonomy name
```

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
| **When** | `Auditor.Handle()` or `Auditor.MustHandle()` is called with an event type name not registered in the taxonomy |
| **Meaning** | The event type string does not match any event defined in the taxonomy |
| **Transient?** | No — permanent. The event type must exist in the taxonomy. |
| **What to do** | Check for typos in the event type name. Use generated constants (`EventUserCreate`) instead of string literals to catch this at compile time. If using `MustHandle()`, note that it **panics** instead of returning an error — use `Handle()` if you want to handle the error gracefully. |

---

## 📚 Further Reading

- [Async Delivery](async-delivery.md) — buffer sizing, delivery guarantee, graceful shutdown
- [Taxonomy YAML Reference](taxonomy-validation.md) — fixing taxonomy validation errors
- [Output Configuration YAML](output-configuration.md) — fixing output config errors
- [Metrics & Monitoring](metrics-monitoring.md) — tracking errors via the Metrics interface
