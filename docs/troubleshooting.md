[&larr; Back to README](../README.md)

# Troubleshooting

- [Events Not Appearing in Output](#-events-not-appearing-in-output)
- [ErrBufferFull at Runtime](#-errbufferfull-at-runtime)
- [Drain Timeout at Shutdown](#-drain-timeout-at-shutdown)
- [Validation Errors on Valid-Looking Events](#-validation-errors-on-valid-looking-events)
- [Syslog Connection Failures](#-syslog-connection-failures)
- [Webhook Events Not Delivered](#-webhook-events-not-delivered)
- [File Output Not Writing](#-file-output-not-writing)
- [Goroutine Leak in Tests](#-goroutine-leak-in-tests)

---

## 🔇 Events Not Appearing in Output

This is the most common problem. Work through this checklist:

| Check | How to Verify | Fix |
|-------|--------------|-----|
| **`logger.Close()` not called** | Events are async — they sit in the buffer until the drain goroutine processes them. If your program exits without calling `Close()`, buffered events are lost. | Call `logger.Close()` before exit. See [Graceful Shutdown](async-delivery.md#-graceful-shutdown). |
| **`Config.Enabled` is false** | A disabled logger silently discards all events. | Set `Config{Enabled: true}`. |
| **Category disabled at runtime** | If `DisableCategory()` was called, events in that category are silently discarded. | Check your code for `DisableCategory()` calls. All categories are enabled by default. |
| **Per-output route filtering** | An output with `route: include_categories: [security]` only receives security events — write events are silently filtered. | Check your output YAML `route:` block. Remove the route to receive all events. See [Event Routing](event-routing.md). |
| **Output disabled in YAML** | `enabled: false` on an output silently disables it. | Check your output YAML for `enabled: false`. |
| **Sensitivity label stripping** | `exclude_labels: [pii]` removes PII-labeled fields — the event is delivered but with fewer fields than expected. | Check your output YAML `exclude_labels`. The event itself is delivered; only labeled fields are stripped. See [Sensitivity Labels](sensitivity-labels.md). |
| **Wrong output type blank import** | If you use `type: file` in YAML but forgot `_ "github.com/axonops/go-audit/file"`, `outputconfig.Load` returns an error. | Add the blank import for every output type you use. See [Output Configuration](output-configuration.md#-factory-registry). |

> 💡 **Quick diagnostic:** Add a `stdout` output with no route. If
> events appear on stdout but not in your file/syslog/webhook, the
> problem is in the output configuration, not the audit pipeline.

---

## 📦 ErrBufferFull at Runtime

```
audit: buffer full
```

The async buffer is at capacity. Events are being produced faster
than the drain goroutine can write them to outputs.

| Cause | Fix |
|-------|-----|
| **Burst of events** | Increase `Config.BufferSize` (default: 10,000, max: 1,000,000) |
| **Slow output** | A syslog server or webhook endpoint with high latency backs up the entire pipeline. Check output connectivity and latency. |
| **Output error loop** | If an output is failing on every write, the drain goroutine spends time on error handling instead of processing events. Check `RecordOutputError` metrics. |

Monitor `RecordBufferDrop()` in your metrics to catch this before
users notice. See [Metrics & Monitoring](metrics-monitoring.md).

---

## ⏱️ Drain Timeout at Shutdown

```
INFO audit: shutdown started
WARN audit: drain timeout expired, N events lost
```

`Logger.Close()` waited up to `DrainTimeout` (default: 5 seconds)
but couldn't flush all buffered events in time.

| Cause | Fix |
|-------|-----|
| **Too many buffered events** | Reduce event volume before shutdown, or increase `Config.DrainTimeout` (max: 60s) |
| **Slow output during shutdown** | A syslog server or webhook endpoint is slow to accept the final batch. Check connectivity. |
| **`DrainTimeout` too short** | Increase `Config.DrainTimeout` for high-volume applications |

> ⚠️ Events lost to drain timeout are gone permanently. This is the
> at-most-once delivery guarantee. Monitor this via your metrics.

---

## ❌ Validation Errors on Valid-Looking Events

```
audit: unknown event type "user_created"
audit: event "user_create": missing required field "actor_id"
audit: event "user_create": unknown field "actorid"
```

| Error | Cause | Fix |
|-------|-------|-----|
| **Unknown event type** | The event type string doesn't match any event in your taxonomy. Likely a typo. | Use generated constants (`EventUserCreate`) instead of string literals. Check your taxonomy YAML `events:` section. |
| **Missing required field** | A field marked `required: true` in the taxonomy is not present in the event. | Add the missing field. Check your taxonomy for which fields are required. |
| **Unknown field** (strict mode) | A field not declared in the taxonomy was included. In `strict` mode (default), this is rejected. | Either add the field to your taxonomy, or switch to `warn` or `permissive` validation mode. See [Validation Modes](taxonomy-validation.md#-validation-modes). |

> 💡 **Use code generation** to eliminate these errors entirely.
> Generated builders have required fields as constructor parameters
> — you can't forget them — and only accept declared fields as
> setters — you can't add unknown ones. See [Code Generation](code-generation.md).

---

## 📡 Syslog Connection Failures

```
audit: output "siem": dial tcp syslog.example.com:6514: connection refused
```

The syslog output dials the server immediately at startup. If the
server is unreachable, `NewLogger()` (or `outputconfig.Load()`) fails.

| Cause | Fix |
|-------|-----|
| **Server not running** | Start the syslog server before the application |
| **Wrong address/port** | Check `syslog.address` in your output YAML |
| **TLS certificate mismatch** | Verify `tls_ca` points to the correct CA that signed the server's certificate |
| **mTLS client cert rejected** | Verify `tls_cert` and `tls_key` are valid and accepted by the server |
| **Firewall blocking** | Check network connectivity to the syslog address and port |
| **TLS version mismatch** | If the server only supports TLS 1.2, set `tls_policy.allow_tls12: true` |

After startup, TCP and TLS connections are re-established
automatically on failure (up to `max_retries` attempts, default: 10).
Monitor `RecordSyslogReconnect` metrics to track reconnection events.

---

## 🌐 Webhook Events Not Delivered

```
audit: output "alerts": POST https://ingest.example.com/audit: 403 Forbidden
```

| Cause | Fix |
|-------|-----|
| **Missing authentication** | Set `headers: { Authorization: "Bearer <token>" }` in webhook YAML |
| **HTTPS required** | The webhook output requires `https://` by default. Set `allow_insecure_http: true` only for local development. |
| **SSRF protection blocking** | Private/loopback IPs are blocked by default. Set `allow_private_ranges: true` for local development. |
| **Server returning errors** | 4xx errors are not retried (client error). 5xx errors are retried up to `max_retries` times. Check the server-side logs. |
| **Buffer full** | The webhook has its own internal buffer. If events arrive faster than batches can be sent, events are dropped. Monitor `RecordWebhookDrop` and increase `buffer_size` if needed. |
| **Redirect blocked** | Webhook follows no redirects. Make sure the URL is the final endpoint, not a redirect. |

---

## 📁 File Output Not Writing

| Cause | Fix |
|-------|-----|
| **Parent directory doesn't exist** | The library creates the file but not the directory. Create the parent directory before starting. |
| **Permission denied** | Check file system permissions. Default file permissions are `0600`. |
| **Symlink in path** | The file output rejects paths containing symlinks (security measure). Use the resolved absolute path. |
| **Disk full** | Check available disk space. Rotation only triggers at `max_size_mb` — if the disk fills before that, writes fail. |
| **Path contains unexpanded env var** | If using `${VAR}` syntax, make sure the variable is set. Unset variables expand to empty string, which may create an invalid path. |

---

## 🧪 Goroutine Leak in Tests

```
goleak: found unexpected goroutines
```

If you use `goleak.VerifyNone(t)` (recommended), a leaked drain
goroutine will cause test failures.

| Cause | Fix |
|-------|-----|
| **`logger.Close()` not called** | The drain goroutine runs until `Close()` is called. Always call `Close()` in tests. |
| **`Close()` called too late** | `goleak` checks at test end. If `Close()` is deferred but another deferred function runs first, the goroutine may still be active. Put `Close()` as the first defer or use `t.Cleanup()`. |
| **Using `audittest.NewLogger`** | The `audittest` constructors register `t.Cleanup(logger.Close)` automatically — but you MUST call `logger.Close()` explicitly before assertions. The cleanup is a safety net, not a substitute. See [Testing](testing.md#️-close-before-assert--critical). |

---

## 📚 Further Reading

- [Error Reference](error-reference.md) — all sentinel errors with recovery guidance
- [Async Delivery](async-delivery.md) — buffering, drain, shutdown
- [Metrics & Monitoring](metrics-monitoring.md) — tracking drops and errors
- [Output Configuration](output-configuration.md) — YAML reference
