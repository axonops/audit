# Migrating from Application Logging

This guide helps teams add audit logging alongside existing application
logging (slog, zap, zerolog).

## Audit Logging vs Application Logging

| | Application Logging | Audit Logging |
|---|---|---|
| **Purpose** | Debugging, observability | Compliance, forensics, accountability |
| **Content** | Technical details (errors, stack traces) | Who did what, when, to which resource |
| **Guarantees** | Best-effort | Schema-enforced, validated |
| **Retention** | Days to weeks | Months to years |

**You need both.** Audit logging does not replace application logging.

## Side-by-Side Coexistence

go-audit and your application logger run independently:

```go
// Application logger (slog)
slog.Info("handling request", "method", r.Method, "path", r.URL.Path)

// Audit logger (go-audit)
logger.AuditEvent(audit.NewEventKV("user_create",
    "outcome", "success",
    "actor_id", userID,
    "target_id", newUser.ID,
))
```

There is no conflict — they write to different destinations with
different formats.

## Pattern Mapping

| slog/zap Pattern | go-audit Equivalent |
|------------------|---------------------|
| `slog.Info("user created", ...)` | `logger.AuditEvent(NewUserCreateEvent(...))` |
| `zap.String("user_id", id)` | `.SetActorID(id)` on the generated builder |
| `logger.With("request_id", rid)` | `.SetRequestID(rid)` on the event |
| `slog.Error("auth failed", ...)` | `logger.AuditEvent(NewAuthFailureEvent(...))` |

## When to Audit vs When to Log

**Audit** (go-audit):
- User authentication success/failure
- Data creation, modification, deletion
- Permission changes
- Configuration changes
- Access to sensitive data

**Log** (slog/zap):
- HTTP request tracing
- Database query timing
- Cache hit/miss ratios
- Error stack traces
- Debug information

## Redirecting go-audit Diagnostics

go-audit uses `log/slog` for its own diagnostic messages (startup,
shutdown, buffer drops). By default these go to `slog.Default()`.
Redirect them with `WithLogger`:

```go
// Send audit library diagnostics to a specific logger
auditDiag := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
    Level: slog.LevelWarn, // only warnings and errors
}))

logger, err := audit.NewLogger(
    audit.WithLogger(auditDiag),
    // ... other options
)
```
