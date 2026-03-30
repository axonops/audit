# Formatters Example

Output the same events as JSON and CEF side by side, with a custom
severity function that maps security events to higher CEF severity.

## What You'll Learn

- Using per-output formatters via `WithNamedOutput`
- Configuring `CEFFormatter` with `Vendor`, `Product`, `Version`
- Writing a `SeverityFunc` to control CEF severity per event type
- How nil formatter defaults to JSON

## Prerequisites

- Go 1.26+
- Completed: [Event Routing](../event-routing/)

## Files

| File | Purpose |
|------|---------|
| `main.go` | Two file outputs with JSON and CEF formatters |

## Run It

```bash
go run .
```

## Expected Output

```
--- json-audit.log ---
{"timestamp":"...","event_type":"user_create","actor_id":"alice","outcome":"success"}
{"timestamp":"...","event_type":"auth_failure","actor_id":"unknown","outcome":"failure"}
{"timestamp":"...","event_type":"auth_success","actor_id":"bob","outcome":"success"}

--- cef-audit.log ---
CEF:0|Example|AuditDemo|1.0|user_create|user_create|3|rt=... act=user_create suser=alice outcome=success
CEF:0|Example|AuditDemo|1.0|auth_failure|auth_failure|8|rt=... act=auth_failure suser=unknown outcome=failure
CEF:0|Example|AuditDemo|1.0|auth_success|auth_success|8|rt=... act=auth_success suser=bob outcome=success
```

Notice the severity column: `user_create` is 3 (low), while
`auth_failure` and `auth_success` are 8 (high). The `suser` extension
key is mapped from `actor_id` by `DefaultCEFFieldMapping`.

## What's Happening

1. **Per-output formatters**: the third argument to `WithNamedOutput` is
   an optional `Formatter`. When nil, the logger's default formatter is
   used (JSON). When set, it overrides the default for that output only.

2. **CEFFormatter** produces Common Event Format lines compatible with
   SIEM tools (Splunk, ArcSight, QRadar). The `Vendor|Product|Version`
   triple identifies your application in the CEF header.

3. **SeverityFunc** receives the event type name and returns a CEF
   severity (0-10). Security events get 8; business events get 3. If nil,
   all events default to severity 5.

4. **JSONFormatter** is the default. You can customize it with
   `Timestamp: audit.TimestampUnixMillis` or `OmitEmpty: true`.

## Next

[Middleware](../middleware/) -- automatic audit logging for HTTP handlers.
