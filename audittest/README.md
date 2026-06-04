# audittest — test helpers for code that emits audit events

[![Go Reference][godoc-badge]][godoc]

In-memory test auditor for unit and integration tests of applications
that use the `audit` library. Captures every emitted event in a
`Recorder` you can assert against, captures every metrics call in a
`MetricsRecorder`, and runs synchronously by default so assertions
do not race the drain goroutine.

> **Module path**: `github.com/axonops/audit/audittest`
> **Status**: pre-release (v0.x)
> **Documentation**: [Testing guide][testing-doc] · [godoc examples][godoc]

## Why

You have an HTTP handler, a gRPC service, or a background worker that
calls `auditor.AuditEvent(...)`. In tests you need to assert:

- The expected event was emitted.
- The expected fields were set.
- Nothing was emitted when nothing should have been.
- Sensitivity-label stripping behaved as configured.
- Metrics (submitted count, validation errors, output errors) match
  the expected pattern.

You **could** spin up a real auditor with a file output, run the test,
read the file, and parse it. That's a lot of moving parts (file I/O,
goroutine timing, cleanup, JSON parsing) for a unit test.

`audittest` gives you a real `*audit.Auditor` — same validation, same
taxonomy enforcement, same options — but with an in-memory `Recorder`
as the output and synchronous delivery as the default. Events are
parsed back into a structured `RecordedEvent` so you assert on Go
values, not raw JSON. No goroutine, no files, no `time.Sleep`, no
Close-before-assert ceremony.

This package is for **library consumers**. It is not for testing the
audit library itself — that work lives in `internal/testhelper`.

## Install

```bash
go get github.com/axonops/audit/audittest
```

## Quick start

```go
package myservice_test

import (
    "testing"

    "github.com/axonops/audit"
    "github.com/axonops/audit/audittest"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

var taxonomyYAML = []byte(`
version: 1
categories:
  write:
    - user_create
events:
  user_create:
    fields:
      outcome: {required: true}
      actor_id: {required: true}
`)

func TestUserCreateEmitsAuditEvent(t *testing.T) {
    auditor, events, metrics := audittest.New(t, taxonomyYAML)

    // Code under test.
    svc := NewUserService(auditor)
    err := svc.CreateUser(ctx, "alice")
    require.NoError(t, err)

    // Synchronous by default — events are already in the Recorder.
    require.Equal(t, 1, events.Count())

    evt := events.RequireEvent(t, "user_create")
    assert.Equal(t, "alice", evt.StringField("actor_id"))
    assert.Equal(t, "success", evt.StringField("outcome"))

    // And metrics were recorded.
    assert.Equal(t, 1, metrics.SubmittedCount())
}
```

`audittest.New` returns three things:

- `*audit.Auditor` — pass it into your service the same way you would
  in production.
- `*audittest.Recorder` — read events out of it after the test runs
  the code under test.
- `*audittest.MetricsRecorder` — already wired in via
  `audit.WithMetrics`; query it for submission counts, output errors,
  validation errors, etc.

`tb.Cleanup` is registered automatically; the auditor closes when the
test finishes.

## Even less ceremony: `NewQuick`

When you do not care about taxonomy validation and just want to assert
that some event types were emitted:

```go
func TestThing(t *testing.T) {
    auditor, events, _ := audittest.NewQuick(t, "user_create", "user_delete")

    _ = auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{
        "anything": "goes",
    }))

    events.RequireEvent(t, "user_create")
}
```

`NewQuick` builds a permissive taxonomy on the fly — every listed
event type accepts any fields, no required fields, no validation
errors. Use it for tests that exercise emission paths but do not
care about field shape.

## Assertions

`Recorder` exposes a fluent assertion API:

```go
// Counts and indexing.
events.Count()
events.Events()             // slice snapshot
events.First()              // (RecordedEvent, ok)
events.Last()               // (RecordedEvent, ok)

// Lookup.
events.FindByType("user_create")
events.FindByField("actor_id", "alice")

// Hard assertions (call tb.Fatal on mismatch).
events.RequireEvents(t, 3)
events.RequireEvent(t, "user_create")
events.RequireEmpty(t)

// Soft assertion (call tb.Error, allow further checks).
events.AssertContains(t, "user_create", audit.Fields{"actor_id": "alice"})
```

Individual `RecordedEvent` values have typed accessors that handle
the JSON round-trip (numbers come back as `float64`):

```go
evt.StringField("actor_id")  // ""
evt.IntField("retry_count")  // 0  (handles float64 → int)
evt.FloatField("amount")     // 0.0
evt.BoolField("first_login") // false
evt.Field("anything")        // any
evt.HasField("k", v)         // reflect.DeepEqual
evt.UserFields()             // strips framework fields (host, app_name, pid, …)
```

## Table-driven tests

Reset between sub-tests instead of creating a new auditor each time:

```go
auditor, events, _ := audittest.New(t, taxonomyYAML)

for _, tc := range []struct {
    name string
    in   request
    want string
}{
    {"alice", request{user: "alice"}, "alice"},
    {"bob",   request{user: "bob"},   "bob"},
} {
    t.Run(tc.name, func(t *testing.T) {
        events.Reset()

        handle(auditor, tc.in)

        evt := events.RequireEvent(t, "user_create")
        assert.Equal(t, tc.want, evt.StringField("actor_id"))
    })
}
```

## Async tests

The default is synchronous. If you need to exercise the actual async
pipeline — drain timeout, buffer backpressure, ordering under
concurrency — opt in with `WithAsync` and use `WaitForN` instead of
asserting immediately:

```go
auditor, events, _ := audittest.New(t, taxonomyYAML, audittest.WithAsync())

go emitBurst(auditor) // 100 events from a goroutine

if !events.WaitForN(t, 100, 2*time.Second) {
    t.Fatalf("timed out waiting for events, got %d", events.Count())
}
```

`WaitForN` polls at 10 ms, returns `true` as soon as the target is
reached, `false` on timeout. Pass a larger timeout for slower CI.

## Sensitivity-label stripping

Verify that a compliance output does **not** see PII-labelled fields:

```go
var taxonomyYAML = []byte(`
version: 1
sensitivity:
  labels:
    pii:
      fields: [email]
categories: {write: [user_create]}
events:
  user_create:
    fields:
      actor_id: {required: true}
      email: {}
`)

auditor, events, _ := audittest.New(t, taxonomyYAML,
    audittest.WithExcludeLabels("recorder", "pii"),
)

_ = auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{
    "actor_id": "alice",
    "email":    "alice@example.com",
}))

evt := events.Events()[0]
assert.Equal(t, "alice", evt.StringField("actor_id"))
assert.Nil(t, evt.Field("email")) // stripped before delivery
```

The string `"recorder"` must match the recorder's name — the default
is `"recorder"` (or whatever you pass to `NewNamedRecorder`).

## Options

| Option | Purpose |
|---|---|
| `WithValidationMode(mode)` | Override validation mode (default: `ValidationStrict`) |
| `WithSync()` / `WithAsync()` | Toggle synchronous (default) / async delivery |
| `WithDisabled()` | No-op auditor — accepts events but never delivers |
| `WithExcludeLabels(name, ...)` | Strip taxonomy-labelled fields before delivery to the named output |
| `WithVerbose()` | Re-enable auditor diagnostic logs (silenced by default) |
| `WithAuditOption(opt)` | Pass through any `audit.Option` not covered above |

`WithAuditOption` is the escape hatch — use it for `audit.WithAppName`,
`audit.WithHost`, `audit.WithFormatter`, or anything else that does not
have a dedicated `audittest.With*` helper.

## TLS test certificates

For tests that exercise the syslog/webhook/Loki/Splunk outputs against
local TLS endpoints, the package also ships `GenerateTestCerts(tb)` —
a self-signed CA plus server and client certificates written to
`tb.TempDir`. ECDSA P-256, one-hour expiry, cleaned up automatically.

```go
certs := audittest.GenerateTestCerts(t)
// certs.CAPath, certs.CertPath, certs.KeyPath, certs.ClientCert, certs.ClientKey
// certs.TLSCfg is a ready-to-use server tls.Config
```

This exists because Go's `internal/` mechanism is module-scoped — the
core's `internal/testhelper` is not visible to the `file`, `syslog`,
`webhook`, etc. sub-modules. `audittest` is the public sibling that
the sub-modules' test code imports for shared TLS plumbing.

## See also

- **[docs/testing.md][testing-doc]** — the broader testing guide for
  audit-enabled services
- **[godoc examples][godoc]** — runnable examples for `New`, `NewQuick`,
  `WaitForN`, `WithExcludeLabels`
- **[github.com/axonops/audit][audit-godoc]** — the core library

[godoc]: https://pkg.go.dev/github.com/axonops/audit/audittest
[godoc-badge]: https://pkg.go.dev/badge/github.com/axonops/audit/audittest.svg
[audit-godoc]: https://pkg.go.dev/github.com/axonops/audit
[testing-doc]: https://github.com/axonops/audit/blob/main/docs/testing.md
