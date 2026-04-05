[&larr; Back to README](../README.md)

# Testing Audit Events in Your Application

- [What Is audittest?](#what-is-audittest)
- [Why a Test Package?](#why-a-test-package)
- [Quick Start](#quick-start)
- [Two Constructor Patterns](#two-constructor-patterns)
- [Recorded Event API](#recorded-event-api)
- [Metrics Assertions](#metrics-assertions)
- [Table-Driven Tests](#table-driven-tests)

## 🔍 What Is audittest?

The `audittest` package provides an in-memory audit logger for your
unit and integration tests. It captures events and metrics in memory for
assertion, with the same validation and async pipeline as production.

## ❓ Why a Test Package?

Testing audit logging without `audittest` requires ~25 lines of
boilerplate per test: implementing `audit.Output`, creating a full
logger, dealing with async drain timing, parsing raw JSON, and
asserting on `map[string]interface{}`.

`audittest` reduces this to one line:

```go
logger, events, metrics := audittest.NewLogger(t, taxonomyYAML)
```

## 🚀 Quick Start

```go
func TestCreateUser(t *testing.T) {
    logger, events, metrics := audittest.NewLogger(t, taxonomyYAML)

    svc := NewUserService(logger)
    svc.CreateUser("alice", "alice@example.com")

    logger.Close() // drain async buffer before asserting

    require.Equal(t, 1, events.Count())
    evt := events.Events()[0]
    assert.Equal(t, "user_create", evt.EventType)
    assert.True(t, evt.HasField("actor_id", "alice"))
    assert.Equal(t, 1, metrics.EventDeliveries("recorder", "success"))
}
```

### ⚠️ Close Before Assert — Critical

The audit logger delivers events asynchronously. Callers MUST call
`logger.Close()` before making assertions — the drain goroutine may
not have processed all events yet, and assertions on `events.Count()`
or `events.Events()` without draining first produce racy results.
`NewLogger` registers `t.Cleanup(logger.Close)` as a safety net
against goroutine leaks, but your explicit Close MUST come first.

## 🔧 Two Constructor Patterns

### NewLogger — full integration test

Uses your real taxonomy YAML. Generated typed builders work because
they compile from the same taxonomy:

```go
logger, events, metrics := audittest.NewLogger(t, taxonomyYAML)
```

### NewLoggerQuick — quick smoke test

Creates a permissive logger — any fields accepted, no required field
enforcement:

```go
logger, events, _ := audittest.NewLoggerQuick(t, "user_create", "auth_failure")
```

## 📋 Recorded Event API

| Method | Returns | Purpose |
|--------|---------|---------|
| `evt.EventType` | `string` | Event type name |
| `evt.Severity` | `int` | Resolved severity (0-10) |
| `evt.Fields` | `map[string]any` | Non-framework field values |
| `evt.Field(key)` | `any` | Single field value (nil if absent) |
| `evt.HasField(key, val)` | `bool` | Deep-equal check |
| `evt.RawJSON` | `[]byte` | Original serialised bytes |
| `evt.ParseErr` | `error` | Non-nil if JSON deserialisation failed; assert nil before inspecting other fields |

> **Note:** Always check `evt.ParseErr == nil` before asserting on
> other fields. A non-nil `ParseErr` means the formatter produced
> invalid JSON; other fields are zero-valued in that case.

## 📊 Metrics Assertions

```go
metrics.EventDeliveries("recorder", "success") // successful deliveries
metrics.ValidationErrors("user_create")        // validation rejections
metrics.BufferDrops()                          // buffer-full drops
metrics.OutputErrors("recorder")               // output write errors
```

## 📊 Table-Driven Tests

Use `events.Reset()` to clear captured events between sub-tests
without creating a new logger:

```go
for _, tc := range tests {
    t.Run(tc.name, func(t *testing.T) {
        events.Reset()
        svc.Do(tc.action)
        // assert on events for this sub-test only
    })
}
```

## 📚 Further Reading

- [Progressive Example: Testing](../examples/17-testing/) — three testing patterns
- [API Reference: audittest](https://pkg.go.dev/github.com/axonops/go-audit/audittest)
