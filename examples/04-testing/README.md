[← Back to examples](../README.md)

> **Previous:** [03 — File Output](../03-file-output/) |
> **Next:** [05 — Formatters](../05-formatters/)

# Example 04: Testing

How to test code that uses audit. The `audittest` package provides
an in-memory test logger that captures events and metrics for assertion.

## What You'll Learn

- Using `audittest.New` for full integration tests
- Using `audittest.NewQuick` for smoke tests with a permissive taxonomy
- Asserting on captured events and metrics
- Table-driven tests with `Reset()`
- Testing validation error paths

## Prerequisites

- Go 1.26+
- Completed: [Capstone](../17-capstone/)

## Files

| File | Purpose |
|------|---------|
| `taxonomy.yaml` | Event definitions (embedded in binary) |
| `audit_generated.go` | Generated typed builders and constants |
| `main.go` | UserService with audit logging |
| `main_test.go` | Tests using audittest |

## Key Concepts

The patterns below address the core challenge of testing async audit
pipelines. Each pattern maps to a distinct testing need.

### The Testing Problem

Your service emits audit events. You need to verify in unit tests
that the right events are emitted with the right fields. Without
`audittest`, you'd need to create a mock output, wire up a full
logger, deal with async timing, parse raw JSON, and assert on
untyped maps. That's ~25 lines of boilerplate per test.

### The Solution: audittest

The `audittest` package gives you an in-memory audit logger that
works exactly like production — same validation, same taxonomy
enforcement, same async pipeline — but events land in a `Recorder`
instead of being written anywhere.

### Pattern 1: Full Integration Test

Use the same taxonomy YAML your production code uses. Generated
typed builders work in tests because they're compiled from the same
taxonomy.

```go
func TestCreateUser(t *testing.T) {
    logger, events, metrics := audittest.New(t, taxonomyYAML)

    svc := NewUserService(logger)
    err := svc.CreateUser("alice", "alice@example.com")
    require.NoError(t, err)

    auditor.Close() // drain async buffer

    require.Equal(t, 1, events.Count())
    evt := events.Events()[0]
    assert.Equal(t, EventUserCreate, evt.EventType)
    assert.True(t, evt.HasField(FieldActorID, "alice"))
    assert.Equal(t, 1, metrics.EventDeliveries("recorder", "success"))
}
```

### Pattern 2: Quick Smoke Test

When you just want to verify an event was emitted without caring
about field validation:

```go
func TestAuditHappens(t *testing.T) {
    logger, events, _ := audittest.NewQuick(t, "user_create")

    svc := NewUserService(logger)
    _ = svc.CreateUser("alice", "alice@example.com")

    auditor.Close()
    assert.Equal(t, 1, events.Count())
}
```

`NewQuick` creates a permissive logger — any fields accepted,
no required field enforcement.

### Pattern 3: Metrics Assertions

Verify that metrics are recorded correctly — validation errors,
buffer drops, delivery counts:

```go
func TestValidationError(t *testing.T) {
    logger, _, metrics := audittest.New(t, taxonomyYAML)

    // Emit event missing required field "actor_id"
    err := auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{
        "outcome": "success",
        // actor_id missing — validation error
    }))
    require.Error(t, err)
    assert.Contains(t, err.Error(), "missing required")

    auditor.Close()
    assert.Equal(t, 1, metrics.ValidationErrors("user_create"))
}
```

### Close Before Assert

The audit logger delivers events asynchronously. Call
`auditor.Close()` before making assertions to drain the buffer.
`New` registers `t.Cleanup(auditor.Close)` as a safety net
against goroutine leaks, but your assertions need the explicit
Close to see events.

### Table-Driven Tests with Reset

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

When sharing an auditor across sub-tests without calling Close(), use
`require.Eventually` to wait for the async drain.

### RecordedEvent API

Each captured event provides structured access:

| Method | Returns | Purpose |
|--------|---------|---------|
| `evt.EventType` | `string` | Event type name |
| `evt.Severity` | `int` | Resolved severity (0-10) |
| `evt.Timestamp` | `time.Time` | When the event was processed |
| `evt.Fields` | `map[string]any` | Non-framework field values |
| `evt.Field(key)` | `any` | Single field value (nil if absent) |
| `evt.HasField(key, val)` | `bool` | Deep-equal check on field value |
| `evt.RawJSON` | `[]byte` | Original serialised bytes |
| `evt.ParseErr` | `error` | JSON deserialisation error (nil on success) |

### Dependency Injection

The key to testable audit logging is dependency injection. Your
service takes `*audit.Auditor` as a parameter — in production you
pass a real logger, in tests you pass the audittest logger:

```go
type UserService struct {
    logger *audit.Auditor
}

func NewUserService(logger *audit.Auditor) *UserService {
    return &UserService{logger: logger}
}
```

## Run the Tests

```bash
go test -v .
```

## Expected Output

```
=== RUN   TestCreateUser_EmitsAuditEvent
--- PASS: TestCreateUser_EmitsAuditEvent
=== RUN   TestLogin_Failure_EmitsAuthEvent
--- PASS: TestLogin_Failure_EmitsAuthEvent
=== RUN   TestLogin_Success_NoAuditEvent
--- PASS: TestLogin_Success_NoAuditEvent
=== RUN   TestAuditEventEmitted_Quick
--- PASS: TestAuditEventEmitted_Quick
=== RUN   TestValidationError_MissingRequiredField
--- PASS: TestValidationError_MissingRequiredField
PASS
```

All five tests pass, each demonstrating a different testing pattern.
You will also see `INFO audit:` lifecycle messages from logger creation
and shutdown — these are normal.

## Further Reading

- [Testing](../../docs/testing.md) — full audittest reference and testing patterns
- [Troubleshooting](../../docs/troubleshooting.md) — common issues and solutions

