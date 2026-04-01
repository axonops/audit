# Testing Example

How to test code that uses go-audit. The `audittest` package provides
an in-memory test logger that captures events and metrics for assertion.

## What You'll Learn

- Using `audittest.NewLogger` for full integration tests
- Using `audittest.NewLoggerQuick` for smoke tests without a taxonomy
- Asserting on captured events and metrics
- Table-driven tests with `Reset()`
- Testing validation error paths

## Prerequisites

- Go 1.26+
- Completed: [CRUD API](../09-crud-api/)

## Files

| File | Purpose |
|------|---------|
| `taxonomy.yaml` | Event definitions (embedded in binary) |
| `audit_generated.go` | Generated typed builders and constants |
| `main.go` | UserService with audit logging |
| `main_test.go` | Tests using audittest |

## Key Concepts

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
    logger, events, metrics := audittest.NewLogger(t, taxonomyYAML)

    svc := NewUserService(logger)
    svc.CreateUser("alice", "alice@example.com")

    logger.Close() // drain async buffer

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
    logger, events, _ := audittest.NewLoggerQuick(t, "user_create")

    svc.CreateUser("alice", "alice@example.com")

    logger.Close()
    assert.Equal(t, 1, events.Count())
}
```

`NewLoggerQuick` creates a permissive logger — any fields accepted,
no required field enforcement.

### Pattern 3: Metrics Assertions

Verify that metrics are recorded correctly — validation errors,
buffer drops, delivery counts:

```go
func TestValidationError(t *testing.T) {
    logger, _, metrics := audittest.NewLogger(t, taxonomyYAML)

    // Emit event missing required field
    err := logger.AuditEvent(audit.NewEvent("user_create", audit.Fields{
        "outcome": "success",
        // actor_id missing — validation error
    }))
    require.Error(t, err)

    logger.Close()
    assert.Equal(t, 1, metrics.ValidationErrors("user_create"))
}
```

### Close Before Assert

The audit logger delivers events asynchronously. Call
`logger.Close()` before making assertions to drain the buffer.
`NewLogger` registers `t.Cleanup(logger.Close)` as a safety net
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

### Dependency Injection

The key to testable audit logging is dependency injection. Your
service takes `*audit.Logger` as a parameter — in production you
pass a real logger, in tests you pass the audittest logger:

```go
type UserService struct {
    logger *audit.Logger
}

func NewUserService(logger *audit.Logger) *UserService {
    return &UserService{logger: logger}
}
```

## Run the Tests

```bash
go test -v .
```

## Previous

[CRUD API](../09-crud-api/) — complete REST API with Postgres,
five outputs, and Docker Compose.
