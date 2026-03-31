# Code Generation Example

Define your audit events in a YAML file, generate type-safe Go
constants, and configure outputs in a separate YAML file. This is the
recommended workflow for go-audit — all subsequent examples follow it.

## What You'll Learn

- Why audit events are defined in YAML and embedded in the binary
- How `audit-gen` generates type-safe constants from your taxonomy
- The two-file pattern: `taxonomy.yaml` (events) + `outputs.yaml` (destinations)
- Loading output configuration with `outputconfig.Load`

## Prerequisites

- Go 1.26+
- Completed: [Basic](../basic/)

## Files

| File | Purpose |
|------|---------|
| `taxonomy.yaml` | Defines what events your application can produce |
| `outputs.yaml` | Defines where audit events are sent |
| `audit_generated.go` | Generated constants — committed, DO NOT EDIT |
| `main.go` | Loads both YAMLs, emits events using generated constants |

## Key Concepts

### Defining Events in YAML

In the [Basic](../basic/) example, we defined the taxonomy inline in Go.
That works, but real applications have dozens or hundreds of event types
with compliance requirements. A YAML file is easier for teams to review
and maintain:

```yaml
version: 1

categories:
  write:
    - user_create
    - user_delete
  read:
    - user_read
  security:
    - auth_failure
    - auth_success

default_enabled:
  - write
  - read
  - security

events:
  user_create:
    description: "A new user account was created"
    fields:
      outcome:
        required: true
      actor_id:
        required: true
      target_id: {}
      reason: {}

  # ... (auth_failure, auth_success, user_read, user_delete defined similarly)
```

Each event belongs to a category and declares its fields in a `fields:`
map. Fields with `required: true` must be present in every `Audit()`
call; all other fields are optional. The `description` field is used by
`audit-gen` as the Go doc comment for the generated constant.

**`default_enabled` is critical.** It lists which categories are active
when the logger starts. If you omit it, all categories are disabled and
every event is silently discarded — the worst failure mode for a
compliance tool. Always list the categories your application needs.

### Why Embed the Taxonomy?

The taxonomy is loaded into the binary at compile time using
`//go:embed`:

```go
//go:embed taxonomy.yaml
var taxonomyYAML []byte

tax, err := audit.ParseTaxonomyYAML(taxonomyYAML)
```

This is deliberate. The taxonomy defines your audit contract — what
events exist, what fields are required. It's part of your source code:

- **Self-contained binary** — no "file not found" in production
- **Immutable after build** — the event schema can't be accidentally
  modified on disk after deployment
- **Version-controlled** — changes go through code review, not config
  management

### Generating Constants with audit-gen

`audit-gen` reads your taxonomy YAML and generates Go constants:

```go
//go:generate go run github.com/axonops/go-audit/cmd/audit-gen -input taxonomy.yaml -output audit_generated.go -package main
```

This produces `audit_generated.go` with three groups of constants:

```go
const (
    EventUserCreate  = "user_create"   // A new user account was created
    EventAuthFailure = "auth_failure"  // An authentication attempt failed
    // ...
)

const (
    CategoryWrite    = "write"
    CategorySecurity = "security"
    // ...
)

const (
    FieldActorID  = "actor_id"
    FieldOutcome  = "outcome"
    // ...
)
```

Now a typo like `EventUserCrate` fails the build instead of silently
passing as a runtime validation error. In a large codebase, this
prevents an entire class of bugs.

**Code generation is optional.** The basic example used raw strings and
it worked fine. But once you have more than a handful of event types,
generated constants are worth the small overhead of running
`go generate` when the taxonomy changes.

The generated file is committed to version control, so the example
compiles without running `go generate` first. `go generate` runs
`audit-gen` via `go run`, which downloads and caches the tool
automatically — no separate install step.

### Lifecycle Events

The generated file includes constants for two built-in events:
`EventStartup` and `EventShutdown` (in `CategoryLifecycle`). You don't
define these in your taxonomy — go-audit injects them automatically.

When you call `logger.Close()`, the library emits a shutdown event
before flushing outputs. This creates a tamper-evident audit trail: if
the log has a startup event but no shutdown, either the application
crashed or someone tampered with the log. The [CRUD API](../crud-api/)
example demonstrates explicit startup events with
`logger.EmitStartup()`.

### Null Fields in JSON Output

You'll notice `"reason":null` in the expected output below. When the
taxonomy declares a field as `optional`, the JSON formatter emits it as
`null` if you don't set it. This makes every event structurally
consistent — consumers can parse all events with the same schema
regardless of which optional fields were populated.

If you prefer to omit null fields entirely, the JSON formatter supports
an `omit_empty` option (shown in the [Formatters](../formatters/)
example).

### Configuring Outputs in YAML

Where events are sent is defined in a separate file, `outputs.yaml`:

```yaml
version: 1
outputs:
  console:
    type: stdout
```

This is loaded at startup with `outputconfig.Load`:

```go
//go:embed outputs.yaml
var outputsYAML []byte

result, err := outputconfig.Load(outputsYAML, &tax, nil)
```

`Load` returns options you pass straight to `NewLogger`:

```go
opts := []audit.Option{audit.WithTaxonomy(tax)}
opts = append(opts, result.Options...)

logger, err := audit.NewLogger(audit.Config{Version: 1, Enabled: true}, opts...)
```

### Two Files, Two Purposes

The pattern from here on is always the same:

| File | Purpose | Changes when... |
|------|---------|-----------------|
| `taxonomy.yaml` | What events exist | You add/remove event types or fields |
| `outputs.yaml` | Where events are sent | You add outputs, change destinations, adjust routing |

They're separate because they change for different reasons. Adding a new
event type doesn't affect where events are sent. Adding a syslog output
doesn't change what events exist.

### Using Generated Constants

```go
if err := logger.Audit(EventUserCreate, audit.Fields{
    FieldOutcome:  "success",
    FieldActorID:  "alice",
    FieldTargetID: "user-42",
}); err != nil {
    log.Printf("audit error: %v", err)
}
```

Compare with the raw-string approach from the basic example:

```go
logger.Audit("user_create", audit.Fields{
    "outcome":  "success",
    "actor_id": "alice",
})
```

Both work. The generated constants add compile-time safety without
changing how the library behaves at runtime.

## Run It

```bash
# Run the example (audit_generated.go is already committed):
go run .

# To regenerate after editing taxonomy.yaml:
go generate .
```

## Expected Output

```
--- Using generated constants ---
{"timestamp":"...","event_type":"user_create","severity":5,"actor_id":"alice","outcome":"success","reason":null,"target_id":"user-42"}
{"timestamp":"...","event_type":"auth_failure","severity":5,"actor_id":"unknown","outcome":"failure","reason":"invalid credentials","source_ip":"192.168.1.100"}
{"timestamp":"...","event_type":"user_read","severity":5,"outcome":"success","actor_id":"bob"}
```

## Previous

[Basic](../basic/)

## Next

[File Output](../file-output/) — write events to a log file with
rotation and size limits.
