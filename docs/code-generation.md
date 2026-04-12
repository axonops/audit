[&larr; Back to README](../README.md)

# Code Generation with audit-gen

- [What Is audit-gen?](#what-is-audit-gen)
- [Why Code Generation?](#why-code-generation)
- [Workflow](#workflow)
- [What Gets Generated](#what-gets-generated)
- [CLI Flags](#cli-flags)

## 🔍 What Is audit-gen?

`audit-gen` is a CLI tool that reads your taxonomy YAML and generates
type-safe Go code: constants for event types, field names, and
categories, plus per-event builder structs with required-field
constructors.

## ❓ Why Code Generation?

Without code generation, emitting an audit event looks like this:

```go
logger.AuditEvent(audit.NewEvent("user_create", audit.Fields{
    "actor_id": "alice",
    "outcom":   "success",  // typo — runtime validation catches it, but only if tested
}))
```

With code generation:

```go
logger.AuditEvent(NewUserCreateEvent("alice", "success"))
// "outcom" typo is impossible — required fields are constructor parameters
// Unknown field "NewUserCrateEvent" fails at compile time
```

Required fields become constructor parameters — you cannot forget them.
Optional fields are chainable setters. A typo in an event name or field
name is a compile error, not a runtime surprise.

## ⚙️ Workflow

1. Define your taxonomy in `taxonomy.yaml`
2. Add a `go:generate` directive to your Go code
3. Run `go generate ./...`
4. Commit the generated file to version control

### Step 1: Add the go:generate Directive

Add this comment to any `.go` file in your package (typically
`main.go` or a dedicated `generate.go`):

```go
//go:generate go run github.com/axonops/audit/cmd/audit-gen -input taxonomy.yaml -output audit_generated.go -package main
```

### Step 2: Run Code Generation

```bash
go generate ./...
```

`go run` automatically downloads and caches `audit-gen` — no
separate install step needed. The generated file appears in the
same directory as the `go:generate` directive.

### Integrating into Your Development Process

**Makefile:**
```makefile
generate:
	go generate ./...

# Run generation before build
build: generate
	go build ./...
```

**CI pipeline (GitHub Actions):**
```yaml
- name: Generate audit code
  run: go generate ./...
- name: Check generated code is committed
  run: git diff --exit-code -- '**/audit_generated.go'
```

The CI step ensures the generated file is always committed and up
to date. If someone changes `taxonomy.yaml` but forgets to
regenerate, the build fails.

**IDE:** Most Go IDEs (VS Code with gopls, GoLand) recognise
`go:generate` directives. In VS Code, run `Go: Generate` from the
command palette. In GoLand, right-click the file and select
"Run go generate."

### What Gets Generated

For a taxonomy with `user_create` (required: `actor_id`, `outcome`)
and `auth_failure` events:

**Constants:**
```go
const (
    EventUserCreate  = "user_create"
    EventAuthFailure = "auth_failure"

    CategoryWrite    = "write"
    CategorySecurity = "security"

    FieldActorID  = "actor_id"
    FieldOutcome  = "outcome"
    FieldSourceIP = "source_ip"
)
```

**Typed Builder:**
```go
// Required fields are constructor parameters — compile-time safety
func NewUserCreateEvent(actorID any, outcome any) *UserCreateEvent

// Optional fields are chainable setters
func (e *UserCreateEvent) SetTargetID(v any) *UserCreateEvent
func (e *UserCreateEvent) SetReason(v any) *UserCreateEvent

// Implements audit.Event — pass directly to logger.AuditEvent()
func (e *UserCreateEvent) EventType() string      // returns "user_create"
func (e *UserCreateEvent) Fields() audit.Fields    // returns the constructed field map

// Metadata accessors for introspection
func (e *UserCreateEvent) FieldInfo() UserCreateFields
func (e *UserCreateEvent) Categories() []audit.CategoryInfo
func (e *UserCreateEvent) Description() string
```

### Usage

```go
// Type-safe — typos fail at compile time
err := logger.AuditEvent(
    NewUserCreateEvent("alice", "success").
        SetTargetID("user-42").
        SetReason("admin request"),
)
```

## ⌨️ CLI Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-input` | (required) | Path to taxonomy YAML file |
| `-output` | (required) | Output Go file path; use `-` for stdout |
| `-package` | (required) | Go package name for the generated file |
| `-types` | `true` | Generate event type constants |
| `-fields` | `true` | Generate field name constants |
| `-categories` | `true` | Generate category constants |
| `-labels` | `true` | Generate sensitivity label constants |
| `-builders` | `true` | Generate typed event builder structs |

## ⚡ Performance

Generated builders allocate one `audit.Fields` map per event
(~1 allocation). This is the cost of type safety — the library
validates the event against the taxonomy just like untyped events.

## 📚 Further Reading

- [Progressive Example: Code Generation](../examples/02-code-generation/) — complete working example
- [Taxonomy Validation](taxonomy-validation.md) — YAML schema reference
