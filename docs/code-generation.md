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
auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{
    "actor_id": "alice",
    "outcom":   "success",  // typo — runtime validation catches it, but only if tested
}))
```

With code generation:

```go
auditor.AuditEvent(NewUserCreateEvent("alice", "success"))
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
func NewUserCreateEvent(actorID string, outcome string) *UserCreateEvent

// Optional fields are chainable setters typed from the YAML `type:`
// annotation (default string)
func (e *UserCreateEvent) SetTargetID(v string) *UserCreateEvent
func (e *UserCreateEvent) SetReason(v string) *UserCreateEvent
func (e *UserCreateEvent) SetQuota(v int) *UserCreateEvent        // type: int
func (e *UserCreateEvent) SetCreatedAt(v time.Time) *UserCreateEvent // type: time
func (e *UserCreateEvent) SetIdleTimeout(v time.Duration) *UserCreateEvent // type: duration

// Implements audit.Event — pass directly to auditor.AuditEvent()
func (e *UserCreateEvent) EventType() string      // returns "user_create"
func (e *UserCreateEvent) Fields() audit.Fields    // returns the constructed field map

// Metadata accessors for introspection
func (e *UserCreateEvent) FieldInfo() UserCreateFields            // typed struct (compile-time field access)
func (e *UserCreateEvent) FieldInfoMap() map[string]audit.FieldInfo // flat map (audit.Event interface, dynamic lookup)
func (e *UserCreateEvent) Categories() []audit.CategoryInfo
func (e *UserCreateEvent) Description() string
```

### Usage

```go
// Type-safe — typos fail at compile time, and wrong value types too
err := auditor.AuditEvent(
    NewUserCreateEvent("alice", "success").
        SetTargetID("user-42").
        SetReason("admin request"),
)
```

### Typed Custom Fields

Every custom (non-reserved) field in the taxonomy may carry a
`type:` annotation to produce a Go-typed setter. Accepted values:

| YAML `type:` | Generated Go setter param | Notes |
|---|---|---|
| `string` (default when omitted) | `v string` | Fallback — no extra annotation needed |
| `int` | `v int` | Most audit counters; JSON-numeric on the wire |
| `int64` | `v int64` | Use when the value clearly exceeds 2³¹ |
| `float64` | `v float64` | Scores, rates, latencies (if stored as seconds) |
| `bool` | `v bool` | Flags, binary outcomes |
| `time` | `v time.Time` | Timestamps (RFC 3339 on the wire) |
| `duration` | `v time.Duration` | Elapsed times, TTLs |

Reserved standard fields (`actor_id`, `source_ip`, `dest_port`, …)
always use the library-authoritative Go type and reject any YAML
`type:` override — the generator's reserved-field table stays
canonical.

Example taxonomy:

```yaml
events:
  request_handled:
    fields:
      outcome:     {required: true}          # reserved → string
      actor_id:    {required: true}          # reserved → string
      endpoint:    {type: string}            # explicit string
      status_code: {type: int}               # typed int
      response_ms: {type: int64}             # typed int64
      received_at: {type: time}              # typed time.Time
      idle_timeout: {type: duration}         # typed time.Duration
      privileged:  {type: bool}              # typed bool
```

Unknown type values are rejected at taxonomy parse time with the
valid-set listed in the error message (e.g. `unknown type "strng"
(valid: string, int, int64, float64, bool, time, duration)`).

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
| `-standard-setters` | `all` | `all` = every builder gets a setter for every reserved standard field (IDE-autocomplete-friendly); `explicit` = only taxonomy-declared reserved fields produce setters (cuts generator output by ~80 % for small schemas) |

## ⚡ Performance

Generated builders satisfy the [`FieldsDonor`] extension interface via
the unexported `donateFields()` sentinel method. When an event reaches
[`Auditor.AuditEvent`] and is recognised as a donor, the auditor takes
ownership of the builder's `Fields` map — no defensive copy. Combined
with the W2 zero-copy drain pipeline (#497), this puts generated
builders on a path that achieves zero allocations per event on the
drain side after pool warm-up.

**Single-use rule:** generated builders are single-use per
`AuditEvent` call. Re-using the same builder for a second
`AuditEvent` is undefined behaviour — the auditor mutates the donated
`Fields` map (merging standard-field defaults) before serialisation.
Build a fresh builder per event.

For the full performance model, fast-path / slow-path comparison, and
benchmark methodology see [`docs/performance.md`](performance.md).

[`FieldsDonor`]: https://pkg.go.dev/github.com/axonops/audit#FieldsDonor
[`Auditor.AuditEvent`]: https://pkg.go.dev/github.com/axonops/audit#Auditor.AuditEvent

## 📚 Further Reading

- [Progressive Example: Code Generation](../examples/02-code-generation/) — complete working example
- [Taxonomy Validation](taxonomy-validation.md) — YAML schema reference
- [Performance: Fast Path and Slow Path](performance.md) — drain pipeline allocation model
- [ADR 0001: Fields Ownership Contract](adr/0001-fields-ownership-contract.md) — `FieldsDonor` design rationale
