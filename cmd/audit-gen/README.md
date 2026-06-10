# audit-gen — code generator for type-safe audit event builders

[![Go Reference][godoc-badge]][godoc]

A command-line code generator for the
[`github.com/axonops/audit`][parent] library. Reads a YAML taxonomy
file and emits one of four artifact types: typed Go event builders
(default), a JSON Schema validator, a CEF mapping template, or a
complete Splunk Technology Add-on directory tree.

> **Module path**: `github.com/axonops/audit/cmd/audit-gen`
> **Status**: pre-release (v0.x)
> **Documentation**: [docs/code-generation.md][cg-doc] · [examples/02-code-generation/][cg-example]

## Why

Without code generation, emitting an event is a `map[string]any`
keyed by raw strings:

```go
auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{
    "actor_id": "alice",
    "outcom":   "success", // typo — caught only at runtime
}))
```

A typo in the event name, a missing required field, or a stale
field name compiles cleanly and fails — silently or at runtime —
later. For an audit-grade event stream that's not acceptable.

`audit-gen` reads the taxonomy you would have written by hand and
generates:

- `const` blocks for every event type, category, field name, and
  sensitivity label
- Typed builders like `NewUserCreateEvent(actorID, outcome)` whose
  required fields are constructor parameters — you cannot forget
  them — and whose optional fields are chainable setters
- A compile-time map of `event type → required/optional fields`

This converts every "did I name this field correctly?" question
from a runtime check into a compile-time check.

`audit-gen` only generates code. To gate `outputs.yaml` against the
same taxonomy at deploy time, use the sibling
[`audit-validate`](../audit-validate/) tool.

## Install

```bash
# As a binary (recommended for CI):
go install github.com/axonops/audit/cmd/audit-gen@latest

# Or via go run (one-shot, no install):
go run github.com/axonops/audit/cmd/audit-gen@latest -input taxonomy.yaml \
    -output audit_generated.go -package mypackage
```

Pre-built binaries for `linux/{amd64,arm64}`, `darwin/{amd64,arm64}`,
and `windows/amd64` are attached to every release tag at
<https://github.com/axonops/audit/releases>.

Requires Go 1.26+ when installing from source.

## Usage

```bash
audit-gen -input <taxonomy.yaml> -output <path|-> -package <name> [flags]
```

| Flag | Default | Effect |
|------|---------|--------|
| `-input` | _(required)_ | Path to the taxonomy YAML file. |
| `-output` | _(required)_ | Output path, or `-` for stdout. For `-format=splunk-ta`, must be a directory. |
| `-package` | _(required for `-format=go`)_ | Go package name for the generated source file. |
| `-format` | `go` | Output format: `go`, `json-schema`, `cef-template`, `splunk-ta`. |
| `-header` | auto | File header. Default is a `DO NOT EDIT` banner with the input filename. |
| `-types` | `true` | Emit event-type constants. |
| `-fields` | `true` | Emit field-name constants. |
| `-categories` | `true` | Emit category constants. |
| `-labels` | `true` | Emit sensitivity-label constants. |
| `-builders` | `true` | Emit typed event builder structs. |
| `-standard-setters` | `all` | Reserved-field setter emission: `all` (every builder gets every reserved setter) or `explicit` (only taxonomy-declared reserved fields). |
| `-vendor-product` | `AxonOps:Audit` | CIM `vendor_product` for the `splunk-ta` format. |
| `-splunk-ta-name` | `TA-axonops-audit` | Splunk app id for the `splunk-ta` format (must match the output directory basename for AppInspect). |
| `-splunk-ta-version` | `0.1.0` | Version stamped into `app.conf` for the `splunk-ta` format. |
| `-version` | — | Print version and exit. |

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Success. |
| `1` | Invalid arguments or missing required flags. |
| `2` | YAML parse error or taxonomy validation failure. |
| `3` | Output file write error. |

## Quick start

Given `taxonomy.yaml`:

```yaml
version: 1
categories:
  write:
    severity: 3
    events: [user_create]
events:
  user_create:
    description: "A new user account was created"
    fields:
      outcome:  { required: true }
      actor_id: { required: true }
```

Generate:

```bash
audit-gen -input taxonomy.yaml \
    -output audit_generated.go \
    -package mypackage
```

The generated `audit_generated.go` contains:

```go
// (abbreviated — see examples/02-code-generation/audit_generated.go
// for the full canonical layout)
const (
    // EventUserCreate — A new user account was created
    EventUserCreate = "user_create"

    FieldActorID = "actor_id"
    FieldOutcome = "outcome"
    // ... plus every reserved standard field
)
```

…and a typed builder you call like this:

```go
import "context"

ev := NewUserCreateEvent("alice", "success") // required fields = ctor params
ev.SetRequestID("req-42")                    // optional reserved-field setter
ev.Audit(ctx, auditor)
```

Forgetting `actor_id` is now a compile error. Misspelling the
event name is a compile error. Sending an `outcome` field that
isn't in the taxonomy fails when the loader parses the YAML.

The complete worked example is at
[`examples/02-code-generation/`][cg-example].

### `go generate` integration

Add a single directive to a Go file in the target package and
commit the generated source:

```go
//go:generate go run github.com/axonops/audit/cmd/audit-gen \
//     -input taxonomy.yaml \
//     -output audit_generated.go \
//     -package mypackage
package mypackage
```

Then:

```bash
go generate ./...
```

## CI integration

Verify the generated file is in sync with the taxonomy on every PR:

```yaml
# .github/workflows/ci.yml
- uses: actions/setup-go@v6
  with:
    go-version: '1.26'

- name: Regenerate
  run: go generate ./...

- name: Fail on drift
  run: git diff --exit-code -- audit_generated.go
```

Or pin a specific binary version into a job:

```yaml
- name: Install audit-gen
  run: go install github.com/axonops/audit/cmd/audit-gen@v0.2.0

- name: Regenerate
  run: audit-gen -input taxonomy.yaml -output audit_generated.go -package mypackage

- run: git diff --exit-code -- audit_generated.go
```

Maintainers triggering proxy.golang.org indexing after a release tag:

```bash
make publish-trigger VERSION=v0.2.0
```

This walks the published modules — including
`github.com/axonops/audit/cmd/audit-gen` — and forces a proxy
fetch so `go install …@v0.2.0` resolves immediately.

## See also

- [Code generation guide][cg-doc] — full reference, including
  `-standard-setters=explicit`, schema/CEF artifact formats, and
  the Splunk TA layout
- [Taxonomy YAML reference][tax-doc] — the schema audit-gen reads
- [Worked example][cg-example] — `examples/02-code-generation/`
- Related tools: [`audit-validate`](../audit-validate/),
  [`bdd-report`](../bdd-report/),
  [`junit-report`](../junit-report/)
- [Source](https://github.com/axonops/audit/tree/main/cmd/audit-gen)

[godoc-badge]: https://pkg.go.dev/badge/github.com/axonops/audit/cmd/audit-gen.svg
[godoc]: https://pkg.go.dev/github.com/axonops/audit/cmd/audit-gen
[parent]: https://github.com/axonops/audit
[cg-doc]: https://github.com/axonops/audit/blob/main/docs/code-generation.md
[cg-example]: https://github.com/axonops/audit/tree/main/examples/02-code-generation
[tax-doc]: https://github.com/axonops/audit/blob/main/docs/taxonomy-validation.md
