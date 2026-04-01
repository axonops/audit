[&larr; Back to README](../README.md)

# Taxonomy and Schema Validation

## What Is a Taxonomy?

A taxonomy is a YAML document that defines every audit event your
application can emit: which event types exist, what fields each event
requires, what fields are optional, and how events are grouped into
categories.

The go-audit library validates every audit event against the registered
taxonomy at runtime. If an event is missing a required field, references
an unknown event type, or includes a field not declared in the taxonomy,
the library rejects it with a descriptive error. This catches bugs
before they reach production — you cannot silently emit a malformed
audit event.

## Why Schema Enforcement Matters

Application logs are best-effort: if a log line is missing a field,
nothing breaks. Audit logs are different — they are compliance
artefacts. A security audit event missing the `actor_id` field is
useless for forensic investigation. A SOX-relevant event with a typo
in the field name (`actorid` instead of `actor_id`) breaks downstream
SIEM parsing rules.

Schema enforcement ensures:
- Every event has the fields your compliance team requires
- No event type exists without a definition
- Unknown fields are caught (strict mode) or flagged (warn mode)
- Changes to the audit schema are explicit and reviewable in YAML

## YAML Taxonomy Format

```yaml
version: 1

categories:
  write:
    severity: 3
    events:
      - user_create
      - user_delete
  security:
    severity: 8
    events:
      - auth_failure

events:
  user_create:
    description: "A new user account was created"
    fields:
      outcome:
        required: true
      actor_id:
        required: true
      target_id: {}       # optional, no labels
      reason: {}

  auth_failure:
    description: "An authentication attempt failed"
    fields:
      outcome:
        required: true
      actor_id:
        required: true
      source_ip: {}
```

### Key Concepts

- **Categories** group related events and control bulk enable/disable
- **Events** define the fields each event type accepts
- **Fields** can be `required: true` or optional (bare `{}` or empty)
- **Severity** can be set per-category (default for all events in that category) or per-event (overrides category)
- **Description** provides a human-readable label, used as the CEF description header

### Validation Modes

| Mode | Behaviour |
|------|-----------|
| `strict` (default) | Rejects events with unknown fields |
| `warn` | Accepts unknown fields but logs a warning |
| `permissive` | Accepts any fields without warning |

## Loading a Taxonomy

```go
//go:embed taxonomy.yaml
var taxonomyYAML []byte

tax, err := audit.ParseTaxonomyYAML(taxonomyYAML)
```

The library accepts `[]byte` only — not file paths. Use `go:embed` to
bundle your taxonomy YAML into the binary.

## Further Reading

- [Progressive Example: Basic](../examples/01-basic/) — inline taxonomy
- [Progressive Example: Code Generation](../examples/02-code-generation/) — YAML taxonomy with audit-gen
- [API Reference: ParseTaxonomyYAML](https://pkg.go.dev/github.com/axonops/go-audit#ParseTaxonomyYAML)
