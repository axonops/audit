# Design: Event Severity in Taxonomy

**Issue:** #179
**Status:** Recommendation ready for review
**Date:** 2026-03-30

## Problem

Audit events need a severity level (0–10) for SIEM integration. CEF
uses this in the header, and SIEM dashboards, alerts, and correlation
rules all key off it. Currently there's no way to declare severity — the
`CEFFormatter` has a `SeverityFunc` callback that must be written in Go.

## Recommendation: Add Severity to EventDef

Severity is a property of the event, not the formatter. An
`auth_failure` is severity 8 whether it's output as JSON, CEF, or
anything else. Put it where events are defined — in the taxonomy:

```yaml
events:
  auth_failure:
    category: security
    description: "An authentication attempt failed"
    severity: 8
    required:
      - outcome
      - actor_id

  user_create:
    category: write
    description: "A new user account was created"
    severity: 3
    required:
      - outcome
      - actor_id
```

### CEF Severity Levels

| Range | Label | Example events |
|-------|-------|----------------|
| 0–3 | Low | Item listed, user profile viewed |
| 4–6 | Medium | Config changed, permission updated |
| 7–8 | High | Auth failure, privilege escalation |
| 9–10 | Very High | Data exfiltration, admin override |

### Go Changes

Add `Severity` to `EventDef` in `taxonomy.go`:

```go
type EventDef struct {
    Category    string
    Description string
    Severity    int      // 0-10; default 5 if omitted
    Required    []string
    Optional    []string
}
```

The CEF formatter reads `def.Severity` directly:

```go
func (cf *CEFFormatter) severity(def *EventDef) int {
    if cf.SeverityFunc != nil {
        return clamp(cf.SeverityFunc(def.Category)) // backwards compat
    }
    if def != nil && def.Severity > 0 {
        return def.Severity
    }
    return 5 // default
}
```

`SeverityFunc` is kept for backwards compatibility but becomes
unnecessary for new code. The formatter's `Format` method already
receives `*EventDef` — no interface change needed.

### YAML Parsing

`ParseTaxonomyYAML` already parses `EventDef` fields. Add `Severity`
to the YAML struct with validation (0–10, default 5 if omitted).

### Validation

`ValidateTaxonomy` should validate severity is in range 0–10. Values
outside this range return an error.

### What About DescriptionFunc?

Same logic applies. The taxonomy already has `Description` on
`EventDef`. The CEF formatter should use `def.Description` as the
default CEF description instead of the event type name. The
`DescriptionFunc` callback becomes unnecessary for most consumers.

### What About FieldMapping?

`FieldMapping` is different — it's genuinely a formatter concern (how
audit field names translate to CEF extension keys), not an event
property. It should stay on the formatter and be added to the YAML
formatter config as `field_mapping: map[string]string`. This is a
separate, smaller change.

## Impact

| File | Change |
|------|--------|
| `taxonomy.go` | Add `Severity int` to `EventDef` |
| `taxonomy_yaml.go` | Parse `severity` field from YAML |
| `taxonomy.go` | Validate severity 0–10 in `ValidateTaxonomy` |
| `format_cef.go` | Read `def.Severity` in `severity()` method; use `def.Description` in `description()` method |
| `cmd/audit-gen` | Include `Severity` in generated comments or constants if useful |
| `outputconfig/formatter.go` | Add `field_mapping` to `yamlFormatterConfig` (separate from severity) |

## What This Replaces

- `SeverityFunc` on `CEFFormatter` — kept for backwards compatibility,
  but no longer needed when severity is in the taxonomy
- `DescriptionFunc` on `CEFFormatter` — kept, but `def.Description`
  is the natural default
- The entire "severity map" / "severity by category" design — severity
  is just a field on the event definition, not a mapping layer

## Follow-Up Issues

1. **feat: add severity field to EventDef** — taxonomy.go, validation,
   YAML parsing
2. **feat: CEF formatter uses def.Severity and def.Description** —
   format_cef.go changes
3. **feat: add field_mapping to CEF YAML config** —
   outputconfig/formatter.go
4. **docs: update examples with severity in taxonomy** — taxonomy.yaml
   files in examples
