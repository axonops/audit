# Design: CEF Severity, Description, and Field Mapping Configuration

**Issue:** #179
**Status:** Recommendation ready for review
**Date:** 2026-03-30

## What This Is About

When go-audit formats events as CEF (Common Event Format) for SIEM tools
like Splunk, ArcSight, or QRadar, each event gets a **severity** number
(0–10) that tells the SIEM how important it is:

| Range | Label | Example events |
|-------|-------|----------------|
| 0–3 | Low | Item listed, user profile viewed |
| 4–6 | Medium | Config changed, permission updated |
| 7–8 | High | Auth failure, privilege escalation |
| 9–10 | Very High | Data exfiltration, admin override |

SIEM dashboards, alerts, and correlation rules all key off this number.
Getting it wrong means security teams either get flooded with false
alarms (everything is severity 8) or miss real threats (everything is
severity 5).

Today, severity is configured via a Go function (`SeverityFunc`) on
`CEFFormatter`. This can't be set from YAML, which means any application
using YAML output config has to drop into Go code just to set severity
levels. The same problem exists for `DescriptionFunc` (human-readable
event descriptions) and `FieldMapping` (translating field names to CEF
extension keys).

## Current State

### CEFFormatter struct (`format_cef.go:85-126`)

```go
type CEFFormatter struct {
    SeverityFunc    func(eventType string) int      // nil = all events severity 5
    DescriptionFunc func(eventType string) string   // nil = use event type name
    FieldMapping    map[string]string               // nil = DefaultCEFFieldMapping
    Vendor          string
    Product         string
    Version         string
    OmitEmpty       bool
}
```

### What the YAML config supports today (`outputconfig/formatter.go:28-35`)

```go
type yamlFormatterConfig struct {
    Type      string `yaml:"type"`
    Timestamp string `yaml:"timestamp"`
    OmitEmpty bool   `yaml:"omit_empty"`
    Vendor    string `yaml:"vendor"`
    Product   string `yaml:"product"`
    Version   string `yaml:"version"`
}
```

**Missing from YAML:** severity mapping, description mapping, field
mapping. A developer who wants security events at severity 8 and
everything else at 3 must write Go code.

## Options Evaluated

### Option A — Event Type Severity Map

Map individual event types to severity levels, with a default for
unlisted types.

**YAML:**
```yaml
formatter:
  type: cef
  vendor: "MyCompany"
  product: "MyApp"
  version: "1.0"
  default_severity: 3
  severity:
    auth_failure: 8
    auth_success: 7
    config_change: 6
    user_delete: 5
```

**Go struct change:**
```go
type CEFFormatter struct {
    // ... existing fields ...
    DefaultSeverity int            // default 5; used when event type not in SeverityMap
    SeverityMap     map[string]int // event type → severity (0-10)
    SeverityFunc    func(eventType string) int // still supported; takes precedence over map
}
```

**Pros:** Precise per-event-type control. Simple to understand.
**Cons:** Verbose when you have many event types in the same category
that should all have the same severity.

### Option B — Category Severity Map

Map categories to severity levels instead of individual event types.

**YAML:**
```yaml
formatter:
  type: cef
  vendor: "MyCompany"
  product: "MyApp"
  version: "1.0"
  default_severity: 3
  severity_by_category:
    security: 8
    admin: 6
    write: 4
    read: 2
```

**Go struct change:**
```go
type CEFFormatter struct {
    // ... existing fields ...
    DefaultSeverity    int               // default 5
    SeveritByCategory  map[string]int    // category → severity
    SeverityFunc       func(eventType string) int // precedence over map
}
```

**Pros:** Concise — one entry covers all events in a category.
Categories are how go-audit groups events, so this is natural.
**Cons:** Can't distinguish `auth_failure` (severity 8) from
`auth_success` (severity 4) if they're in the same `security` category.
Requires the formatter to know the taxonomy (to resolve event type →
category), which it currently doesn't.

### Option C — Default + Overrides

A `default_severity` with per-event-type overrides. Simpler variant of
Option A.

**YAML:**
```yaml
formatter:
  type: cef
  vendor: "MyCompany"
  product: "MyApp"
  version: "1.0"
  default_severity: 5
  severity_overrides:
    auth_failure: 8
    data_export: 9
```

**Go struct change:** Same as Option A (just different YAML key names).

**Pros:** Clear mental model — "everything is severity 5 unless I
override it."
**Cons:** Functionally identical to Option A with different naming. The
word "overrides" implies there's a base to override, which is just the
default.

### Option D — Hybrid (Category + Event Type)

Both category-level and event-type-level severity, with event type
taking precedence.

**YAML:**
```yaml
formatter:
  type: cef
  vendor: "MyCompany"
  product: "MyApp"
  version: "1.0"
  default_severity: 3
  severity_by_category:
    security: 7
    admin: 6
  severity:
    auth_failure: 9    # overrides category "security" (7) for this specific event
    data_export: 10
```

**Resolution order:** event type map → category map → default severity.

**Go struct change:**
```go
type CEFFormatter struct {
    // ... existing fields ...
    DefaultSeverity    int               // default 5
    SeverityMap        map[string]int    // event type → severity (highest precedence)
    SeverityByCategory map[string]int    // category → severity
    SeverityFunc       func(eventType string) int // Go code; highest precedence of all
}
```

**Pros:** Maximum flexibility. Categories set the baseline, individual
events can override. Matches how security teams think: "security events
are high, but auth_failure is critical."
**Cons:** Three levels of precedence (func → event → category → default)
is complex. Requires the formatter to know the taxonomy to resolve
categories. More ways to misconfigure.

## Recommendation: Option A — Event Type Severity Map

**Why Option A over the others:**

1. **YAML round-trip capability** — fully expressible in YAML, no Go
   code needed for the common case. ✓

2. **Consistency with existing patterns** — the `yamlFormatterConfig`
   uses flat fields. A `severity` map and `default_severity` int fit
   naturally. No new concepts like "category resolution" are needed. ✓

3. **Go API ergonomics** — adding `DefaultSeverity int` and
   `SeverityMap map[string]int` to `CEFFormatter` is clean. The existing
   `SeverityFunc` still works for programmatic consumers. When both are
   set, `SeverityFunc` takes precedence (documented). ✓

4. **Simplicity** — one map, one default, one precedence rule. Category
   mapping (Options B/D) requires the formatter to receive taxonomy
   context, which is a bigger architectural change. ✓

5. **Sufficient for real use** — most applications have 10-50 event
   types. A map entry per event type is manageable. If a future
   application has 500 event types and needs category-level mapping, it
   can use `SeverityFunc` in Go.

**Why not Option B (category)?** The CEF formatter doesn't currently
receive category information — it gets `eventType string` and `Fields`.
Adding category awareness would require changing the `Formatter`
interface signature or passing taxonomy context, which is a much larger
change for a narrow benefit.

**Why not Option D (hybrid)?** Same category-awareness problem, plus
three-level precedence is hard to debug when severity isn't what you
expect.

## What About DescriptionFunc and FieldMapping?

### DescriptionFunc → `descriptions` map

Same pattern as severity. Add a `descriptions` map and
`default_description` to the YAML config:

```yaml
formatter:
  type: cef
  descriptions:
    auth_failure: "Authentication attempt failed"
    user_create: "New user account created"
```

**Go struct change:**
```go
type CEFFormatter struct {
    // ... existing ...
    DescriptionMap map[string]string  // event type → description
    // DescriptionFunc still works; takes precedence
}
```

When `DescriptionMap` has an entry, use it. When `DescriptionFunc` is
set, it takes precedence. When neither is set, use the event type name
(current default).

**However:** The taxonomy already has a `Description` field on
`EventDef`. The formatter receives `*EventDef` in its `Format` method.
A simpler approach: if `DescriptionFunc` is nil and no `DescriptionMap`
entry exists, use `def.Description` from the taxonomy. This means
developers who already write descriptions in their `taxonomy.yaml` get
CEF descriptions for free — no extra config.

**Recommendation:** Use `def.Description` as the default fallback (free
win), add `descriptions` map for overrides, keep `DescriptionFunc` for
programmatic use. Three-level resolution: func → map → taxonomy
description → event type name.

### FieldMapping → `field_mapping` in YAML

This is already a `map[string]string` on the Go struct. It should be
trivially addable to YAML:

```yaml
formatter:
  type: cef
  field_mapping:
    target_id: duser
    department: cs1
    department_label: cs1Label
```

**Go struct change:** None — `FieldMapping` is already
`map[string]string`. Only the YAML config struct needs the field:

```go
type yamlFormatterConfig struct {
    // ... existing ...
    DefaultSeverity int               `yaml:"default_severity"`
    Severity        map[string]int    `yaml:"severity"`
    Descriptions    map[string]string `yaml:"descriptions"`
    FieldMapping    map[string]string `yaml:"field_mapping"`
}
```

**Recommendation:** Add `field_mapping` to YAML. No Go API change
needed.

## Impact Assessment

### Files to change

| File | Change |
|------|--------|
| `format_cef.go` | Add `DefaultSeverity int`, `SeverityMap map[string]int`, `DescriptionMap map[string]string` to `CEFFormatter`. Update `severity()` method to check `SeverityMap` before returning default. Update `description()` to check `DescriptionMap` then `def.Description`. |
| `outputconfig/formatter.go` | Add `default_severity`, `severity`, `descriptions`, `field_mapping` to `yamlFormatterConfig`. Update `buildCEFFormatter` to map YAML fields to the new struct fields. Add validation: severity values must be 0–10. |
| `format_cef_test.go` | Add tests for `SeverityMap`, `DescriptionMap`, and the precedence rules (func > map > default). |
| `outputconfig/formatter_test.go` | Add tests for YAML round-trip of new fields. |

### Functions to change

- `CEFFormatter.severity()` — check `SeverityMap[eventType]` before
  `SeverityFunc` before default
- `CEFFormatter.description()` — check `DescriptionMap[eventType]`
  before `DescriptionFunc` before `def.Description` before event type
  name
- `buildCEFFormatter()` in `outputconfig/formatter.go` — map new YAML
  fields to `CEFFormatter` struct
- `CEFFormatter.Format()` — no change needed (it calls `severity()` and
  `description()` which handle the new fields internally)

### Precedence rules (documented in godoc)

**Severity:** `SeverityFunc` → `SeverityMap[eventType]` →
`DefaultSeverity` → 5

**Description:** `DescriptionFunc` → `DescriptionMap[eventType]` →
`def.Description` → event type name

**Field mapping:** `FieldMapping` (merged with `DefaultCEFFieldMapping`)
— unchanged behaviour, just now settable from YAML.

## Comparable Libraries

### Splunk CIM

Splunk's Common Information Model uses **lookup tables** (CSV files) to
map raw severity values to normalised labels. The mapping is defined in
`props.conf`:

```
LOOKUP-severity = severity_lookup severity_id OUTPUT severity
```

This is a static table approach — equivalent to our Option A
(`SeverityMap`). Splunk does not use functions for severity mapping.

### ArcSight CEF Producer

The original ArcSight CEF spec (revision 25, 2018) defines severity as
part of the CEF header:

```
CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|Extensions
```

Severity is set by the **producing application** at emit time — there is
no "severity mapping configuration" in the CEF spec itself. Each
application hard-codes or configures its own severity per event type.
ArcSight's connector framework allows severity to be remapped on
ingestion via connector configuration files, but this is
consumer-side, not producer-side.

Our approach (producer-side severity mapping via YAML) is more
developer-friendly than the ArcSight pattern (remap on ingestion) and
aligns with how Splunk handles it (lookup tables).

## Follow-Up Issues

If this recommendation is accepted:

1. **feat: add SeverityMap and DefaultSeverity to CEFFormatter** —
   implement the Go struct changes in `format_cef.go`
2. **feat: add severity, descriptions, and field_mapping to CEF YAML
   config** — implement the YAML config changes in
   `outputconfig/formatter.go`
3. **feat: use taxonomy description as CEF description fallback** —
   update `CEFFormatter.description()` to check `def.Description`
4. **docs: update formatters and crud-api examples with CEF severity
   config** — demonstrate the new YAML fields

## Trade-Offs

- **Category-level severity is not supported in YAML.** A developer who
  wants "all security events = severity 8" must list each security event
  type individually. This is acceptable for 10-50 event types; if it
  becomes painful at scale, we can add `severity_by_category` later
  (but that requires passing taxonomy context to the formatter).
- **SeverityFunc still exists** for programmatic consumers who need
  computed severity (e.g., severity based on field values, not just event
  type). The YAML approach covers the static mapping case only.
- **No migration needed.** All new fields have sensible defaults
  (`DefaultSeverity` = 5, `SeverityMap` = nil, `DescriptionMap` = nil,
  `FieldMapping` = nil). Existing code continues to work unchanged.
