[&larr; Back to README](../README.md)

# Taxonomy YAML Reference

The taxonomy is a single YAML file that defines your complete audit
event schema: which event types exist, what fields each requires,
how events are grouped into categories, and optionally how fields
are classified for sensitivity filtering.

This is a complete reference for everything that can go in a
`taxonomy.yaml` file.

## ❓ Why a Taxonomy?

Application logs are best-effort — a missing field doesn't break
anything. Audit logs are compliance artefacts. A security event
missing `actor_id` is useless for forensic investigation. A field
typo (`actorid` instead of `actor_id`) breaks SIEM parsing rules.

The taxonomy is a contract: "these are the audit events we produce,
and each one always includes these fields." The library validates
every event against this contract at runtime.

## 📋 Complete Schema

```yaml
version: 1

# ── Categories ──────────────────────────────────────────────
# Group related events. Used for per-output event routing.

categories:
  write:
    severity: 3                    # default severity for events in this category (0-10)
    events:
      - user_create
      - user_delete

  read:                            # categories can also be a simple list of event names
    - user_read
    - config_read

  security:
    severity: 8
    events:
      - auth_failure
      - auth_success

# ── Sensitivity Labels (optional) ──────────────────────────
# Classify fields by data sensitivity. Used with per-output
# exclude_labels to strip fields before delivery.

sensitivity:
  labels:
    pii:
      description: "Personally identifiable information"
      fields:                      # global field name mapping — any event with these fields
        - email
        - phone
      patterns:                    # regex patterns — matches field names across all events
        - "^user_"
    financial:
      description: "Financial and payment data"
      patterns:
        - "^card_"

# ── Events ──────────────────────────────────────────────────
# Define each audit event type and its fields.

events:
  user_create:
    description: "A new user account was created"   # used as CEF description header
    severity: 4                    # per-event severity override (takes priority over category)
    fields:
      outcome:
        required: true             # must be present in every event of this type
      actor_id:
        required: true
      email: {}                    # optional field — matched by pii.fields globally
      user_name:
        labels: [pii]             # explicit per-field sensitivity label annotation
      # target_id, reason, source_ip are reserved standard fields —
      # always available without declaration. Use SetTargetID(), etc.

  auth_failure:
    description: "An authentication attempt failed"
    fields:
      outcome:  { required: true }   # compact syntax
      actor_id: { required: true }
```

## 📋 Top-Level Fields

| Field | Required | Description |
|-------|----------|-------------|
| `version` | Yes | Must be `1`. Schema version for future migration. |
| `categories` | Yes | Map of category name to event list or struct. |
| `events` | Yes | Map of event type name to event definition. |
| `sensitivity` | No | Sensitivity label configuration for field classification. |

## 📂 Categories

Categories group related events. Each category maps to either a
simple list of event names or a struct with optional severity:

**Simple list:**
```yaml
categories:
  read:
    - user_read
    - config_read
```

**Struct with severity:**
```yaml
categories:
  security:
    severity: 8
    events:
      - auth_failure
      - auth_success
```

Both formats can be mixed in the same taxonomy. Severity is optional
(defaults to `5` if not set at either category or event level).

An event can belong to multiple categories. Events not in any
category are valid and always globally enabled.

## 📋 Events

Each event defines its description, optional severity override, and
fields:

```yaml
events:
  user_create:
    description: "A new user account was created"
    severity: 4            # optional — overrides category severity
    fields:
      outcome:
        required: true     # this field must be present
      actor_id:
        required: true
      email: {}            # optional field
      user_name:
        labels: [pii]     # optional field with sensitivity label
```

| Event Field | Required | Description |
|-------------|----------|-------------|
| `description` | No | Human-readable label. Used as CEF description header. |
| `severity` | No | Per-event severity (0-10). Overrides category severity. |
| `fields` | No | Map of field name to field definition. If omitted, the event accepts only framework fields in strict mode. |

### Field Definitions

Fields can be defined in three ways:

```yaml
fields:
  outcome:                 # expanded — required field
    required: true
  actor_id:                # expanded — required field with label
    required: true
    labels: [pii]
  email: {}                # compact — optional field, no labels
  user_name:               # expanded — optional field with label
    labels: [pii]
  custom_field: {}         # compact — optional, no labels
  notes:                   # bare — same as {}
  quota:                   # typed custom field — generates SetQuota(v int)
    type: int
  created_at:
    type: time             # generates SetCreatedAt(v time.Time)
```

| Field Property | Default | Description |
|----------------|---------|-------------|
| `required` | `false` | If `true`, the library rejects events missing this field. |
| `labels` | `[]` | List of sensitivity label names applied to this field. |
| `type` | `string` | Go type emitted by [audit-gen] in the typed setter for this custom field. Accepts `string`, `int`, `int64`, `float64`, `bool`, `time` (→ `time.Time`), `duration` (→ `time.Duration`). Reserved standard fields (`actor_id`, `source_ip`, etc.) reject `type:` — their Go type is library-authoritative. Unknown values are rejected at parse time. |

## 🔒 Sensitivity Labels

Sensitivity labels classify fields by data sensitivity. There are
three ways to assign labels to fields:

### 1. Explicit per-field annotation

Directly on the field definition in the event:

```yaml
events:
  user_create:
    fields:
      user_name:
        labels: [pii]     # this specific field in this event
```

### 2. Global field name mapping

Any field with this name in any event gets the label:

```yaml
sensitivity:
  labels:
    pii:
      description: "Personally identifiable information"
      fields:
        - email            # every event with an "email" field
        - phone            # every event with a "phone" field
```

### 3. Regex patterns

Any field name matching the pattern in any event gets the label:

```yaml
sensitivity:
  labels:
    financial:
      description: "Financial and payment data"
      patterns:
        - "^card_"         # matches card_number, card_expiry, etc.
```

All three mechanisms are resolved at taxonomy parse time — there is
no per-event runtime cost. Labels from all three sources are additive.

Per-output field stripping is configured in `outputs.yaml`, not in
the taxonomy. See [Sensitivity Labels](sensitivity-labels.md) and
[Outputs](outputs.md) for the `exclude_labels` configuration.

## 🛡️ Name Character Set and Length

Every consumer-controlled taxonomy identifier — category name, event
type key, required/optional field name, and sensitivity label name —
must match this pattern:

```
^[a-z][a-z0-9_]*$
```

That is: start with a lowercase letter, followed by lowercase letters,
digits, or underscores only. Names are additionally capped at **128
bytes**.

Rejected examples:

| Name | Reason |
|------|--------|
| `UserCreate` | uppercase letter |
| `user-create` | hyphen |
| `user.create` | dot |
| `user create` | space |
| `1create` | starts with digit |
| `_create` | starts with underscore |
| `user\u202eadmin` | bidi override character |
| `user` + 129 bytes | exceeds 128-byte cap |

### Why this is enforced

The pure-ASCII rule keeps the following out of downstream log
consumers, SIEM dashboards, and error messages:

- **Bidi override characters** (U+202E, U+2066-2069) that could
  reorder terminal output (CVE-2021-42574 class).
- **Unicode confusables** — Cyrillic `а` (U+0430) vs ASCII `a`, Greek
  omicron (U+03BF) vs `o`, full-width letters (U+FF21-FF5A), etc.
- **CEF metacharacters** (`|`, `=`, `\`, `"`) that would corrupt CEF
  header or extension parsing.
- **C0/C1 control bytes** (0x00-0x1F, 0x7F, 0x80-0x9F) that could
  embed ANSI escape sequences, cursor manipulation, or NUL-injection
  into log lines.
- **Length DoS** — a multi-kilobyte identifier blown through every
  log line.

When a name fails either check, `ValidateTaxonomy` returns an error
that wraps both [`ErrTaxonomyInvalid`](error-reference.md#errtaxonomyinvalid)
and [`ErrInvalidTaxonomyName`](error-reference.md#errinvalidtaxonomyname),
so consumers can discriminate name-shape violations from other
taxonomy errors:

```go
tax, err := audit.ParseTaxonomyYAML(data)
if errors.Is(err, audit.ErrInvalidTaxonomyName) {
    // bad name — fix the YAML
}
if errors.Is(err, audit.ErrTaxonomyInvalid) {
    // any taxonomy validation failure, including the above
}
```

Error messages render the offending name through `%q`, so control
bytes and bidi characters appear as Go escape sequences
(`\x00`, `\u202e`) rather than as raw bytes that could hijack
terminal output.

The same rule is enforced by the `cmd/audit-gen` code generator — a
malformed name causes codegen to fail before any Go source is written,
preventing a "generates fine, never loads at runtime" trap.

## 🚫 Reserved Field Names

The following field names are managed by the framework and cannot be
used as required or optional fields in your taxonomy:

| Field | Purpose |
|-------|---------|
| `timestamp` | Event timestamp, set by the drain goroutine |
| `event_type` | Event type name from the taxonomy |
| `severity` | Resolved severity (0-10) |
| `event_category` | Delivery-specific category (see below) |
| `app_name` | Application name (set via outputs YAML or `WithAppName`) |
| `host` | Hostname (set via outputs YAML or `WithHost`) |
| `timezone` | Timezone context (set via outputs YAML or `WithTimezone`) |
| `pid` | Process ID (auto-captured at construction) |
| `_hmac` | HMAC integrity signature (set by HMAC config) |
| `_hmac_version` | HMAC salt version (set by HMAC config) |

If you try to define any of these as a required or optional field,
taxonomy validation fails with:

```
event "auth.login" field "event_category" is a reserved framework field
```

> 💡 `duration_ms` is a framework field for sensitivity protection
> but is NOT reserved — it can be used as an optional field because
> the HTTP middleware legitimately sets it as a user-provided value.

## 📂 Event Category in Output

When an event belongs to a category, the `event_category` field is
automatically appended to the serialised output (JSON and CEF). This
tells downstream consumers (SIEMs, log aggregators) which category
triggered the delivery.

### Configuration

```yaml
categories:
  emit_event_category: true    # default: true (can be omitted)
  security:
    events: [auth_failure]
```

| Setting | Behaviour |
|---------|-----------|
| Absent from YAML | `event_category` is appended (default: true) |
| `emit_event_category: true` | `event_category` is appended |
| `emit_event_category: false` | `event_category` is never appended, zero overhead |

### Output Examples

**JSON:**
```json
{"timestamp":"...","event_type":"auth_failure","severity":8,"outcome":"failure","event_category":"security"}
```

**CEF:**
```
CEF:0|...|auth_failure|...|8|... outcome=failure cat=security
```

### Multi-Category Events

Events in multiple categories produce separate deliveries, each with
a different `event_category` value. The base event data is serialised
once (cached); only the appended category differs per delivery.

### Uncategorised Events

Events not in any category do not include `event_category` in the
output — the field is omitted entirely (not null, not empty string).

## 📊 Severity Resolution

Severity is a 0-10 scale used in CEF output and event routing.
Resolution order:

1. Per-event `severity` (highest priority)
2. Category `severity`
3. Default: `5`

See [CEF Format — Severity Levels](cef-format.md#severity-levels)
for practical guidance on choosing severity values.

## ✅ Validation Modes

| Mode | Behaviour |
|------|-----------|
| `strict` (default) | Rejects events with fields not declared in the taxonomy |
| `warn` | Accepts unknown fields but logs a warning via `log/slog` |
| `permissive` | Accepts any fields without warning |

Set via `audit.WithValidationMode(audit.ValidationWarn)` on
`New`, the `validation_mode` key in your outputs YAML, or
`audittest.WithValidationMode(audit.ValidationWarn)` in tests.

## 📦 Loading a Taxonomy

The library accepts `[]byte` only — not file paths. Use `go:embed`
to bundle the YAML into your binary:

```go
//go:embed taxonomy.yaml
var taxonomyYAML []byte

tax, err := audit.ParseTaxonomyYAML(taxonomyYAML)
```

**Constraints:**
- Input is limited to 1 MiB. Inputs exceeding this are rejected
  with `ErrInvalidInput`.
- The input must be a single YAML document. Multi-document YAML
  (separated by `---`) is rejected.
- Unknown YAML keys are rejected. A typo like `sevrity` instead
  of `severity` produces a parse error, not a silently ignored field.

## 📚 Further Reading

- [Progressive Example: Basic](../examples/01-basic/) — inline taxonomy
- [Progressive Example: Code Generation](../examples/02-code-generation/) — YAML taxonomy with audit-gen
- [Sensitivity Labels](sensitivity-labels.md) — per-output field stripping
- [CEF Format](cef-format.md) — severity levels and SIEM integration
- [API Reference: ParseTaxonomyYAML](https://pkg.go.dev/github.com/axonops/audit#ParseTaxonomyYAML)
