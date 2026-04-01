[&larr; Back to README](../README.md)

# JSON Format

## What Is the JSON Format?

The JSON formatter serialises each audit event as a single line of
JSON — one event per line, no pretty-printing. This is the default
format used by go-audit. JSON output is designed for log aggregation
platforms (ELK/Elasticsearch, Datadog, Loki, CloudWatch) and for
custom analytics pipelines that parse structured data.

For SIEM platforms (Splunk, ArcSight, QRadar), consider using the
[CEF format](cef-format.md) instead — SIEMs understand CEF natively
without custom field mapping.

## Example Output

```json
{"timestamp":"2026-01-15T10:30:00.123456789Z","event_type":"user_create","severity":5,"actor_id":"alice","outcome":"success","target_id":"user-42"}
```

### Field Order

Fields are emitted in a deterministic order:

1. **Framework fields** (always present, always first):
   - `timestamp` — event timestamp (RFC 3339 with nanoseconds by default)
   - `event_type` — the taxonomy event type name
   - `severity` — resolved severity (0-10)
   - `duration_ms` — only present if the event includes a duration

2. **Required fields** — sorted alphabetically
3. **Optional fields** — sorted alphabetically
4. **Extra fields** — any fields not declared in the taxonomy, sorted alphabetically

This deterministic ordering makes JSON output diff-friendly and
predictable for downstream parsers.

## Configuration

### YAML

```yaml
# JSON is the default — you only need a formatter block if you want
# to change the timestamp format or enable omit_empty.
outputs:
  audit_log:
    type: file
    file:
      path: "./audit.log"
    formatter:
      type: json
      timestamp: rfc3339nano    # or "unix_ms" for Unix milliseconds
      omit_empty: false         # true to skip fields with zero values
```

### Timestamp Formats

| Value | Output | Example |
|-------|--------|---------|
| `rfc3339nano` (default) | RFC 3339 with nanoseconds | `"2026-01-15T10:30:00.123456789Z"` |
| `unix_ms` | Unix epoch milliseconds | `1737193800123` |

### OmitEmpty

When `omit_empty` is `true`, optional fields with zero values (`""`,
`0`, `nil`, `false`) are omitted from the output. This reduces payload
size but makes the JSON structure variable between events.

When `omit_empty` is `false` (default), all declared fields appear in
every event, with `null` for unset optional fields. This provides
structural consistency — every event of the same type has the same
set of keys.

## Further Reading

- [CEF Format](cef-format.md) — alternative format for SIEM integration
- [Progressive Example: Formatters](../examples/07-formatters/) — JSON and CEF side-by-side
- [API Reference: JSONFormatter](https://pkg.go.dev/github.com/axonops/go-audit#JSONFormatter)
