[&larr; Back to README](../README.md)

# Common Event Format (CEF)

## What Is CEF?

The Common Event Format (CEF) is a standardised log format designed for
interoperability between security products. Originally developed by
ArcSight (now part of OpenText), CEF is widely supported by SIEM
platforms including Splunk, ArcSight, IBM QRadar, Elasticsearch, and
many others.

CEF provides a structured format that SIEM platforms can parse without
custom configuration. Where JSON requires each SIEM to be configured
with field mappings, CEF uses a well-known schema that SIEM platforms
understand out of the box.

## Format Structure

A CEF message is a single line with a fixed header and a variable
extension section:

```
CEF:0|Vendor|Product|Version|EventType|Description|Severity|Extensions
```

| Part | Example | Purpose |
|------|---------|---------|
| `CEF:0` | `CEF:0` | Format identifier and version |
| Vendor | `MyCompany` | Organisation producing the events |
| Product | `MyApp` | Application name |
| Version | `1.0` | Application version |
| EventType | `user_create` | Audit event type identifier |
| Description | `A new user account was created` | Human-readable description (from taxonomy) |
| Severity | `3` | Event severity (0-10 scale) |
| Extensions | `suser=alice outcome=success` | Key=value pairs with event data |

### Example Output

```
CEF:0|MyCompany|MyApp|1.0|user_create|A new user account was created|3|rt=1704067200000 act=user_create suser=alice outcome=success
CEF:0|MyCompany|MyApp|1.0|auth_failure|An authentication attempt failed|8|rt=1704067200000 act=auth_failure suser=unknown outcome=failure reason=invalid_credentials
```

## CEF vs JSON

| Aspect | CEF | JSON |
|--------|-----|------|
| **Primary use** | SIEM integration | Log aggregation, custom analytics |
| **Parsing** | SIEM-native — no custom field mapping | Requires per-SIEM field configuration |
| **Severity** | Built into the header (0-10 scale) | Just another field |
| **Description** | Built into the header | Not standard |
| **Readability** | Structured but compact | Human-readable |
| **Schema** | Well-known extension keys (suser, src, etc.) | Application-defined |
| **Best for** | Security operations, compliance reporting | Developer debugging, custom pipelines |

Use CEF when your events are consumed by a SIEM. Use JSON when events
go to log aggregators (ELK, Datadog) or custom analytics pipelines.
You can use both simultaneously — go-audit supports per-output
formatter overrides.

## Field Mapping

go-audit maps audit field names to standard CEF extension keys:

| Audit Field | CEF Extension Key | CEF Meaning |
|-------------|-------------------|-------------|
| `actor_id` | `suser` | Source user |
| `source_ip` | `src` | Source IP address |
| `request_id` | `externalId` | External identifier |
| `user_agent` | `requestClientApplication` | Client application |
| `method` | `requestMethod` | HTTP method |
| `path` | `request` | Request path |
| `outcome` | `outcome` | Event outcome |

Framework fields are always present:
- `rt` — event timestamp (Unix milliseconds)
- `act` — event type identifier

Custom field mappings can override the defaults via `CEFFormatter.FieldMapping`.
See [`DefaultCEFFieldMapping`](https://pkg.go.dev/github.com/axonops/go-audit#DefaultCEFFieldMapping)
for the complete default mapping.

## Severity Resolution

CEF severity (0-10) is resolved in this order:

1. **Per-event severity** — if the event definition has `severity: 8`
2. **Per-category severity** — if the event's category has `severity: 3`
3. **Default** — `5` if neither is set

Severity is pre-computed at taxonomy registration time, not resolved
per-event.

## Configuration

### YAML (recommended)

```yaml
outputs:
  siem_log:
    type: file
    file:
      path: "/var/log/audit/cef.log"
    formatter:
      type: cef
      vendor: "MyCompany"
      product: "MyApp"
      version: "1.0"
```

### Programmatic

```go
cef := &audit.CEFFormatter{
    Vendor:  "MyCompany",
    Product: "MyApp",
    Version: "1.0",
}
```

## Escaping and Security

CEF escaping follows the standard specification:
- Header fields: pipes (`|`) and backslashes are escaped
- Extension values: equals signs (`=`) and backslashes are escaped
- Newlines in values are escaped to prevent log injection attacks
- Control characters (0x00-0x1F) are stripped from extension values

**Note:** Spaces in CEF extension values are not escaped — spaces are
the key=value pair separator in the CEF specification. Avoid embedding
literal spaces in field values intended for CEF output; use underscores
or structured identifiers at the application level.

## Further Reading

- [Progressive Example: Formatters](../examples/07-formatters/) — JSON and CEF side-by-side
- [Event Routing](event-routing.md) — route security events to a CEF-formatted SIEM output
- [API Reference: CEFFormatter](https://pkg.go.dev/github.com/axonops/go-audit#CEFFormatter)
