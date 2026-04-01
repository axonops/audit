[&larr; Back to README](../README.md)

# Per-Output Event Routing

## What Is Event Routing?

Event routing controls which events reach which outputs. Instead of
sending every event to every output, you can filter by category,
event type, or severity so that each output receives only the events
it needs.

## Why Route Events?

A typical deployment has multiple outputs with different purposes:

- **SIEM** — needs only security-relevant events (authentication, access control)
- **Compliance file** — needs everything, unfiltered
- **Alerting webhook** — needs only high-severity events (severity 7+)
- **Debug log** — needs only write operations during development

Without routing, every output receives every event, increasing storage
costs and noise. Routing lets you send security events to your SIEM,
verbose read events to local files only, and critical alerts to your
webhook — all from the same audit pipeline.

## Configuration

### YAML

```yaml
outputs:
  siem:
    type: syslog
    syslog:
      network: "tcp+tls"
      address: "syslog.example.com:6514"
    route:
      include_categories:
        - security

  writes_log:
    type: file
    file:
      path: "./writes.log"
    route:
      include_categories:
        - write

  critical_alerts:
    type: webhook
    webhook:
      url: "https://alerts.example.com/audit"
    route:
      min_severity: 7
```

## Routing Modes

### Include Mode

Only matching events are delivered:

```yaml
route:
  include_categories: [security]       # only security category
  include_event_types: [auth_failure]  # or specific event types
```

### Exclude Mode

All events are delivered except matching ones:

```yaml
route:
  exclude_categories: [read]           # everything except reads
  exclude_event_types: [user_read]     # or specific event types
```

Include and exclude modes are mutually exclusive — you cannot use both
in the same route.

### Severity Filtering

Filter by severity range (0-10 scale):

```yaml
route:
  min_severity: 7    # only severity 7 and above
  max_severity: 10   # optional upper bound
```

Severity filtering can be combined with category/event type filtering.

## How Events Flow

```
AuditEvent()
  ├── global category filter (enabled/disabled categories)
  └── for each output:
       ├── per-output route filter (include/exclude/severity)
       ├── per-output sensitivity filter (label exclusion)
       └── write to output
```

An event must pass both the global category filter AND the per-output
route filter to reach an output. If an output has no route configured,
it receives all globally-enabled events.

## Runtime Route Changes

Routes can be changed at runtime without restarting the logger:

```go
logger.SetOutputRoute("siem", &audit.EventRoute{
    IncludeCategories: []string{"security", "write"},
})

logger.ClearOutputRoute("siem")  // receive all events again
```

## Uncategorised Events

Events that do not belong to any category are always globally enabled
and cannot be filtered by category-based routing. They can still be
filtered by event type or severity.

## Further Reading

- [Progressive Example: Event Routing](../examples/05-event-routing/) — complete routing configuration
- [Outputs](outputs.md) — output types and fan-out architecture
- [API Reference: EventRoute](https://pkg.go.dev/github.com/axonops/go-audit#EventRoute)
