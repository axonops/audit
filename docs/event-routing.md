[&larr; Back to README](../README.md)

# Per-Output Event Routing

- [What Is Event Routing?](#what-is-event-routing)
- [Why Route Events?](#why-route-events)
- [Configuration](#configuration)
- [Include Mode](#include-mode)
- [Exclude Mode](#exclude-mode)
- [Severity Filtering](#severity-filtering)
- [Combining Severity with Include/Exclude](#combining-severity-with-includeexclude)
- [How Events Flow](#how-events-flow)
- [Runtime Route Changes](#runtime-route-changes)
- [Events Without Categories](#events-without-categories)

## What Is Event Routing?

Event routing controls which events reach which outputs. Instead of
sending every event to every output, you can filter by category,
event type, or severity so that each output receives only the events
relevant to its purpose.

## Why Route Events?

A typical deployment has multiple outputs with different purposes:

- **SIEM** — needs only security-relevant events (authentication, access control)
- **Compliance file** — needs everything, unfiltered
- **Alerting webhook** — needs only high-severity events (severity 7+)
- **Debug log** — needs only write operations during development

Without routing, every output receives every event, increasing storage
costs and noise.

## Configuration

Routes are configured per-output in the output YAML:

```yaml
outputs:
  # No route — receives ALL events
  full_log:
    type: file
    file:
      path: "./full-audit.log"

  # Include mode — only security events
  siem:
    type: syslog
    syslog:
      address: "syslog.example.com:514"
    route:
      include_categories:
        - security

  # Severity filtering — only high-severity events
  alerts:
    type: webhook
    webhook:
      url: "https://alerts.example.com/audit"
    route:
      min_severity: 7
```

## Include Mode

Only events matching the filter are delivered to this output:

```yaml
route:
  include_categories: [security]         # events in the "security" category
  include_event_types: [config_change]   # OR this specific event type
```

If you include both a category and an event type that belongs to that
category, the event is delivered **once** — it is not duplicated.

## Exclude Mode

All events are delivered **except** those matching the filter:

```yaml
route:
  exclude_categories: [read]             # everything except "read" events
  exclude_event_types: [health_check]    # AND exclude this specific event
```

> **Include and exclude are mutually exclusive.** You cannot use both
> on the same route. Setting both causes a startup error.

## Severity Filtering

Filter by severity range (0-10 scale). Events outside the range are
not delivered to this output:

```yaml
route:
  min_severity: 7    # only severity 7 and above
  max_severity: 10   # optional upper bound (default: no upper limit)
```

If only `min_severity` is set, all events at or above that severity
pass. If only `max_severity` is set, all events at or below that
severity pass.

## Combining Severity with Include/Exclude

Severity filtering combines with include/exclude as an **AND**
condition — an event must pass **both** the category/event filter
AND the severity filter to reach the output.

### Example: Security events with high severity only

```yaml
route:
  include_categories: [security]
  min_severity: 8
```

This delivers only events that are in the "security" category **AND**
have severity 8 or higher. A security event with severity 5 is
filtered out. A non-security event with severity 9 is also filtered
out.

### Example: Exclude reads, but only keep high severity

```yaml
route:
  exclude_categories: [read]
  min_severity: 5
```

This delivers events that are NOT in the "read" category **AND** have
severity 5 or higher. Low-severity write events (severity 3) are
filtered out even though they pass the exclude filter.

## How Events Flow

```
AuditEvent()
  ├── validate fields
  ├── check category enabled (all enabled by default;
  │   DisableCategory() can disable at runtime)
  │
  └── for each output:
       ├── per-output route filter (include/exclude + severity)
       ├── per-output sensitivity filter (label exclusion)
       └── write to output
```

An event must pass the category check AND the per-output route filter
to reach an output. If an output has no route configured, it receives
all events.

## Runtime Route Changes

Routes can be modified at runtime without restarting the logger:

```go
// Restrict an output to security events only.
err := logger.SetOutputRoute("siem", &audit.EventRoute{
    IncludeCategories: []string{"security"},
})

// Remove the route — output receives all events again.
err = logger.ClearOutputRoute("siem")

// Query the current route.
route, err := logger.OutputRoute("siem")
```

The output name must match the key used in your output YAML
configuration (e.g., `"siem"`, `"alerts"`, `"full_log"`).

Route changes are thread-safe and take effect immediately for the
next event processed by the drain goroutine.

See [Progressive Example: Event Routing](../examples/05-event-routing/)
for runtime route changes in a working application.

## Events Without Categories

Events that are not assigned to any category in the taxonomy are
always delivered at the global level — they cannot be disabled via
`DisableCategory()` since they have no category.

However, they CAN be filtered by per-output routes using
`exclude_event_types` or severity filtering. They also pass
`include_event_types` if explicitly listed.

Category-based include/exclude routes do not affect uncategorised
events — an `include_categories: [security]` route will NOT deliver
uncategorised events (they are not in the "security" category).

## Further Reading

- [Progressive Example: Event Routing](../examples/05-event-routing/) — complete routing configuration
- [Outputs](outputs.md) — output types and fan-out architecture
- [Output Configuration YAML](output-configuration.md) — full YAML reference
- [API Reference: EventRoute](https://pkg.go.dev/github.com/axonops/go-audit#EventRoute)
