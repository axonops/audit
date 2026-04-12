[← Back to examples](../README.md)

> **Previous:** [03 — Standard Fields](../03-standard-fields/) |
> **Next:** [05 — File Output](../05-file-output/)

# Example 04: Stdout Output

The simplest possible go-audit setup: events written to standard output
as JSON, one line per event. No external dependencies, no blank imports
for output registration, no type-specific configuration.

## What You'll Learn

1. How to configure the **stdout output** — the only output built into
   the core module
2. Why stdout requires **no blank import** (unlike file, syslog,
   webhook, and loki)
3. How to **pipe audit output** to `jq`, `grep`, or other tools for
   filtering and formatting
4. When stdout is the right choice (and when it isn't)

## Files

| File | Purpose |
|------|---------|
| [`main.go`](main.go) | Creates a logger with stdout output, emits 3 events |
| [`outputs.yaml`](outputs.yaml) | Minimal YAML config — just `type: stdout` |
| [`taxonomy.yaml`](taxonomy.yaml) | 3 event types across 2 categories |
| [`audit_generated.go`](audit_generated.go) | Generated typed builders |

## Running the Example

```bash
go run .
```

**Output** (3 JSON lines on stdout + a tip on stderr):

```
{"timestamp":"...","event_type":"auth_login","severity":5,"app_name":"stdout-example","host":"dev-machine","timezone":"Local","pid":12345,"actor_id":"alice","method":"password","outcome":"success","event_category":"security"}
{"timestamp":"...","event_type":"user_create","severity":5,"app_name":"stdout-example","host":"dev-machine","timezone":"Local","pid":12345,"actor_id":"alice","outcome":"success","target_id":"user-42","event_category":"write"}
{"timestamp":"...","event_type":"auth_logout","severity":5,"app_name":"stdout-example","host":"dev-machine","timezone":"Local","pid":12345,"actor_id":"alice","outcome":"success","event_category":"security"}

--- Tip: pipe to jq for pretty-printing ---
  go run . 2>/dev/null | jq .
  go run . 2>/dev/null | jq 'select(.event_type == "auth_login")'
  go run . 2>/dev/null | jq .  # 2>/dev/null suppresses this tip
```

The JSON events go to **stdout**, the tip goes to **stderr**. This
means you can pipe stdout to `jq` without the tip contaminating the
JSON stream.

### Pipe to jq for Pretty-Printing

```bash
go run . 2>/dev/null | jq .
```

The `2>/dev/null` suppresses the tip message printed to stderr,
leaving only the JSON audit events on stdout.

### Filter with jq

Find only authentication events:

```bash
go run . 2>/dev/null | jq 'select(.event_category == "security")'
```

Find only the `user_create` event:

```bash
go run . 2>/dev/null | jq 'select(.event_type == "user_create")'
```

**Output:**

```json
{
  "timestamp": "2026-04-05T12:00:00.000000001+02:00",
  "event_type": "user_create",
  "severity": 5,
  "app_name": "stdout-example",
  "host": "dev-machine",
  "timezone": "Local",
  "pid": 12345,
  "actor_id": "alice",
  "outcome": "success",
  "target_id": "user-42",
  "event_category": "write"
}
```

## Key Concepts

### Why No Blank Import?

Every other output type requires a blank import to register its factory:

```go
import _ "github.com/axonops/audit/file"    // registers "file" factory
import _ "github.com/axonops/audit/syslog"  // registers "syslog" factory
import _ "github.com/axonops/audit/webhook" // registers "webhook" factory
import _ "github.com/axonops/audit/loki"    // registers "loki" factory
```

Stdout is different — its factory is registered in the core
`github.com/axonops/audit` package's `init()` function. Since you
already import the core package, stdout is always available.

Note: You still need `github.com/axonops/audit/outputconfig` to
load YAML configuration — that's a separate module. But you don't need
any output-specific blank import for stdout.

### YAML Configuration

The stdout output configuration is the simplest of all outputs:

```yaml
outputs:
  console:
    type: stdout
```

No type-specific configuration block. The `stdout` type does not accept
any additional fields — if you add a `stdout:` block, the library
rejects it with an error.

### When to Use Stdout

| Use case | Stdout? | Why |
|----------|---------|-----|
| Local development | Yes | See events immediately, pipe to `jq` |
| Debugging in staging | Yes | Inspect events without configuring outputs |
| Container logging (Docker, K8s) | Yes | Container runtimes capture stdout |
| CI/CD test verification | Yes | Assert on program output |
| Production file retention | **No** | Use [file output](../05-file-output/) — rotation, compression, permissions |
| SIEM integration | **No** | Use [syslog](../../docs/outputs.md#syslog-output) or [webhook](../../docs/outputs.md#webhook-output) |
| Structured querying | **No** | Use [Loki output](../08-loki-output/) — stream labels, LogQL |

### What's in Each JSON Field?

| Field | Source | Description |
|-------|--------|-------------|
| `timestamp` | Automatic | When the event was processed |
| `event_type` | `NewAuthLoginEvent(...)` | The taxonomy event type |
| `severity` | Taxonomy default (5) | Numeric severity level |
| `app_name` | `outputs.yaml` | Application name |
| `host` | `outputs.yaml` | Hostname |
| `timezone` | Auto-detected | System timezone |
| `pid` | Auto-captured | Process ID |
| `actor_id` | Event fields | Who performed the action |
| `method` | Event fields | Authentication method |
| `outcome` | Event fields | success/failure |
| `target_id` | Event fields | What was affected |
| `event_category` | Taxonomy categories | Which category this event belongs to |

## Limitations

- **No rotation** — stdout writes are unbounded; the consuming process
  (terminal, container runtime, pipe) must handle volume
- **No retry** — if the write fails (e.g., broken pipe), the event is
  lost
- **No compression** — every byte is written as-is
- **No persistence** — if the process crashes, unflushed events in the
  buffer are lost (this applies to all outputs, not just stdout)

## Further Reading

- [Stdout Output Reference](../../docs/stdout-output.md) — detailed documentation
- [Output Types Overview](../../docs/outputs.md) — all five output types
- [Example 05: File Output](../05-file-output/) — persistent output with rotation
- [Output Configuration YAML](../../docs/output-configuration.md) — full YAML reference
