# File Output Example

Write audit events to a log file with automatic rotation, size limits,
and restricted file permissions.

## What You'll Learn

- Configuring a file output in `outputs.yaml`
- Enabling output types with blank imports
- File rotation, backup retention, and permissions
- Why `Close()` is critical for file output

## Prerequisites

- Go 1.26+
- Completed: [Basic](../basic/), [Code Generation](../code-generation/)

## Files

| File | Purpose |
|------|---------|
| `taxonomy.yaml` | Event definitions (embedded in binary) |
| `outputs.yaml` | File output configuration |
| `audit_generated.go` | Generated constants (committed) |
| `main.go` | Loads config, emits events, reads file back |

## Key Concepts

### File Output in YAML

The `outputs.yaml` configures a single file output with rotation:

```yaml
version: 1
outputs:
  audit_log:
    type: file
    file:
      path: "./audit.log"
      max_size_mb: 10
      max_backups: 3
      permissions: "0600"
```

The `type: file` tells the library to use the file output module. The
type-specific settings are nested under a key matching the type name
(`file:`).

### Available File Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `path` | (required) | File path. Created if it doesn't exist. |
| `max_size_mb` | 100 | Rotate when the file exceeds this size. |
| `max_backups` | 5 | Number of rotated files to keep. |
| `max_age_days` | 30 | Delete rotated files older than this. |
| `permissions` | `"0600"` | File permissions (must be quoted — see below). |
| `compress` | `true` | Gzip rotated files. |

### Why Permissions Must Be Quoted

```yaml
permissions: "0600"    # correct
permissions: 0600      # WRONG — YAML reads this as integer 384
```

In YAML, an unquoted `0600` is parsed as the integer 384 (octal
interpretation). The library requires a string to prevent this silent
misconfiguration.

### Enabling the File Output Type

The file output lives in its own Go module. A blank import registers it
with the output factory:

```go
import (
    _ "github.com/axonops/go-audit/file"
    "github.com/axonops/go-audit/outputconfig"
)
```

If you reference `type: file` in YAML without this import,
`outputconfig.Load` returns an error like:
`output "audit_log": unknown output type "file" (registered: [stdout]); did you import _ "github.com/axonops/go-audit/file"?`

### Close Flushes to Disk

For file outputs, `Close()` is especially important. The logger buffers
events in memory and writes them asynchronously. If you exit without
`Close()`, events still in the buffer never reach the file.

## Run It

```bash
go run .
```

## Expected Output

```
--- Contents of audit.log ---
{"timestamp":"...","event_type":"user_create","severity":5,"actor_id":"alice","outcome":"success"}
{"timestamp":"...","event_type":"user_create","severity":5,"actor_id":"bob","outcome":"success"}
{"timestamp":"...","event_type":"user_create","severity":5,"actor_id":"carol","outcome":"success"}
{"timestamp":"...","event_type":"user_create","severity":5,"actor_id":"dave","outcome":"success"}
{"timestamp":"...","event_type":"user_create","severity":5,"actor_id":"eve","outcome":"success"}
```

Five JSON events written to `audit.log`. The file is cleaned up at the
end of the example.

## Previous

[Code Generation](../code-generation/)

## Next

[Multi-Output](../multi-output/) — send events to multiple destinations
simultaneously.
