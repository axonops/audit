# File Output Example

Write audit events to a log file with automatic rotation, size limits,
and restricted file permissions.

## What You'll Learn

- Creating a `file.Output` with `file.New`
- Configuring rotation: `MaxSizeMB`, `MaxBackups`
- Setting file permissions with `Permissions: "0600"`
- How `logger.Close()` flushes buffered events before exit

## Prerequisites

- Go 1.26+
- Completed: [Basic](../basic/)

## Files

| File | Purpose |
|------|---------|
| `main.go` | File output creation, event emission, file readback |

## Run It

```bash
go run .
```

## Expected Output

```
--- Contents of audit.log ---
{"timestamp":"...","event_type":"user_create","actor_id":"alice","outcome":"success"}
{"timestamp":"...","event_type":"user_create","actor_id":"bob","outcome":"success"}
{"timestamp":"...","event_type":"user_create","actor_id":"carol","outcome":"success"}
{"timestamp":"...","event_type":"user_create","actor_id":"dave","outcome":"success"}
{"timestamp":"...","event_type":"user_create","actor_id":"eve","outcome":"success"}
```

Five JSON events written to `audit.log`, one per user.

## What's Happening

1. **file.Config** sets the output path and rotation policy. When the file
   reaches `MaxSizeMB`, it is rotated and up to `MaxBackups` old files are
   kept. `Permissions` is an octal string (must be quoted in YAML to avoid
   integer interpretation).

2. **file.Metrics** (second parameter to `file.New`) is nil here. In
   production, pass a metrics implementation to track file rotations.

3. **Close** is critical for file output: it flushes the async buffer and
   syncs the file. Without it, events may be lost.

## Next

[Multi-Output](../multi-output/) -- send events to multiple destinations
simultaneously.
