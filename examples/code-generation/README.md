# Code Generation Example

Define your audit taxonomy in YAML and generate type-safe Go constants
with `audit-gen`. Typos in event types or field names become compile
errors instead of runtime surprises.

## What You'll Learn

- Defining a taxonomy in `taxonomy.yaml`
- Running `audit-gen` to generate constants
- Using `//go:generate` for reproducible builds
- Embedding taxonomy YAML with `//go:embed`
- Referencing `EventUserCreate`, `FieldActorID`, etc. instead of strings

## Prerequisites

- Go 1.26+
- Completed: [Basic](../basic/)

## Files

| File | Purpose |
|------|---------|
| `taxonomy.yaml` | Event definitions: categories, required/optional fields |
| `audit_generated.go` | Generated constants (committed, DO NOT EDIT) |
| `main.go` | Uses generated constants for type-safe auditing |

## Run It

```bash
# Run the example (audit_generated.go is already committed):
go run .

# To regenerate after editing taxonomy.yaml:
go generate .
```

## Expected Output

```
--- Using generated constants ---
{"timestamp":"...","event_type":"user_create","actor_id":"alice","outcome":"success","target_id":"user-42"}
{"timestamp":"...","event_type":"auth_failure","actor_id":"unknown","outcome":"failure","reason":"invalid credentials","source_ip":"192.168.1.100"}
{"timestamp":"...","event_type":"user_read","actor_id":"bob","outcome":"success"}
```

## What's Happening

1. **taxonomy.yaml** declares 5 event types across 3 categories, each
   with required and optional fields. This file is the single source of
   truth for your audit schema.

2. **audit-gen** reads the YAML and produces `audit_generated.go` with
   three groups of constants:
   - `Event*` -- event type names (e.g., `EventUserCreate = "user_create"`)
   - `Category*` -- category names (e.g., `CategorySecurity = "security"`)
   - `Field*` -- field names (e.g., `FieldActorID = "actor_id"`)

3. **//go:generate** lets you regenerate with `go generate .` after
   editing the taxonomy. The generated file is committed to version
   control so the example works without running generate first.

4. **//go:embed** loads the taxonomy YAML at compile time. No file I/O at
   startup, no path to get wrong, no missing-file errors in production.

5. **Compile-time safety**: using `EventUserCrate` (typo) instead of
   `EventUserCreate` fails the build. With raw strings, the typo would
   only surface as a runtime validation error.

## Next

[Event Routing](../event-routing/) -- send different event categories to
different outputs.
