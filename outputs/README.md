# outputs — one blank import registers every built-in output

[![Go Reference][godoc-badge]][godoc]

Convenience umbrella that blank-imports `file`, `syslog`, `webhook`,
`loki`, and `splunk`, and registers the built-in `stdout` factory.
Use it when you want every output type available in a single line.

> **Module path**: `github.com/axonops/audit/outputs`
> **Status**: pre-release (v0.x)
> **Documentation**: [Outputs overview][outputs-doc] · [Writing custom outputs][custom-outputs-doc]

## Why

Output types live in their own Go modules (`audit/file`, `audit/syslog`,
`audit/webhook`, `audit/loki`, `audit/splunk`) so adopters only pay for
the dependencies they actually use. Each module's `init()` registers
its factory with the core registry, so a blank import is enough — you
do not call the constructor by hand.

Once you go past two or three output types, the import block becomes
boilerplate:

```go
import (
    _ "github.com/axonops/audit/file"
    _ "github.com/axonops/audit/syslog"
    _ "github.com/axonops/audit/webhook"
    _ "github.com/axonops/audit/loki"
    _ "github.com/axonops/audit/splunk"
)
```

This package is the one-liner replacement. It blank-imports the five
sub-modules above and registers the built-in `stdout` factory in its
own `init()`, so any of the YAML `type:` strings just work.

```go
import _ "github.com/axonops/audit/outputs"
```

This is the same pattern as the standard library's `image/all`:
import for the side effect, get every codec registered.

## When NOT to use it

Production deployments that ship binaries to constrained environments
should blank-import only the output types they actually use. Pulling in
this package transitively brings in every output module's dependencies
— HTTP clients, syslog libraries, compression codecs — even if the
deployment only ever writes to a local file.

```go
// Smaller binary, file-only:
import (
    "github.com/axonops/audit/outputconfig"
    _ "github.com/axonops/audit/file"
)
```

Use the umbrella for development, examples, demos, the capstone, and
internal services where binary size is not a concern. Reach for the
individual imports when it matters.

## Install

```bash
go get github.com/axonops/audit/outputs
```

## Quick start

```go
package main

import (
    "context"
    _ "embed"
    "log"

    "github.com/axonops/audit/outputconfig"
    _ "github.com/axonops/audit/outputs" // registers all built-in output types
)

//go:embed taxonomy.yaml
var taxonomyYAML []byte

func main() {
    auditor, err := outputconfig.New(context.Background(), taxonomyYAML, "outputs.yaml")
    if err != nil {
        log.Fatalf("audit setup: %v", err)
    }
    defer func() { _ = auditor.Close() }()

    // ... use the auditor ...
}
```

The package exposes **no identifiers** — there is nothing to call. The
import is the API. The `_ "..."` syntax is required; an unblank import
would fail to compile because nothing in `outputs.outputs` is
referenced.

## What it registers

| YAML `type:` | Registered by | Lives in |
|---|---|---|
| `stdout` | `outputs.init()` | core `audit` package (factory) |
| `file` | `audit/file.init()` | `github.com/axonops/audit/file` |
| `syslog` | `audit/syslog.init()` | `github.com/axonops/audit/syslog` |
| `webhook` | `audit/webhook.init()` | `github.com/axonops/audit/webhook` |
| `loki` | `audit/loki.init()` | `github.com/axonops/audit/loki` |
| `splunk` | `audit/splunk.init()` | `github.com/axonops/audit/splunk` |

Double-registration is safe — `audit.RegisterOutputFactory` overwrites
the previous entry silently. So you can blank-import this package
alongside a custom factory registration:

```go
import (
    _ "github.com/axonops/audit/outputs" // built-ins
    _ "your.org/audit-kafka"             // your custom 'kafka' type
)
```

## See also

- **[docs/outputs.md][outputs-doc]** — overview of every built-in output type
- **[docs/writing-custom-outputs.md][custom-outputs-doc]** — implement
  your own output type and register a factory
- **[github.com/axonops/audit/outputconfig][outputconfig-godoc]** — the
  YAML loader that consumes the factories this package registers
- **[examples/02-code-generation][example-02]** — the canonical
  blank-import + `outputconfig.New` pattern

[godoc]: https://pkg.go.dev/github.com/axonops/audit/outputs
[godoc-badge]: https://pkg.go.dev/badge/github.com/axonops/audit/outputs.svg
[outputconfig-godoc]: https://pkg.go.dev/github.com/axonops/audit/outputconfig
[outputs-doc]: https://github.com/axonops/audit/blob/main/docs/outputs.md
[custom-outputs-doc]: https://github.com/axonops/audit/blob/main/docs/writing-custom-outputs.md
[example-02]: https://github.com/axonops/audit/tree/main/examples/02-code-generation
