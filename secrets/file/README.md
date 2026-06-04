# secrets/file — filesystem secret provider

[![Go Reference][godoc-badge]][godoc]

Resolves `ref+file:///absolute/path` references in audit YAML
configuration to file contents on the local filesystem. Designed for
Kubernetes mounted Secret volumes, Docker secrets, and systemd
`LoadCredential=`. Stateless, zero-config, safe for concurrent use.

> **Module path**: `github.com/axonops/audit/secrets/file`
> **Status**: pre-release (v0.x)
> **Documentation**: [Secrets reference](../../docs/secrets.md) · [Capstone example](../../examples/21-capstone/)

## Why

Kubernetes Secret volumes, Docker secrets, and systemd
`LoadCredential=` all converge on the same pattern: the platform
mounts secret material at a path on the container/process filesystem,
typically under `/var/run/secrets/...` or `/run/credentials/...`.
This is the dominant production pattern for Kubernetes workloads.

The `file` provider reads those files at `outputconfig.Load` time
and substitutes the contents into the YAML config tree. A single
`outputs.yaml` works across environments because the operator
controls what is mounted where.

Compared to [`secrets/env`](../env/):

- **Survives rotation.** Kubernetes Secret volumes use an atomic
  `..data` symlink swap on rotation; subsequent reads see the new
  value without a pod restart.
- **Smaller blast radius.** Only processes that read the path see
  the value; not visible via `/proc/PID/environ`.
- **Larger values.** Bearer tokens, multi-line PEM bundles, JSON
  blobs (the provider supports a JSON-key fragment for multi-field
  files).

Use [`secrets/openbao`](../openbao/) or [`secrets/vault`](../vault/)
when you need centralised audit logging on every secret read,
dynamic secrets, or fine-grained ACLs beyond filesystem permissions.

## Install

```bash
go get github.com/axonops/audit/secrets/file
```

Requires Go 1.26+. Stdlib-only.

## Quick start

YAML — reference absolute file paths. The fragment is optional:

```yaml
outputs:
  alerts:
    type: webhook
    webhook:
      url: "https://siem.example.com/ingest"
      # Whole-file mode: trailing newline is trimmed.
      bearer_token: "ref+file:///var/run/secrets/myapp/token"

  secure_log:
    type: file
    file:
      path: "/var/log/audit/secure.log"
    hmac:
      enabled: true
      salt:
        version: "2026-Q1"
        # JSON file with dotted-fragment path into a nested object.
        value: "ref+file:///etc/secrets/audit.json#hmac.salt"
      algorithm: HMAC-SHA-256
```

Go — register before calling `outputconfig.Load`:

```go
import (
    "github.com/axonops/audit/outputconfig"
    "github.com/axonops/audit/secrets/file"
)

provider := file.New()
defer provider.Close() // no-op; here for symmetry

result, err := outputconfig.Load(ctx, yamlData, taxonomy,
    outputconfig.WithSecretProvider(provider),
)
```

The provider has no configuration. The zero value (`file.Provider{}`)
is also usable. A variadic `Option` parameter is reserved for future
settings; no options exist today.

## Resolution modes

| Ref form                                | Behaviour |
|-----------------------------------------|-----------|
| `ref+file:///path/to/file`              | Returns the entire file contents. A single trailing `\n` is trimmed. |
| `ref+file:///path/to/file.json#a.b.c`   | Parses the file as JSON and traverses the dotted path. Only string leaves are returned; numeric / boolean / object terminals return `ErrSecretResolveFailed`. |

Symlinks are followed (required for the Kubernetes `..data` atomic
swap pattern).

## Configuration reference

No struct fields. `New(opts ...Option)` accepts a variadic option
list for forward compatibility; no options are defined today.

| Constraint                | Value                                                      |
|---------------------------|------------------------------------------------------------|
| Path must be absolute     | `filepath.IsAbs` (must start with `/` on Unix).            |
| Path validation           | No `..` segments, no NUL byte, no percent-encoding.        |
| Max file size             | 1 MiB. Files larger return `ErrSecretResolveFailed`.       |
| JSON key separator        | `.` (dotted path into nested objects).                     |
| Empty key segment in path | Rejected: `ErrMalformedRef`.                               |

The file path is **never echoed** in error messages — knowing the
secret path leaks deployment topology. Distinguish failure modes via
`errors.Is` against the sentinels below.

| Sentinel                          | When                                                     |
|-----------------------------------|----------------------------------------------------------|
| `secrets.ErrMalformedRef`         | Non-absolute path, traversal segment, NUL byte, percent-encoding, empty JSON key segment. |
| `secrets.ErrSecretResolveFailed`  | File not found, permission denied, exceeds 1 MiB, invalid JSON when `#fragment` is set, JSON key not found, terminal value not a string. |

## When NOT to use it

**Do not use `file://` to read arbitrary host paths in production.**
The provider trusts the operator-supplied YAML — the path is the
trust boundary. A malicious or compromised YAML source could read
`/etc/shadow` or any file the process can open. In multi-tenant
deployments where YAML is supplied by anything other than the
operator (a config API, a templated render), use
[`secrets/openbao`](../openbao/) or [`secrets/vault`](../vault/)
instead — they constrain reads to a backend ACL, not a filesystem
permission set.

**Do not use `file://` for files larger than 1 MiB.** The provider
caps reads at 1 MiB to bound memory if a misconfigured ref points at
`/dev/zero` or a runaway log file. Large secret bundles must be split.

## See also

- [Secrets reference](../../docs/secrets.md) — `ref+` URI grammar,
  resolution pipeline, caching (note: `file` provider re-reads on
  every `Load` invocation, which is the correct semantics for K8s
  atomic-swap rotation).
- [Writing custom secret providers](../../docs/writing-custom-secret-providers.md) —
  worked AWS Secrets Manager example.
- Sibling providers:
  - [`secrets/env`](../env/) — environment variables (smaller values,
    no rotation survival)
  - [`secrets/openbao`](../openbao/) — OpenBao KV v2 (centralised, audited)
  - [`secrets/vault`](../vault/) — HashiCorp Vault KV v2 (centralised, audited)

[godoc]: https://pkg.go.dev/github.com/axonops/audit/secrets/file
[godoc-badge]: https://pkg.go.dev/badge/github.com/axonops/audit/secrets/file.svg
