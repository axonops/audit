# secrets/env — environment-variable secret provider

[![Go Reference][godoc-badge]][godoc]

Resolves `ref+env://VAR_NAME` references in audit YAML configuration
to the value of the named process environment variable. Stateless,
zero-config, safe for concurrent use.

> **Module path**: `github.com/axonops/audit/secrets/env`
> **Status**: pre-release (v0.x)
> **Documentation**: [Secrets reference](../../docs/secrets.md) · [Capstone example](../../examples/21-capstone/)

## Why

For deployments where credentials are already injected into the
process environment — Kubernetes `env.valueFrom.secretKeyRef`, ECS
task definitions, Nomad templates, Helm `secretRef` — there is no
benefit in routing through Vault or the filesystem just to read the
same value back. `ref+env://` lets a single YAML file work across
environments without conditional logic: the operator controls which
env vars are populated.

Use this provider for:

- **Development.** Quick iteration with `EXPORT WEBHOOK_TOKEN=...`.
- **CI.** Job-scoped credentials via GitHub Actions / GitLab CI
  variables.
- **Kubernetes with env-injected secrets.** When the platform already
  projects a Secret into the container's environment.

For Kubernetes deployments using **mounted Secret volumes** (the
more common pattern), prefer [`secrets/file`](../file/) — it survives
rotation via the `..data` atomic-symlink swap without a pod restart.

## Install

```bash
go get github.com/axonops/audit/secrets/env
```

Requires Go 1.26+. Stdlib-only.

## Quick start

YAML — reference env vars in any string field:

```yaml
outputs:
  alerts:
    type: webhook
    webhook:
      url: "ref+env://WEBHOOK_URL"
      headers:
        Authorization: "ref+env://WEBHOOK_AUTH_HEADER"
```

Go — register the provider before calling `outputconfig.Load`:

```go
import (
    "github.com/axonops/audit/outputconfig"
    "github.com/axonops/audit/secrets/env"
)

provider := env.New()
defer provider.Close() // no-op; here for symmetry

result, err := outputconfig.Load(ctx, yamlData, taxonomy,
    outputconfig.WithSecretProvider(provider),
)
```

The provider has no configuration. The zero value (`env.Provider{}`)
is also usable.

## Configuration reference

No configuration. `New()` takes no arguments.

`Resolve` is called with a `Ref` parsed from `ref+env://VAR_NAME`:

| URI component | Constraint                                              |
|---------------|---------------------------------------------------------|
| `VAR_NAME`    | POSIX env var name: `[A-Z_][A-Z0-9_]*`. Validated by the provider. |
| `#fragment`   | Not supported. Refs containing `#` are rejected at parse time. |

The variable name is **never echoed** in error messages — knowing
which env var your config consults is itself information a log
scraper should not gain. Distinguish failure modes via `errors.Is`
against the sentinels listed below; the provider's slog category
surfaces the failure class for local debugging.

| Sentinel                  | When                                                     |
|---------------------------|----------------------------------------------------------|
| `secrets.ErrMalformedRef` | Var name fails POSIX validation, or ref carries a `#fragment`. |
| `secrets.ErrSecretResolveFailed` | Var is unset, **or set to an empty string**. Empty audit secrets are never legitimate; set-to-empty is treated identically to unset. |

## When NOT to use it

**Do not use `env://` in production for high-value credentials.**
Environment variables are visible to any process running as the
same UID via `/proc/PID/environ` (Linux), `procfs`-equivalent
interfaces on other Unixes, and process-listing tools. They also
appear in core dumps and heap profiles. A compromised sidecar, a
debugging tool left in production, or a logging agent that scrapes
process metadata can extract them.

For production:

- **Mounted secrets** (K8s `volumeMounts`, Docker secrets) →
  [`secrets/file`](../file/). Survives rotation; smaller blast
  radius (only processes that read the file path see the value).
- **Centralised secret store** with audit logging and ACLs →
  [`secrets/vault`](../vault/) or [`secrets/openbao`](../openbao/).

## See also

- [Secrets reference](../../docs/secrets.md) — `ref+` URI grammar,
  resolution pipeline, security model.
- [Writing custom secret providers](../../docs/writing-custom-secret-providers.md) —
  if `env`, `file`, `vault`, and `openbao` all miss your platform.
- Sibling providers:
  - [`secrets/file`](../file/) — filesystem (K8s mounted secrets, the
    rotation-safe alternative to `env`)
  - [`secrets/openbao`](../openbao/) — OpenBao KV v2 (production)
  - [`secrets/vault`](../vault/) — HashiCorp Vault KV v2 (production)

[godoc]: https://pkg.go.dev/github.com/axonops/audit/secrets/env
[godoc-badge]: https://pkg.go.dev/badge/github.com/axonops/audit/secrets/env.svg
