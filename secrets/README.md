# secrets — secret-reference interfaces and `ref+` URI parser

[![Go Reference][godoc-badge]][godoc]

The core types for resolving `ref+SCHEME://PATH#KEY` URIs in audit
output configuration. Defines the `Provider` and `BatchProvider`
interfaces, the `Ref` struct and parser, and the sentinel error set.
No backends — concrete providers ship as separate sub-modules.

> **Module path**: `github.com/axonops/audit/secrets`
> **Status**: pre-release (v0.x)
> **Documentation**: [Secrets reference](../docs/secrets.md) · [Writing custom providers](../docs/writing-custom-secret-providers.md)

## Why

Credentials in YAML files are a recurring incident: they leak via
backups, source control, container images, and config-dump endpoints.
The `ref+` URI convention (borrowed from [vals]) lets a YAML value
declare its source without containing the value:

```yaml
hmac:
  salt:
    value: "ref+openbao://secret/data/audit/hmac#salt"
```

`outputconfig.Load` parses the YAML, resolves each `ref+` URI through
the registered provider for its scheme, and substitutes the plaintext
into the typed config tree before constructing outputs. Resolution
runs at load time — once — so the hot path is unaffected.

This package defines the protocol; it ships no provider code. That
keeps the core module dependency-free (stdlib-only). Vault, OpenBao,
file, and env providers each live in their own sub-module so consumers
pay only for the backends they use.

## Install

```bash
go get github.com/axonops/audit/secrets
```

Requires Go 1.26+. Stdlib-only.

## Quick start

Most consumers never import this package directly — `outputconfig.Load`
handles parse + resolve. Import a provider instead:

```go
import (
    "github.com/axonops/audit/outputconfig"
    "github.com/axonops/audit/secrets/openbao"
)

provider, err := openbao.New(&openbao.Config{
    Address: os.Getenv("BAO_ADDR"),
    Token:   os.Getenv("BAO_TOKEN"),
})
if err != nil {
    return err
}
defer provider.Close()

result, err := outputconfig.Load(ctx, yamlData, taxonomy,
    outputconfig.WithSecretProvider(provider),
)
```

Or skip programmatic setup entirely and declare providers in
`outputs.yaml` — `outputconfig.Load` constructs and closes them:

```yaml
secrets:
  timeout: "15s"
  openbao:
    address: "${BAO_ADDR}"
    token: "${BAO_TOKEN}"
```

Direct use of this package is for implementing a custom provider, or
for parsing/validating refs in tooling. See
[Writing custom providers](../docs/writing-custom-secret-providers.md).

## URI grammar

```
ref+SCHEME://PATH#KEY
```

| Component | Rules |
|-----------|-------|
| `ref+`    | Literal lowercase prefix. |
| `SCHEME`  | Lowercase alphanumeric + hyphens. First char a letter. |
| `://`     | Required separator. |
| `PATH`    | Scheme-dependent. Vault/OpenBao: no leading/trailing `/`, no `..`, no `.`, no empty segments, no percent-encoding. `file://`: must start with `/`. `env://`: POSIX variable name. |
| `#KEY`    | Required for vault/openbao/file-with-JSON. Forbidden for `env://`. |

Full grammar table in [docs/secrets.md §URI Syntax](../docs/secrets.md#uri-syntax).

`ParseRef` returns `(zero, nil)` for inputs that do not start with
`ref+` — they are treated as literal YAML values. It returns
`(zero, ErrMalformedRef)` for inputs that start with `ref+` but
violate any rule. Error messages never echo the input substring
(the input may contain attacker-influenced bytes); see the
redaction notes on `Ref.String` and `redactRef` in the godoc.

## The `Provider` interface

```go
type Provider interface {
    Scheme() string
    Resolve(ctx context.Context, ref Ref) (string, error)
    Close() error
}
```

The optional `BatchProvider` extension enables path-level caching —
implementing it lets the resolver fetch all keys at one path in a
single API call, useful for KV v2 stores:

```go
type BatchProvider interface {
    Provider
    ResolvePath(ctx context.Context, path string) (map[string]string, error)
}
```

The resolver calls `Provider` methods from a single goroutine during
`outputconfig.Load`. Providers carry credentials and MUST redact them
in their `fmt.Stringer` output. Construction MUST NOT perform network
I/O — defer connection to the first `Resolve` call. See the godoc on
each method for the full contract.

## How providers are registered

There is no package-level registry and no blank-import side effects.
Providers reach the resolver by one of two routes:

1. **Programmatic.** Construct the provider and pass it to
   `outputconfig.Load` via `outputconfig.WithSecretProvider`. The
   caller owns the provider's lifecycle (including `defer
   provider.Close()`).
2. **YAML.** Declare the provider in the `secrets:` block of
   `outputs.yaml`. `outputconfig.Load` constructs it, uses it,
   and closes it before returning. Today this route supports
   `openbao` and `vault`; `file` and `env` providers are stateless
   and have no YAML config to declare — programmatic setup is the
   one-liner `file.New()` / `env.New()`.

Duplicate registration (same scheme via both routes) is a config
error: `Load` returns an error wrapping `ErrOutputConfigInvalid`.

## Built-in providers

| Scheme    | Module                                                       | Backend                                  |
|-----------|--------------------------------------------------------------|------------------------------------------|
| `env`     | [`secrets/env`](./env/)         | Process environment variables            |
| `file`    | [`secrets/file`](./file/)       | Filesystem (K8s mounted secrets, Docker secrets) |
| `openbao` | [`secrets/openbao`](./openbao/) | [OpenBao] KV v2                          |
| `vault`   | [`secrets/vault`](./vault/)     | [HashiCorp Vault] KV v2                  |

Each provider lives in its own Go sub-module — import only the ones
you need. To add a backend the library does not ship (AWS Secrets
Manager, GCP Secret Manager, Azure Key Vault, an internal API), see
[Writing custom providers](../docs/writing-custom-secret-providers.md).

## Sentinel errors

All provider errors wrap one of these — use `errors.Is`:

| Sentinel                   | Meaning                                                       |
|----------------------------|---------------------------------------------------------------|
| `ErrMalformedRef`          | Structural error in a `ref+` URI (parse-time).                |
| `ErrProviderNotRegistered` | No provider registered for the URI's scheme.                  |
| `ErrSecretNotFound`        | Path or key does not exist at the backend.                    |
| `ErrSecretResolveFailed`   | Transient or permanent network / auth failure.                |
| `ErrUnresolvedRef`         | Safety-net: a `ref+` URI survived resolution (typo, missing provider). |

`ErrSecretResolveFailed` is the only sentinel where retry may help
(token rotation, restored connectivity); the others are permanent
until config is corrected.

## Security model (summary)

The full model is in [docs/secrets.md §Security Model](../docs/secrets.md#security-model);
the headline guarantees the interfaces enforce:

- **Path redaction.** `Ref.String`, `Ref.GoString`, and `Ref.Format`
  return `ref+SCHEME://[REDACTED]#KEY`. The path reveals
  infrastructure topology (mount points, secret engine names) and
  MUST NOT appear in logs.
- **No substring echo in errors.** `ParseRef` errors describe the
  failure category, never the input substring (the input may be
  attacker-influenced).
- **Single-pass resolution.** Resolved values are not re-scanned.
  A secret value containing `ref+...` is treated as a literal,
  preventing confused-deputy redirection.
- **Stdlib-only.** This package has no third-party dependencies.

## See also

- [Secrets reference](../docs/secrets.md) — full URI grammar, resolution
  pipeline, caching, timeout, rotation, anti-patterns.
- [Writing custom secret providers](../docs/writing-custom-secret-providers.md) —
  worked AWS Secrets Manager example + security checklist.
- [Output configuration YAML](../docs/output-configuration.md) — the
  `secrets:` block reference (timeout, provider fields).
- Built-in providers:
  - [`secrets/env`](./env/) — environment variables (dev / K8s env injection)
  - [`secrets/file`](./file/) — filesystem (K8s mounted secrets)
  - [`secrets/openbao`](./openbao/) — OpenBao KV v2
  - [`secrets/vault`](./vault/) — HashiCorp Vault KV v2

[vals]: https://github.com/helmfile/vals
[OpenBao]: https://openbao.org/
[HashiCorp Vault]: https://www.vaultproject.io/
[godoc]: https://pkg.go.dev/github.com/axonops/audit/secrets
[godoc-badge]: https://pkg.go.dev/badge/github.com/axonops/audit/secrets.svg
