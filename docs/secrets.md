[&larr; Back to README](../README.md)

# Secret Provider Integration

- [Overview](#overview)
- [URI Syntax](#uri-syntax)
- [Resolution Pipeline](#resolution-pipeline)
- [Supported Providers](#supported-providers)
- [Provider Setup](#provider-setup)
- [YAML Configuration Examples](#yaml-configuration-examples)
- [Caching Behaviour](#caching-behaviour)
- [Security Model](#security-model)
- [Error Reference](#error-reference)
- [Anti-Patterns](#anti-patterns)

## Overview

go-audit resolves secret references in YAML configuration values at
startup. Any string value in the output configuration YAML can contain
a `ref+SCHEME://PATH#KEY` URI instead of a literal value. During
`outputconfig.Load`, the library replaces each ref URI with the
plaintext value fetched from the corresponding secret provider.

This keeps credentials, HMAC salts, and bearer tokens out of
configuration files and environment variables.

The URI convention follows [vals](https://github.com/helmfile/vals).

## URI Syntax

```
ref+SCHEME://PATH#KEY
```

| Component | Rules | Example |
|-----------|-------|---------|
| `ref+` | Literal prefix. MUST be lowercase. | `ref+` |
| `SCHEME` | Provider identifier. Lowercase alphanumeric and hyphens. First character MUST be a letter. | `openbao`, `vault` |
| `://` | Separator. MUST be present. | `://` |
| `PATH` | Secret path within the provider. MUST NOT start or end with `/`. MUST NOT contain `..`, `.`, empty segments, or percent-encoded characters. | `secret/data/audit/hmac` |
| `#` | Fragment separator. MUST be present. | `#` |
| `KEY` | Field name within the secret. MUST NOT be empty. MUST NOT contain `#`. | `salt` |

Complete example:

```
ref+openbao://secret/data/audit/hmac#salt
```

`ParseRef` returns `(zero, nil)` when the input does not start with
`ref+` -- the value is treated as a literal. It returns
`(zero, ErrMalformedRef)` when the input starts with `ref+` but
violates any of the rules above.

### KV v2 Path Convention

Both OpenBao and Vault providers expect the **API path**, not the CLI
logical path. The CLI command `bao kv get secret/audit/hmac` maps to
the API path `secret/data/audit/hmac`. Ref URIs MUST use the API path:

```
ref+openbao://secret/data/audit/hmac#salt
```

Not:

```
ref+openbao://secret/audit/hmac#salt
```

## Resolution Pipeline

`outputconfig.Load` processes YAML values through a four-stage
pipeline. Each stage runs on the parsed YAML tree (not raw bytes),
which prevents injection attacks.

```
 1. YAML parse
    Raw bytes -> typed value tree (map, slice, string, number, bool)

 2. Environment variable expansion
    ${VAR} and ${VAR:-default} in string leaves

 3. Secret reference resolution
    ref+SCHEME://PATH#KEY in string leaves -> plaintext from provider

 4. Safety-net scan
    Reject any remaining ref+ URIs (catches typos, missing providers)
```

Stage 3 runs only when at least one provider is registered via
`WithSecretProvider`. Stage 4 always runs.

Resolved values are NOT re-scanned. A secret value that itself
contains `ref+...` is treated as a literal string. This single-pass
guarantee prevents confused-deputy attacks where a secret value
redirects resolution to a different path.

### Combining Environment Variables and Refs

Environment variables expand first. A ref URI can be assembled from
environment variables:

```yaml
hmac:
  enabled: true
  salt:
    version: "2026-Q1"
    value: "ref+openbao://${BAO_SECRET_PATH:-secret/data/audit/hmac}#salt"
```

After env var expansion, the value becomes a complete ref URI
(e.g. `ref+openbao://secret/data/audit/hmac#salt`), which stage 3
resolves.

## Supported Providers

| Scheme | Module | Backend | KV Version |
|--------|--------|---------|------------|
| `openbao` | `github.com/axonops/go-audit/secrets/openbao` | [OpenBao](https://openbao.org/) | KV v2 |
| `vault` | `github.com/axonops/go-audit/secrets/vault` | [HashiCorp Vault](https://www.vaultproject.io/) | KV v2 |

Both providers implement `secrets.BatchProvider`, enabling path-level
caching (see [Caching Behaviour](#caching-behaviour)).

## Provider Setup

### OpenBao

```go
import (
    "context"
    "os"

    "github.com/axonops/go-audit/outputconfig"
    "github.com/axonops/go-audit/secrets/openbao"
)

provider, err := openbao.New(&openbao.Config{
    Address: os.Getenv("BAO_ADDR"),
    Token:   os.Getenv("BAO_TOKEN"),
})
if err != nil {
    return fmt.Errorf("openbao provider: %w", err)
}
defer provider.Close()

result, err := outputconfig.Load(ctx, yamlData, &taxonomy, metrics,
    outputconfig.WithSecretProvider(provider),
)
```

### HashiCorp Vault

```go
import (
    "context"
    "os"

    "github.com/axonops/go-audit/outputconfig"
    "github.com/axonops/go-audit/secrets/vault"
)

provider, err := vault.New(&vault.Config{
    Address: os.Getenv("VAULT_ADDR"),
    Token:   os.Getenv("VAULT_TOKEN"),
})
if err != nil {
    return fmt.Errorf("vault provider: %w", err)
}
defer provider.Close()

result, err := outputconfig.Load(ctx, yamlData, &taxonomy, metrics,
    outputconfig.WithSecretProvider(provider),
)
```

### Multiple Providers

Register one provider per scheme. `Load` returns an error if two
providers share the same scheme.

```go
result, err := outputconfig.Load(ctx, yamlData, &taxonomy, metrics,
    outputconfig.WithSecretProvider(baoProvider),
    outputconfig.WithSecretProvider(vaultProvider),
)
```

This allows a single YAML file to reference secrets from both backends:

```yaml
outputs:
  siem:
    type: webhook
    webhook:
      url: "https://siem.example.com/ingest"
      headers:
        Authorization: "ref+vault://secret/data/siem/creds#authorization_header"
    hmac:
      enabled: true
      salt:
        version: "2026-Q1"
        value: "ref+openbao://secret/data/audit/hmac#salt"
      hash: HMAC-SHA-256
```

### Config Reference

Both `openbao.Config` and `vault.Config` share the same field set:

| Field | Required | Description |
|-------|----------|-------------|
| `Address` | Yes | Server URL. MUST use `https://`. |
| `Token` | Yes | Authentication token. |
| `Namespace` | No | Namespace prefix. Sent as `X-Vault-Namespace` header. |
| `TLSCA` | No | Path to CA certificate PEM file for server verification. |
| `TLSCert` | No | Client certificate path for mTLS. MUST be set together with `TLSKey`. |
| `TLSKey` | No | Client private key path for mTLS. MUST be set together with `TLSCert`. |
| `TLSPolicy` | No | `*audit.TLSPolicy`. Nil defaults to TLS 1.3 only. |
| `AllowPrivateRanges` | No | Permit connections to RFC 1918 addresses and loopback. Required for local development. Default: `false`. |

### WithSecretTimeout

`outputconfig.WithSecretTimeout` sets the overall timeout for all
secret resolution during a single `Load` call. The caller's context
deadline takes precedence when it is earlier.

```go
result, err := outputconfig.Load(ctx, yamlData, &taxonomy, metrics,
    outputconfig.WithSecretProvider(provider),
    outputconfig.WithSecretTimeout(30*time.Second),
)
```

Default: `10s` (`outputconfig.DefaultSecretTimeout`).

## YAML Configuration Examples

### HMAC Salt from OpenBao

```yaml
outputs:
  secure_log:
    type: file
    hmac:
      enabled: true
      salt:
        version: "2026-Q1"
        value: "ref+openbao://secret/data/audit/hmac#salt"
      hash: HMAC-SHA-256
    file:
      path: "/var/log/audit/secure.log"
```

### Webhook Bearer Token from Vault

A ref URI MUST be the complete string value of the YAML field -- the
resolver does not perform substring replacement. Store the full header
value (e.g. `Bearer eyJhbG...`) as the secret key:

```yaml
outputs:
  alerts:
    type: webhook
    webhook:
      url: "https://siem.example.com/audit"
      headers:
        Authorization: "ref+vault://secret/data/siem/creds#authorization_header"
```

The secret's `authorization_header` key contains the complete value
`Bearer eyJhbGciOiJSUzI1NiIs...`. See
[Anti-Patterns: Embedding Refs in Larger Strings](#embedding-refs-in-larger-strings)
for details.

### Loki Basic Auth Password from OpenBao

```yaml
outputs:
  loki_audit:
    type: loki
    loki:
      url: "https://loki.example.com/loki/api/v1/push"
      basic_auth:
        username: "loki-writer"
        password: "ref+openbao://secret/data/loki/auth#password"
```

### Environment-Variable-Driven Paths

Operators control which secret path is used via environment variables,
without changing the YAML file between environments:

```yaml
outputs:
  secure_log:
    type: file
    hmac:
      enabled: true
      salt:
        version: "${HMAC_SALT_VERSION:-2026-Q1}"
        value: "ref+openbao://${BAO_HMAC_PATH:-secret/data/audit/hmac}#salt"
      hash: HMAC-SHA-256
    file:
      path: "/var/log/audit/secure.log"
```

In staging: `BAO_HMAC_PATH=secret/data/staging/hmac`

In production: `BAO_HMAC_PATH=secret/data/prod/hmac`

## Caching Behaviour

The resolver deduplicates API calls within a single `Load` invocation.

Providers that implement `secrets.BatchProvider` (both OpenBao and
Vault) get **path-level caching**: a single API call fetches all keys
at a path. Multiple refs to the same path with different `#KEY`
fragments result in one network call.

```yaml
# One API call to secret/data/audit/hmac, two keys extracted:
hmac:
  salt:
    version: "ref+openbao://secret/data/audit/hmac#version"
    value: "ref+openbao://secret/data/audit/hmac#salt"
```

Providers that implement only `secrets.Provider` get **ref-level
caching**: one call per unique scheme + path + key combination.

The cache is not shared across `Load` calls. Each `Load` invocation
starts with an empty cache.

## Security Model

### HTTPS-Only

Both providers MUST connect over HTTPS. `New` rejects any address
that does not use the `https` scheme:

```
openbao: address must use https (got "http")
```

There is no `AllowInsecureHTTP` escape hatch for provider connections.

### SSRF Protection

Provider HTTP clients use `audit.NewSSRFDialControl` to block
connections to:

- Link-local addresses (`169.254.0.0/16`, `fe80::/10`)
- Cloud metadata endpoints (`169.254.169.254`)
- IPv6 mapped/embedded IPv4 addresses

By default, private ranges (`10.0.0.0/8`, `172.16.0.0/12`,
`192.168.0.0/16`, `127.0.0.0/8`) are also blocked. Set
`AllowPrivateRanges: true` for local development where the secret
backend runs on `127.0.0.1`.

### Redirect Blocking

Provider HTTP clients reject all HTTP redirects. A redirect from a
secret backend is unexpected and could be used to exfiltrate the auth
token to a different host.

### Token Handling

- Tokens are stored as `[]byte` internally, not `string`, to enable
  zeroing on `Close()`
- `Close()` zeroes the token bytes (best-effort; Go GC may retain copies)
- `String()`, `GoString()`, and `Format()` on the provider all return
  `vault{host: ..., token: [REDACTED]}` -- the token never appears in
  `fmt.Printf`, `%v`, `%+v`, or `%#v` output

### Ref Path Redaction

`Ref.String()` returns `ref+SCHEME://[REDACTED]#KEY` -- the vault
path is never included in log output or error messages. The path
reveals infrastructure topology (mount points, secret engine names)
that MUST NOT appear in application logs.

`Ref.Format()` ensures this redaction applies across all `fmt` verbs
(`%v`, `%+v`, `%#v`, `%s`).

Error messages from `ParseRef` that include the raw input use
`redactRef()` to show the scheme only: `ref+openbao://...`.

### Error Message Redaction

Provider HTTP errors strip `*url.Error` wrappers before returning.
`url.Error.Error()` embeds the full request URL, which would leak the
vault path. The provider unwraps to the underlying error.

### Response Size Limit

Provider responses are limited to 1 MiB (`maxResponseSize`). A
compromised server cannot exhaust memory.

Resolved secret values are limited to 64 KiB
(`outputconfig.MaxSecretValueSize`). Values exceeding this are
rejected.

### Trust Model

> **Warning:** Secret provider addresses and tokens come from
> environment variables or Go code. Environment variables are
> operator-controlled -- if an operator can set `BAO_ADDR` and
> `BAO_TOKEN`, they can point secret resolution at an arbitrary
> server. This is by design: the threat model assumes operators are
> trusted. The library protects against infrastructure-level attacks
> (SSRF, redirect, response size) but not against a malicious
> operator.

### Single-Pass Resolution

Resolved secret values are NOT re-scanned for further `ref+` URIs.
This prevents a confused-deputy attack where a secret value at path A
contains `ref+openbao://path-B#key`, causing the library to fetch a
path the operator did not intend.

## Error Reference

All errors wrap one of the sentinel values in `github.com/axonops/go-audit/secrets`.
Use `errors.Is` to check:

```go
if errors.Is(err, secrets.ErrMalformedRef) {
    // ref+ URI is structurally invalid
}
```

| Sentinel | When | Example Message |
|----------|------|-----------------|
| `ErrMalformedRef` | `ParseRef` finds a structural error in a `ref+` URI | `secrets: malformed secret reference: empty key fragment` |
| `ErrProviderNotRegistered` | No provider registered for the scheme in a ref URI | `secrets: no provider registered for scheme: scheme "openbao"` |
| `ErrSecretNotFound` | Secret path exists but the requested key is missing, or the path does not exist (404) | `secrets: secret not found at path: path returned 404` |
| `ErrSecretResolveFailed` | Network error, authentication failure, or server error during resolution | `secrets: secret resolution failed: authentication failed (403)` |
| `ErrUnresolvedRef` | After all resolution passes, a config value still contains a `ref+` URI | `secrets: unresolved secret reference in config: field outputs.siem.webhook.headers.Authorization still contains a secret reference` |

### Provider-Specific Errors

| Error Message | Cause |
|---------------|-------|
| `openbao: address is required` | `Config.Address` is empty |
| `openbao: address must use https (got "http")` | Non-HTTPS address |
| `openbao: address must not contain embedded credentials` | URL contains `user:pass@` |
| `openbao: token is required` | `Config.Token` is empty |
| `openbao: tls_cert and tls_key must both be set or both empty` | Only one of `TLSCert`/`TLSKey` provided |

The `vault` provider returns identical errors with a `vault:` prefix.

## Anti-Patterns

### Hardcoded HMAC Salts

```yaml
# WRONG: salt is visible to anyone who reads the YAML file
hmac:
  salt:
    value: "my-secret-salt-value-2026"
```

Use a ref URI or at minimum an environment variable:

```yaml
# CORRECT: salt fetched from secret backend at startup
hmac:
  salt:
    value: "ref+openbao://secret/data/audit/hmac#salt"
```

### Refs in Untrusted Input

Secret references MUST only appear in operator-controlled YAML
configuration files. If an application accepts YAML from end users
(e.g. a multi-tenant config API), the YAML MUST NOT be passed to
`outputconfig.Load` with a secret provider registered. A malicious
user could craft a `ref+` URI that reads arbitrary secrets from the
backend.

### AllowPrivateRanges in Production

```go
// WRONG: disables SSRF protection in production
provider, err := openbao.New(&openbao.Config{
    Address:            os.Getenv("BAO_ADDR"),
    Token:              os.Getenv("BAO_TOKEN"),
    AllowPrivateRanges: true,  // only for local development
})
```

`AllowPrivateRanges` MUST NOT be `true` in production. It permits
connections to private IP ranges, disabling SSRF protection that
guards against server-side request forgery.

### Embedding Refs in Larger Strings

```yaml
# WRONG: ref+ must be the entire string value
headers:
  Authorization: "Bearer ref+vault://secret/data/creds#token"
```

The resolver replaces the entire string value. If the ref is embedded
in a larger string, `ParseRef` does not match it as a ref URI (it
only matches when `ref+` is the start of the string). The value is
treated as a literal, passes through unchanged, and the safety-net
scan catches it as an unresolved ref.

Store the complete value as the secret:

```yaml
# CORRECT: entire value is the ref URI
headers:
  Authorization: "ref+vault://secret/data/creds#authorization"
# The secret's "authorization" key contains "Bearer eyJhbG..."
```

## Further Reading

- [Output Configuration YAML](output-configuration.md) -- full YAML schema reference
- [HMAC Integrity](hmac-integrity.md) -- per-output HMAC with salt management
- [Error Reference](error-reference.md) -- all go-audit error sentinels
- [API Reference: secrets](https://pkg.go.dev/github.com/axonops/go-audit/secrets) -- `Provider`, `Ref`, `ParseRef`
- [API Reference: secrets/openbao](https://pkg.go.dev/github.com/axonops/go-audit/secrets/openbao) -- OpenBao provider
- [API Reference: secrets/vault](https://pkg.go.dev/github.com/axonops/go-audit/secrets/vault) -- Vault provider
- [API Reference: outputconfig](https://pkg.go.dev/github.com/axonops/go-audit/outputconfig) -- `WithSecretProvider`, `WithSecretTimeout`
- [vals](https://github.com/helmfile/vals) -- the `ref+` URI convention
