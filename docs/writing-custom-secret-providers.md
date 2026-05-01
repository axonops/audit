[&larr; Back to README](../README.md)

# Writing Custom Secret Providers

This guide explains how to implement a custom `secrets.Provider`
for resolving `ref+SCHEME://...` URIs against a backend that the
audit library does not ship a built-in provider for (AWS Secrets
Manager, GCP Secret Manager, Azure Key Vault, Doppler, 1Password
Connect, an internal secrets API, etc.).

For the existing built-in providers (Vault, OpenBao, file, env)
see [`docs/secrets.md`](secrets.md). For the conceptual model
(`ref+` URI syntax, resolution pipeline, caching, memory
retention) see that document first — this guide assumes
familiarity with those concepts.

## Contents

- [When to write a custom provider](#when-to-write-a-custom-provider)
- [The `secrets.Provider` interface](#the-secretsprovider-interface)
- [Worked example: AWS Secrets Manager](#worked-example-aws-secrets-manager)
- [Registration](#registration)
- [Error semantics](#error-semantics)
- [Memory retention](#memory-retention)
- [Optional `BatchProvider` extension](#optional-batchprovider-extension)
- [Security checklist](#security-checklist)
- [Testing your provider](#testing-your-provider)
- [Further reading](#further-reading)

## When to write a custom provider

The library ships providers for [Vault](secrets.md#hashicorp-vault),
[OpenBao](secrets.md#openbao), [file](secrets.md#file-k8s-mounted-secrets),
and [env](secrets.md#env). Before writing a custom provider,
verify that none of these fits your deployment. In particular:

- Files mounted by Kubernetes Secret volumes, Vault Agent
  Injector, or systemd `LoadCredential=` are usually best served
  by the [**file**](secrets.md#file-k8s-mounted-secrets) provider.
  You do not need a custom AWS provider just to read a file.
- Environment variables injected by your platform (ECS task
  definitions, Nomad templates, Helm chart `secretRef`) are
  usually best served by the [**env**](secrets.md#env) provider.

Write a custom provider when **the audit library must call your
secret backend's network API directly** — typically because:

- Your platform has no file/env injection layer (a desktop or
  CLI tool, a long-running daemon outside Kubernetes/Nomad).
- Your backend is unique to your organisation (an internal
  secrets API, a HashiCorp Vault deployment that exposes a
  different KV layout than the upstream KV v2 plugin).
- You need backend-specific features (audit logging on every
  read, dynamic secrets, lease renewal, cross-region failover).

## The `secrets.Provider` interface

Defined in `github.com/axonops/audit/secrets/secrets.go`:

```go
type Provider interface {
    // Scheme returns the URI scheme this provider handles
    // (e.g. "aws-sm"). Lowercase, must match the scheme used
    // in ref+ URIs.
    Scheme() string

    // Resolve fetches the plaintext secret for the given ref.
    // ctx controls timeout and cancellation for network I/O.
    Resolve(ctx context.Context, ref Ref) (string, error)

    // Close releases resources (HTTP clients, connection pools,
    // session tokens). Idempotent.
    Close() error
}
```

The library calls these methods from a single goroutine during
the `outputconfig.Load` phase. Implementations need not be
goroutine-safe, but **must** be safe for repeated `Resolve`
calls within a single `Load` (the resolver caches results
per-ref but may call `Resolve` multiple times for distinct
refs).

The optional [`BatchProvider`](#optional-batchprovider-extension)
extension lets the resolver fetch all keys at a path in a single
API call.

## Worked example: AWS Secrets Manager

Below is a complete reference implementation for a provider that
resolves `ref+aws-sm://my/path#field` URIs against
[AWS Secrets Manager](https://aws.amazon.com/secrets-manager/).
The example assumes AWS credentials are supplied via the standard
SDK chain (IAM role, env vars, profile) — no application-level
credential handling.

> **Module layout.** Place the provider in its own Go
> sub-module to keep the AWS SDK out of consumers that don't
> use it. Mirror the project's `secrets/openbao` and
> `secrets/vault` sub-module structure (`go.mod`, `go.sum`,
> `package awssm`, `package awssm_test`). The example below is
> the contents of `secrets/awssm/awssm.go`.

```go
package awssm

import (
    "context"
    "encoding/json"
    "errors"
    "fmt"

    "github.com/aws/aws-sdk-go-v2/config"
    "github.com/aws/aws-sdk-go-v2/service/secretsmanager"
    smtypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"

    "github.com/axonops/audit/secrets"
)

// Scheme is the URI scheme this provider handles. Use it as the
// scheme component in ref+aws-sm://path#key references.
const Scheme = "aws-sm"

// Provider implements secrets.Provider against AWS Secrets Manager.
// Construct via New; the zero value is NOT ready to use.
type Provider struct {
    client *secretsmanager.Client
    region string
}

// Compile-time interface satisfaction check.
var _ secrets.Provider = (*Provider)(nil)

// Config controls Provider construction. Defaults are sensible —
// the zero value uses the SDK's default credential chain and the
// region resolved from AWS_REGION / config files.
type Config struct {
    // Region is the AWS region. If empty, resolved from the
    // standard SDK chain (AWS_REGION env var, ~/.aws/config).
    Region string
}

// New constructs a Provider. Network I/O to AWS Secrets Manager
// is deferred to the first Resolve call. Note that the SDK's
// default credential chain may itself contact the EC2 / EKS /
// Fargate IMDS endpoint at construction time to resolve
// instance-role credentials — this is unavoidable when relying
// on the standard chain. Pre-load credentials and pass them
// explicitly via aws.Config if your security model forbids any
// network I/O during construction.
//
// The returned Provider holds an *secretsmanager.Client that
// caches a connection pool. Call Close when done.
func New(ctx context.Context, cfg Config) (*Provider, error) {
    awsCfg, err := config.LoadDefaultConfig(ctx)
    if err != nil {
        return nil, fmt.Errorf("audit/secrets/awssm: load AWS config: %w", err)
    }
    if cfg.Region != "" {
        awsCfg.Region = cfg.Region
    }
    return &Provider{
        client: secretsmanager.NewFromConfig(awsCfg),
        region: awsCfg.Region,
    }, nil
}

// Scheme returns "aws-sm".
func (*Provider) Scheme() string { return Scheme }

// Close releases resources. The AWS SDK v2 client uses an
// http.Client with no explicit cleanup; a future Close
// implementation could call CloseIdleConnections on it. For now,
// Close is a no-op.
func (*Provider) Close() error { return nil }

// Resolve fetches the secret value for ref. The ref path is the
// AWS Secrets Manager secret name (or ARN); the ref key is the
// JSON field name to extract from the secret value.
//
// Returns secrets.ErrSecretNotFound when the secret does not
// exist or the requested key is not present in the JSON object.
// Returns secrets.ErrSecretResolveFailed for transient and auth
// errors (network failure, AccessDenied, throttling).
func (p *Provider) Resolve(ctx context.Context, ref secrets.Ref) (string, error) {
    if err := ref.Valid(); err != nil {
        return "", fmt.Errorf("audit/secrets/awssm: %w", err)
    }
    if ref.Scheme != Scheme {
        // Should never happen — outputconfig dispatches by scheme.
        return "", fmt.Errorf("audit/secrets/awssm: unexpected scheme: %w", secrets.ErrMalformedRef)
    }
    if ref.Key == "" {
        // AWS Secrets Manager values are typically JSON objects
        // with multiple keys; require the consumer to be explicit.
        return "", fmt.Errorf("audit/secrets/awssm: missing #key fragment: %w", secrets.ErrMalformedRef)
    }

    out, err := p.client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
        SecretId: &ref.Path,
    })
    if err != nil {
        var notFound *smtypes.ResourceNotFoundException
        if errors.As(err, &notFound) {
            // Path-level redaction — never echo ref.Path.
            return "", fmt.Errorf("audit/secrets/awssm: secret not found (path redacted): %w", secrets.ErrSecretNotFound)
        }
        // Cover everything else under ResolveFailed: network errors,
        // AccessDeniedException, ThrottlingException, KMS errors, etc.
        return "", fmt.Errorf("audit/secrets/awssm: get secret failed (path redacted): %w", secrets.ErrSecretResolveFailed)
    }

    if out.SecretString == nil {
        // Binary secrets are not supported by this provider — the
        // audit library expects string values for ref+ resolution.
        return "", fmt.Errorf("audit/secrets/awssm: binary secret unsupported (path redacted): %w", secrets.ErrSecretResolveFailed)
    }

    // AWS Secrets Manager values are typically JSON objects.
    var fields map[string]string
    if jsonErr := json.Unmarshal([]byte(*out.SecretString), &fields); jsonErr != nil {
        // The secret is not a JSON object. If the caller wants the
        // raw string, they can use #_raw or implement a different
        // convention; here we surface it as a malformed key request.
        return "", fmt.Errorf("audit/secrets/awssm: secret not a JSON object (path redacted): %w", secrets.ErrSecretResolveFailed)
    }
    val, ok := fields[ref.Key]
    if !ok {
        // Key redaction — never echo ref.Key in case the key name
        // itself reveals deployment topology.
        return "", fmt.Errorf("audit/secrets/awssm: key not found in secret (key redacted): %w", secrets.ErrSecretNotFound)
    }
    if val == "" {
        return "", fmt.Errorf("audit/secrets/awssm: empty value for key (redacted): %w", secrets.ErrSecretResolveFailed)
    }
    return val, nil
}
```

The example follows the same patterns as the built-in providers:

- `Scheme` is a package constant (also exported on the
  `Provider` for runtime inspection).
- `Provider` is a struct, not an interface. `New` is the
  constructor; the zero value is documented as not-ready.
- A `var _ secrets.Provider = (*Provider)(nil)` compile-time
  check fails the build if the interface ever changes.
- Errors wrap one of the four sentinels
  ([`ErrMalformedRef`](#error-semantics),
  [`ErrSecretNotFound`](#error-semantics),
  [`ErrSecretResolveFailed`](#error-semantics)) so consumers
  can `errors.Is` them.
- Path and key redaction in error messages — see
  [Security checklist](#security-checklist) and
  [`docs/secrets.md` § Error Message Redaction](secrets.md#error-message-redaction).

## Registration

Pass your provider to `outputconfig.Load` via
`outputconfig.WithSecretProvider`:

```go
import (
    "github.com/axonops/audit/outputconfig"
    "github.com/axonops/audit/secrets/awssm"
)

func loadAuditor(ctx context.Context, taxonomyYAML, outputsYAML []byte) (*audit.Auditor, error) {
    provider, err := awssm.New(ctx, awssm.Config{Region: "us-east-1"})
    if err != nil {
        return nil, fmt.Errorf("create awssm provider: %w", err)
    }
    // The CALLER owns the provider's lifetime — Load does NOT
    // close providers registered via WithSecretProvider. (Providers
    // configured in the YAML `secrets:` section ARE closed inside
    // Load.) Always defer Close, regardless of whether Load
    // succeeds.
    defer func() { _ = provider.Close() }()

    loaded, err := outputconfig.Load(ctx, outputsYAML, taxonomy,
        outputconfig.WithSecretProvider(provider),
    )
    if err != nil {
        return nil, err
    }
    // ... use loaded.Options() to construct audit.New(...)
}
```

> ⚠️ **Provider lifetime.** `Load` closes only the providers it
> constructed itself from the YAML `secrets:` section. Providers
> passed via `WithSecretProvider` are owned by the caller and
> MUST be `Close`d after `Load` returns — typically with a
> `defer` immediately after construction. Forgetting `Close` is
> the most common antipattern in custom providers because it
> defeats the bootstrap-credential zeroing recommended in
> [Memory retention](#memory-retention) below.

Multiple providers may be registered with separate
`WithSecretProvider` calls. The resolver dispatches by scheme —
each `ref+SCHEME://...` URI is resolved by the provider whose
`Scheme()` matches `SCHEME`. Registering two providers with the
same scheme is an error (the second registration fails
`outputconfig.Load`).

In your `outputs.yaml`:

```yaml
version: 1
app_name: my-service
host: prod-01

outputs:
  webhook_alerts:
    type: webhook
    webhook:
      url: https://alerts.example.com/audit
      headers:
        Authorization: "Bearer ref+aws-sm://prod/audit/webhook-token#bearer"
```

## Error semantics

The library defines five sentinel errors in `secrets/secrets.go`
(`ErrMalformedRef`, `ErrProviderNotRegistered`, `ErrSecretNotFound`,
`ErrSecretResolveFailed`, `ErrUnresolvedRef`). Four of them are
relevant when implementing a provider:

| Sentinel | When to wrap |
|---|---|
| `secrets.ErrMalformedRef` | The ref is structurally invalid — empty scheme, empty path, missing required `#key`, scheme mismatch, etc. Use this in `Resolve` only when validating the parsed `Ref` (the loader pre-validates with `ParseRef`, but defence in depth is encouraged). |
| `secrets.ErrSecretNotFound` | The path or key does not exist in the backend. **Permanent** — the loader does not retry. |
| `secrets.ErrSecretResolveFailed` | Transient or auth failure — network error, AccessDenied, ThrottlingException, KMS error, malformed secret value, empty resolved value. |
| `secrets.ErrUnresolvedRef` | Returned by the loader when, after all provider calls, a string still contains a `ref+` prefix. **Do not** wrap this in your provider — it is loader-side. |

Wrap the sentinel as the outermost `%w` so consumers can use
`errors.Is`. When you also need to preserve the underlying
backend error, use Go 1.20 multi-wrap (`%w: %w`) with the
sentinel first:

```go
// Sentinel only (path/key redacted):
return "", fmt.Errorf("audit/secrets/awssm: secret not found (path redacted): %w",
    secrets.ErrSecretNotFound)

// Sentinel + backend error preserved (the backend error may
// reach diagnostic logs but the sentinel governs errors.Is):
return "", fmt.Errorf("audit/secrets/awssm: get failed: %w: %w",
    secrets.ErrSecretResolveFailed, err)
```

```go
if errors.Is(err, secrets.ErrSecretNotFound) {
    // permanent — no retry, alert ops
}
if errors.Is(err, secrets.ErrSecretResolveFailed) {
    // transient or auth — verify credentials, network, throttling
}
```

The `path` and `key` MUST NOT appear in error messages. They are
infrastructure topology that a log scraper should not see (the
existing built-in providers redact aggressively; #486 documents
the threat). When a redacted error obscures legitimate
debugging, the auditor's diagnostic logger output (typically
stderr, not shipped to a SIEM) is the correct channel.

## Memory retention

Go strings cannot be zeroed. A secret returned from `Resolve`
will be embedded in long-lived `outputconfig.Loaded` config
structs, copied into HTTP headers, and persist in the heap until
GC reclaims the memory. The library cannot reduce this retention
window — it is a property of the language.

Provider authors **can** reduce the retention of *bootstrap
credentials* (the token, access key, or session that authenticates
the provider itself):

- Store the bootstrap credential as `[]byte`, not `string`.
- Zero it in `Close` (`for i := range token { token[i] = 0 }`).
- Avoid wrapping it in `string()` conversions that allocate
  immortal copies (notably `http.Header.Set` and
  `fmt.Sprintf("Bearer %s", token)` both allocate strings the
  GC owns).

The built-in `vault` and `openbao` providers demonstrate this
pattern. See [`docs/secrets.md` § Memory Retention](secrets.md#memory-retention-and-rotation-strategy)
and [SECURITY.md § Secrets and Memory Retention](../SECURITY.md)
for the full model.

## Optional `BatchProvider` extension

If your backend can return all keys at a path in a single API
call (Vault KV v2, OpenBao KV v2, AWS Secrets Manager when the
secret is a JSON object), implement `secrets.BatchProvider` as
well. The resolver uses it to deduplicate API calls when the
same path appears under multiple `#key` fragments.

```go
// Compile-time check that the provider implements both
// interfaces.
var _ secrets.BatchProvider = (*Provider)(nil)

// ResolvePath fetches all keys at the given path in a single
// AWS Secrets Manager API call. The caller has already
// validated the path via Ref.Valid.
func (p *Provider) ResolvePath(ctx context.Context, path string) (map[string]string, error) {
    out, err := p.client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
        SecretId: &path,
    })
    if err != nil {
        var notFound *smtypes.ResourceNotFoundException
        if errors.As(err, &notFound) {
            return nil, fmt.Errorf("audit/secrets/awssm: secret not found (path redacted): %w", secrets.ErrSecretNotFound)
        }
        return nil, fmt.Errorf("audit/secrets/awssm: get secret failed (path redacted): %w", secrets.ErrSecretResolveFailed)
    }
    if out.SecretString == nil {
        return nil, fmt.Errorf("audit/secrets/awssm: binary secret unsupported (path redacted): %w", secrets.ErrSecretResolveFailed)
    }
    var fields map[string]string
    if jsonErr := json.Unmarshal([]byte(*out.SecretString), &fields); jsonErr != nil {
        return nil, fmt.Errorf("audit/secrets/awssm: secret not a JSON object (path redacted): %w", secrets.ErrSecretResolveFailed)
    }
    return fields, nil
}
```

The resolver detects `BatchProvider` via type assertion. No
opt-in is required.

## Security checklist

Before shipping a custom provider, verify each item:

- [ ] **HTTPS only** — reject any URL or endpoint that is not
      `https://`. The library's existing providers refuse
      `http://` unless `AllowInsecureHTTP: true` is explicitly
      set in the provider config (dev-only knob).
- [ ] **TLS policy** — surface `tls_policy` in your provider's
      config (allowed minimum version, allowed cipher suites,
      CA file). Reuse `audit.TLSPolicy` from the core module so
      your provider's TLS stance is consistent with the outputs.
- [ ] **SSRF protection** — if your provider talks to an
      HTTP backend, install `audit.NewSSRFDialControl()` on the
      `*http.Transport`'s `Control` (or `ControlContext`) hook.
      Use `audit.AllowPrivateRanges()` as an `SSRFOption` only
      when explicitly opted in by config to permit RFC 1918 /
      loopback / link-local addresses. Cloud metadata endpoints
      (`169.254.169.254`, `fd00:ec2::254`) MUST always be
      blocked, even with the opt-in.
- [ ] **Redirect blocking** — install a `CheckRedirect` on the
      `*http.Client` that returns `http.ErrUseLastResponse`
      (or any non-nil error) on every redirect. The built-in
      `secrets/openbao` and `secrets/vault` providers do this
      inline. Cross-origin redirects are an SSRF amplifier.
- [ ] **Token zeroing** — store bootstrap credentials as
      `[]byte`, zero in `Close`, avoid `string` conversions.
- [ ] **Path / key redaction** — error messages MUST NOT echo
      `ref.Path` or `ref.Key`. The `Ref` type's `String`,
      `GoString`, and `Format` methods all redact, but if you
      log raw fields, redact yourself.
- [ ] **Response size limit** — cap the response body at a sane
      size (the built-in HTTP providers cap at 1 MiB via
      `io.LimitReader`) so a malicious or misconfigured backend
      cannot exhaust memory. Apply this even when the backend
      itself caps responses (AWS Secrets Manager caps at 64 KiB
      today) — defence in depth.
- [ ] **Single-pass resolution** — your `Resolve` MUST NOT
      return a value that itself contains `ref+`. The loader
      enforces this for you (`ErrUnresolvedRef`); your
      responsibility is not to construct one.
- [ ] **Network-I/O deferred to `Resolve`** — `New` should not
      contact the backend. Construction must succeed offline.
- [ ] **No goroutine leaks** — every goroutine started by your
      provider must terminate within `Close`.
- [ ] **Compile-time interface check** — `var _ secrets.Provider = (*Provider)(nil)` (and `_ secrets.BatchProvider` if implemented) catches interface drift at build time.
- [ ] **Sentinel error wrapping** — every error returned from
      `Resolve` wraps one of the four sentinels.
- [ ] **`Close` idempotent** — multiple `Close` calls succeed.

## Testing your provider

Unit tests should cover, at minimum:

- A successful `Resolve` returning the expected plaintext.
- `ErrSecretNotFound` for a missing path.
- `ErrSecretNotFound` for a missing key within an existing path.
- `ErrSecretResolveFailed` for a transient backend error
  (mocked timeout / 500 / AccessDenied).
- `ErrSecretResolveFailed` for an empty resolved value.
- `ErrMalformedRef` for an invalid `Ref` (scheme mismatch,
  empty path, invalid characters in path).
- Path / key are NOT echoed in any error message — assert with
  `assert.NotContains(t, err.Error(), secretPath)`.
- `Close` is idempotent — second call returns nil.

For integration tests that hit a real backend, follow the
pattern in `tests/integration/secrets/...` (Docker Compose
with the testcontainers harness; per-test isolation; never
commit production-bound credentials).

The `audittest` package does not expose secret-provider mocks
directly — instead, write a small in-memory provider in your
test code (the existing `secrets_test.go` files in the
core module show the pattern).

## Further reading

- [`docs/secrets.md`](secrets.md) — `ref+` URI syntax, resolution
  pipeline, caching, the four built-in providers, security model.
- [`SECURITY.md`](../SECURITY.md) — secrets memory-retention model,
  threat model.
- [`secrets/env/env.go`](../secrets/env/env.go) — minimal stateless
  provider (~100 lines, no network I/O).
- [`secrets/file/file.go`](../secrets/file/file.go) — file-system
  provider with mtime caching.
- [`secrets/openbao/openbao.go`](../secrets/openbao/openbao.go) —
  full-fat HTTP provider with TLS, SSRF protection, redirect
  blocking, token zeroing — the closest model for an
  HTTP-backed custom provider.
- [`docs/writing-custom-outputs.md`](writing-custom-outputs.md) —
  the analogous guide for custom outputs.
