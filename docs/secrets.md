[&larr; Back to README](../README.md)

# Secret Provider Integration

- [Overview](#overview)
- [Installation](#installation)
- [URI Syntax](#uri-syntax)
- [Resolution Pipeline](#resolution-pipeline)
- [Supported Providers](#supported-providers)
- [Provider Setup](#provider-setup)
- [Authentication](#authentication)
- [YAML Configuration Examples](#yaml-configuration-examples)
- [Fields That Cannot Contain Refs](#fields-that-cannot-contain-refs)
- [Caching Behaviour](#caching-behaviour)
- [Timeout Behaviour](#timeout-behaviour)
- [Secret Rotation](#secret-rotation)
- [Security Model](#security-model)
- [Testing](#testing)
- [Error Reference](#error-reference)
- [Anti-Patterns](#anti-patterns)

## Overview

audit resolves secret references in YAML configuration values at
startup. Any string value in the output configuration YAML can contain
a `ref+SCHEME://PATH#KEY` URI instead of a literal value, with
[specific exceptions](#fields-that-cannot-contain-refs). During
`outputconfig.Load`, the library replaces each ref URI with the
plaintext value fetched from the corresponding secret provider.

This keeps credentials, HMAC salts, and bearer tokens out of
configuration files and environment variables.

The URI convention follows [vals](https://github.com/helmfile/vals).

## Installation

Install the core secrets package and the provider for your backend:

```bash
# OpenBao provider
go get github.com/axonops/audit/secrets/openbao

# HashiCorp Vault provider
go get github.com/axonops/audit/secrets/vault

# The outputconfig package (required for Load)
go get github.com/axonops/audit/outputconfig
```

Both providers are separate Go modules. Import them alongside
`outputconfig` in your application code.

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

`ParseRef` returns `(zero)` when the input does not start with
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

> **Warning:** Using the CLI path instead of the API path is the
> single most common misconfiguration. The provider returns a 404
> (`ErrSecretNotFound`) because the KV v2 engine expects the `/data/`
> segment in the API path.

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
| `file` | `github.com/axonops/audit/secrets/file` | Filesystem (K8s mounted secrets, Docker secrets) | n/a |
| `env` | `github.com/axonops/audit/secrets/env` | Process environment variables | n/a |
| `openbao` | `github.com/axonops/audit/secrets/openbao` | [OpenBao](https://openbao.org/) | KV v2 |
| `vault` | `github.com/axonops/audit/secrets/vault` | [HashiCorp Vault](https://www.vaultproject.io/) | KV v2 |

The OpenBao and Vault providers implement `secrets.BatchProvider`,
enabling path-level caching (see [Caching Behaviour](#caching-behaviour)).
The `file` and `env` providers are intentionally simple and read on
every Resolve — appropriate for K8s mounted secrets, where rotation
is signalled by atomic-symlink swap and re-reading is the correct
semantics.

### When to use which

- **`file://`** — Kubernetes mounted secrets at `/var/run/secrets/...`,
  Docker secrets, host-bind-mounted credential files. The dominant
  pattern for K8s deployments.
- **`env://`** — Development, CI, simple deployments. Note that env
  values are visible to any process running as the same UID via
  `/proc/PID/environ` (Linux) or equivalent. Prefer `file://` or
  `vault`/`openbao` for production.
- **`vault`** / **`openbao`** — Centralised secret store with audit
  log, dynamic secrets, fine-grained ACLs. Use when you need
  out-of-process secret rotation or centralised access control.

## Provider Setup

### File (K8s mounted secrets)

```go
import (
	"context"

	"github.com/axonops/audit/outputconfig"
	"github.com/axonops/audit/secrets/file"
)

// ctx, yamlData, taxonomy defined by caller
provider := file.New()
defer provider.Close()

result, err := outputconfig.Load(ctx, yamlData, taxonomy,
	outputconfig.WithSecretProvider(provider),
)
```

YAML usage:

```yaml
outputs:
  - name: webhook
    type: webhook
    url: "https://logs.example.com/ingest"
    bearer_token: "ref+file:///var/run/secrets/myapp/token"

  # JSON file with dotted-fragment path
  hmac:
    secret_ref: "ref+file:///etc/secrets/audit.json#hmac.salt"
```

### Env

```go
import (
	"context"

	"github.com/axonops/audit/outputconfig"
	"github.com/axonops/audit/secrets/env"
)

provider := env.New()
defer provider.Close()

result, err := outputconfig.Load(ctx, yamlData, taxonomy,
	outputconfig.WithSecretProvider(provider),
)
```

YAML usage:

```yaml
outputs:
  - name: webhook
    type: webhook
    url: "ref+env://WEBHOOK_URL"
    bearer_token: "ref+env://WEBHOOK_TOKEN"
```

### OpenBao

```go
import (
	"context"
	"fmt"
	"os"

	"github.com/axonops/audit/outputconfig"
	"github.com/axonops/audit/secrets/openbao"
)

// ctx, yamlData, taxonomy defined by caller
provider, err := openbao.New(&openbao.Config{
	Address: os.Getenv("BAO_ADDR"),
	Token:   os.Getenv("BAO_TOKEN"),
})
if err != nil {
	return fmt.Errorf("openbao provider: %w", err)
}
defer provider.Close()

result, err := outputconfig.Load(ctx, yamlData, taxonomy,
	outputconfig.WithSecretProvider(provider),
)
```

### HashiCorp Vault

```go
import (
	"context"
	"fmt"
	"os"

	"github.com/axonops/audit/outputconfig"
	"github.com/axonops/audit/secrets/vault"
)

// ctx, yamlData, taxonomy defined by caller
provider, err := vault.New(&vault.Config{
	Address: os.Getenv("VAULT_ADDR"),
	Token:   os.Getenv("VAULT_TOKEN"),
})
if err != nil {
	return fmt.Errorf("vault provider: %w", err)
}
defer provider.Close()

result, err := outputconfig.Load(ctx, yamlData, taxonomy,
	outputconfig.WithSecretProvider(provider),
)
```

### Multiple Providers

Register one provider per scheme. `Load` returns an error wrapping
`ErrOutputConfigInvalid` if two providers share the same scheme.

```go
// ctx, yamlData, taxonomy defined by caller
result, err := outputconfig.Load(ctx, yamlData, taxonomy,
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
      algorithm: HMAC-SHA-256
```

### Config Reference

Both `openbao.Config` and `vault.Config` share the same field set:

| Field | Required | Description |
|-------|----------|-------------|
| `Address` | Yes | Server URL. MUST use `https://` unless `AllowInsecureHTTP` is set. |
| `Token` | Yes | Authentication token. See [Authentication](#authentication). |
| `Namespace` | No | Namespace prefix. Sent as `X-Vault-Namespace` header. |
| `TLSCA` | No | Path to CA certificate PEM file for server verification. |
| `TLSCert` | No | Client certificate path for mTLS. MUST be set together with `TLSKey`. |
| `TLSKey` | No | Client private key path for mTLS. MUST be set together with `TLSCert`. |
| `TLSPolicy` | No | `*audit.TLSPolicy`. Nil defaults to TLS 1.3 only. |
| `AllowInsecureHTTP` | No | Permit `http://` URLs. **MUST NOT be `true` in production.** Plaintext HTTP exposes the authentication token to network observers. Use only for local development with Docker Compose where the provider runs on the internal Docker network. Default: `false`. |
| `AllowPrivateRanges` | No | Permit connections to RFC 1918 addresses (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), IPv6 ULA (`fc00::/7`), and loopback (`127.0.0.0/8`, `::1`). Cloud metadata endpoints (`169.254.169.254`) remain blocked even when this is `true`. Required for local development. Default: `false`. |

### WithSecretTimeout

`outputconfig.WithSecretTimeout` sets the overall timeout for all
secret resolution during a single `Load` call. The caller's context
deadline takes precedence when it is earlier.

```go
// ctx, yamlData, taxonomy, provider defined by caller
result, err := outputconfig.Load(ctx, yamlData, taxonomy,
	outputconfig.WithSecretProvider(provider),
	outputconfig.WithSecretTimeout(30*time.Second),
)
```

Default: `10s` (`outputconfig.DefaultSecretTimeout`).

### YAML-Based Provider Configuration

Instead of creating providers programmatically, you can configure them
declaratively in the `secrets:` section of `outputs.yaml`. Providers
are constructed, used for resolution, and closed automatically within
`outputconfig.Load` — no manual lifecycle management is needed.

**Before (programmatic):**

```go
provider, err := openbao.New(&openbao.Config{
    Address:            os.Getenv("BAO_ADDR"),
    Token:              os.Getenv("BAO_TOKEN"),
    AllowPrivateRanges: true,
    AllowInsecureHTTP:  true,
})
if err != nil {
    return fmt.Errorf("openbao provider: %w", err)
}
defer provider.Close()

result, err := outputconfig.Load(ctx, yamlData, taxonomy,
    outputconfig.WithSecretProvider(provider),
)
```

**After (YAML):**

```yaml
# outputs.yaml
secrets:
  timeout: "15s"
  openbao:
    address: "${BAO_ADDR}"
    token: "${BAO_TOKEN}"
    allow_insecure_http: true    # dev-only — NEVER in production
    allow_private_ranges: true   # Docker internal network
```

```go
// No programmatic provider setup — Load handles everything.
result, err := outputconfig.Load(ctx, yamlData, taxonomy)
```

The YAML approach eliminates the `secrets/openbao` import, the manual
`Close()` call, the conditional env var checks, and the `LoadOption`
assembly. Provider config becomes an ops concern, not a code change.

The YAML field names use `snake_case` equivalents of the Go struct
fields (e.g. `allow_insecure_http` for `AllowInsecureHTTP`, `tls_ca`
for `TLSCA`).

Only environment variable substitution (`${VAR}`) is applied in the
`secrets:` section — `ref+` secret references are NOT resolved, since
that would be circular (providers must exist before secrets can be
resolved).

**Timeout precedence:** If you set both, the programmatic value wins:
`WithSecretTimeout` (programmatic) > `secrets.timeout` (YAML) >
`DefaultSecretTimeout` (10s).

For the complete field table, see
[Secrets Configuration](output-configuration.md#secrets-configuration)
in the output configuration reference.

## Authentication

Both providers authenticate with a token passed via the
`X-Vault-Token` HTTP header. The token MUST have a policy granting
`read` capability on the secret paths referenced in the YAML
configuration.

### Obtaining a Token

**Development (root token):** OpenBao and Vault dev servers emit a
root token at startup. Pass it via environment variable:

```bash
export BAO_ADDR=https://127.0.0.1:8200
export BAO_TOKEN=dev-root-token
```

**Production (AppRole login):** Use AppRole authentication to obtain
a short-lived token. The token is the `.auth.client_token` field of
the login response:

```bash
# Log in with AppRole, extract the client token
TOKEN=$(curl -s \
  --request POST \
  --data '{"role_id":"...","secret_id":"..."}' \
  "${BAO_ADDR}/v1/auth/approle/login" | jq -r '.auth.client_token')
export BAO_TOKEN="${TOKEN}"
```

**Production (Kubernetes auth):** The Kubernetes auth method
exchanges a service account JWT for a Vault/OpenBao token:

```bash
SA_JWT=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
TOKEN=$(curl -s \
  --request POST \
  --data "{\"role\":\"audit-reader\",\"jwt\":\"${SA_JWT}\"}" \
  "${BAO_ADDR}/v1/auth/kubernetes/login" | jq -r '.auth.client_token')
export BAO_TOKEN="${TOKEN}"
```

**Direct token creation:**

```bash
bao token create -policy=audit-reader -ttl=1h -format=json | jq -r '.auth.client_token'
```

### Required Policy

The token MUST have `read` capability on every secret path referenced
in the YAML configuration. A minimal policy:

```hcl
path "secret/data/audit/*" {
  capabilities = ["read"]
}
```

### Token Lifecycle

The provider stores the token at construction time (`New`). The token
is used for the lifetime of the provider. There is no built-in token
renewal. If the token expires during a `Load` call, the provider
returns `ErrSecretResolveFailed` wrapping a 403 status.

### Environment Variables

| Variable | Provider | Description |
|----------|----------|-------------|
| `BAO_ADDR` | OpenBao | Server URL (`https://bao.example.com:8200`) |
| `BAO_TOKEN` | OpenBao | Authentication token |
| `VAULT_ADDR` | Vault | Server URL (`https://vault.example.com:8200`) |
| `VAULT_TOKEN` | Vault | Authentication token |

> **Warning:** These environment variables contain credentials. They
> MUST NOT be logged, exposed in process listings with `ps`, or
> included in container image layers. Use Kubernetes secrets,
> Docker secrets, or your platform's secrets injection mechanism.

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
      algorithm: HMAC-SHA-256
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
      algorithm: HMAC-SHA-256
    file:
      path: "/var/log/audit/secure.log"
```

In staging: `BAO_HMAC_PATH=secret/data/staging/hmac`

In production: `BAO_HMAC_PATH=secret/data/prod/hmac`

## Fields That Cannot Contain Refs

Secret resolution applies to string values in the type-specific
config block, route, formatter, and HMAC sections. The following
output-level fields are parsed **before** secret expansion and MUST
NOT contain `ref+` URIs:

| Field | Why | Parsed As |
|-------|-----|-----------|
| `type` | Determines which factory to invoke; MUST be a literal string. | `string` |
| `enabled` (output-level) | Determines whether the output is constructed at all. | `bool` |
| `exclude_labels` | Converted to a string slice before expansion. | `[]string` |

The HMAC `enabled` field is a special case: it IS resolved from a
ref+ URI (via `extractAndResolveEnabled`), but the resolved value
MUST be a valid boolean string (`true`, `false`, `1`, `0`).

All other string values in the YAML tree -- including `app_name`,
`host`, `timezone`, `standard_fields`, `logger` settings, and
`tls_policy` -- support ref+ URIs when a provider is registered.

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

## Timeout Behaviour

`outputconfig.Load` applies a timeout to all secret resolution
network I/O. The default is `10s` (`outputconfig.DefaultSecretTimeout`).

When the timeout fires:

1. The `context.Context` passed to `Provider.Resolve` (or
   `BatchProvider.ResolvePath`) is cancelled.
2. The provider's HTTP request fails with a context deadline exceeded
   error.
3. The resolver wraps the error as `ErrSecretResolveFailed` and
   `Load` returns it.
4. No partial configuration is returned. All outputs constructed so
   far are closed.

The caller's context deadline takes precedence when it is earlier than
the configured secret timeout. Both timeouts apply to all provider
calls combined, not per-call.

To increase the timeout:

```go
// ctx, yamlData, taxonomy, provider defined by caller
result, err := outputconfig.Load(ctx, yamlData, taxonomy,
	outputconfig.WithSecretProvider(provider),
	outputconfig.WithSecretTimeout(60*time.Second),
)
```

## Secret Rotation

Secrets are resolved once, at `outputconfig.Load` time. The resolved
plaintext values are embedded in the constructed outputs for the
lifetime of the `Auditor`.

To rotate a secret (e.g. an HMAC salt or webhook bearer token):

1. Update the secret in OpenBao/Vault.
2. Restart the application process (or the component that creates the
   `Auditor`).

There is no built-in hot-reload mechanism. A reload pattern for
long-running services:

```go
import (
	"context"
	"fmt"
	"os"

	audit "github.com/axonops/audit"
	"github.com/axonops/audit/outputconfig"
	"github.com/axonops/audit/secrets/openbao"
)

// reload rebuilds the auditor with fresh secrets.
func reload(ctx context.Context, yamlData []byte, taxonomy *audit.Taxonomy) (*audit.Auditor, error) {
	provider, err := openbao.New(&openbao.Config{
		Address: os.Getenv("BAO_ADDR"),
		Token:   os.Getenv("BAO_TOKEN"),
	})
	if err != nil {
		return nil, fmt.Errorf("openbao: %w", err)
	}
	defer provider.Close()

	result, err := outputconfig.Load(ctx, yamlData, taxonomy,
		outputconfig.WithSecretProvider(provider),
	)
	if err != nil {
		return nil, fmt.Errorf("load config: %w", err)
	}

	opts := []audit.Option{audit.WithTaxonomy(taxonomy)}
	opts = append(opts, result.Options...)
	return audit.New(opts...)
}
```

Trigger the reload on SIGHUP or via an admin endpoint. Close the old
logger before replacing it -- `Close` drains buffered events.

## Memory Retention and Rotation Strategy

Secrets resolved from a provider flow into output-configuration
fields that persist in process memory for the auditor's lifetime.
Go strings are immutable and cannot be zeroed; byte slices can be
zeroed but the library cannot do so for values that consumers may
reference. Memory dumps, core files, and heap profiles captured
while the auditor is running will contain resolved plaintext.

**Rotation is the primary mitigation.** The auditor's lifetime is
the upper bound on how long a compromised credential remains
valid in process memory. Plan accordingly:

| Mitigation | Effect |
|---|---|
| **Short-lived tokens (TTL ≤ 1 hour)** | Bounds the window in which an exfiltrated token is usable against the provider. Does not reduce the in-memory retention window of the resolved plaintext, but limits the damage if it is extracted. |
| **Workload identity** (AWS IAM role, K8s service account, GCP workload identity) | Eliminates long-lived bootstrap credentials from the library's reach. Token is minted per-process and rotated by the platform. |
| **Periodic auditor restart** | Frees retained plaintext at process exit. Combined with short-lived tokens, bounds the in-memory lifetime to the restart interval. |
| **Provider-side audit logging** | Detects exfiltration even when the in-memory lifetime itself cannot be shortened. OpenBao/Vault audit logs record every token-use attempt. |

The library's `Provider.Close()` zeroes the `[]byte` token storage
best-effort — see [Token Handling](#security-model) above. HTTP
request headers built from tokens contain string copies that
cannot be zeroed; the library drops the header-map references
after each request (defence-in-depth per #479).

For the full memory-retention model — including the specific
config fields that retain plaintext — see
[SECURITY.md §Secrets and Memory Retention](../SECURITY.md#secrets-and-memory-retention).

## Security Model

### HTTPS by Default

Both providers enforce HTTPS by default. `New` rejects any address
that does not use the `https` scheme:

```
vault: address must use https (got "http"); set AllowInsecureHTTP for local development
```

The `AllowInsecureHTTP` field (Go) / `allow_insecure_http` (YAML)
overrides this check for local development only. **MUST NOT be
`true` in production** — plaintext HTTP exposes the authentication
token to network observers. Use only when the provider runs on the
Docker internal network or localhost during development.

### SSRF Protection

Provider HTTP clients use `audit.NewSSRFDialControl` to block
connections to:

- Loopback addresses (`127.0.0.0/8`, `::1`)
- Link-local addresses (`169.254.0.0/16`, `fe80::/10`)
- Cloud metadata endpoints (`169.254.169.254`)
- RFC 1918 private ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`)
- IPv6 unique local addresses (`fc00::/7`)
- Multicast addresses (`224.0.0.0/4`, `ff00::/8`)
- Unspecified addresses (`0.0.0.0`, `::`)

Setting `AllowPrivateRanges: true` permits RFC 1918 private ranges,
IPv6 ULA (`fc00::/7`), and loopback (`127.0.0.0/8`, `::1`). Cloud
metadata endpoints (`169.254.169.254`) remain blocked even when
private ranges are allowed.

### Redirect Blocking

Provider HTTP clients reject all HTTP redirects. A redirect from a
secret backend is unexpected and could be used to exfiltrate the auth
token to a different host.

### Token Handling

- Tokens are stored as `[]byte` internally, not `string`, to enable
  zeroing on `Close()`
- `Close()` zeroes the token bytes (best-effort; Go GC may retain copies)
- `String()`, `GoString()`, and `Format()` on the provider all return
  a redacted form -- the token never appears in `fmt.Printf`, `%v`,
  `%+v`, or `%#v` output:
  - OpenBao: `openbao{host: bao.example.com:8200, token: [REDACTED]}`
  - Vault: `vault{host: vault.example.com:8200, token: [REDACTED]}`

### Ref Path Redaction

`Ref.String()` returns `ref+SCHEME://[REDACTED]#KEY` -- the vault
path is never included in log output or error messages. The path
reveals infrastructure topology (mount points, secret engine names)
that MUST NOT appear in application logs.

`Ref.Format()` ensures this redaction applies across all `fmt` verbs
(`%v`, `%+v`, `%#v`, `%s`).

Error messages from `ParseRef` that reference the raw input when the
`://` separator is missing use `redactRef()` to return the fixed
string `ref+[malformed]`.

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

## Testing

Both providers expose a `NewWithHTTPClient` constructor that accepts
a custom `*http.Client`. Use this with `net/http/httptest` to test
secret resolution without a running OpenBao or Vault server.

```go
import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/axonops/audit/secrets"
	"github.com/axonops/audit/secrets/openbao"
	"github.com/stretchr/testify/require"
)

func TestSecretResolution(t *testing.T) {
	// Fake KV v2 response. NOTE: do not use require/assert inside
	// the handler — it runs in a separate goroutine and FailNow
	// would silently exit without failing the test.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/secret/data/audit/hmac" {
			http.Error(w, "unexpected path", http.StatusNotFound)
			return
		}
		resp := map[string]any{
			"data": map[string]any{
				"data": map[string]any{
					"salt": "test-salt-value-at-least-16-bytes",
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	provider, err := openbao.NewWithHTTPClient(
		&openbao.Config{
			Address: srv.URL,
			Token:   "test-token",
		},
		srv.Client(),
	)
	require.NoError(t, err)
	defer provider.Close()

	ref, err := secrets.ParseRef("ref+openbao://secret/data/audit/hmac#salt")
	require.NoError(t, err)

	val, err := provider.Resolve(context.Background(), ref)
	require.NoError(t, err)
	require.Equal(t, "test-salt-value-at-least-16-bytes", val)
}
```

> **Note:** `httptest.NewTLSServer` uses a self-signed certificate.
> `srv.Client()` returns an `*http.Client` that trusts this
> certificate. `NewWithHTTPClient` skips TLS configuration from the
> `Config` struct when a custom client is provided, and accepts
> `https://127.0.0.1:PORT` addresses because the custom client
> bypasses the SSRF dial control.

## Error Reference

All errors wrap one of the sentinel values in `github.com/axonops/audit/secrets`.
Use `errors.Is` to check:

```go
import (
	"errors"

	"github.com/axonops/audit/secrets"
)

if errors.Is(err, secrets.ErrMalformedRef) {
	// ref+ URI is structurally invalid
}
```

| Sentinel | When | Example Message |
|----------|------|-----------------|
| `ErrMalformedRef` | `ParseRef` finds a structural error in a `ref+` URI | `audit/secrets: malformed secret reference: empty key fragment` |
| `ErrProviderNotRegistered` | No provider registered for the scheme in a ref URI | `audit/secrets: no provider registered for scheme: scheme "openbao" (field outputs.siem.webhook.headers.Authorization)` |
| `ErrSecretNotFound` | Secret path exists but the requested key is missing, or the path does not exist (404) | `audit/secrets: secret not found at path: path returned 404` |
| `ErrSecretResolveFailed` | Network error, authentication failure, or server error during resolution | `audit/secrets: secret resolution failed: authentication failed (403)` |
| `ErrUnresolvedRef` | After all resolution passes, a config value still contains a `ref+` URI | `audit/secrets: unresolved secret reference in config: field outputs.siem.webhook.headers.Authorization still contains a secret reference` |

Duplicate-scheme errors from registering two providers with the same
scheme wrap `ErrOutputConfigInvalid`:

```
audit: output config validation failed: duplicate secret provider for scheme "openbao"
```

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
connections to private IP ranges and IPv6 ULA, disabling SSRF
protection that guards against server-side request forgery.

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
- [Error Reference](error-reference.md) -- all audit error sentinels
- [Troubleshooting](troubleshooting.md#secret-provider-failures) -- diagnosing secret resolution problems
- [API Reference: secrets](https://pkg.go.dev/github.com/axonops/audit/secrets) -- `Provider`, `Ref`, `ParseRef`
- [API Reference: secrets/openbao](https://pkg.go.dev/github.com/axonops/audit/secrets/openbao) -- OpenBao provider
- [API Reference: secrets/vault](https://pkg.go.dev/github.com/axonops/audit/secrets/vault) -- Vault provider
- [API Reference: outputconfig](https://pkg.go.dev/github.com/axonops/audit/outputconfig) -- `WithSecretProvider`, `WithSecretTimeout`
- [vals](https://github.com/helmfile/vals) -- the `ref+` URI convention
