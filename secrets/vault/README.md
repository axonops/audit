# secrets/vault — HashiCorp Vault KV v2 secret provider

[![Go Reference][godoc-badge]][godoc]

Resolves `ref+vault://PATH#KEY` references in audit YAML
configuration against a [HashiCorp Vault] KV v2 secret engine.
SSRF-safe by default (private ranges, loopback, cloud-metadata
endpoints blocked), HTTPS-only by default, with path-level caching
via `secrets.BatchProvider`.

> **Module path**: `github.com/axonops/audit/secrets/vault`
> **Status**: pre-release (v0.x)
> **Documentation**: [Secrets reference](../../docs/secrets.md) · [Capstone example](../../examples/21-capstone/)

## Why

HashiCorp Vault is the production-grade option in the audit library's
secret provider matrix. Compared to filesystem and env-var providers
it adds:

- **Centralised audit log.** Every token use is recorded by the
  server — you see who read which secret and when, independent of
  the application's logs.
- **Out-of-process rotation.** Rotate the underlying secret in Vault;
  restart consumers to pick up the new value. No file redeploy, no
  env var change.
- **Fine-grained ACLs.** Policies scope read access by path; the
  audit service's token sees only what its policy permits.
- **Dynamic secrets.** When backed by dynamic-secret engines (PKI,
  database, AWS), secrets are minted per request with a TTL.
- **Vault Enterprise namespaces.** Multi-tenant isolation via the
  `Namespace` field.

The `vault` and [`openbao`](../openbao/) providers are nearly
identical — OpenBao is an open-source fork that maintains KV v2 API
compatibility. Choose `vault` for HashiCorp Vault deployments; choose
[`openbao`](../openbao/) for OpenBao.

## Install

```bash
go get github.com/axonops/audit/secrets/vault
```

Requires Go 1.26+. Depends on the core `audit` package for `TLSPolicy`,
`SSRFDialControl`, and `LoadX509KeyPairWithPassword`.

## Quick start

### YAML-driven (recommended)

Declare the provider in `outputs.yaml` — `outputconfig.Load`
constructs, uses, and closes it for you:

```yaml
secrets:
  timeout: "15s"
  vault:
    address: "${VAULT_ADDR}"
    token: "${VAULT_TOKEN}"
    namespace: "engineering"          # optional, Vault Enterprise

outputs:
  alerts:
    type: webhook
    webhook:
      url: "https://siem.example.com/audit"
      headers:
        Authorization: "ref+vault://secret/data/siem/creds#authorization_header"
```

```go
result, err := outputconfig.Load(ctx, yamlData, taxonomy)
```

### Programmatic

```go
import (
    "github.com/axonops/audit/outputconfig"
    "github.com/axonops/audit/secrets/vault"
)

provider, err := vault.New(&vault.Config{
    Address: os.Getenv("VAULT_ADDR"),
    Token:   os.Getenv("VAULT_TOKEN"),
})
if err != nil {
    return fmt.Errorf("vault: %w", err)
}
defer provider.Close()

result, err := outputconfig.Load(ctx, yamlData, taxonomy,
    outputconfig.WithSecretProvider(provider),
)
```

`New` validates the address and constructs the HTTP client but does
not perform network I/O — the first `Resolve` call initiates the
connection.

## KV v2 path convention

The provider expects the **API path**, not the CLI logical path.
This is the single most common misconfiguration: the CLI command

```
vault kv get secret/siem/creds
```

maps to the API path `secret/data/siem/creds`. Ref URIs MUST include
the `/data/` segment:

```
ref+vault://secret/data/siem/creds#authorization_header
```

Using `secret/siem/creds` returns a 404 (`ErrSecretNotFound`).

## Configuration reference

### Go struct (`vault.Config`)

| Field                | Required | Default          | Description |
|----------------------|----------|------------------|-------------|
| `Address`            | Yes      | —                | Server URL. MUST use `https://` unless `AllowInsecureHTTP` is set. Trailing `/` is stripped. Embedded credentials (`user:pass@`) are rejected. |
| `Token`              | Yes      | —                | Authentication token sent as `X-Vault-Token`. Stored as `[]byte` and zeroed on `Close()` (best-effort; see [memory retention](#memory-retention)). |
| `Namespace`          | No       | `""`             | Vault Enterprise namespace prefix; sent as `X-Vault-Namespace` header on every request. |
| `TLSCA`              | No       | system roots     | Path to a CA certificate PEM file for verifying the server certificate. |
| `TLSCert`            | No       | —                | Path to a client certificate for mTLS. MUST be set together with `TLSKey`. |
| `TLSKey`             | No       | —                | Path to the client private key for mTLS. MUST be set together with `TLSCert`. |
| `TLSKeyPassword`     | No       | `nil`            | Password for a PKCS#8 v2 `ENCRYPTED PRIVATE KEY` PEM in `TLSKey`. See [encrypted keys](#encrypted-client-keys) (#896). |
| `TLSPolicy`          | No       | TLS 1.3 only     | `*audit.TLSPolicy`. Controls minimum TLS version and cipher selection. |
| `AllowInsecureHTTP`  | No       | `false`          | Permit `http://` URLs. **MUST NOT be `true` in production** — plaintext HTTP exposes the auth token to any in-network observer. |
| `AllowPrivateRanges` | No       | `false`          | Permit connections to RFC 1918 private addresses, IPv6 ULA, and loopback. Cloud metadata endpoints (`169.254.169.254`) remain blocked regardless. Required for local development. |

### YAML

The YAML schema mirrors the Go struct with `snake_case` field names.
TLS settings live in a nested `tls:` block — not as flat keys.

```yaml
secrets:
  timeout: "15s"        # optional; default 10s, min 1s, max 120s
  vault:
    address: "${VAULT_ADDR}"
    token: "${VAULT_TOKEN}"
    namespace: "engineering"           # optional, Vault Enterprise
    allow_insecure_http: false         # default; never true in production
    allow_private_ranges: false        # default; true for local dev
    tls:
      ca: /etc/ssl/vault-ca.pem        # optional
      cert: /etc/ssl/audit-client.pem  # optional, with key
      key: /etc/ssl/audit-client.key   # optional, with cert
      key_password: "${TLS_KEY_PW}"    # optional; for PKCS#8 v2 encrypted keys
      allow_tls12: false               # default; true to accept TLS 1.2
      allow_weak_ciphers: false        # default; true permits CBC suites on TLS 1.2
```

Only `${ENV}` substitution applies inside `secrets:` — `ref+` URIs
are NOT resolved here (they would be circular: providers must exist
before secrets can be resolved). Tokens MUST come from environment
variables.

See [Per-Output TLS](../../docs/output-configuration.md#per-output-tls)
for the full TLS block reference. Note that for HTTP-based providers,
`allow_insecure_http` and `allow_private_ranges` live at the
**top level** of the provider block, not inside `tls:` (they govern
the URL scheme and the SSRF dial control, not the TLS handshake).

### Encrypted client keys

When `tls.key` is a PKCS#8 v2 `ENCRYPTED PRIVATE KEY` PEM block
(PBKDF2 or scrypt + AES-CBC), supply the password via
`tls.key_password`. Legacy PKCS#1 `DEK-Info` encrypted keys are
refused with `audit.ErrLegacyEncryptedPEMKey` — rewrap with:

```bash
openssl pkcs8 -topk8 -v2 aes256 -in legacy.key -out modern.key
```

Full details and validation matrix in
[Encrypted private keys](../../docs/output-configuration.md#encrypted-private-keys-tlskey_password)
(#896).

## Authentication

Pass the Vault token in `Config.Token` (Go) or `secrets.vault.token`
(YAML). The token MUST have `read` capability on every secret path
referenced from the YAML. A minimal policy:

```hcl
path "secret/data/audit/*" {
  capabilities = ["read"]
}
```

There is no built-in token renewal — the provider stores the token for
its lifetime. If the token expires during a `Load`, you get
`ErrSecretResolveFailed` wrapping a 403. For long-lived processes,
prefer short-TTL tokens via:

- **AppRole** — role_id + secret_id login produces a short-lived
  client token.
- **Kubernetes auth** — exchanges the service account JWT for a
  Vault token, rotated by the platform.
- **Workload identity** — AWS IAM, GCP, Azure auth methods.

Login recipes in [Authentication](../../docs/secrets.md#authentication).

## Vault Enterprise namespaces

Set `Namespace` (Go) or `namespace` (YAML) to address a Vault Enterprise
namespace. The value is sent as `X-Vault-Namespace` on every request:

```yaml
secrets:
  vault:
    address: "${VAULT_ADDR}"
    token: "${VAULT_TOKEN}"
    namespace: "tenant-acme/audit"
```

Open-source Vault and OpenBao ignore this header; setting it is
harmless on those deployments. For multi-namespace consumers,
register two providers (programmatically) with distinct
`Config.Namespace` values — or, in YAML, the `secrets:` block
supports one provider per scheme, so a process needing two namespaces
must use the programmatic path.

## Memory retention

Tokens are stored as `[]byte` and zeroed on `Close()`. This is
best-effort:

- Setting the `X-Vault-Token` HTTP header converts the bytes to an
  immutable Go string. `Close()` zeros the underlying slice; the
  header-map string copy persists until GC.
- The provider drops header-map references after each request as
  defence-in-depth (#479), narrowing the retention window.
- `Provider.String`, `GoString`, and `Format` always return
  `vault{host: HOST, token: [REDACTED]}` — the token never appears
  in any `fmt` verb (`%v`, `%+v`, `%#v`).

Resolved secret values flow into output config structs and persist
for the auditor's lifetime; memory dumps will contain them. Rotation
is the primary mitigation. Full model in
[SECURITY.md §Secrets and Memory Retention](../../SECURITY.md#secrets-and-memory-retention).

## When NOT to use it

- **No Vault cluster yet.** For local development, see
  [`secrets/file`](../file/) (mounted secret files) or
  [`secrets/env`](../env/) (environment variables). Both ship with
  zero infrastructure.
- **OpenBao deployment.** Use [`secrets/openbao`](../openbao/) — the
  API surface is identical but the scheme is `openbao` and there is
  a separate Go module.
- **`allow_insecure_http: true` in production.** The auth token is
  sent on every request; plaintext HTTP exposes it to any in-network
  observer. Acceptable only for local Docker Compose where the
  provider runs on the internal Docker network.
- **`allow_private_ranges: true` in untrusted networks.** Disables
  SSRF protection against RFC 1918 ranges and IPv6 ULA. Acceptable
  only when the operator owns both endpoints (in-cluster Vault with
  NetworkPolicy isolation). Cloud-metadata endpoints remain blocked
  regardless.

See [Production Checklist — Dangerous Opt-In Flags](../../docs/secrets.md#production-checklist--dangerous-opt-in-flags).

## See also

- [Secrets reference](../../docs/secrets.md) — `ref+` URI grammar,
  caching, timeout, secret rotation, security model.
- [Writing custom secret providers](../../docs/writing-custom-secret-providers.md) —
  for backends not in the built-in set.
- [Per-output TLS](../../docs/output-configuration.md#per-output-tls) —
  the shared TLS block schema used by HTTP-based providers and outputs.
- [Encrypted private keys](../../docs/output-configuration.md#encrypted-private-keys-tlskey_password) —
  `TLSKeyPassword` / `tls.key_password` reference (#896).
- [Capstone example](../../examples/21-capstone/) — end-to-end CRUD
  service demonstrating secret-backed HMAC salts and route credentials.
- Sibling providers:
  - [`secrets/openbao`](../openbao/) — OpenBao KV v2 (identical API)
  - [`secrets/file`](../file/) — filesystem (dev, K8s mounted secrets)
  - [`secrets/env`](../env/) — environment variables (dev, CI)

[HashiCorp Vault]: https://www.vaultproject.io/
[godoc]: https://pkg.go.dev/github.com/axonops/audit/secrets/vault
[godoc-badge]: https://pkg.go.dev/badge/github.com/axonops/audit/secrets/vault.svg
