# Pre-deploy validation with `audit-validate`

`audit-validate` is a small standalone CLI that validates an
`outputs.yaml` configuration against your taxonomy YAML before you
ship it. It runs the same loader the audit library uses at startup
(`outputconfig.Load`) and exits with a distinct code per failure
class so CI pipelines can gate deployments on it.

The validator is **offline by default and offline-only in the
default release binary**: it does not contact Vault, OpenBao, or any
other secret provider. It performs parse, schema, and semantic
checks — and rejects unresolved `ref+` secret references (exit 3)
because the default binary has no secret providers compiled in. To
validate against a live provider, build a custom validator binary
that blank-imports the appropriate `secrets/...` sub-modules.

## Why a separate binary?

`audit-validate` ships as a separate binary because it serves a
different audience from the rest of the toolchain:

- **`audit-gen`** is for developers — it generates typed event
  builders from your taxonomy and runs at build time.
- **`audit-validate`** is for operators — it validates the
  `outputs.yaml` you ship next to your application and runs at
  deploy time, typically in CI.

Keeping the two binaries separate means CI runners that gate a
release on operator config never have to pull in code-generation
machinery, and vice versa. This mirrors the pattern in the Go
toolchain itself (`vet`, `goimports`, `stringer` are all separate
small binaries).

## Installation

```bash
# Pin the version to keep CI reproducible:
go install github.com/axonops/audit/cmd/audit-validate@v0.1.11

# Or, for ad-hoc local use:
go install github.com/axonops/audit/cmd/audit-validate@latest
```

Released versions are also published as pre-built binaries by
GoReleaser alongside `audit-gen`; see the GitHub Releases page.

In CI, **always pin to a specific version** (`@v0.1.11`, not
`@latest`). `@latest` resolves to whatever the proxy serves at run
time and makes validation results non-reproducible across runs.

## Usage

```
audit-validate -taxonomy <file|-> -outputs <file|-> [-format text|json] [-quiet] [-resolve-secrets] [-version]
```

Flags:

| Flag                | Description                                                       | Default |
|---------------------|-------------------------------------------------------------------|---------|
| `-taxonomy <file>`  | Path to taxonomy YAML, or `-` for stdin. **Required.**            | —       |
| `-outputs <file>`   | Path to outputs YAML, or `-` for stdin. **Required.**             | —       |
| `-format`           | Output format: `text` (human-readable) or `json` (machine-parsable). | `text`  |
| `-quiet`            | Suppress all output; rely on the exit code.                       | `false` |
| `-resolve-secrets`  | Reserved. The default binary REJECTS this flag with exit 2 because it has no secret providers compiled in. See "Secret references" below. | `false` |
| `-version`          | Print the audit-validate version and exit 0.                      | `false` |

Both `-taxonomy` and `-outputs` MUST be set; one MAY be `-` to read
from stdin, but both MUST NOT be `-` (stdin can be read once).
Setting both to `-` rejects with exit 2.

### Exit codes

| Code | Meaning                                                                 |
|------|-------------------------------------------------------------------------|
| `0`  | Configuration is valid.                                                 |
| `1`  | Parse error — file not found, invalid YAML.                             |
| `2`  | Schema or usage error — missing required field, wrong type, unknown field, missing/invalid CLI flag, stdin double-use, `-resolve-secrets` in a binary that does not support it. |
| `3`  | Semantic error — route references unknown taxonomy entries, output type unknown, unresolved `ref+` secret reference. |

CI scripts can branch on these codes to print actionable feedback
without parsing the message body.

## Examples

### Local round-trip

```bash
audit-validate -taxonomy taxonomy.yaml -outputs outputs/prod.yaml
echo $?  # 0 if valid
```

### Stdin pipeline

`audit-validate` accepts `-` as either flag's value to read from
stdin. This is the natural pattern when the taxonomy lives behind a
`go:embed` and the application exposes a sub-command that prints it:

```bash
# Replace ./cmd/myapp with your own taxonomy-printing helper.
go run ./cmd/myapp dump-taxonomy | \
  audit-validate -taxonomy - -outputs config/prod.yaml
```

If you have a taxonomy file on disk, the simpler form is:

```bash
cat taxonomy.yaml | audit-validate -taxonomy - -outputs config/prod.yaml
```

### JSON output for CI annotations

```bash
audit-validate \
  -taxonomy taxonomy.yaml \
  -outputs outputs/prod.yaml \
  -format json
```

A typical failure response looks like:

```json
{
  "errors": [
    {
      "code": "semantic",
      "message": "audit/outputconfig: output config validation failed: audit: config validation failed: output \"audit_log\": unknown output type \"nonexistent_type\""
    }
  ],
  "valid": false
}
```

The `message` field is the raw error returned by `outputconfig.Load`
(or by the validator itself for the `ref+` pre-scan). The schema is
documented as `{"valid":bool,"errors":[{"code","message"}]}`;
stability is not guaranteed until v1.0.

## GitHub Actions: pre-deploy gate

Drop this into a workflow that runs on every PR or push to a
deploy branch. The job fails if `outputs.yaml` is invalid for any
reason, blocking the deploy.

```yaml
name: validate-audit-config
on:
  pull_request:
    paths:
      - 'config/audit/**'
  push:
    branches: [main]

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.26'
          cache: true
      - name: Install audit-validate
        # Pin the version; never use @latest in CI.
        run: go install github.com/axonops/audit/cmd/audit-validate@v0.1.11
      - name: Validate audit configuration
        run: |
          audit-validate \
            -taxonomy config/audit/taxonomy.yaml \
            -outputs config/audit/outputs.yaml
```

For richer CI output, swap `-format text` for `-format json` and
pipe the result through `jq` to surface the first error in the
job summary.

For a hardened production workflow, pin every action to a full SHA
(see this repository's own `.github/workflows/ci.yml` for the
pattern) and pin the validator to a specific release tag.

## What the validator checks

- **Parse**: the taxonomy and outputs YAML are syntactically valid.
- **Schema**: required fields are present, fields have the correct
  types, no unknown fields appear in strict-mode sections.
- **Semantic**:
  - every output `type` is a registered output factory (built-ins:
    `stdout`, `file`, `loki`, `syslog`, `webhook`);
  - every routing rule references categories and event types that
    exist in the taxonomy;
  - every formatter is registered;
  - the validator MUST reject any unresolved `ref+SCHEME://...`
    string as a semantic error (exit 3) in the default binary.

## Secret references and offline validation

The default release binary is **offline-only**. If your
`outputs.yaml` contains `ref+vault://...`, `ref+openbao://...`,
`ref+file://...` or `ref+env://...` references, the validator
rejects them as a **semantic** error (exit 3) rather than silently
passing.

Why? CI runners typically do not have credentials for production
Vault or OpenBao instances, and the default binary has no secret
providers compiled in. Failing fast is far more helpful than passing
locally and then crashing at startup in production.

`-resolve-secrets` is reserved and rejected by the default binary.
To validate against a live provider:

1. Build a custom validator binary that blank-imports the
   appropriate `secrets/...` sub-modules (e.g.
   `_ "github.com/axonops/audit/secrets/vault"`).
2. Run that custom binary inside an environment with provider
   credentials.

A simpler alternative is to split your config into a structural
part (validated in CI by the default binary) and an
environment-specific overlay (validated at deploy time by the
runtime auditor when it boots).

## Comparison with related tools

- `helm lint` — schema-only, offline. Same model as `audit-validate`.
- `terraform validate` — offline, no provider calls. Same model.
- `terraform plan` — hits provider APIs. Not the model used here.

## See also

- [`outputs.md`](outputs.md) — the full schema reference for
  `outputs.yaml`.
- [`secrets.md`](secrets.md) — how `ref+SCHEME://...` secret
  references work at runtime.
- [`code-generation.md`](code-generation.md) — `audit-gen`, the
  developer-facing companion CLI.
