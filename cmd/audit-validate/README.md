# audit-validate — pre-deploy validator for outputs.yaml

[![Go Reference][godoc-badge]][godoc]

A command-line validator for the
[`github.com/axonops/audit`][parent] library. Reads a taxonomy YAML
and an `outputs.yaml` and reports parse errors, schema violations,
and semantic mismatches (route references unknown event types,
unknown output kind, unresolved `ref+` secrets, etc.) — the same
checks the library runs at startup, but as a CI gate before the
config reaches production.

> **Module path**: `github.com/axonops/audit/cmd/audit-validate`
> **Status**: pre-release (v0.x)
> **Documentation**: [docs/validation.md][val-doc] · [docs/taxonomy-validation.md][tax-doc]

## Why

An invalid `outputs.yaml` only fails when the application starts
up — typically in production, after the deployment pipeline has
already run. By then the audit library refuses to start and the
service it lives in either crashes or runs without audit logging,
both bad outcomes for a compliance-sensitive system.

`audit-validate` runs the same loader as the library
([`outputconfig.Load`][load]) against the same taxonomy your
binary embeds. If it exits zero, the runtime will accept the
config. If it exits non-zero, it tells you which class of error
fired and where, before any deployment happens.

It's deliberately a separate binary from
[`audit-gen`](../audit-gen/): different audience (developers vs
operators), different lifecycle (build time vs deploy time), so
neither pulls in the other's machinery.

The default release binary is **offline-only** — it has no secret
providers compiled in and rejects `ref+SCHEME://...` references in
the outputs YAML as semantic errors. Validate against a live Vault
or OpenBao by building a custom validator that blank-imports the
relevant `github.com/axonops/audit/secrets/...` sub-modules.

## Install

```bash
# As a binary (recommended for CI):
go install github.com/axonops/audit/cmd/audit-validate@latest

# Or via go run (one-shot, no install):
go run github.com/axonops/audit/cmd/audit-validate@latest \
    -taxonomy taxonomy.yaml -outputs outputs.yaml
```

Pre-built binaries for `linux/{amd64,arm64}`, `darwin/{amd64,arm64}`,
and `windows/amd64` are attached to every release tag at
<https://github.com/axonops/audit/releases>.

Requires Go 1.26+ when installing from source.

## Usage

```bash
audit-validate -taxonomy <file|-> -outputs <file|-> [flags]
```

| Flag | Default | Effect |
|------|---------|--------|
| `-taxonomy` | _(required)_ | Path to the taxonomy YAML, or `-` for stdin. |
| `-outputs` | _(required)_ | Path to the outputs YAML, or `-` for stdin. |
| `-format` | `text` | Output format: `text` (human-readable) or `json` (machine-readable). |
| `-quiet` | `false` | Suppress all output; rely on the exit code only. |
| `-resolve-secrets` | `false` | Reserved. The default release binary rejects this flag because it has no secret providers compiled in. |
| `-version` | — | Print version and exit. |

Only one of `-taxonomy` / `-outputs` may be `-` at a time (stdin
can only be read once).

### Exit codes

| Code | Class | Meaning |
|------|-------|---------|
| `0` | valid | Configuration passes parse, schema, and semantic checks. |
| `1` | parse | File missing or YAML failed to parse. |
| `2` | schema | Required field missing, wrong type, unknown field, usage error, stdin double-use, or `-resolve-secrets` on an offline binary. |
| `3` | semantic | Route references an unknown event type or category, unknown output type, or an unresolved `ref+` secret string. |

The three classes are distinct on purpose: a parse error means
"the file is broken" (typically a hand-edit mistake); a schema
error means "the file is well-formed YAML but doesn't match the
expected structure"; a semantic error means "the file is valid
YAML matching the structure but contradicts the taxonomy".

## Quick start

Given a `taxonomy.yaml` defining `user_create` and `user_delete`
events grouped under a `write` category, and the following
`outputs.yaml`:

```yaml
version: 1
app_name: example
host: localhost
outputs:
  stdout:
    type: stdout
  audit-file:
    type: file
    file:
      path: /var/log/audit.jsonl
    route:
      include_categories:
        write: {}
```

Run:

```bash
$ audit-validate -taxonomy taxonomy.yaml -outputs outputs.yaml
audit-validate: configuration is valid
$ echo $?
0
```

Now introduce a typo — route the `wirte` category instead of `write`:

```bash
$ audit-validate -taxonomy taxonomy.yaml -outputs outputs.yaml
audit-validate: semantic error: output "audit-file": route references unknown taxonomy entries: category "wirte" not found
$ echo $?
3
```

Machine-readable form for downstream tooling:

```bash
$ audit-validate -format json -taxonomy taxonomy.yaml -outputs outputs.yaml
{
  "errors": [
    {
      "code": "semantic",
      "message": "route 0 references unknown taxonomy entries: category \"wirte\" not found"
    }
  ],
  "valid": false
}
```

### stdin

For Kubernetes templating pipelines that don't write the rendered
YAML to disk:

```bash
helm template ./chart | yq '.data."outputs.yaml"' \
    | audit-validate -taxonomy ./taxonomy.yaml -outputs -
```

## CI integration

Gate every PR that touches `taxonomy.yaml` or `outputs.yaml`:

```yaml
# .github/workflows/ci.yml
name: validate audit config
on:
  pull_request:
    paths:
      - 'taxonomy.yaml'
      - 'config/outputs/**.yaml'

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - uses: actions/setup-go@v6
        with:
          go-version: '1.26'

      - name: Install audit-validate
        run: go install github.com/axonops/audit/cmd/audit-validate@v0.2.3

      - name: Validate every env
        run: |
          for f in config/outputs/*.yaml; do
            echo "::group::$f"
            audit-validate -taxonomy taxonomy.yaml -outputs "$f"
            echo "::endgroup::"
          done
```

Exit code 3 (semantic) typically indicates the taxonomy and
outputs drifted apart — for example, an event type was renamed in
`taxonomy.yaml` but the route in `outputs.yaml` still references
the old name. Wire both files to the same review path.

## See also

- [Validation guide][val-doc] — full workflow, including
  custom-built validators with secret providers blank-imported
- [Taxonomy YAML reference][tax-doc] — the schema validated against
- [Output configuration reference][out-doc] — what goes in `outputs.yaml`
- Related tools: [`audit-gen`](../audit-gen/),
  [`bdd-report`](../bdd-report/),
  [`junit-report`](../junit-report/)
- [Source](https://github.com/axonops/audit/tree/main/cmd/audit-validate)

[godoc-badge]: https://pkg.go.dev/badge/github.com/axonops/audit/cmd/audit-validate.svg
[godoc]: https://pkg.go.dev/github.com/axonops/audit/cmd/audit-validate
[parent]: https://github.com/axonops/audit
[val-doc]: https://github.com/axonops/audit/blob/main/docs/validation.md
[tax-doc]: https://github.com/axonops/audit/blob/main/docs/taxonomy-validation.md
[out-doc]: https://github.com/axonops/audit/blob/main/docs/output-configuration.md
[load]: https://pkg.go.dev/github.com/axonops/audit/outputconfig#Load
